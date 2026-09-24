"""
engines/secrets.py -- hardcoded credential scanner.

Semgrep only opens files it can parse as code. The credentials that actually leak
out of vibe-coded projects usually are not in code: they sit in .env, config.json,
docker-compose.yml, a notebook cell, or pasted into a README. This engine reads
every text file in the project as raw lines, so file type is irrelevant.

Two design rules drive everything below, both aimed at the same failure mode --
a non-technical user who gets twenty false CRITICALs stops using the tool:

  1. Provider-specific formats over generic guessing. "AKIA" plus 16 uppercase
     characters is an AWS key and nothing else. A 32-character string is not
     evidence of anything.
  2. Severity depends on reachability, not just presence. A key in a gitignored
     .env is a different problem from the same key committed to history, and the
     report says so.
"""

import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass


class SecretScanError(Exception):
    """Raised when the scan cannot run at all (bad target, unreadable root)."""


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretPattern:
    id: str                  # stable rule id, becomes part of check_id
    name: str                # human label, e.g. "AWS Access Key ID"
    severity: str            # ERROR | WARNING | INFO, matching Semgrep's scale
    regex: re.Pattern
    remediation: str
    secret_group: int = 0    # which capture group holds the credential itself
    confidence: str = "high"
    # When set, the rule applies only to files whose basename matches. Used to
    # keep env-file syntax rules away from source code, where the same shape
    # means something entirely different.
    filename_re: object = None


def _p(id, name, severity, pattern, remediation, secret_group=0,
       confidence="high", flags=0, filename_re=None):
    return SecretPattern(
        id, name, severity, re.compile(pattern, flags), remediation,
        secret_group, confidence,
        re.compile(filename_re, re.IGNORECASE) if filename_re else None,
    )


# Ordered roughly by how badly a leak hurts. Every regex here is anchored to a
# format the provider actually issues -- there are no "long random-looking string"
# rules, which is where generic scanners generate most of their noise.
PATTERNS = [
    _p("private-key", "Private key file contents", "ERROR",
       r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----",
       "Move the key out of the repo, then reissue it. Anything that had a copy of "
       "this file has the key."),

    _p("aws-access-key-id", "AWS Access Key ID", "ERROR",
       r"\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b",
       "Deactivate the key in IAM, then create a new one and read it from an "
       "environment variable. AWS keys are scraped from public repos within minutes.",
       secret_group=1),

    _p("aws-secret-access-key", "AWS Secret Access Key", "ERROR",
       r"(?i)aws[_\-.]?secret[_\-.]?access[_\-.]?key\W{0,4}([A-Za-z0-9/+=]{40})\b",
       "Deactivate the key pair in IAM and issue a new one.",
       secret_group=1),

    _p("anthropic-api-key", "Anthropic API key", "ERROR",
       r"\b(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,120})\b",
       "Revoke it at console.anthropic.com and load the new key from the environment.",
       secret_group=1),

    _p("openai-project-key", "OpenAI API key", "ERROR",
       r"\b(sk-proj-[A-Za-z0-9_\-]{40,})",
       "Revoke it at platform.openai.com/api-keys and load the new key from the "
       "environment.",
       secret_group=1),

    _p("openai-legacy-key", "OpenAI API key (legacy format)", "ERROR",
       r"\b(sk-(?!ant-|proj-)[A-Za-z0-9]{48})\b",
       "Revoke it at platform.openai.com/api-keys and load the new key from the "
       "environment.",
       secret_group=1),

    # pk_live_ is deliberately absent: Stripe publishable keys are meant to ship in
    # client code. Flagging them is the classic false positive that makes a security
    # tool look like it does not understand the platform it is auditing.
    _p("stripe-live-secret", "Stripe live secret key", "ERROR",
       r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,99})\b",
       "Roll the key in the Stripe dashboard immediately. A live secret key can move "
       "real money.",
       secret_group=1),

    _p("stripe-test-secret", "Stripe test secret key", "INFO",
       r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,99})\b",
       "Test keys cannot touch real money, so this is low risk -- but keep the habit "
       "of loading keys from the environment.",
       secret_group=1),

    _p("github-token", "GitHub access token", "ERROR",
       r"\b(gh[pousr]_[A-Za-z0-9]{36})\b",
       "Revoke it in GitHub Settings > Developer settings > Tokens. A token with repo "
       "scope can push to every repo you can push to.",
       secret_group=1),

    _p("github-fine-grained-pat", "GitHub fine-grained token", "ERROR",
       r"\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b",
       "Revoke it in GitHub Settings > Developer settings > Tokens.",
       secret_group=1),

    _p("google-api-key", "Google API key", "ERROR",
       r"\b(AIza[A-Za-z0-9_\-]{35})\b",
       "Delete the key in Google Cloud Console. If you must expose one in a browser "
       "app, restrict it by HTTP referrer and by API.",
       secret_group=1),

    _p("slack-token", "Slack token", "ERROR",
       r"\b(xox[abprs]-[A-Za-z0-9\-]{10,72})\b",
       "Revoke it in your Slack app's OAuth settings.",
       secret_group=1),

    _p("slack-webhook", "Slack incoming webhook URL", "WARNING",
       r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)",
       "Anyone with this URL can post into the channel. Regenerate it in the Slack "
       "app config.",
       secret_group=1),

    _p("sendgrid-api-key", "SendGrid API key", "ERROR",
       r"\b(SG\.[A-Za-z0-9_\-]{20,24}\.[A-Za-z0-9_\-]{39,45})\b",
       "Delete the key in SendGrid. A stolen mail key gets used to send phishing from "
       "your own domain.",
       secret_group=1),

    _p("npm-token", "npm access token", "ERROR",
       r"\b(npm_[A-Za-z0-9]{36})\b",
       "Revoke it with `npm token revoke`. A publish-scoped token lets someone ship "
       "code to your package name.",
       secret_group=1),

    _p("pypi-token", "PyPI API token", "ERROR",
       r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})",
       "Revoke it in your PyPI account settings.",
       secret_group=1),

    _p("twilio-api-key", "Twilio API key SID", "WARNING",
       r"(?i)twilio\W{0,20}\b(SK[0-9a-fA-F]{32})\b",
       "Delete the key in the Twilio console. This rule requires the word 'twilio' "
       "nearby, because SK plus 32 hex characters is otherwise a common shape.",
       secret_group=1, confidence="medium"),

    _p("db-connection-password", "Database URL with embedded password", "ERROR",
       r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)"
       r"://[^\s'\"<>:@/]+:([^\s'\"<>@/]{3,})@[^\s'\"<>]+)",
       "Rotate the database password and build the URL from environment variables.",
       secret_group=1),

    _p("jwt", "JSON Web Token", "WARNING",
       r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})",
       "A JWT in source is usually a copied-in session token. If it is a signing "
       "secret instead, rotate it -- anyone holding it can mint valid logins.",
       secret_group=1, confidence="medium"),

    _p("gcp-service-account", "Google service account key file", "ERROR",
       r"\"type\"\s*:\s*\"(service_account)\"",
       "Delete the key in Google Cloud IAM. This file authenticates as the service "
       "account it names.",
       secret_group=1),

    # The catch-all, in two halves. Deliberately WARNING, not ERROR: it matches a
    # naming convention rather than a credential format.
    #
    # WHY THE VALUE MUST BE QUOTED HERE
    #   The first version accepted unquoted values so it could read .env syntax
    #   (API_KEY=abc123). Run against 12,775 files of real third-party code that
    #   produced 554 false positives and 8 true ones -- because in a *code* file an
    #   unquoted value is a reference, not a credential:
    #       api_key=resolved_api_key,
    #       api_key_env_vars: Sequence[str] = (...)
    #   Every one of those is the correct pattern being flagged as the bug. None of
    #   the 554 were in a .env file.
    #
    #   So quoted values are matched everywhere, and the unquoted form is scoped to
    #   the env-style files where it is the actual syntax. Fixtures never caught
    #   this: they were all written as NAME = "literal".
    _p("generic-assigned-secret", "Hardcoded credential", "WARNING",
       # The leading class includes quotes so JSON and YAML keys match too:
       # `"api_key": "..."` has a quote immediately before the name.
       r"(?:^|[\s{,;(\"'])(?:export\s+)?"
       r"([A-Za-z0-9_.\-]*(?:api[_\-]?key|apikey|secret|token|password|passwd|pwd)"
       r"[A-Za-z0-9_.\-]*)"
       # The optional quote before [:=] closes a JSON or YAML key. Without it the
       # rule never matched `"api_key": "..."` at all -- the leading quote was
       # allowed but the closing one was not, so the whole JSON case was dead.
       r"[\"']?\s*[:=]\s*[\"']([^\"'\n]{8,})[\"']",
       "Read this from an environment variable instead of writing it into the file.",
       secret_group=2, confidence="medium", flags=re.IGNORECASE),

    # The unquoted half, scoped to configuration formats rather than to code.
    #
    # The distinction that matters is not "env file" but "config file": in .env,
    # YAML, INI and TOML an unquoted value is a literal, so `POSTGRES_PASSWORD:
    # hunter2` really is a committed credential. In Python or JavaScript the same
    # shape is one identifier assigned to another, which is the correct pattern,
    # not the bug. Scoping this to .env alone lost the docker-compose case.
    _p("config-assigned-secret", "Hardcoded credential in a config file", "WARNING",
       r"^\s*(?:export\s+|-\s+)?"
       r"([A-Za-z0-9_.\-]*(?:api[_\-]?key|apikey|secret|token|password|passwd|pwd)"
       r"[A-Za-z0-9_.\-]*)"
       r"\s*[:=]\s*[\"']?([^\"'\s#]{8,})[\"']?\s*$",
       "Read this from the environment at runtime rather than committing the value.",
       secret_group=2, confidence="medium", flags=re.IGNORECASE | re.MULTILINE,
       filename_re=r"(^|[./])\.?env(\.|$)|\.env$"
                   r"|\.(ya?ml|ini|cfg|conf|toml|properties)$"
                   r"|^docker-?compose|^Dockerfile"),
]


# ---------------------------------------------------------------------------
# False-positive filters
# ---------------------------------------------------------------------------

# Substrings that mean "this is a stand-in, not a credential". Checked
# case-insensitively against the matched value.
PLACEHOLDER_MARKERS = (
    "example", "changeme", "change_me", "placeholder", "your_", "your-", "yourkey",
    "dummy", "sample", "insert", "replace", "todo", "fixme", "xxxx", "...",
    "<", ">", "{{", "}}", "${", "%s", "abc123", "foobar", "notarealkey",
    "redacted", "hunter2", "password", "123456", "test_key", "fake",
    # Local-only hosts. A password that only works against a database on the
    # developer's own machine is not a credential leak worth waking someone up
    # for, and "postgresql://user:password@localhost/dbname" appears in roughly
    # every .env.example on earth. Remove these two if you want them reported.
    "localhost", "127.0.0.1",
    # Documentation connection strings. Every one of these was a false positive
    # in library docstrings when run over real third-party code -- polars,
    # ultralytics and others all document their URI format this way.
    "user:pass@", "username:password@", "user:password@", "://user:",
    "://username:", "://root:", "://admin:", ":port/",
)

# A value that is just a reference to a real secret stored elsewhere. Very common
# in exactly the files this engine reads, and never a finding.
INDIRECTION_MARKERS = (
    "os.environ", "os.getenv", "process.env", "getenv(", "config(", "secrets.",
    "vault", "$env:", "import.meta.env",
)


# Matches a dotted identifier such as `settings.SECRET_KEY` -- a reference to a
# credential rather than the credential itself.
_DOTTED_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")


def _looks_like_placeholder(value, generic=False):
    """True when the matched value is a stand-in rather than a real credential.

    `generic` enables the looser checks that only make sense for the catch-all
    name-based rule. They are too aggressive to apply to provider formats -- a
    real SendGrid key contains dots and would be thrown away by the dotted
    identifier check below.
    """
    low = value.lower()
    if any(marker in low for marker in PLACEHOLDER_MARKERS):
        return True
    if any(marker in low for marker in INDIRECTION_MARKERS):
        return True
    # "your_api_key_here" and friends: all lowercase words, few distinct characters.
    if re.fullmatch(r"[a-z_\-]+", low) and len(set(low)) < 12:
        return True
    # Repeated single character, e.g. "xxxxxxxxxxxx" or "000000000000".
    if len(set(value)) <= 2:
        return True

    if generic:
        # `password = get_password()` -- credentials never contain parentheses,
        # so anything that does is code fetching one from somewhere safer.
        if "(" in value or ")" in value:
            return True
        # `api_key = settings.OPENAI_KEY` -- same reasoning.
        if _DOTTED_IDENT_RE.fullmatch(value):
            return True

        # The four shapes below were every remaining false positive when this
        # engine was run over 12,775 files of real third-party code. None of
        # them is a credential, and all four are common in correct code.
        #
        #   TOKEN_COMMENT_BEGIN: "begin of comment"     -- a human label
        if any(ch.isspace() for ch in value):
            return True
        #   ENV_API_KEY = "ANTHROPIC_API_KEY"           -- a variable's *name*
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", value):
            return True
        #   TOKEN_ENDPOINT = "/v1/oauth/token"          -- a route or URL
        if value.startswith("/") or "://" in value:
            return True
        #   CHALLENGE_PASSWORD: "challengePassword"     -- an identifier as text
        if re.fullmatch(r"[A-Za-z]+", value):
            return True

        # Three more, every one of them measured on 13,107 files of installed
        # third-party libraries rather than imagined.
        #
        #   szOID_RSA_challengePwd = "1.2.840.113549.1.9.7"  -- an X.509 OID.
        # Digits and dots, never a credential. The existing dotted-identifier
        # check misses these because it requires a letter to start.
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", value):
            return True
        #   token_endpoint_auth_method="private_key_jwt"     -- a method name
        #   "adls.sas-token": "azure_storage_sas_key"        -- a config key
        # Lowercase words joined by _ . or -, each optionally ending in digits.
        # The separator is load-bearing: it is what distinguishes these from a
        # real lowercase secret like 8f4c2e9a7b1d6350fae82c94d17b0e63, which has
        # no separators, and from sk_live_51QpR7m..., whose last segment is not
        # lowercase-alphabetic. Without the separator requirement this filter
        # would eat genuine hex credentials.
        if re.fullmatch(r"[a-z]+[0-9]*(?:[_.\-][a-z]+[0-9]*)+", value):
            return True
        #   f"AccessToken(token='{masked}')"                 -- an interpolation
        # A value with braces is a template; the real value is computed at run
        # time and is not in the file. PLACEHOLDER_MARKERS already has "{{" and
        # "${" but single braces are what f-strings actually use.
        if "{" in value and "}" in value:
            return True
    return False


# A run of base64 long enough to be actual key material rather than a word.
_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")


def _pem_has_body(lines, lineno, line, match_end):
    """True when real key material follows a `-----BEGIN ... PRIVATE KEY-----`.

    WHY THIS EXISTS: cryptography's own ssh.py contains

        _SK_START = b"-----BEGIN OPENSSH PRIVATE KEY-----"

    which is the delimiter its parser looks *for*, not a key. Across 13,107
    files of installed libraries this was the only false positive rated
    critical -- the most expensive kind, because critical is the one a user
    drops everything to act on.

    A header on its own is a constant. A header followed by base64 is a leak.
    Both shapes are checked: the body may sit on the same line (a one-line
    PEM in a .env, newlines escaped) or on the next non-blank line (a real
    key pasted into a file).
    """
    if _PEM_BODY_RE.search(line, match_end):
        return True
    for following in lines[lineno:lineno + 3]:
        stripped = following.strip()
        if not stripped:
            continue
        return bool(_PEM_BODY_RE.search(stripped))
    return False


def _shannon_entropy(value):
    """Bits of entropy per character. Used only to filter, never to detect."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(value):
    """Show enough to recognise which key it is, not enough to use it."""
    if len(value) <= 12:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)"


# ---------------------------------------------------------------------------
# Filesystem walking
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "venv", ".venv", "env", "virtualenv", "site-packages",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit",
    "coverage", ".idea", ".vscode", ".gradle", ".terraform",
}

# Binary or generated files. Lockfiles are excluded because their integrity hashes
# look exactly like credentials to a generic matcher.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".avif",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo", ".o", ".a",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".webm", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".db", ".sqlite", ".sqlite3", ".mdb", ".pack", ".idx",
}

SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum",
}

MAX_FILE_BYTES = 2_000_000
_MAX_LINE_LEN = 4000  # minified bundles produce single lines megabytes long


def iter_files(root, max_file_bytes=MAX_FILE_BYTES):
    """Yield absolute paths of candidate text files under root."""
    if os.path.isfile(root):
        yield os.path.abspath(root)
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # Mutating dirnames in place is what stops os.walk descending into them.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in SKIP_FILENAMES:
                continue
            if os.path.splitext(name)[1].lower() in SKIP_EXTENSIONS:
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > max_file_bytes:
                    continue
            except OSError:
                continue
            yield os.path.abspath(full)


def _read_lines(path):
    """Return the file's lines, or None if it is binary or unreadable."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
            if b"\x00" in head:      # NUL byte: binary, whatever the extension claims
                return None
            rest = fh.read()
    except OSError:
        return None
    return (head + rest).decode("utf-8", errors="replace").splitlines()


# ---------------------------------------------------------------------------
# Git awareness -- the difference between "exposed" and "merely present"
# ---------------------------------------------------------------------------

def norm_path(path):
    """Canonical form for path comparison.

    normcase matters on Windows: git reports the repo root with forward slashes
    and its own idea of drive-letter case, so raw string equality against an
    os.walk path fails even when both name the same file.
    """
    return os.path.normcase(os.path.abspath(path))


def tracked_files(root):
    """Normalised paths of files git is tracking, or None if root is not a repo.

    One subprocess call for the whole tree. Running `git ls-files --error-unmatch`
    per file would be one process per file and unusably slow on a real project.

    --full-name is load-bearing. Without it `git ls-files` reports paths relative
    to the directory it was invoked in, so scanning a subdirectory yields bare
    filenames that resolve against the repo root to files that do not exist, and
    every tracked file silently looks untracked.
    """
    base = root if os.path.isdir(root) else os.path.dirname(root)
    base = base or "."
    try:
        proc = subprocess.run(["git", "-C", base, "ls-files", "--full-name", "-z"],
                              capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return None
        top = subprocess.run(["git", "-C", base, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=30)
        if top.returncode != 0:
            return None
    except (OSError, subprocess.TimeoutExpired):
        return None

    repo_root = top.stdout.strip()
    return {
        norm_path(os.path.join(repo_root, rel))
        for rel in proc.stdout.split("\0") if rel
    }


_ENV_FILE_RE = re.compile(r"(^|[./])\.?env(\.|$)", re.IGNORECASE)
_TEMPLATE_MARKERS = (".example", ".sample", ".template", ".dist")


def _exposure(path, tracked):
    """Classify how exposed a file is. Returns (label, downgrade, note).

    `downgrade` counts steps toward less severe: 1 turns ERROR into WARNING.
    """
    name = os.path.basename(path)
    is_env = bool(_ENV_FILE_RE.search(name))
    is_template = any(s in name.lower() for s in _TEMPLATE_MARKERS)

    if tracked is None:
        return ("unknown", 0, "")

    if norm_path(path) in tracked:
        if is_template:
            return ("committed-template", 0,
                    "This is a committed template file. A real key here reaches "
                    "everyone who clones the repo.")
        return ("committed", 0,
                "This file is committed to git, so the credential is in your "
                "repository history even if you delete the line now.")

    if is_env:
        return ("local-env", 1,
                "This .env file is not tracked by git, which is correct. Still rotate "
                "the key if the file has ever been shared or deployed.")
    return ("untracked", 1,
            "This file is not tracked by git, so it is not in your repo history.")


_SEVERITY_STEPS = ["ERROR", "WARNING", "INFO"]


def _shift_severity(severity, downgrade):
    """Move `severity` `downgrade` steps toward INFO, clamped at both ends."""
    try:
        idx = _SEVERITY_STEPS.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_STEPS[max(0, min(len(_SEVERITY_STEPS) - 1, idx + downgrade))]


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

# A repo with more historical blobs than this is not the audience for this tool,
# and streaming all of them through cat-file stops being instant. Hitting the cap
# produces a visible finding rather than a quietly shorter report.
MAX_HISTORY_BLOBS = 20000


def _git(root, args, binary=False):
    """Run a git command in `root`. Returns None when the command fails.

    A missing git executable raises instead, because that is a broken toolchain
    and the user should be told. A non-zero exit is ordinary -- "not a
    repository" comes back that way -- and the caller decides what it means.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", root] + args,
            capture_output=True,
            timeout=120,
        )
    except FileNotFoundError:
        raise SecretScanError(
            "git is not installed or not on PATH, so history cannot be scanned."
        )
    if proc.returncode != 0:
        return None
    return proc.stdout if binary else proc.stdout.decode("utf-8", "replace")


def _blobs_only_in_history(root):
    """Blob SHAs that exist in history but not in the current commit.

    WHY THE DIFFERENCE, AND NOT EVERY BLOB
        A credential still present at HEAD is already reported by the
        working-tree scan, and reporting it twice under two headings teaches the
        reader that the history section is noise. What history scanning uniquely
        answers is the opposite case: *the secret you deleted*. Removing a key
        from a file and committing the removal looks like a fix and is not one --
        the old blob is still in the object store, still in every clone, and
        still recoverable by anyone who has ever pulled.

        That is also the case people get wrong most confidently, because the
        file looks clean when they check.

    Returns (blobs, current_blobs, truncated). `blobs` is a list of
    (sha, path); `current_blobs` is the same for what HEAD holds, which the
    caller needs in order to exclude credentials by VALUE as well as by blob.
    """
    everything = _git(root, ["rev-list", "--objects", "--all"])
    if everything is None:
        return None, None, False

    current, current_blobs = set(), []
    head = _git(root, ["ls-tree", "-r", "HEAD"])
    if head:
        for line in head.splitlines():
            # "<mode> blob <sha>\t<path>"
            meta, _, path = line.partition("\t")
            parts = meta.split()
            if len(parts) >= 3 and parts[1] == "blob":
                current.add(parts[2])
                current_blobs.append((parts[2], path))

    blobs, seen = [], set()
    for line in everything.splitlines():
        sha, _, path = line.partition(" ")
        # Commits and trees appear here too; they have no path attached.
        if not path or sha in current or sha in seen:
            continue
        seen.add(sha)
        blobs.append((sha, path))

    truncated = len(blobs) > MAX_HISTORY_BLOBS
    return blobs[:MAX_HISTORY_BLOBS], current_blobs, truncated


def _read_blobs(root, shas):
    """Stream blob contents via one `git cat-file --batch`, not one call each."""
    if not shas:
        return {}
    proc = subprocess.Popen(
        ["git", "-C", root, "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    try:
        proc.stdin.write(("\n".join(shas) + "\n").encode())
        proc.stdin.close()
        out = {}
        for _ in shas:
            header = proc.stdout.readline()
            if not header:
                break
            parts = header.decode("utf-8", "replace").split()
            if len(parts) < 3:
                continue
            sha, kind, size = parts[0], parts[1], int(parts[2])
            payload = proc.stdout.read(size)
            proc.stdout.read(1)  # trailing newline
            if kind == "blob" and size <= MAX_FILE_BYTES:
                out[sha] = payload
        return out
    finally:
        proc.stdout.close()
        proc.wait(timeout=60)


def _commit_for_blob(root, sha):
    """The commit that INTRODUCED this blob, as (short_sha, iso_date).

    `git log --find-object` lists every commit where the blob entered or left,
    newest first -- so taking the first one names the commit that *removed* the
    credential. Reporting "committed in <the commit that deleted it>" is worse
    than reporting nothing: it sends someone to the wrong place in the history
    and makes the tool look wrong about the thing it is warning them about.
    The oldest entry is the one that added it.
    """
    out = _git(root, ["log", "--all", "--find-object", sha,
                      "--format=%h%x00%ad", "--date=short"])
    if not out:
        return None, None
    entries = [line for line in out.splitlines() if "\x00" in line]
    if not entries:
        return None, None
    short, _, date = entries[-1].partition("\x00")
    return short, date.strip()


def _iter_matches(lines, basename, min_entropy):
    """Yield (lineno, line, pattern, match, value) for every credential in `lines`.

    The single place the pattern list and the false-positive filters are
    applied. Both the working-tree scan and the git-history scan go through
    here, because two copies of a filter chain is two copies that drift, and the
    filters are most of what makes this engine worth running -- they are what
    took 563 findings on real library code down to 1.
    """
    for lineno, line in enumerate(lines, start=1):
        if len(line) > _MAX_LINE_LEN:
            continue

        for pattern in PATTERNS:
            if (pattern.filename_re is not None
                    and not pattern.filename_re.search(basename)):
                continue
            for match in pattern.regex.finditer(line):
                value = match.group(pattern.secret_group) or match.group(0)

                is_generic = pattern.id == "generic-assigned-secret"
                if _looks_like_placeholder(value, generic=is_generic):
                    continue
                if (pattern.id == "private-key"
                        and not _pem_has_body(lines, lineno, line, match.end())):
                    continue
                if (pattern.confidence == "medium"
                        and _shannon_entropy(value) < min_entropy):
                    continue

                yield lineno, line, pattern, match, value


def scan(target, min_entropy=2.0, max_file_bytes=MAX_FILE_BYTES):
    """Scan a file or directory for hardcoded credentials.

    Args:
        target: file or directory to scan.
        min_entropy: values below this many bits per character are dropped, for
            the medium-confidence rules only. Provider-format matches are never
            entropy-filtered -- a real AWS key ID is structured, not random.
        max_file_bytes: files larger than this are skipped.

    Returns:
        A list of Semgrep-shaped finding dicts. An empty list means clean.

    Raises:
        SecretScanError: the target does not exist.
    """
    if not os.path.exists(target):
        raise SecretScanError(f"Target does not exist: {target}")

    tracked = tracked_files(target)
    findings = []
    seen = set()  # (path, line, value) -- one credential yields one finding

    for path in iter_files(target, max_file_bytes):
        lines = _read_lines(path)
        if lines is None:
            continue

        exposure, downgrade, note = _exposure(path, tracked)
        basename = os.path.basename(path)

        for lineno, line, pattern, match, value in _iter_matches(
                lines, basename, min_entropy):
            key = (path, lineno, value)
            if key in seen:
                continue
            seen.add(key)

            message = f"{pattern.name} found in {os.path.basename(path)}."
            if note:
                message += " " + note
            message += " " + pattern.remediation

            findings.append({
                "check_id": f"safeship.secrets.{pattern.id}",
                "path": path,
                "start": {"line": lineno, "col": match.start() + 1},
                "end": {"line": lineno, "col": match.end() + 1},
                "extra": {
                    "message": message,
                    "severity": _shift_severity(pattern.severity, downgrade),
                    # The redacted line, never the raw one. A security report
                    # that prints the key it found has leaked it again --
                    # into logs, terminals, and pasted screenshots.
                    "lines": line.replace(value, _redact(value)).strip()[:200],
                    "metadata": {
                        "engine": "secrets",
                        "secret_type": pattern.name,
                        "redacted": _redact(value),
                        "confidence": pattern.confidence,
                        "exposure": exposure,
                        # Kept as separate fields as well as glued into
                        # `message`, so a report can lay them out under
                        # its own headings instead of printing the
                        # remediation twice.
                        "exposure_note": note,
                        "remediation": pattern.remediation,
                    },
                },
            })

    findings.sort(key=lambda f: (f["path"], f["start"]["line"]))
    return findings


def scan_history(target, min_entropy=2.0):
    """Find credentials that were committed and later removed.

    WHY THIS IS A SEPARATE PASS
        Deleting a key from a file and committing the removal looks like a fix
        and is not one. The old blob stays in the object store, in every clone,
        and in every fork, and `git show` brings it back in one command. The
        working-tree scan cannot see it, because by then the file is clean --
        which is exactly why people are confident the problem is gone.

        Benchmarking against gitleaks is what put this here. Its primary mode is
        history scanning and ours had none, so a credential removed from HEAD
        but alive in the reflog was one we missed completely.

    WHAT IT DELIBERATELY DOES NOT REPORT
        Anything still present at HEAD. The working-tree scan already has it,
        and listing it again under a second heading trains the reader to skim
        the history section. Only blobs absent from the current commit qualify.

    NO EXPOSURE DOWNGRADE
        `scan()` lowers severity for untracked files, because a credential that
        never reached git is a smaller problem. Nothing here qualifies: every
        finding is by definition something that was committed.

    Raises:
        SecretScanError: git is missing, or its history could not be read.

    A target that simply is not a git repository returns [] rather than
    raising. There is no history to examine, so nothing went unchecked -- and
    reporting "NOT SCANNED" for a directory that never had commits would cry
    wolf on the one warning that has to stay meaningful.
    """
    root = target if os.path.isdir(target) else os.path.dirname(os.path.abspath(target))
    root = root or "."

    inside = _git(root, ["rev-parse", "--is-inside-work-tree"])
    if inside is None or inside.strip() != "true":
        return []

    # Git reports blob paths relative to the repository root, which is not
    # necessarily the directory being scanned. Two things follow, and both were
    # wrong before they were handled:
    #
    #   - Paths must be made absolute against the repo root. Handing the report
    #     a repo-relative path made it render "../../../../../../.env".
    #   - Blobs outside the scan target must be dropped. Scanning one
    #     subdirectory of a monorepo otherwise reports credentials from every
    #     other project in it, which is not what the user asked about.
    toplevel = _git(root, ["rev-parse", "--show-toplevel"])
    if not toplevel:
        return []
    repo_root = toplevel.strip()
    target_abs = norm_path(root)

    blobs, current_blobs, truncated = _blobs_only_in_history(root)
    if blobs is None:
        raise SecretScanError(f"Could not read git history for {target}.")

    # Excluding by blob is not enough. A file that was reformatted, or had one
    # unrelated line changed, leaves an OLD blob containing the SAME credential
    # that is still sitting in HEAD -- so a blob-only check reports secrets the
    # working-tree scan already found, under a heading that says they were
    # deleted. Measured on this repo: 13 findings, 12 of them still in HEAD.
    # The unit that matters is the credential, not the object that held it.
    current_values = set()
    for sha, payload in _read_blobs(root, [s for s, _ in current_blobs]).items():
        if b"\x00" in payload[:8000]:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue
        basename = os.path.basename(dict(current_blobs).get(sha, ""))
        for _lineno, _line, _pattern, _match, value in _iter_matches(
                text.splitlines(), basename, min_entropy):
            current_values.add(value)

    def absolute(blob_path):
        return os.path.join(repo_root, blob_path.replace("/", os.sep))

    def in_scope(blob_path):
        candidate = norm_path(absolute(blob_path))
        return candidate == target_abs or candidate.startswith(target_abs + os.sep)

    blobs = [(sha, path) for sha, path in blobs if in_scope(path)]

    contents = _read_blobs(root, [sha for sha, _ in blobs])
    paths = dict(blobs)

    findings = []
    seen = set()

    for sha, payload in contents.items():
        # A NUL byte means binary; there is no line structure to scan.
        if b"\x00" in payload[:8000]:
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            continue

        rel = paths.get(sha, "")
        path = absolute(rel)
        basename = os.path.basename(rel)
        lines = text.splitlines()

        for lineno, line, pattern, match, value in _iter_matches(
                lines, basename, min_entropy):
            # Still present at HEAD: the working-tree scan owns this one.
            if value in current_values:
                continue

            # One credential, however many old blobs happen to contain it.
            key = (rel, value)
            if key in seen:
                continue
            seen.add(key)

            commit, date = _commit_for_blob(root, sha)
            where = f"{commit} ({date})" if commit else "an earlier commit"

            findings.append({
                "check_id": f"safeship.secrets.history.{pattern.id}",
                "path": path,
                "start": {"line": lineno, "col": match.start() + 1},
                "end": {"line": lineno, "col": match.end() + 1},
                "extra": {
                    "message": (
                        f"{pattern.name} committed in {where} and since removed "
                        f"from {basename or rel}. It is still in git history, so "
                        "it is still in every clone and fork of this repository. "
                        "Deleting the file did not revoke the credential. "
                        + pattern.remediation
                    ),
                    "severity": pattern.severity,
                    "lines": line.replace(value, _redact(value)).strip()[:200],
                    "metadata": {
                        "engine": "secrets",
                        "secret_type": pattern.name,
                        "redacted": _redact(value),
                        "confidence": pattern.confidence,
                        "exposure": "git history",
                        "exposure_note": (
                            "Removed from the working tree but recoverable with "
                            "`git show`. Rotate the credential; rewriting history "
                            "does not help anyone who already cloned."
                        ),
                        "history_commit": commit or sha[:7],
                        "history_date": date or "",
                        "remediation": pattern.remediation,
                    },
                },
            })

    if truncated:
        findings.append({
            "check_id": "safeship.secrets.history.truncated",
            "path": root,
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 1},
            "extra": {
                "message": (
                    f"History scan stopped after {MAX_HISTORY_BLOBS} objects. "
                    "Older history was not examined, so this section is "
                    "incomplete -- not clean."
                ),
                "severity": "WARNING",
                "lines": "",
                "metadata": {
                    "engine": "secrets",
                    "secret_type": "Incomplete history scan",
                    "confidence": "high",
                    "exposure": "git history",
                    "remediation": "Run gitleaks for a full history sweep.",
                },
            },
        })

    findings.sort(key=lambda f: (f["path"], f["start"]["line"]))
    return findings


_SEVERITY_WORDS = {"ERROR": "critical", "WARNING": "medium", "INFO": "low"}


def to_report_json(findings, root=None):
    """Flatten findings into the compact shape the CLI and report layer consume."""
    out = []
    for f in findings:
        path = f["path"]
        if root:
            try:
                path = os.path.relpath(path, root)
            except ValueError:
                pass  # different drive on Windows; keep the absolute path
        meta = f["extra"]["metadata"]
        out.append({
            "file": path.replace("\\", "/"),
            "line": f["start"]["line"],
            "secret_type": meta["secret_type"],
            "severity": _SEVERITY_WORDS.get(f["extra"]["severity"], "medium"),
            "confidence": meta["confidence"],
            "exposure": meta["exposure"],
            "redacted": meta["redacted"],
            "rule": f["check_id"],
            "remediation": meta["remediation"],
        })
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv

    if not args:
        print("usage: python engines/secrets.py <file-or-directory> [--json]")
        sys.exit(1)

    root = args[0]
    try:
        results = scan(root)
    except SecretScanError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(json.dumps(to_report_json(results, root), indent=2))
        sys.exit(0)

    if not results:
        print(f"No hardcoded credentials found in {root}")
        sys.exit(0)

    print(f"{len(results)} potential credential(s) in {root}\n")
    for item in to_report_json(results, root):
        print(f"  [{item['severity']:>8}] {item['file']}:{item['line']}")
        print(f"             {item['secret_type']} -- {item['redacted']}")
        print(f"             exposure: {item['exposure']}, confidence: {item['confidence']}")
        print()
