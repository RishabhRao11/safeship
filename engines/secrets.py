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
    "dummy", "sample", "insert", "replace", "todo", "fixme", "xxxx", "....",
    "<", ">", "{{", "}}", "${", "%s", "abc123", "foobar", "notarealkey",
    "redacted", "hunter2", "password123", "123456", "test_key", "fake",
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
                    if (pattern.confidence == "medium"
                            and _shannon_entropy(value) < min_entropy):
                        continue

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
