"""
engines/config.py -- insecure configuration and environment scanner.

Finds the settings people leave on the default that ships with the tutorial:
debug mode in production, CORS opened to the whole internet, TLS verification
switched off to make an error go away, databases published on 0.0.0.0.

TWO KINDS OF CHECK, AND WHY THEY ARE SEPARATED
    Presence checks say "this line is wrong": DEBUG = True, origin: "*". They
    are regexes over single lines, they are cheap, and they are confident.

    Absence checks say "something that should be here is missing": no rate
    limiting on a login route, no helmet() on an Express app. These are the
    dangerous ones. Anything can be missing for a good reason -- it lives in a
    reverse proxy, in Cloudflare, in a file we did not scan -- so an absence
    check that fires on thin evidence produces exactly the confident nonsense
    that makes people stop reading a report.

    So absence checks here obey one rule: only speak when there is positive
    evidence the thing should exist. Missing rate limiting is reported only if
    we found a web framework AND found a route that looks like authentication
    AND found no rate limiting library anywhere in the project. All three, or
    silence. They are reported once per project, never once per file, and they
    are capped at WARNING because we cannot see your infrastructure.
"""

import io
import json
import os
import re
import sys
import tokenize
from dataclasses import dataclass, field

try:
    from engines.secrets import SKIP_DIRS, norm_path, tracked_files
except ImportError:  # invoked as `python engines/config.py`, not as a package
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engines.secrets import SKIP_DIRS, norm_path, tracked_files


class ConfigScanError(Exception):
    """Raised when the scan cannot run at all (bad target)."""


# Files worth reading. Config lives in code as often as in config files, so this
# is deliberately broad -- but it is an allowlist, because reading every file in
# a repo to regex it for `DEBUG = True` finds it in documentation too.
SCAN_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env",
}
SCAN_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Procfile",
}
MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class ConfigRule:
    id: str
    name: str
    severity: str          # ERROR | WARNING | INFO
    regex: re.Pattern
    remediation: str
    # Only applied to files whose name matches. None means every scanned file.
    filename_hint: str = None
    confidence: str = "high"


def _r(id, name, severity, pattern, remediation, filename_hint=None,
       confidence="high", flags=0):
    return ConfigRule(id, name, severity, re.compile(pattern, flags),
                      remediation, filename_hint, confidence)


# ---------------------------------------------------------------------------
# Presence rules
# ---------------------------------------------------------------------------

PRESENCE_RULES = [
    # --- Debug mode -------------------------------------------------------
    _r("django-debug-true", "Django DEBUG enabled", "ERROR",
       r"^\s*DEBUG\s*=\s*True\b",
       "Set DEBUG = False and read it from an environment variable. With DEBUG on, "
       "any error page shows your source code, local variables, and settings -- "
       "including database credentials -- to whoever triggered the error.",
       filename_hint="settings.py", flags=re.MULTILINE),

    _r("flask-debug-true", "Flask debug mode enabled", "ERROR",
       r"\.run\s*\([^)]*debug\s*=\s*True",
       "Remove debug=True before deploying. Flask's debugger exposes an interactive "
       "Python console on the error page; anyone who reaches it can run code on "
       "your server."),

    _r("flask-debug-config", "Flask DEBUG config enabled", "ERROR",
       r"""(?:app\.config\[["']DEBUG["']\]|app\.debug)\s*=\s*True""",
       "Set this to False in production. It enables the same interactive debugger."),

    _r("env-debug-flag", "Debug flag enabled in environment file", "WARNING",
       r"^\s*(?:FLASK_DEBUG|DJANGO_DEBUG|DEBUG)\s*=\s*(?:1|true|True|TRUE)\s*$",
       "Turn this off for anything reachable from the internet.",
       filename_hint=".env", flags=re.MULTILINE),

    # --- CORS -------------------------------------------------------------
    _r("cors-allow-all-origins", "CORS opened to every origin", "ERROR",
       r"(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*=\s*True",
       "List the origins you actually serve instead. Allowing every origin lets any "
       "website read authenticated responses from your API using a visitor's session."),

    _r("cors-wildcard-header", "Access-Control-Allow-Origin set to *", "ERROR",
       r"""Access-Control-Allow-Origin["']?\s*[:,=]\s*["']\*["']""",
       "Replace * with the specific origins you serve. Combined with credentials "
       "this is the classic way an API leaks logged-in users' data to any site."),

    # Next.js and Netlify write headers as {key: ..., value: ...} objects rather
    # than "Header: value", so the rule above never sees them adjacent.
    _r("cors-wildcard-header-object", "Access-Control-Allow-Origin set to *",
       "ERROR",
       r"""key\s*:\s*["']Access-Control-Allow-Origin["']\s*,\s*"""
       r"""value\s*:\s*["']\*["']""",
       "Replace * with the specific origins you serve. Combined with credentials "
       "this is the classic way an API leaks logged-in users' data to any site.",
       flags=re.IGNORECASE),

    _r("express-cors-unconfigured", "Express cors() with no origin restriction",
       "WARNING",
       r"\buse\s*\(\s*cors\s*\(\s*\)\s*\)",
       "cors() with no arguments sends Access-Control-Allow-Origin: * on every "
       "route. Pass {origin: [...]} listing your front-end's URLs.",
       confidence="medium"),

    _r("cors-origin-wildcard-literal", "CORS origin configured as *", "ERROR",
       r"""origin\s*:\s*["']\*["']""",
       "Name the origins you serve. A wildcard here defeats the browser's "
       "same-origin protection for your API."),

    # --- Next.js ----------------------------------------------------------
    _r("nextjs-public-secret", "Secret published to the browser bundle", "ERROR",
       r"^\s*NEXT_PUBLIC_[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)"
       r"[A-Z0-9_]*\s*=\s*\S+",
       "Drop the NEXT_PUBLIC_ prefix and read this only in server code. Next.js "
       "inlines every NEXT_PUBLIC_ variable into the JavaScript it sends to "
       "browsers, so this value is readable by anyone who opens developer tools -- "
       "the prefix is a publication instruction, not a naming convention.",
       flags=re.MULTILINE),

    _r("nextjs-allow-svg", "Next.js image optimizer allows SVG", "WARNING",
       r"dangerouslyAllowSVG\s*:\s*true",
       "Remove dangerouslyAllowSVG. SVG files can carry scripts, so serving "
       "user-supplied ones through the image optimizer turns an avatar upload into "
       "stored cross-site scripting."),

    _r("nextjs-image-host-wildcard", "Next.js image host accepts any domain",
       "WARNING",
       r"""hostname\s*:\s*["']\*\*?["']|domains\s*:\s*\[\s*["']\*["']""",
       "List the image hosts you actually load from. A wildcard turns your image "
       "optimizer into an open proxy anyone can point at any URL, on your bandwidth "
       "and from your IP address."),

    # --- Transport security ----------------------------------------------
    _r("node-tls-verification-off", "TLS certificate verification disabled",
       "ERROR",
       r"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0",
       "Remove this. It disables certificate checking for every outbound HTTPS "
       "request in the process, so anyone on the network path can read and modify "
       "that traffic."),

    _r("reject-unauthorized-false", "TLS certificate verification disabled",
       "ERROR",
       r"rejectUnauthorized\s*:\s*false",
       "Remove this and fix the underlying certificate problem. It turns HTTPS into "
       "HTTP with extra steps."),

    _r("python-verify-false", "TLS certificate verification disabled", "ERROR",
       r"\b(?:requests|httpx|session)\b[^\n]{0,80}\bverify\s*=\s*False",
       "Remove verify=False. It makes the connection encrypted but unauthenticated, "
       "so a man-in-the-middle can impersonate the server.",
       confidence="medium"),

    # --- Cookies and hosts ------------------------------------------------
    _r("django-allowed-hosts-wildcard", "Django ALLOWED_HOSTS accepts any host",
       "WARNING",
       r"""^\s*ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']""",
       "List your real domains. A wildcard here enables Host header poisoning, "
       "which turns password-reset emails into links to an attacker's site.",
       filename_hint="settings.py", flags=re.MULTILINE),

    _r("session-cookie-insecure", "Session cookie not restricted to HTTPS",
       "WARNING",
       r"^\s*SESSION_COOKIE_SECURE\s*=\s*False",
       "Set SESSION_COOKIE_SECURE = True so the session cookie is never sent over "
       "plain HTTP where it can be read off the wire.",
       filename_hint="settings.py", flags=re.MULTILINE),

    _r("csrf-cookie-insecure", "CSRF cookie not restricted to HTTPS", "WARNING",
       r"^\s*CSRF_COOKIE_SECURE\s*=\s*False",
       "Set CSRF_COOKIE_SECURE = True.",
       filename_hint="settings.py", flags=re.MULTILINE),

    _r("cookie-httponly-false", "Cookie readable by JavaScript", "WARNING",
       r"httpOnly\s*:\s*false",
       "Set httpOnly: true so a cross-site scripting bug cannot read the session "
       "cookie and hand the account over.",
       confidence="medium"),

    # --- Containers and networking ---------------------------------------
    _r("compose-privileged", "Container running in privileged mode", "ERROR",
       r"^\s*privileged\s*:\s*true",
       "Remove privileged: true. It gives the container effectively root on the "
       "host, so a break-in inside the container is a break-in on the machine.",
       filename_hint="docker-compose", flags=re.MULTILINE),

    _r("compose-database-port-published", "Database port published to the host",
       "WARNING",
       r"^\s*-\s*[\"']?(?:0\.0\.0\.0:)?\d{2,5}:(?:5432|3306|27017|6379|9200|1433)[\"']?\s*$",
       "Remove the ports: entry for your database. Other containers reach it over "
       "the compose network already; publishing it exposes it to anything that can "
       "reach the host.",
       filename_hint="docker-compose", confidence="medium", flags=re.MULTILINE),

    _r("bind-all-interfaces-debug", "Development server bound to all interfaces",
       "INFO",
       r"\.run\s*\([^)]*host\s*=\s*[\"']0\.0\.0\.0[\"']",
       "Fine inside a container, risky on a laptop -- it publishes the development "
       "server to every network you join. Use a real WSGI server in production.",
       confidence="medium"),
]


# ---------------------------------------------------------------------------
# Project facts, gathered during the same pass, used by the absence checks
# ---------------------------------------------------------------------------

FRAMEWORK_SIGNS = {
    "express": re.compile(r"""require\(\s*["']express["']|from\s+["']express["']"""),
    "flask": re.compile(r"\bfrom\s+flask\s+import\b|\bFlask\s*\("),
    "fastapi": re.compile(r"\bfrom\s+fastapi\s+import\b|\bFastAPI\s*\("),
    "django": re.compile(r"\bINSTALLED_APPS\b|\bDJANGO_SETTINGS_MODULE\b"),
}

RATE_LIMIT_SIGNS = re.compile(
    r"express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|"
    r"fastify-rate-limit|@nestjs/throttler|"
    r"flask[-_]limiter|slowapi|django[-_]ratelimit|django-axes|"
    r"\bRateLimiter\b|\brate_limit\b|\bthrottle\b",
    re.IGNORECASE,
)

HELMET_SIGNS = re.compile(r"""require\(\s*["']helmet["']|from\s+["']helmet["']""")

# Route definitions that look like they handle credentials. Deliberately narrow:
# a false hit here creates a false absence finding, which is the worst kind.
AUTH_ROUTE_SIGNS = re.compile(
    r"""["'`/](?:login|signin|sign-in|signup|sign-up|register|auth|token|"""
    r"""password|forgot|reset|session)s?["'`/]""",
    re.IGNORECASE,
)


# Files that mark the root of a self-contained project. Used to scope the facts
# the absence checks reason over.
PROJECT_MARKERS = {
    "package.json", "requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
    "manage.py", "go.mod", "Cargo.toml", "composer.json", "Gemfile",
}


def project_roots(target):
    """Normalised directories that each count as one project.

    WHY THIS EXISTS
        Absence checks used one set of facts for the whole scan. In a monorepo
        that is wrong in the dangerous direction: an `import helmet` in one
        service marks the fact true, and the service next door that has no
        helmet is never reported. Facts have to be scoped to the project they
        were observed in.

    The scan root is always included, so files that belong to no marked project
    still have somewhere to go.
    """
    if os.path.isfile(target):
        return [norm_path(os.path.dirname(target) or ".")]

    roots = {norm_path(target)}
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(marker in filenames for marker in PROJECT_MARKERS):
            roots.add(norm_path(dirpath))
    # Longest first, so the nearest ancestor wins in _root_for().
    return sorted(roots, key=len, reverse=True)


def _root_for(path, roots):
    """The nearest ancestor project root for a file."""
    normalised = norm_path(path)
    for root in roots:  # already longest-first
        if normalised.startswith(root + os.sep) or normalised == root:
            return root
    return roots[-1] if roots else ""


@dataclass
class ProjectFacts:
    frameworks: set = field(default_factory=set)
    has_rate_limiting: bool = False
    has_helmet: bool = False
    auth_routes: list = field(default_factory=list)   # (path, line) pairs
    # Keyed by framework. A single shared entry_file let the Flask file claim it
    # first and then get reported for missing Express middleware.
    entry_files: dict = field(default_factory=dict)


def _observe(facts, path, line, text):
    """Accumulate project-wide facts from one line of one file."""
    for name, pattern in FRAMEWORK_SIGNS.items():
        if pattern.search(text):
            facts.frameworks.add(name)
            facts.entry_files.setdefault(name, path)
    if RATE_LIMIT_SIGNS.search(text):
        facts.has_rate_limiting = True
    if HELMET_SIGNS.search(text):
        facts.has_helmet = True
    # Only count a route-shaped line, not any string containing "token".
    if re.search(r"""\b(?:app|router|api)\.(?:get|post|put|patch|delete|route)\s*\(""", text) \
            or re.search(r"""@(?:app|router)\.(?:get|post|route)\s*\(""", text) \
            or re.search(r"""\bpath\s*\(|\bre_path\s*\(""", text):
        if AUTH_ROUTE_SIGNS.search(text):
            facts.auth_routes.append((path, line))


def _absence_findings(facts):
    """Run the absence checks. Silence unless the evidence is complete."""
    findings = []
    web = facts.frameworks & {"express", "flask", "fastapi", "django"}
    if not web:
        return findings

    if facts.auth_routes and not facts.has_rate_limiting:
        path, line = facts.auth_routes[0]
        others = len(facts.auth_routes) - 1
        findings.append(_absence_finding(
            "missing-rate-limiting",
            "No rate limiting found on authentication routes",
            path, line,
            f"This project defines {len(facts.auth_routes)} authentication-shaped "
            f"route(s) and imports no rate limiting library. Without one, an "
            f"attacker can try passwords as fast as your server will answer."
            + (f" First of {others + 1} shown." if others else ""),
            "Add a rate limiter in front of login and password-reset routes -- "
            "express-rate-limit for Express, flask-limiter for Flask, slowapi for "
            "FastAPI, django-axes for Django. If you already rate limit at a proxy "
            "or CDN, this finding is expected and can be ignored.",
        ))

    express_entry = facts.entry_files.get("express")
    if express_entry and not facts.has_helmet:
        findings.append(_absence_finding(
            "missing-helmet",
            "Express app without security headers middleware",
            express_entry, 1,
            "This Express app does not use helmet, so responses ship without "
            "the standard protective headers.",
            "Add `app.use(helmet())`. It sets Content-Security-Policy, "
            "X-Content-Type-Options, and related headers in one line. If your "
            "headers are set by a proxy instead, ignore this.",
        ))

    return findings


def _absence_finding(rule_id, name, path, line, message, remediation):
    """Absence findings are capped at WARNING -- we cannot see your proxy."""
    return {
        "check_id": f"safeship.config.{rule_id}",
        "path": os.path.abspath(path),
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 1},
        "extra": {
            "message": f"{message} {remediation}",
            "severity": "WARNING",
            "lines": "",
            "metadata": {
                "engine": "config",
                "issue": name,
                "check_type": "absence",
                "confidence": "medium",
                "remediation": remediation,
            },
        },
    }


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

def _should_scan(name):
    if name in SCAN_FILENAMES or name.startswith(".env"):
        return True
    if name.startswith("docker-compose") or name.startswith("next.config"):
        return True
    return os.path.splitext(name)[1].lower() in SCAN_EXTENSIONS


def iter_files(root):
    if os.path.isfile(root):
        yield os.path.abspath(root)
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not _should_scan(name):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield os.path.abspath(full)


def _is_triple_quoted(text):
    """True if a STRING token's text uses triple quotes, prefixes included."""
    body = text.lstrip("rRbBuUfF")
    return body.startswith('"""') or body.startswith("'''")


def _docstring_lines(lines):
    """1-indexed line numbers occupied by Python triple-quoted strings.

    Prose describing insecure config is not insecure config. This engine's own
    module docstring explains `origin: "*"` and was duly reported as a critical
    finding against itself.

    WHY tokenize AND NOT A REGEX
        The obvious approach -- scan for triple-quote delimiters and toggle a
        flag -- was tried and is wrong. It cannot tell a delimiter from the same
        characters inside an ordinary string, and this very module contains
        `re.compile(r'\"\"\"|...')`. That line flipped the flag with no matching
        close, which inverted the parser's idea of inside and outside for the
        rest of the file: every real docstring below it was then treated as code.
        Python's own tokenizer knows the difference, so it is what we use.

    Whole triple-quoted strings are excluded, not just multi-line ones. Live
    configuration is essentially never written inside one; documentation,
    templates, and rule definitions frequently are.
    """
    marked = set()
    source = "\n".join(lines) + "\n"
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.STRING and _is_triple_quoted(token.string):
                marked.update(range(token.start[0], token.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        # Unparseable file (Python 2, a template, a partial edit). Scanning every
        # line risks a false positive; skipping every line risks missing a real
        # finding. Prefer the noisy failure.
        return frozenset()
    return marked


_YAML_RULES_HEADER = re.compile(r"^rules\s*:\s*$", re.MULTILINE)


def _is_rule_definition(path, lines):
    """True for linter rule files, which describe bad patterns as their content.

    A Semgrep ruleset lists `Access-Control-Allow-Origin: '*'` because that is the
    thing it detects. Scanning it reports the rule as the vulnerability.
    """
    if os.path.splitext(path)[1].lower() not in (".yml", ".yaml"):
        return False
    head = "\n".join(lines[:200])
    return bool(_YAML_RULES_HEADER.search(head)) and "pattern" in head


_ENV_FAMILY_RE = re.compile(r"^\.env(\.|$)|\.env$", re.IGNORECASE)
_ENV_TEMPLATE_MARKERS = (".example", ".sample", ".template", ".dist")


def _committed_env_finding(path, tracked):
    """Report a .env file that is tracked by git. Returns a finding or None.

    This is a check on the file, not on its contents, and that distinction is the
    whole point. The secret engine reads a .env and reports the credentials it
    recognises -- but a committed .env whose values match no known provider
    format produces nothing at all, while still being a .env in your git history.
    The file being tracked is itself the finding.
    """
    if tracked is None:
        return None
    name = os.path.basename(path)
    if not _ENV_FAMILY_RE.search(name):
        return None
    # Templates are supposed to be committed; that is what they are for.
    if any(marker in name.lower() for marker in _ENV_TEMPLATE_MARKERS):
        return None
    if norm_path(path) not in tracked:
        return None

    remediation = (
        "Remove it from git with `git rm --cached " + name + "`, add it to "
        ".gitignore, and rotate every credential it held. Deleting the file in a "
        "later commit does not help -- it stays readable in the history."
    )
    return {
        "check_id": "safeship.config.dotenv-committed",
        "path": os.path.abspath(path),
        "start": {"line": 1, "col": 1},
        "end": {"line": 1, "col": 1},
        "extra": {
            "message": f"Environment file {name} is committed to git. {remediation}",
            "severity": "ERROR",
            "lines": "",
            "metadata": {
                "engine": "config",
                "issue": f"Environment file {name} is committed to version control",
                "check_type": "presence",
                "confidence": "high",
                "remediation": remediation,
            },
        },
    }


def _applies(rule, path):
    """Is this rule scoped to a particular filename?"""
    if rule.filename_hint is None:
        return True
    return rule.filename_hint in os.path.basename(path)


def scan(target):
    """Scan for insecure configuration. Returns Semgrep-shaped finding dicts."""
    if not os.path.exists(target):
        raise ConfigScanError(f"Target does not exist: {target}")

    findings = []
    tracked = tracked_files(target)

    # One ProjectFacts per project, not one per scan. See project_roots().
    roots = project_roots(target)
    facts_by_root = {root: ProjectFacts() for root in roots}

    for path in iter_files(target):
        env_finding = _committed_env_finding(path, tracked)
        if env_finding:
            findings.append(env_finding)

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue

        if _is_rule_definition(path, lines):
            continue

        # Computed once per file, not per rule.
        skip_lines = (_docstring_lines(lines)
                      if path.lower().endswith(".py") else frozenset())

        facts = facts_by_root[_root_for(path, roots)]

        for lineno, text in enumerate(lines, start=1):
            if len(text) > 2000 or lineno in skip_lines:
                continue
            _observe(facts, path, lineno, text)

            stripped = text.strip()
            # Skip comment-only lines: a rule that fires on
            # "# don't set DEBUG = True in production" is pure noise.
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue

            for rule in PRESENCE_RULES:
                if not _applies(rule, path):
                    continue
                match = rule.regex.search(text)
                if not match:
                    continue

                # NOTE: no git-exposure downgrade here, unlike the secret engine.
                # There it is sound -- a credential's risk really is a function of
                # whether it reached your history. Here it would conflate "is in
                # version control" with "is deployed", which are unrelated:
                # DEBUG = True is exactly as dangerous in an untracked settings.py
                # if that file is what ships. Downgrading on tracking would also
                # mute every finding in a project that has not run `git add` yet.
                findings.append({
                    "check_id": f"safeship.config.{rule.id}",
                    "path": path,
                    "start": {"line": lineno, "col": match.start() + 1},
                    "end": {"line": lineno, "col": match.end() + 1},
                    "extra": {
                        "message": f"{rule.name}. {rule.remediation}",
                        "severity": rule.severity,
                        "lines": stripped[:200],
                        "metadata": {
                            "engine": "config",
                            "issue": rule.name,
                            "check_type": "presence",
                            "confidence": rule.confidence,
                            "remediation": rule.remediation,
                        },
                    },
                })

    for facts in facts_by_root.values():
        findings.extend(_absence_findings(facts))
    findings.sort(key=lambda f: (f["path"], f["start"]["line"]))
    return findings


def to_report_json(findings, root=None):
    out = []
    for finding in findings:
        path = finding["path"]
        if root:
            try:
                path = os.path.relpath(path, root)
            except ValueError:
                pass
        meta = finding["extra"]["metadata"]
        out.append({
            "file": path.replace("\\", "/"),
            "line": finding["start"]["line"],
            "issue": meta["issue"],
            "check_type": meta["check_type"],
            "severity": {"ERROR": "critical", "WARNING": "medium",
                         "INFO": "low"}[finding["extra"]["severity"]],
            "confidence": meta["confidence"],
            "rule": finding["check_id"],
            "remediation": meta["remediation"],
        })
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv

    if not args:
        print("usage: python engines/config.py <file-or-directory> [--json]")
        sys.exit(1)

    root = args[0]
    try:
        results = scan(root)
    except ConfigScanError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(json.dumps(to_report_json(results, root), indent=2))
        sys.exit(0)

    if not results:
        print(f"No insecure configuration found in {root}")
        sys.exit(0)

    print(f"{len(results)} configuration issue(s) in {root}\n")
    for item in to_report_json(results, root):
        print(f"  [{item['severity']:>8}] {item['file']}:{item['line']}  ({item['check_type']})")
        print(f"             {item['issue']}")
        print(f"             {item['remediation'][:100]}")
        print()
