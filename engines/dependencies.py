"""
engines/dependencies.py -- known-vulnerable dependency checker.

The other two engines look for code you wrote. This one looks for code you
inherited. A vibecoder's biggest security surface is usually not their own 40
lines of Flask -- it is the 300 transitive packages an AI told them to install,
pinned to whatever version was current when the model was trained.

Findings come back Semgrep-shaped, like every other engine, so analyze.py does
not need to know this one talks to the network.

DATA SOURCE
    OSV.dev, Google's open vulnerability database. It aggregates GitHub Security
    Advisories, PyPA, RustSec, and others behind one free API with no key and no
    rate limit worth worrying about at our volume.

    Two calls per scan, not two per package:
      1. POST /v1/querybatch  -- one request for every dependency, returns only
                                 the IDs of anything affected.
      2. POST /v1/query       -- full details, but only for the packages that
                                 step 1 flagged. Usually a handful.
    Querying details for all N packages instead would mean N round trips to
    learn that most of them are fine.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_TIMEOUT = 30


class DependencyScanError(Exception):
    """Raised when the scan cannot run: bad target, or OSV unreachable."""


@dataclass
class Dependency:
    name: str
    version: str          # concrete version string
    ecosystem: str        # OSV ecosystem name: "PyPI" or "npm"
    path: str             # manifest the dependency was declared in
    line: int             # line within that manifest
    pinned: bool          # False when the version was inferred from a range
    source: str           # which file the version actually came from


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

# name[extras] followed by an operator and a version. Captures name and version
# separately so we can tell "==1.2.3" (exact) from ">=1.2.3" (a floor).
_REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*"
    r"(?P<op>==|>=|~=|<=|>|<|!=)?\s*"
    r"(?P<version>[A-Za-z0-9._*+!-]+)?"
)


def parse_requirements(path):
    """Parse a requirements.txt into Dependency records.

    Skips the things that are not packages: comments, blank lines, pip flags
    (-r, --index-url), editable installs, and direct URL/VCS requirements, which
    have no version OSV could match against.
    """
    deps = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        raise DependencyScanError(f"Could not read {path}: {exc}")

    for lineno, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line or "@" in line:
            continue

        match = _REQ_LINE_RE.match(line)
        if not match or not match.group("name"):
            continue
        version = match.group("version")
        if not version or "*" in version:
            # Unpinned. OSV needs a concrete version to answer, and guessing one
            # would produce findings about a version that may not be installed.
            continue

        deps.append(Dependency(
            name=match.group("name"),
            version=version,
            ecosystem="PyPI",
            path=path,
            line=lineno,
            pinned=match.group("op") == "==",
            source=os.path.basename(path),
        ))
    return deps


# Strips npm range syntax down to the base version: "^4.17.15" -> "4.17.15".
_NPM_RANGE_RE = re.compile(r"^[\^~>=<\s v]*([0-9]+(?:\.[0-9]+)*(?:-[A-Za-z0-9.]+)?)")


def _npm_base_version(spec):
    match = _NPM_RANGE_RE.match(spec or "")
    return match.group(1) if match else None


def parse_package_json(path):
    """Parse a package.json, preferring exact versions from package-lock.json.

    WHY THE LOCKFILE MATTERS
        package.json records intent ("^4.17.15" = anything compatible), the
        lockfile records reality (what is actually installed). Checking the
        manifest alone reports on a version that may not be the one running --
        it can both miss real vulnerabilities and invent ones already upgraded
        away. When a lockfile is present it wins.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
            manifest = json.loads(text)
            lines = text.splitlines()
    except (OSError, json.JSONDecodeError) as exc:
        raise DependencyScanError(f"Could not parse {path}: {exc}")

    locked = _load_lockfile(os.path.join(os.path.dirname(path), "package-lock.json"))

    declared = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (manifest.get(section) or {}).items():
            declared[name] = spec

    deps = []
    for name, spec in declared.items():
        if not isinstance(spec, str) or "://" in spec or spec.startswith("file:"):
            continue  # git/file/link dependency, no registry version to check

        if name in locked:
            version, pinned, source = locked[name], True, "package-lock.json"
        else:
            base = _npm_base_version(spec)
            if not base:
                continue
            version, pinned, source = base, spec == base, "package.json"

        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="npm",
            path=path,
            line=_find_line(lines, name),
            pinned=pinned,
            source=source,
        ))
    return deps


def _load_lockfile(lock_path):
    """Return {package_name: exact_version} from a package-lock.json, if present."""
    if not os.path.isfile(lock_path):
        return {}
    try:
        with open(lock_path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}

    versions = {}
    # lockfileVersion 2/3: a flat "packages" map keyed by install path.
    for install_path, meta in (data.get("packages") or {}).items():
        if not install_path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or install_path.split("node_modules/")[-1]
        if meta.get("version"):
            versions[name] = meta["version"]
    # lockfileVersion 1: a nested "dependencies" tree.
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version"):
            versions.setdefault(name, meta["version"])
    return versions


def _find_line(lines, name):
    """Best-effort line number for a package name inside a JSON manifest."""
    needle = f'"{name}"'
    for index, text in enumerate(lines, start=1):
        if needle in text:
            return index
    return 1


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements,
    "package.json": parse_package_json,
}


def find_manifests(target):
    """Locate dependency manifests under target (or target itself if it is one)."""
    if os.path.isfile(target):
        name = os.path.basename(target)
        return [target] if name in MANIFEST_PARSERS else []

    skip = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build"}
    found = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for filename in filenames:
            if filename in MANIFEST_PARSERS:
                found.append(os.path.join(dirpath, filename))
    return sorted(found)


# ---------------------------------------------------------------------------
# OSV.dev
# ---------------------------------------------------------------------------

def _post(url, payload, timeout):
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "vibesec"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise DependencyScanError(f"OSV returned HTTP {exc.code} for {url}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DependencyScanError(
            f"Could not reach OSV.dev ({exc}). This engine needs network access; "
            "run with --no-deps to skip it."
        )


def _affected_packages(deps, timeout):
    """One batch call. Returns the indexes of deps that have any known vuln."""
    hits = set()
    # OSV caps batch size; chunking keeps large projects working.
    for offset in range(0, len(deps), 500):
        chunk = deps[offset:offset + 500]
        payload = {"queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in chunk
        ]}
        results = _post(OSV_BATCH_URL, payload, timeout).get("results", [])
        for index, result in enumerate(results):
            if result.get("vulns"):
                hits.add(offset + index)
    return hits


def _details(dep, timeout):
    """Full vulnerability records for one dependency."""
    payload = {"package": {"name": dep.name, "ecosystem": dep.ecosystem},
               "version": dep.version}
    return _post(OSV_QUERY_URL, payload, timeout).get("vulns", [])


# ---------------------------------------------------------------------------
# Interpreting OSV records
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3,
                  "NONE": 4}
_OSV_TO_SEMGREP = {"CRITICAL": "ERROR", "HIGH": "ERROR", "MODERATE": "WARNING",
                   "MEDIUM": "WARNING", "LOW": "INFO", "NONE": "INFO"}

# The report's own scale. Semgrep's three levels collapse CRITICAL and HIGH into
# ERROR, which would print a moderate-severity advisory and a remote-code-execution
# advisory identically. Reports read this instead.
OSV_SEVERITY_WORDS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
                      "MEDIUM": "medium", "LOW": "low", "NONE": "low",
                      "UNKNOWN": "medium"}


# CVSS v3.1 metric weights, from the specification's Table 15. PR depends on
# Scope: privileges buy you more when compromising one component lets you reach
# another, so the Changed column is weighted higher.
_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}


def parse_cvss_vector(vector):
    """Turn "CVSS:3.1/AV:N/AC:L/..." into {"AV": "N", "AC": "L", ...}."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        if key and value:
            metrics[key] = value
    return metrics or None


def _roundup(value):
    """CVSS's own rounding: the smallest one-decimal number >= value.

    Ordinary round() is wrong here and visibly so -- it turns a 8.95 into 8.9
    when the specification requires 9.0, which moves the advisory from High to
    Critical. This is the integer-arithmetic form given in the CVSS 3.1 spec.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0


def cvss3_base_score(vector):
    """Compute the CVSS v3.1 base score from a vector string, or None."""
    metrics = parse_cvss_vector(vector)
    if not metrics:
        return None
    try:
        scope = metrics.get("S", "U")
        av = _CVSS3_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS3_WEIGHTS["AC"][metrics["AC"]]
        ui = _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        pr = _CVSS3_PR[scope][metrics["PR"]]
        conf = _CVSS3_WEIGHTS["C"][metrics["C"]]
        integ = _CVSS3_WEIGHTS["I"][metrics["I"]]
        avail = _CVSS3_WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return None  # malformed or partial vector; better blank than invented

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope == "C":
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def _cvss_rating(score):
    """The CVSS qualitative rating band for a base score."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _vuln_severity(vuln):
    """Return (word, score, vector) for one OSV record.

    The curated word from database_specific wins when present -- it is what the
    GitHub advisory page shows, so it is what a user will see if they follow the
    link. The computed score is reported alongside it either way, and becomes the
    severity source for records that carry only a vector.
    """
    vector = None
    for entry in vuln.get("severity") or []:
        candidate = str(entry.get("score") or "")
        if entry.get("type") == "CVSS_V3" or candidate.startswith("CVSS:3"):
            vector = candidate
            break
    score = cvss3_base_score(vector)

    specific = vuln.get("database_specific") or {}
    word = (specific.get("severity") or "").upper()
    if word not in _SEVERITY_RANK:
        word = _cvss_rating(score)
    return word, score, vector


def _version_key(version):
    """Sort key for version strings.

    Two things this has to get right, both found by running it:

    "5.2b1" must sort BELOW "5.4". Splitting on separators gives the chunk "2b1",
    and treating any non-numeric chunk as a constant made every prerelease sort
    above every release -- so the tool recommended upgrading PyYAML to a beta.
    A numeric chunk with a suffix is a prerelease of that number, and ranks just
    under the bare number.
    """
    parts = []
    for chunk in re.split(r"[._-]", version or ""):
        match = re.match(r"(\d+)(.*)", chunk)
        if match:
            parts.append((int(match.group(1)), 0 if not match.group(2) else -1))
        else:
            parts.append((-1, 0))
    return parts


# OSV records the same fix in several coordinate systems. GIT ranges give commit
# SHAs, which are useless in a "pip install" line -- without this filter the tool
# told you to upgrade requests to c45d7c49ea75133e52ab22a8e9e13173938e36ff.
_VERSION_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}


def _fixed_versions(vuln, dep):
    """Every published version that OSV says fixes this vuln for our package."""
    fixes = []
    for affected in vuln.get("affected", []):
        package = affected.get("package") or {}
        if package.get("name", "").lower() != dep.name.lower():
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type", "").upper() not in _VERSION_RANGE_TYPES:
                continue
            for event in rng.get("events", []):
                if event.get("fixed"):
                    fixes.append(event["fixed"])
    return fixes


def _best_upgrade(fixes):
    """The version to recommend: the highest fix, preferring stable releases.

    Highest, because a package with several advisories needs the version that
    clears all of them. Stable, because "upgrade to 5.2b1" is not advice anyone
    should follow -- prereleases are only offered if nothing else fixes it.
    """
    if not fixes:
        return None
    stable = [f for f in fixes if not re.search(r"[a-zA-Z]", f)]
    return max(stable or fixes, key=_version_key)


def _cve_ids(vuln):
    return [alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")]


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

def scan(target, timeout=DEFAULT_TIMEOUT):
    """Check every dependency manifest under target against OSV.dev.

    Returns one finding per vulnerable *package*, not per CVE. A package with
    nine advisories is one action -- upgrade it -- and nine near-identical report
    entries would bury the other packages.
    """
    if not os.path.exists(target):
        raise DependencyScanError(f"Target does not exist: {target}")

    manifests = find_manifests(target)
    if not manifests:
        return []

    deps = []
    for manifest in manifests:
        parser = MANIFEST_PARSERS[os.path.basename(manifest)]
        deps.extend(parser(manifest))
    if not deps:
        return []

    affected = _affected_packages(deps, timeout)

    findings = []
    for index in sorted(affected):
        dep = deps[index]
        vulns = _details(dep, timeout)
        if not vulns:
            continue

        graded = [_vuln_severity(v) for v in vulns]
        worst = min((word for word, _, _ in graded),
                    key=lambda s: _SEVERITY_RANK.get(s, 9))
        # The highest base score across this package's advisories, with the vector
        # it came from so the number can be checked rather than trusted.
        scored = [(score, vec) for _, score, vec in graded if score is not None]
        top_score, top_vector = max(scored, key=lambda pair: pair[0]) if scored else (None, None)

        all_fixes = [f for v in vulns for f in _fixed_versions(v, dep)]
        upgrade_to = _best_upgrade(all_fixes)

        cves = sorted({c for v in vulns for c in _cve_ids(v)})
        ids = sorted({v["id"] for v in vulns})

        headline = (vulns[0].get("summary") or "").strip()
        message = (
            f"{dep.name} {dep.version} has {len(vulns)} known "
            f"{'vulnerability' if len(vulns) == 1 else 'vulnerabilities'}"
            f"{' (' + worst.lower() + ' severity' if worst != 'UNKNOWN' else ''}"
            f"{f', CVSS {top_score}' if top_score is not None else ''}"
            f"{')' if worst != 'UNKNOWN' else ''}. "
        )
        if headline:
            message += f"Most severe: {headline} "
        if upgrade_to:
            message += f"Upgrade to {upgrade_to} or later."
        else:
            message += "No fixed version is published yet; consider replacing it."
        if not dep.pinned:
            message += (
                f" Note: the version was read from {dep.source} as a range, not an "
                "exact pin, so the installed version may differ."
            )

        findings.append({
            "check_id": f"vibesec.dependencies.{dep.ecosystem.lower()}-known-vulnerability",
            "path": os.path.abspath(dep.path),
            "start": {"line": dep.line, "col": 1},
            "end": {"line": dep.line, "col": 1},
            "extra": {
                "message": message,
                "severity": _OSV_TO_SEMGREP.get(worst, "WARNING"),
                "lines": f"{dep.name}=={dep.version}",
                "metadata": {
                    "engine": "dependencies",
                    "package": dep.name,
                    "installed_version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "pinned": dep.pinned,
                    "version_source": dep.source,
                    "vulnerability_count": len(vulns),
                    "osv_ids": ids,
                    "cve_ids": cves,
                    "osv_severity": worst,
                    "cvss_score": top_score,
                    "cvss_vector": top_vector,
                    "fixed_version": upgrade_to,
                    "summary": headline,
                    "remediation": (
                        f"Upgrade {dep.name} to {upgrade_to} or later."
                        if upgrade_to else
                        f"No patched release of {dep.name} exists yet. Pin to a "
                        "different package or accept the risk deliberately."
                    ),
                },
            },
        })

    findings.sort(key=lambda f: (f["path"], f["start"]["line"]))
    return findings


def to_report_json(findings, root=None):
    """Flatten findings into the compact shape the CLI and report layer consume."""
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
            "package": meta["package"],
            "installed_version": meta["installed_version"],
            "ecosystem": meta["ecosystem"],
            "severity": OSV_SEVERITY_WORDS.get(meta["osv_severity"], "medium"),
            "cvss_score": meta["cvss_score"],
            "cvss_vector": meta["cvss_vector"],
            "vulnerability_count": meta["vulnerability_count"],
            "cve_ids": meta["cve_ids"],
            "osv_ids": meta["osv_ids"],
            "fixed_version": meta["fixed_version"],
            "remediation": meta["remediation"],
        })
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv

    if not args:
        print("usage: python engines/dependencies.py <file-or-directory> [--json]")
        sys.exit(1)

    root = args[0]
    try:
        results = scan(root)
    except DependencyScanError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if as_json:
        print(json.dumps(to_report_json(results, root), indent=2))
        sys.exit(0)

    if not results:
        print(f"No known-vulnerable dependencies found in {root}")
        sys.exit(0)

    print(f"{len(results)} vulnerable package(s) in {root}\n")
    for item in to_report_json(results, root):
        score = f"  CVSS {item['cvss_score']}" if item["cvss_score"] is not None else ""
        print(f"  [{item['severity']:>8}] {item['package']} {item['installed_version']}"
              f"  ({item['ecosystem']}){score}")
        print(f"             {item['file']}:{item['line']}")
        print(f"             {item['vulnerability_count']} advisory(ies)"
              + (f", {len(item['cve_ids'])} CVE(s): " + ", ".join(item['cve_ids'][:3])
                 if item['cve_ids'] else ""))
        print(f"             fix: {item['remediation']}")
        print()
