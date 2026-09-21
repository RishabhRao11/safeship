"""
analyze.py -- SafeShip's command-line entry point.

WHAT THIS DOES
    Runs every scanning engine over one target and prints a single report.

        Semgrep                 ->  patterns in parseable code
        engines/secrets         ->  credentials in any text file
        engines/dependencies    ->  known CVEs in declared packages (needs network)
                                ->  merge, dedupe by (file, line)
                                ->  Semgrep findings go to Claude for judgment
                                ->  the other engines already carry their answer
                                ->  print one report with a summary on top

USAGE
    python analyze.py myproject/                    # everything, all engines
    python analyze.py myproject/ --secrets-only     # offline, no API key needed
    python analyze.py myproject/ --no-deps          # skip the only networked engine
    python analyze.py myapp.py --config auto --config rules/vibe_patterns.yaml
    python analyze.py myapp.py --no-explain         # scan only, no API calls
    python analyze.py myproject/ --json             # machine-readable output
    python analyze.py myproject/ --html report.html # shareable single-file report

WHY THE ORCHESTRATION IS ITS OWN FILE
    scanner.py knows nothing about Claude. explainer.py knows nothing about Semgrep.
    Everything that knows about both lives here. That means when the report looks
    wrong you can immediately tell which layer to go debug -- and you can run any
    engine standalone (each has a __main__ block) to isolate the problem.

ADDING AN ENGINE
    Return Semgrep-shaped finding dicts, tag them with a "_engine" name in main(),
    and decide whether they need the LLM's judgment or already carry their answer.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter

import explainer
import report
import scanner
# Aliased because `secrets` is also a standard-library module. Importing ours
# under its bare name would shadow it for the whole file.
from engines import config as config_engine
from engines import dependencies as dependencies_engine
from engines import secrets as secrets_engine

# Lines of context below the flagged line, and the floor for context above it.
#
# Above the finding, extract_snippet() prefers the start of the enclosing function
# (see find_enclosing_start) and only falls back to this count when it cannot find
# one. It is a floor, never a ceiling: the window never shrinks below what this
# number alone would have given.
CONTEXT_LINES = 5

# Ceiling on the upward walk. A 300-line handler would otherwise put 300 lines in
# every prompt for one finding -- paying for tokens that mostly distract, on a
# per-finding basis across a whole scan.
MAX_LOOKBACK = 40

# What counts as the start of an enclosing scope. Deliberately covers Python and
# JavaScript/TypeScript in one pattern: findings arrive from Semgrep in either
# language, and the caller does not know which file it is looking at.
_SCOPE_START_RE = re.compile(
    r"""^\s*(?:
        (?:async\s+)?def\s+\w+                          # Python def / async def
      | class\s+\w+                                     # Python class
      | (?:export\s+)?(?:default\s+)?(?:async\s+)?function\b   # JS function decl
      | (?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*     # JS assigned function:
        (?:async\s*)?(?:function\b|\(|\w+\s*=>)          #   = function / = ( / = x =>
      | (?:app|router|api|server)\s*\.\s*\w+\s*\(        # Express route handler
    )""",
    re.VERBOSE,
)


def _indent(line):
    return len(line) - len(line.lstrip())


def find_enclosing_start(lines, start_line, max_lookback=MAX_LOOKBACK):
    """1-indexed line where the flagged line's enclosing scope begins, or None.

    WHY THIS EXISTS -- MEASURED, NOT GUESSED
        A fixed window is the wrong shape. `test_targets/safe_but_flagged.py` has
        one function, one allowlist, and three findings; the only difference
        between them is what the window happened to include. Line 52 saw the
        allowlist and was dismissed. Line 59 saw neither the definition nor the
        guard, and Claude invented a blind-SQLi payload to explain the gap --
        saying so in its own answer: "we don't see that check". A false positive
        on safe code is the one error this tool is built to avoid.

        No constant fixes it: that file wants 12 lines of lookback and
        `mass_assignment.py` wants 20. What both actually want is the function.

    Scope is decided by indentation, not by brace or block parsing: a line that
    both starts a scope AND is indented less than the finding encloses it. That
    is exactly true in Python and true in practice for formatted JavaScript,
    without this module having to know which language it is reading.

    Decorators directly above the definition are included -- `@app.route(...)` is
    frequently the single strongest clue that a handler is reachable by a request
    at all, which is the question the explainer is being asked.
    """
    index = start_line - 1
    if index < 0 or index >= len(lines):
        return None

    target_indent = _indent(lines[index])
    stop = max(-1, index - 1 - max_lookback)

    for i in range(index - 1, stop, -1):
        line = lines[i]
        if not line.strip():
            continue
        if _indent(line) < target_indent and _SCOPE_START_RE.match(line):
            # Absorb decorator lines sitting directly above the definition.
            first = i
            while first - 1 >= 0 and lines[first - 1].lstrip().startswith("@"):
                first -= 1
            return first + 1
    return None

# Sort order for the report. Worst first -- someone skimming a report reads the top.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def read_source_lines(path):
    """Read the target file as a list of lines.

    errors="replace" rather than letting a UnicodeDecodeError propagate: a file with
    one weird byte in it should still get scanned. Losing one character to a
    replacement marker is better than refusing to analyse the file at all.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().splitlines()
    except OSError as exc:
        raise SystemExit(f"Could not read {path}: {exc}")


def extract_snippet(lines, start_line, end_line, context=CONTEXT_LINES):
    """Cut out the flagged lines plus surrounding context, with line numbers attached.

    Semgrep reports 1-indexed line numbers; Python lists are 0-indexed. That
    off-by-one is the single easiest bug to introduce here, so the conversion is done
    once, explicitly, right at the top.

    Line numbers are prefixed onto each line because the prompt tells the model
    "the flagged line is line N" -- without visible numbers it would have to count,
    and it will sometimes count wrong.
    """
    # max(0, ...) stops a finding on line 2 from producing a negative index, which
    # would silently wrap around and slice from the END of the file.
    fallback = max(0, start_line - 1 - context)

    # Prefer the enclosing function, but only ever to widen the window. min()
    # rather than a plain assignment: when a finding sits on the first line of a
    # function, the definition alone would give less surrounding code than the
    # fixed count did, and this change must not make any case worse.
    enclosing = find_enclosing_start(lines, start_line)
    first = min(enclosing - 1, fallback) if enclosing is not None else fallback

    # Slicing past the end of a list is safe in Python, so no min() needed here.
    last = end_line + context

    numbered = []
    for offset, text in enumerate(lines[first:last]):
        line_number = first + offset + 1  # back to 1-indexed for display
        marker = ">>" if start_line <= line_number <= end_line else "  "
        numbered.append(f"{marker} {line_number:4d} | {text}")

    return "\n".join(numbered)


def display_path(path, root):
    """Render a finding's path relative to the scan root.

    Semgrep echoes back whatever path it was given, while the secret engine always
    returns absolute paths. Left alone, one report would mix
    `test_targets/vulnerable.py` with `C:\\Users\\...\\test_targets\\secrets\\.env`.
    """
    if not path:
        return "?"
    base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(base or "."))
    except ValueError:
        return path  # different drive on Windows; nothing sensible to compute
    return rel.replace("\\", "/")


# The secret engine speaks Semgrep's ERROR/WARNING/INFO; the report speaks the
# explainer's critical/high/medium/low. This is the bridge between the two.
SECRET_SEVERITY = {"ERROR": "critical", "WARNING": "medium", "INFO": "low"}
CONFIG_SEVERITY = {"ERROR": "critical", "WARNING": "medium", "INFO": "low"}


def secret_explanation(finding):
    """Build a report record for a secret finding without calling the API.

    SECRET FINDINGS DELIBERATELY SKIP THE LLM.
        To explain one, we would have to send the surrounding source lines -- which
        are, by definition, the lines containing the credential. A tool that reacts
        to finding your AWS key by transmitting it to a third party has done the
        exact thing it is warning you about.

        Nothing is lost by skipping. The explainer exists to answer "is this
        pattern actually exploitable here?", a question that genuinely needs
        judgment. For a leaked credential there is no such question: the engine
        already knows what the key is, whether it is committed, and how to revoke
        it. That is the whole answer.
    """
    extra = finding.get("extra", {})
    meta = extra.get("metadata", {})
    secret_type = meta.get("secret_type", "Credential")
    # Composed from the separate metadata fields rather than from extra["message"],
    # which glues the exposure note and the remediation together -- printing that
    # under "Attacker scenario" would repeat the fix verbatim two lines later.
    scenario = meta.get("exposure_note") or (
        "Anyone who can read this file can use this credential."
    )
    return {
        "is_real_vulnerability": True,
        "severity": SECRET_SEVERITY.get(extra.get("severity"), "medium"),
        "what_it_is": f"{secret_type} found in this file: {meta.get('redacted', '')}",
        "attacker_scenario": scenario,
        "fix": meta.get("remediation", ""),
        "explained_by": "engine",
    }


def dependency_explanation(finding):
    """Build a report record for a dependency finding without calling the API.

    Skipped for the same reason as secrets, by a different route. The explainer
    answers "is this pattern exploitable in *your* code". For a CVE in a
    third-party package, answering that honestly needs whole-program reachability
    analysis we do not do -- so asking the model would produce a confident guess
    about whether you call the vulnerable function. A published advisory and a
    fixed version number are a better answer than a guess.
    """
    extra = finding.get("extra", {})
    meta = extra.get("metadata", {})
    cves = meta.get("cve_ids") or meta.get("osv_ids") or []
    identifiers = ", ".join(cves[:4]) + (f" and {len(cves) - 4} more" if len(cves) > 4 else "")
    return {
        "is_real_vulnerability": True,
        "severity": dependencies_engine.OSV_SEVERITY_WORDS.get(
            meta.get("osv_severity"), "medium"),
        "what_it_is": (
            f"{meta.get('package')} {meta.get('installed_version')} "
            f"({meta.get('ecosystem')}) has {meta.get('vulnerability_count')} "
            f"known advisory(ies)"
            + (f", worst scoring CVSS {meta['cvss_score']}"
               if meta.get("cvss_score") is not None else "")
            + f": {identifiers or 'see OSV'}"
        ),
        "attacker_scenario": meta.get("summary")
        or "See the linked advisories for the specific attack each one describes.",
        "fix": meta.get("remediation", ""),
        "explained_by": "engine",
    }


def config_explanation(finding):
    """Build a report record for a configuration finding without calling the API.

    Consistent with the other engines, but this is the one where that choice is
    closest. "Is this CORS wildcard actually a problem here?" is a real judgment
    call the explainer could help with -- unlike a leaked key, where there is
    nothing to judge. See the note in the module docstring: routing presence
    checks through Claude is the obvious next improvement, and absence checks
    should never go, because there is no code at the location to reason about.
    """
    extra = finding.get("extra", {})
    meta = extra.get("metadata", {})
    issue = meta.get("issue", "Insecure configuration")
    remediation = meta.get("remediation", "")

    # Every rule's remediation text is authored as "<what to do>. <why it
    # matters>." Split on that boundary so the report's two headings say
    # different things -- without it both lines read "TLS certificate
    # verification disabled" and the entry tells the reader nothing.
    instruction, separator, reason = remediation.partition(". ")
    if separator and reason.strip():
        fix, scenario = instruction + ".", reason.strip()
    else:
        fix, scenario = remediation, issue

    return {
        "is_real_vulnerability": True,
        "severity": CONFIG_SEVERITY.get(extra.get("severity"), "medium"),
        "what_it_is": issue,
        "attacker_scenario": scenario,
        "fix": fix,
        "explained_by": "engine",
    }


TAINT_SEVERITY = {"ERROR": "critical", "WARNING": "high", "INFO": "medium"}


def is_taint_finding(finding):
    """True for a rule that traced a dataflow rather than matching a shape."""
    metadata = finding.get("extra", {}).get("metadata") or {}
    return metadata.get("analysis") == "taint"


def taint_explanation(finding):
    """Build a record for a proven dataflow finding without calling the API.

    THE THIRD CONFIDENCE TIER
        A taint rule has already answered the question the explainer exists to
        ask. "Is this actually reachable with attacker input?" is not a judgment
        call when the analysis traced the value from a request to the sink and
        found no sanitizer on the way -- it is a result.

        So proven flows skip the model, the same way credentials and CVEs do,
        and for the same reason: the answer is already in hand. What remains for
        the model is the genuinely ambiguous middle -- a pattern matched, and
        nobody knows whether the value reaching it is attacker-controlled.

    Severity outranks the scanner tier deliberately. `scanner_explanation` caps
    at "high" because nobody assessed reachability; here reachability is the
    thing that was proven, so a traced injection is critical.
    """
    extra = finding.get("extra", {})
    metadata = extra.get("metadata", {})
    return {
        "is_real_vulnerability": True,
        "severity": TAINT_SEVERITY.get(extra.get("severity"), "high"),
        "what_it_is": (metadata.get("cwe") or clean_rule_id(finding.get("check_id", ""))),
        "attacker_scenario": (extra.get("message") or "").strip(),
        "fix": "",
        "explained_by": "taint",
    }


SCANNER_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def scanner_explanation(finding):
    """Build a record for a Semgrep finding when the API is not being called.

    Used by --no-explain. The severity deliberately tops out at "high", never
    "critical": Semgrep grades the *pattern*, and whether the pattern is actually
    reachable with attacker input is the judgment the explainer exists to make.
    Printing "critical" for something nobody has assessed would be inventing
    confidence we do not have.
    """
    extra = finding.get("extra", {})
    return {
        "is_real_vulnerability": True,
        "severity": SCANNER_SEVERITY.get(extra.get("severity"), "medium"),
        "what_it_is": clean_rule_id(finding.get("check_id", "Finding")),
        "attacker_scenario": (extra.get("message") or "").strip(),
        "fix": "",
        "explained_by": "scanner",
    }


def clean_rule_id(check_id):
    """Shorten Semgrep's rule ID for display.

    Registry rules look like:
        python.lang.security.audit.eval-detected.eval-detected
    Custom rules loaded from an absolute path get the whole path baked in:
        C.Users.you.projects.safeship.rules.vibe-eval-exec-on-variable

    That second form is Semgrep deriving a namespace from wherever the config file
    happened to live -- it says nothing about the rule and swamps the actual name.
    Keep the last couple of dot-separated segments, which is the part that identifies
    the rule.
    """
    parts = check_id.split(".")
    if len(parts) <= 2:
        return check_id
    # Registry rules repeat the rule name as the final two segments
    # (....eval-detected.eval-detected) -- collapse that duplication.
    if parts[-1] == parts[-2]:
        return parts[-1]
    return ".".join(parts[-2:])


def _key_path(path):
    """Canonical path for comparing findings from different engines.

    Semgrep echoes back whatever path it was handed, so a relative target gives
    relative paths, while every engine in engines/ returns absolute ones. Keying
    the dedupe on the raw string then compares "test_targets/js/vulnerable.js"
    against "C:\\...\\test_targets\\js\\vulnerable.js", they never match, and
    cross-engine duplicates survive -- silently, and only when the target is
    relative, which is the way people actually invoke it.
    """
    if not path:
        return ""
    return os.path.normcase(os.path.abspath(path))


def deduplicate(findings):
    """Collapse findings that fire on the same line into one.

    WHY THIS EXISTS
        Running `--config auto` on the test file produced 16 findings across 8
        distinct lines. Line 271 alone was flagged by four separate rules -- a
        generic SQL rule, a SQLAlchemy rule, a Django rule, and a Flask rule -- all
        describing the same string-formatted query.

        Sending all four to the API means paying four times to be told the same
        thing, and printing four near-identical entries in the report, which trains
        the reader to skim past them. Grouping by line and keeping the
        highest-severity rule cuts both roughly in half on this file.

    THE TRADE-OFF, STATED HONESTLY
        Two genuinely different bugs can share a line. `eval(request.args.get('x'))`
        is both unvalidated input and code execution; collapsing them loses one. In
        practice the overlapping-rules case is far more common than the
        two-real-bugs-one-line case, but you can turn this off with --no-dedupe and
        see the raw output for yourself.

    THE KEY IS (path, line), NOT line
        This was a real bug. Grouping by line number alone was harmless while the
        tool only ever scanned one file, but the secret engine walks directories --
        and once it does, a finding on line 7 of config.json and a finding on line 7
        of docker-compose.yml collapse into each other. That is not a duplicate
        being cleaned up, it is a second vulnerability being deleted.
    """
    by_location = {}
    for finding in findings:
        location = (_key_path(finding.get("path", "")),
                    finding.get("start", {}).get("line", 0))
        metadata = finding.get("extra", {}).get("metadata") or {}

        # Dependency findings are anchored to a manifest line that is frequently
        # the same for every package: a package.json written on one line gives
        # every one of them line 1, and this dedupe then keeps exactly one. The
        # package name is what makes them distinct, so it joins the key. Other
        # engines anchor to genuinely distinct lines and are left alone, so a
        # secret and a Semgrep rule firing on one line still collapse.
        if metadata.get("package"):
            location = location + (metadata["package"],)

        severity = finding.get("extra", {}).get("severity", "INFO")

        if location not in by_location:
            # Track the other rule IDs so the report can still show that several
            # rules agreed -- that agreement is a genuine confidence signal.
            finding["_also_matched"] = []
            by_location[location] = finding
            continue

        kept = by_location[location]
        kept["_also_matched"].append(finding.get("check_id", "?"))

        # ERROR outranks WARNING outranks INFO. If the newcomer is more severe,
        # promote it and demote the incumbent into the also-matched list.
        rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        if rank.get(severity, 3) < rank.get(kept.get("extra", {}).get("severity"), 3):
            finding["_also_matched"] = kept["_also_matched"] + [kept.get("check_id", "?")]
            by_location[location] = finding

    return _merge_adjacent(by_location[key] for key in sorted(by_location))


# How close two findings must be to count as "the same bug reported twice".
#
# Tuned against the test file rather than guessed. At 5 this merged the two CORS
# findings on lines 313 and 318 -- and those are genuinely separate locations (a
# config dict and a response header), so merging them hid one. At 3 the debug-route
# block (lines 222-225, gaps of 1) and the adjacent hardcoded secrets (61-62) still
# collapse correctly while the CORS pair stays separate.
#
# The general principle: consecutive or near-consecutive lines are usually one
# statement or one block reported repeatedly; a gap of several lines usually means
# two real occurrences. When in doubt, prefer the smaller window -- an extra entry in
# the report costs a reader two seconds, a merged-away finding costs them a bug.
ADJACENT_LINE_WINDOW = 3


def _merge_adjacent(findings):
    """Second dedupe pass: merge same-rule findings on nearby lines.

    WHY A SECOND PASS IS NEEDED
        Line-level dedupe only catches rules that fire on the *identical* line. Two
        real cases from the test file slip through it:

        1. One rule, several lines. The vibe-unauthenticated-debug-route rule matches
           each sensitive expression inside the handler, so a route body containing
           os.environ, os.getcwd(), os.listdir(), and sys.path fires four times --
           lines 222, 223, 224, 225. That is one vulnerability, and explaining it
           four times costs four API calls to print four near-identical entries.

        2. One bug, two anchors. A string-formatted SQL query gets flagged by the
           custom rule at the assignment (line 96, `query = f"..."`) and by the
           registry rule at the execution (line 97, `cursor.execute(query)`). Same
           bug, adjacent lines, different rule IDs.

        This pass handles case 1 -- same rule ID, lines within a small window. Case 2
        is deliberately left alone: the rule IDs genuinely differ, so collapsing them
        would mean guessing that two different rules mean the same thing, and that
        guess is wrong often enough to cost real findings. Two adjacent entries in a
        report is a much cheaper problem than a silently dropped vulnerability.

    THIS PASS APPLIES TO SEMGREP FINDINGS ONLY
        The whole heuristic assumes "same rule, adjacent lines" means one rule
        fired repeatedly on one construct. That assumption holds for pattern
        matching and is flatly false for the other engines, where every finding
        is already a distinct object.

        Found by running it: requirements.txt declares one package per line, so
        six vulnerable packages on lines 2-7 all carry the check_id
        `pypi-known-vulnerability` with gaps of 1. This pass merged them into a
        single finding and silently discarded five real vulnerabilities. The same
        trap exists for two credentials on neighbouring lines of a .env.
    """
    merged = []
    for finding in findings:
        line = finding.get("start", {}).get("line", 0)
        check_id = finding.get("check_id")
        path = _key_path(finding.get("path", ""))

        previous = merged[-1] if merged else None
        if (
            previous is not None
            and finding.get("_engine", "semgrep") == "semgrep"
            and previous.get("_engine", "semgrep") == "semgrep"
            # Same file, too: without this the last finding in one file and the
            # first in the next merge whenever their line numbers happen to be
            # close, which across a directory is often.
            and _key_path(previous.get("path", "")) == path
            and previous.get("check_id") == check_id
            and line - previous.get("start", {}).get("line", 0) <= ADJACENT_LINE_WINDOW
        ):
            # Same rule, close by: fold into the previous entry. The first line is
            # kept as the anchor since that is usually where the problem starts.
            previous["_also_matched"].append(f"{check_id} (line {line})")
            continue

        merged.append(finding)

    return merged


def print_report(results, target, scan_count, deduped_count, skipped=()):
    """Print the formatted report: summary block, then one entry per finding."""
    # Split real findings from ones the model judged safe. Both are worth showing --
    # the dismissals are how you calibrate whether to trust the tool.
    # A finding whose explanation FAILED also has is_real_vulnerability False, so
    # without the error guard it lands in both lists: counted twice in the summary,
    # then crashing here on the attacker_scenario key it never got. "Dismissed"
    # means Claude looked and found no attack; "failed" means nobody looked. Saying
    # the second is the first is the worst possible confusion for a security tool.
    real = [r for r in results
            if r["explanation"].get("is_real_vulnerability") and not r.get("error")]
    dismissed = [r for r in results
                 if not r["explanation"].get("is_real_vulnerability")
                 and not r.get("error")]
    failed = [r for r in results if r.get("error")]

    real.sort(key=lambda r: SEVERITY_ORDER.get(r["explanation"].get("severity"), 9))

    print()
    print("=" * 78)
    print(f"  SafeShip report: {target}")
    print("=" * 78)
    print()
    # Broken out by engine: the two make claims of very different kinds, and one
    # combined "N vulnerabilities" number would blur that. A confirmed leaked key
    # is a fact; a confirmed injection is Claude's judgment call.
    taint_hits = [r for r in results if r["engine"] == "taint"]
    secret_hits = [r for r in results if r["engine"] == "secrets"]
    dep_hits = [r for r in results if r["engine"] == "dependencies"]
    config_hits = [r for r in results if r["engine"] == "config"]
    judged = [r for r in results if r["engine"] == "semgrep"]

    print(f"  {scan_count} raw finding(s) across {deduped_count} location(s).")
    for label, reason in skipped:
        print(f"  NOT SCANNED -- {label}: {reason}")
        print("  Findings of that kind cannot appear below. This is not a clean result.")
    if taint_hits:
        print(f"  Dataflow: {len(taint_hits)} proven flow(s) from user input to a "
              "dangerous sink (traced, not guessed -- no model needed).")
    if secret_hits:
        print(f"  Credentials: {len(secret_hits)} found by pattern match "
              "(never sent to the API).")
    if dep_hits:
        print(f"  Dependencies: {len(dep_hits)} package(s) with known advisories.")
    if config_hits:
        absent = len([r for r in config_hits if "missing-" in r["check_id"]])
        print(f"  Configuration: {len(config_hits)} issue(s)"
              + (f", {absent} of them things that are missing rather than wrong."
                 if absent else "."))
    if judged:
        confirmed = len([r for r in judged if r["explanation"].get("is_real_vulnerability")])
        print(f"  Static analysis: {len(judged)} finding(s); Claude confirmed "
              f"{confirmed}, dismissed {len(judged) - confirmed}.")

    if real:
        counts = Counter(r["explanation"]["severity"] for r in real)
        breakdown = "  ".join(
            f"{sev}: {counts[sev]}"
            for sev in ("critical", "high", "medium", "low")
            if counts[sev]
        )
        print(f"  Severity: {breakdown}")

    if failed:
        print(f"  {len(failed)} finding(s) could not be explained (see end of report).")
    print()

    for result in real:
        exp = result["explanation"]
        print("-" * 78)
        print(f"[{exp['severity'].upper()}] {clean_rule_id(result['check_id'])}")
        print(f"{result['path']}:{result['line']}")
        if result["also_matched"]:
            print(f"({len(result['also_matched'])} other rule(s) matched this line too)")
        print()
        print(f"What it is: {exp['what_it_is']}")
        print()
        print(f"Attacker scenario: {exp['attacker_scenario']}")
        print()
        # Taint findings carry their remediation inside the rule message, so
        # there is no separate fix block. An empty "Fix:" heading reads as a
        # missing answer rather than a deliberate one.
        if exp.get("fix"):
            print("Fix:")
            for fix_line in exp["fix"].splitlines():
                print(f"    {fix_line}")
            print()

    # Dismissals get a compact section. They're the tool telling you where it thinks
    # Semgrep over-fired -- useful for judging how much to trust it, and the first
    # place to look when hunting for false negatives.
    if dismissed:
        print("-" * 78)
        print(f"DISMISSED AS SAFE ({len(dismissed)})")
        print("Claude found no concrete attack against these. Worth spot-checking --")
        print("a wrong dismissal is a vulnerability the tool told you to ignore.")
        print()
        for result in dismissed:
            exp = result["explanation"]
            print(f"  {result['path']}:{result['line']}  {clean_rule_id(result['check_id'])}")
            print(f"    {exp.get('attacker_scenario', '(no explanation recorded)')}")
            print()

    if failed:
        print("-" * 78)
        print(f"COULD NOT EXPLAIN ({len(failed)})")
        print("These were flagged by Semgrep but the API call failed. They are NOT")
        print("cleared -- review them by hand.")
        print()
        for result in failed:
            print(f"  {result['path']}:{result['line']}  {clean_rule_id(result['check_id'])}")
            print(f"    {result['error']}")
            print()

    print("=" * 78)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a Python file for vulnerabilities and explain them in plain English.",
    )
    parser.add_argument("target", help="Python file (or directory) to scan")
    parser.add_argument(
        "--config",
        action="append",
        help=(
            "Semgrep ruleset. 'auto' for the curated registry rules, or a path such "
            "as rules/vibe_patterns.yaml. Repeat to run several. Default: auto"
        ),
    )
    parser.add_argument(
        "--no-explain",
        action="store_true",
        help="Scan only, skip the API calls. Useful for testing rules without spending tokens.",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Show every finding, including multiple rules firing on the same line.",
    )
    parser.add_argument(
        "--no-secrets",
        action="store_true",
        help="Skip the hardcoded-credential engine and run Semgrep only.",
    )
    parser.add_argument(
        "--no-semgrep",
        action="store_true",
        help="Skip Semgrep. Leaves the engines that answer without the API.",
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Skip the insecure-configuration engine.",
    )
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Skip the dependency check. Use when offline: it is the one engine "
             "that needs network access.",
    )
    parser.add_argument(
        "--secrets-only",
        action="store_true",
        help="Run only the credential engine. Fast, offline, and needs no API key.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON instead of the text report.",
    )
    parser.add_argument(
        "--html",
        metavar="PATH",
        help="Also write a self-contained HTML report to PATH.",
    )
    args = parser.parse_args()

    if args.no_secrets and args.secrets_only:
        parser.error("--no-secrets and --secrets-only cancel each other out.")

    configs = args.config or ["auto"]

    # --- Step 1: scan -------------------------------------------------------
    # Both engines run over the same target and their findings go into one list.
    # Every finding is tagged with the engine that produced it, because from here
    # on the two are treated differently: Semgrep findings go to the API for a
    # judgment call, secret findings never do.
    print(f"Scanning {args.target} ...", file=sys.stderr)
    all_findings = []
    skipped = []  # (label, reason) for engines that could not run

    # Which engines run, resolved once. Previously each block tested its own
    # combination of flags inline, which is how --secrets-only ended up as the
    # only way to skip Semgrep -- and it disabled config and dependencies too.
    run_semgrep = not (args.no_semgrep or args.secrets_only)
    run_secrets = not args.no_secrets
    run_config = not (args.no_config or args.secrets_only)
    run_deps = not (args.no_deps or args.secrets_only)

    if not any((run_semgrep, run_secrets, run_config, run_deps)):
        raise SystemExit("Every engine is disabled; nothing to scan.")

    # ONE ENGINE FAILING MUST NOT END THE SCAN
    #   Found by running this on real projects: Windows blocked Semgrep's native
    #   binary with an application-control policy, scanner.scan() raised, and the
    #   whole run exited -- so a user with a perfectly working credential,
    #   dependency and configuration scan got nothing at all.
    #
    #   Every engine now degrades instead. What did not run is collected in
    #   `skipped` and printed at the top of the report, because silence about a
    #   layer that never ran is how a security tool tells you that you are clean
    #   when in fact nobody looked.
    planned = []
    if run_semgrep:
        for config in configs:
            planned.append((
                "semgrep", f"static analysis ({config})",
                lambda c=config: scanner.scan(args.target, config=c),
                scanner.ScannerError,
            ))
    if run_secrets:
        planned.append((
            "secrets", "credential scan",
            lambda: secrets_engine.scan(args.target),
            secrets_engine.SecretScanError,
        ))
    if run_config:
        planned.append((
            "config", "configuration scan",
            lambda: config_engine.scan(args.target),
            config_engine.ConfigScanError,
        ))
    if run_deps:
        planned.append((
            "dependencies", "dependency scan",
            lambda: dependencies_engine.scan(args.target),
            dependencies_engine.DependencyScanError,
        ))

    def first_line(exc):
        """First line of an exception message, or its type when it has none."""
        lines = str(exc).strip().splitlines()
        return lines[0] if lines else type(exc).__name__

    for tag, label, produce, failure in planned:
        try:
            for finding in produce():
                finding["_engine"] = tag
                all_findings.append(finding)
        except failure as exc:
            reason = first_line(exc)
            skipped.append((label, reason))
            print(f"[{label} skipped] {reason}", file=sys.stderr)
        except Exception as exc:
            # The declared type is the failure we ANTICIPATED. Catching only that
            # quietly reintroduces the bug this whole table exists to prevent:
            # Semgrep raised a bare OSError (WinError 4551, Windows Application
            # Control) which is not a ScannerError, so it escaped and took three
            # working engines down with it -- exit 1, empty report, after the
            # credential, dependency and config scans had already succeeded.
            # Whatever an engine throws, it costs us that engine and nothing else.
            reason = f"{type(exc).__name__}: {first_line(exc)}"
            skipped.append((label, reason))
            print(f"[{label} skipped] {reason}", file=sys.stderr)

    if skipped and len(skipped) == len(planned):
        raise SystemExit(
            "Every engine failed; nothing was scanned. Run `safeship doctor` "
            "or check the messages above."
        )

    scan_count = len(all_findings)
    if scan_count == 0:
        print(f"\nNo findings in {args.target}.")
        # The most dangerous line in the program to get wrong. "No findings"
        # plus a silently skipped engine reads as a clean bill of health for
        # checks that never ran, so the skip is stated here first and loudest.
        for label, reason in skipped:
            print(f"\n  BUT: {label} did not run -- {reason}")
            print("  Findings of that kind could not have been reported.")
        print("\nWorth remembering: this means the rules that ran matched nothing,")
        print("not that the project is secure. A scanner only finds what it knows")
        print("to look for.")
        return

    findings = all_findings if args.no_dedupe else deduplicate(all_findings)
    print(
        f"Found {scan_count} finding(s) at {len(findings)} location(s).",
        file=sys.stderr,
    )

    # --- Step 2 & 3: snippet + explain -------------------------------------
    # Source files are cached by path. A directory scan routinely puts several
    # findings in one file, and re-reading it per finding is wasted work.
    sources = {}

    # Built on first use rather than up front, so a run that turns up only secrets
    # -- or a --secrets-only run -- never needs an API key at all.
    client = None

    results = []
    for index, finding in enumerate(findings, start=1):
        path = finding.get("path") or args.target
        start_line = finding.get("start", {}).get("line", 1)
        end_line = finding.get("end", {}).get("line", start_line)

        record = {
            "check_id": finding.get("check_id", "?"),
            "path": display_path(path, args.target),
            "line": start_line,
            "engine": finding.get("_engine", "semgrep"),
            "also_matched": finding.get("_also_matched", []),
            # Carried through so the report can show engine-specific detail --
            # CVE ids, the redacted credential, whether a file is committed --
            # without re-running the engine that produced it.
            "metadata": finding.get("extra", {}).get("metadata", {}),
            "explanation": {},
            "error": None,
        }

        if record["engine"] == "secrets":
            record["explanation"] = secret_explanation(finding)
            results.append(record)
            continue

        if record["engine"] == "dependencies":
            record["explanation"] = dependency_explanation(finding)
            results.append(record)
            continue

        if record["engine"] == "config":
            record["explanation"] = config_explanation(finding)
            results.append(record)
            continue

        # A traced dataflow already answered "is this reachable?", so it does
        # not need the model. This runs even without --no-explain: it is a
        # confidence tier, not a cost-saving fallback.
        if is_taint_finding(finding):
            record["explanation"] = taint_explanation(finding)
            record["engine"] = "taint"
            results.append(record)
            continue

        if args.no_explain:
            record["explanation"] = scanner_explanation(finding)
            results.append(record)
            continue

        if client is None:
            client = anthropic_client()

        if path not in sources:
            sources[path] = read_source_lines(path)
        snippet = extract_snippet(sources[path], start_line, end_line)

        # Progress goes to stderr so that `python analyze.py foo.py > report.txt`
        # writes a clean report to the file while you still see progress live.
        print(
            f"  Explaining {index}/{len(findings)} "
            f"({record['path']}:{start_line}) ...",
            file=sys.stderr,
        )

        try:
            record["explanation"] = explainer.explain(finding, snippet, client=client)
        except explainer.ExplainerError as exc:
            # One failed finding must not discard the other fifteen. Record it and
            # keep going -- the report has a dedicated section for these so they
            # never get silently counted as "clean."
            record["error"] = str(exc)
            record["explanation"] = {"is_real_vulnerability": False, "severity": "none"}

        results.append(record)

    # --- Step 4 & 5: report -------------------------------------------------
    if args.html:
        written = report.write(results, args.target, args.html,
                               scan_count=scan_count, deduped_count=len(findings),
                               skipped=skipped)
        print(f"HTML report: {written}", file=sys.stderr)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    if args.no_explain:
        # The skipped-engine warning belongs here too, not only in print_report.
        # This is the path the README points people at when they have no API key
        # (`--no-explain`, `--secrets-only`), so it is the path most likely to be
        # read as a clean bill of health -- which is precisely wrong when an
        # engine never ran. It went to stderr only, which a redirect throws away.
        for label, reason in skipped:
            print(f"  NOT SCANNED -- {label}: {reason}")
            print("  Findings of that kind cannot appear below. "
                  "This is not a clean result.")
        # Compact listing: the findings exist, but nothing has judged them.
        for record in results:
            severity = record["explanation"].get("severity", "?")
            print(f"  [{severity:>8}] {record['path']}:{record['line']}"
                  f"  {clean_rule_id(record['check_id'])}")
        return

    print_report(results, args.target, scan_count, len(findings), skipped)


ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def load_dotenv(path=ENV_FILE):
    """Read KEY=value pairs from a .env file into os.environ.

    WHY NOT python-dotenv
        This is twenty lines of standard library, and SafeShip has exactly two
        runtime dependencies. Adding a third to parse `KEY=value` is not a
        trade worth making.

    WHY ONLY SAFESHIP'S OWN .env, NEVER THE SCANNED PROJECT'S
        `path` defaults to the file beside this script, not to one in the
        current directory. The scanned project's .env belongs to the scanned
        project: reading it would pull a stranger's credentials into our
        process environment -- which every subprocess then inherits -- purely as
        a side effect of pointing a security scanner at their code. The key
        SafeShip uses is SafeShip's own.

    A real environment variable always wins, so an exported key overrides the
    file and CI needs no file at all.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return  # No .env is the normal case; the environment may still be set.

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        name, sep, value = line.partition("=")
        if not sep:
            continue
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        # `KEY=(sk-ant-...)` -- pasting *into* the () placeholder instead of over
        # it is the obvious reading of it, and the resulting failure is a useless
        # "API key rejected" from the server. No credential contains parentheses,
        # so unwrapping them is free and saves a baffling round trip.
        if len(value) > 2 and value.startswith("(") and value.endswith(")"):
            value = value[1:-1].strip()
        # Already-set variables win, and the bare placeholder is not a key.
        if name and value and value != "()" and name not in os.environ:
            os.environ[name] = value


def _dotenv_value(name, path=ENV_FILE):
    """Read one value straight from the .env file, ignoring os.environ."""
    saved = os.environ.pop(name, None)
    try:
        load_dotenv(path)
        return os.environ.get(name)
    finally:
        os.environ.pop(name, None)
        if saved is not None:
            os.environ[name] = saved


def anthropic_client():
    """Build the API client, failing early with a useful message if the key is unset.

    Checking here rather than on the first request means you find out before the scan
    results are thrown away, not after waiting through a scan.
    """
    import anthropic

    # Captured before load_dotenv() so we can tell "the file supplied it" from
    # "the environment already had one".
    preset = os.environ.get("ANTHROPIC_API_KEY")
    load_dotenv()

    # A shell variable outranks the file, which is correct and conventional -- and
    # is also how a stale exported key silently beats the fresh one you just put
    # in .env, producing an "API key rejected" that points nowhere. Say it out
    # loud rather than letting the user debug a key they already fixed.
    if preset:
        file_key = _dotenv_value("ANTHROPIC_API_KEY")
        if file_key and file_key != preset:
            print(
                "[warning] ANTHROPIC_API_KEY is set in your shell AND differs from "
                f"the one in {ENV_FILE}.\n"
                "          The shell value wins. If auth fails, that stale value is "
                "why -- clear it with:\n"
                '          [Environment]::SetEnvironmentVariable('
                '"ANTHROPIC_API_KEY", $null, "User")',
                file=sys.stderr,
            )

    key = os.environ.get("ANTHROPIC_API_KEY", "")
    # Catch a malformed key here rather than letting the server say "rejected"
    # after a scan has already run. Anthropic keys start with a known prefix, so
    # anything else is a paste error, not an auth failure worth debugging.
    if key and not key.startswith("sk-ant-"):
        raise SystemExit(
            f"ANTHROPIC_API_KEY does not look like an Anthropic key "
            f"(starts with {key[:6]!r}, expected 'sk-ant-').\n\n"
            f"Check {ENV_FILE} -- the value should be the bare key with no "
            "quotes, brackets, or trailing spaces:\n"
            "  ANTHROPIC_API_KEY=sk-ant-api03-...\n\n"
            "Note a shell variable overrides the file, so if one is exported "
            "with an old value, that is what gets used."
        )

    if not key:
        raise SystemExit(
            "ANTHROPIC_API_KEY is not set.\n\n"
            f"Easiest: put it in {ENV_FILE}\n"
            "  ANTHROPIC_API_KEY=sk-ant-...\n\n"
            "PowerShell (this session only):\n"
            '  $env:ANTHROPIC_API_KEY = "sk-ant-..."\n\n'
            "PowerShell (persist for future sessions):\n"
            '  [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...", "User")\n\n'
            "Or run with --no-explain to scan without the API."
        )
    return anthropic.Anthropic()


if __name__ == "__main__":
    main()
