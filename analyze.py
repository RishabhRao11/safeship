"""
analyze.py -- VibeSec's command-line entry point.

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
import sys
from collections import Counter

import explainer
import scanner
# Aliased because `secrets` is also a standard-library module. Importing ours
# under its bare name would shadow it for the whole file.
from engines import config as config_engine
from engines import dependencies as dependencies_engine
from engines import secrets as secrets_engine

# How many lines of context to include on either side of a flagged line.
#
# This number matters more than it looks. Too few and the model can't tell whether
# the flagged code is reachable with attacker input -- it sees `cursor.execute(query)`
# with no idea where `query` came from. Too many and you pay for tokens that don't
# help, and the model has more places to get distracted. Five each way is a starting
# point; if you find explanations are missing obvious context, raise it and compare.
CONTEXT_LINES = 5

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
    first = max(0, start_line - 1 - context)
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


def clean_rule_id(check_id):
    """Shorten Semgrep's rule ID for display.

    Registry rules look like:
        python.lang.security.audit.eval-detected.eval-detected
    Custom rules loaded from an absolute path get the whole path baked in:
        C.Users.rishi.OneDrive.Desktop.Rishabh.Projects.VibeSec.rules.vibe-eval-exec-on-variable

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
        location = (finding.get("path", ""), finding.get("start", {}).get("line", 0))
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
        path = finding.get("path", "")

        previous = merged[-1] if merged else None
        if (
            previous is not None
            and finding.get("_engine", "semgrep") == "semgrep"
            and previous.get("_engine", "semgrep") == "semgrep"
            # Same file, too: without this the last finding in one file and the
            # first in the next merge whenever their line numbers happen to be
            # close, which across a directory is often.
            and previous.get("path", "") == path
            and previous.get("check_id") == check_id
            and line - previous.get("start", {}).get("line", 0) <= ADJACENT_LINE_WINDOW
        ):
            # Same rule, close by: fold into the previous entry. The first line is
            # kept as the anchor since that is usually where the problem starts.
            previous["_also_matched"].append(f"{check_id} (line {line})")
            continue

        merged.append(finding)

    return merged


def print_report(results, target, scan_count, deduped_count):
    """Print the formatted report: summary block, then one entry per finding."""
    # Split real findings from ones the model judged safe. Both are worth showing --
    # the dismissals are how you calibrate whether to trust the tool.
    real = [r for r in results if r["explanation"].get("is_real_vulnerability")]
    dismissed = [r for r in results if not r["explanation"].get("is_real_vulnerability")]
    failed = [r for r in results if r.get("error")]

    real.sort(key=lambda r: SEVERITY_ORDER.get(r["explanation"].get("severity"), 9))

    print()
    print("=" * 78)
    print(f"  VibeSec report: {target}")
    print("=" * 78)
    print()
    # Broken out by engine: the two make claims of very different kinds, and one
    # combined "N vulnerabilities" number would blur that. A confirmed leaked key
    # is a fact; a confirmed injection is Claude's judgment call.
    secret_hits = [r for r in results if r["engine"] == "secrets"]
    dep_hits = [r for r in results if r["engine"] == "dependencies"]
    config_hits = [r for r in results if r["engine"] == "config"]
    judged = [r for r in results if r["engine"] == "semgrep"]

    print(f"  {scan_count} raw finding(s) across {deduped_count} location(s).")
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
            print(f"    {exp['attacker_scenario']}")
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

    # Which engines run, resolved once. Previously each block tested its own
    # combination of flags inline, which is how --secrets-only ended up as the
    # only way to skip Semgrep -- and it disabled config and dependencies too.
    run_semgrep = not (args.no_semgrep or args.secrets_only)
    run_secrets = not args.no_secrets
    run_config = not (args.no_config or args.secrets_only)
    run_deps = not (args.no_deps or args.secrets_only)

    if not any((run_semgrep, run_secrets, run_config, run_deps)):
        raise SystemExit("Every engine is disabled; nothing to scan.")

    if run_semgrep:
        for config in configs:
            try:
                for finding in scanner.scan(args.target, config=config):
                    finding["_engine"] = "semgrep"
                    all_findings.append(finding)
            except scanner.ScannerError as exc:
                raise SystemExit(f"Scan failed: {exc}")

    if run_secrets:
        try:
            for finding in secrets_engine.scan(args.target):
                finding["_engine"] = "secrets"
                all_findings.append(finding)
        except secrets_engine.SecretScanError as exc:
            raise SystemExit(f"Secret scan failed: {exc}")

    if run_config:
        try:
            for finding in config_engine.scan(args.target):
                finding["_engine"] = "config"
                all_findings.append(finding)
        except config_engine.ConfigScanError as exc:
            raise SystemExit(f"Config scan failed: {exc}")

    if run_deps:
        try:
            for finding in dependencies_engine.scan(args.target):
                finding["_engine"] = "dependencies"
                all_findings.append(finding)
        except dependencies_engine.DependencyScanError as exc:
            # The only engine that needs the network, so it is the only one that
            # can fail for reasons unrelated to the code being scanned. A dead
            # connection must not throw away the findings the other two produced.
            print(f"[dependency scan skipped] {exc}", file=sys.stderr)

    scan_count = len(all_findings)
    if scan_count == 0:
        print(f"\nNo findings in {args.target}.")
        print("Worth remembering: that means these rules matched nothing, not that")
        print("the file is secure. See test 3 in the red-team notes.")
        return

    findings = all_findings if args.no_dedupe else deduplicate(all_findings)
    print(
        f"Found {scan_count} finding(s) at {len(findings)} location(s).",
        file=sys.stderr,
    )

    if args.no_explain:
        for finding in findings:
            line = finding.get("start", {}).get("line", "?")
            sev = finding.get("extra", {}).get("severity", "?")
            where = f"{display_path(finding.get('path', ''), args.target)}:{line}"
            print(f"  [{sev:>7}] {where}  {clean_rule_id(finding.get('check_id', '?'))}")
        return

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
    if args.json:
        print(json.dumps(results, indent=2))
        return
    print_report(results, args.target, scan_count, len(findings))


def anthropic_client():
    """Build the API client, failing early with a useful message if the key is unset.

    Checking here rather than on the first request means you find out before the scan
    results are thrown away, not after waiting through a scan.
    """
    import os

    import anthropic

    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit(
            "ANTHROPIC_API_KEY is not set.\n\n"
            "PowerShell (this session only):\n"
            '  $env:ANTHROPIC_API_KEY = "sk-ant-..."\n\n'
            "PowerShell (persist for future sessions):\n"
            '  [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...", "User")\n\n'
            "Or run with --no-explain to scan without the API."
        )
    return anthropic.Anthropic()


if __name__ == "__main__":
    main()
