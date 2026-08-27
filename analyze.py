"""
analyze.py -- VibeSec's command-line entry point.

WHAT THIS DOES
    Wires scanner.py and explainer.py together and prints a readable report.

        scan the file  ->  for each finding, cut out the relevant code
                       ->  ask Claude to explain it
                       ->  print a formatted report with a summary on top

USAGE
    python analyze.py test_targets/vulnerable.py
    python analyze.py myapp.py --config rules/vibe_patterns.yaml
    python analyze.py myapp.py --config auto --config rules/vibe_patterns.yaml
    python analyze.py myapp.py --no-explain        # scan only, no API calls

WHY THE ORCHESTRATION IS ITS OWN FILE
    scanner.py knows nothing about Claude. explainer.py knows nothing about Semgrep.
    Everything that knows about both lives here. That means when the report looks
    wrong you can immediately tell which layer to go debug -- and you can run either
    half standalone (each has a __main__ block) to isolate the problem.
"""

import argparse
import sys
from collections import Counter

import explainer
import scanner

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
    """
    by_line = {}
    for finding in findings:
        line = finding.get("start", {}).get("line", 0)
        severity = finding.get("extra", {}).get("severity", "INFO")

        if line not in by_line:
            # Track the other rule IDs so the report can still show that several
            # rules agreed -- that agreement is a genuine confidence signal.
            finding["_also_matched"] = []
            by_line[line] = finding
            continue

        kept = by_line[line]
        kept["_also_matched"].append(finding.get("check_id", "?"))

        # ERROR outranks WARNING outranks INFO. If the newcomer is more severe,
        # promote it and demote the incumbent into the also-matched list.
        rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        if rank.get(severity, 3) < rank.get(kept.get("extra", {}).get("severity"), 3):
            finding["_also_matched"] = kept["_also_matched"] + [kept.get("check_id", "?")]
            by_line[line] = finding

    return _merge_adjacent(by_line[line] for line in sorted(by_line))


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
    """
    merged = []
    for finding in findings:
        line = finding.get("start", {}).get("line", 0)
        check_id = finding.get("check_id")

        previous = merged[-1] if merged else None
        if (
            previous is not None
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
    print(f"  Semgrep raised {scan_count} finding(s) across {deduped_count} location(s).")
    print(f"  Claude confirmed {len(real)} as exploitable; dismissed {len(dismissed)}.")

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
        print(f"Line {result['line']}")
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
            print(f"  Line {result['line']}: {clean_rule_id(result['check_id'])}")
            print(f"    {exp['attacker_scenario']}")
            print()

    if failed:
        print("-" * 78)
        print(f"COULD NOT EXPLAIN ({len(failed)})")
        print("These were flagged by Semgrep but the API call failed. They are NOT")
        print("cleared -- review them by hand.")
        print()
        for result in failed:
            print(f"  Line {result['line']}: {clean_rule_id(result['check_id'])}")
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
    args = parser.parse_args()

    configs = args.config or ["auto"]

    # --- Step 1: scan -------------------------------------------------------
    print(f"Scanning {args.target} ...", file=sys.stderr)
    all_findings = []
    for config in configs:
        try:
            all_findings.extend(scanner.scan(args.target, config=config))
        except scanner.ScannerError as exc:
            raise SystemExit(f"Scan failed: {exc}")

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
            print(f"  [{sev}] line {line}: {clean_rule_id(finding.get('check_id', '?'))}")
        return

    # --- Step 2 & 3: snippet + explain -------------------------------------
    lines = read_source_lines(args.target)

    # One client reused across every request. Building a fresh anthropic.Anthropic()
    # per finding would throw away the connection pool each time.
    client = anthropic_client()

    results = []
    for index, finding in enumerate(findings, start=1):
        start_line = finding.get("start", {}).get("line", 1)
        end_line = finding.get("end", {}).get("line", start_line)
        snippet = extract_snippet(lines, start_line, end_line)

        # Progress goes to stderr so that `python analyze.py foo.py > report.txt`
        # writes a clean report to the file while you still see progress live.
        print(f"  Explaining {index}/{len(findings)} (line {start_line}) ...", file=sys.stderr)

        record = {
            "check_id": finding.get("check_id", "?"),
            "line": start_line,
            "also_matched": finding.get("_also_matched", []),
            "explanation": {},
            "error": None,
        }

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
