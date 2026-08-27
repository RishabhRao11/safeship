"""
manual_review.py -- run the VibeSec pipeline without spending API credits.

WHY THIS EXISTS
    explainer.py needs Anthropic API credits, which are billed separately from a
    Claude Pro subscription. But the interesting questions in this project --
    does the LLM dismiss false positives? does it catch what Semgrep misses? does
    the prompt-injection defence hold? -- don't need an automated pipeline. They
    need an LLM reading the findings.

    So this does everything analyze.py does EXCEPT the network call: scan, dedupe,
    cut out the code, and build the exact prompt. Then it prints that prompt instead
    of sending it. Paste it to any Claude session, get the answer back, and you have
    the same result the API would have given -- one copy-paste slower.

WHAT THIS IS AND ISN'T
    It IS a way to validate the prompt design before paying for anything. If the
    prompt produces bad answers here, it will produce bad answers through the API
    too, and you have found that out for free.

    It is NOT identical to the automated path. A chat session runs a different model
    with the conversation's context available, and explainer.py sends a clean,
    isolated request. Treat results here as strong evidence, not proof.

USAGE
    python manual_review.py test_targets/safe_but_flagged.py
    python manual_review.py test_targets/vulnerable.py --config auto --config rules/vibe_patterns.yaml
    python manual_review.py somefile.py --out prompts.md      # write to a file
    python manual_review.py somefile.py --only 3              # just finding #3
"""

import argparse
import sys

# Reuse the real pipeline pieces. Importing rather than reimplementing matters here:
# if these ever drift apart, this script stops telling you anything about what
# analyze.py actually does, which would make it worse than useless.
import analyze
import explainer
import scanner


def build_prompt_bundle(target, configs, no_dedupe=False):
    """Run the scan and return a list of (finding, prompt) pairs, ready to paste."""
    findings = []
    for config in configs:
        try:
            findings.extend(scanner.scan(target, config=config))
        except scanner.ScannerError as exc:
            raise SystemExit(f"Scan failed: {exc}")

    raw_count = len(findings)
    if not no_dedupe:
        findings = analyze.deduplicate(findings)

    lines = analyze.read_source_lines(target)

    bundle = []
    for finding in findings:
        start = finding.get("start", {}).get("line", 1)
        end = finding.get("end", {}).get("line", start)
        snippet = analyze.extract_snippet(lines, start, end)
        # The SAME function explainer.py calls -- so what's printed here is byte for
        # byte what would have gone over the wire.
        bundle.append((finding, explainer.build_user_prompt(finding, snippet)))

    return bundle, raw_count


def render(bundle, raw_count, target, only=None):
    """Format the prompts for pasting into a chat session."""
    out = []
    out.append(f"# VibeSec manual review: {target}")
    out.append("")
    out.append(
        f"Semgrep raised **{raw_count}** finding(s) at **{len(bundle)}** location(s) "
        f"after dedupe."
    )
    out.append("")
    out.append("## System prompt")
    out.append("")
    out.append("Give the assistant this first, then each finding below.")
    out.append("")
    out.append("```")
    out.append(explainer.SYSTEM_PROMPT)
    out.append("```")
    out.append("")
    out.append("Answer each finding as JSON with exactly these keys:")
    out.append("")
    out.append("```json")
    out.append(
        '{"is_real_vulnerability": true, "severity": "critical|high|medium|low|none",\n'
        ' "what_it_is": "...", "attacker_scenario": "...", "fix": "..."}'
    )
    out.append("```")
    out.append("")

    for index, (finding, prompt) in enumerate(bundle, start=1):
        if only is not None and index != only:
            continue
        line = finding.get("start", {}).get("line", "?")
        rule = analyze.clean_rule_id(finding.get("check_id", "?"))
        out.append("---")
        out.append("")
        out.append(f"## Finding {index} of {len(bundle)} - line {line} - `{rule}`")
        out.append("")
        out.append("```")
        out.append(prompt)
        out.append("```")
        out.append("")

    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(
        description="Build VibeSec prompts without calling the API."
    )
    parser.add_argument("target", help="Python file to scan")
    parser.add_argument("--config", action="append", help="Semgrep ruleset (repeatable)")
    parser.add_argument("--no-dedupe", action="store_true", help="Keep duplicate findings")
    parser.add_argument("--only", type=int, help="Print only finding N")
    parser.add_argument("--out", help="Write to this file instead of stdout")
    args = parser.parse_args()

    configs = args.config or ["auto"]

    print(f"Scanning {args.target} ...", file=sys.stderr)
    bundle, raw_count = build_prompt_bundle(args.target, configs, args.no_dedupe)

    if not bundle:
        print(f"No findings in {args.target}.")
        return

    text = render(bundle, raw_count, args.target, only=args.only)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Wrote {len(bundle)} prompt(s) to {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
