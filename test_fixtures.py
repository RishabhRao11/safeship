"""
test_fixtures.py -- the regression sweep, as something you can run.

WHY THIS TEST EXISTS
    Every number in CLAUDE.md -- 16/16 secrets, 22/22 config, 9/9 deps, 7/7 and
    11/11 rules, zero on both safe fixtures -- was being checked by hand, with a
    different ad-hoc `grep -c` each time. A measurement you have to remember to
    take is a measurement that eventually stops being taken.

    The good fixtures matter more than the bad ones. Anyone can make a scanner
    find things. `test_targets/config/good/` and `test_targets/js/safe.js`
    expecting exactly zero is what stops a false-positive regression shipping.

THE SEMGREP PROBLEM, AND WHY THIS FILE SOLVES IT
    Windows Application Control has blocked Semgrep on the development machine
    for days at a time, which means the rule counts go unverified for days at a
    time -- silently, because the other three engines keep working.

    So the Semgrep checks SKIP when Semgrep cannot run, and setting
    SAFESHIP_REQUIRE_SEMGREP=1 turns that skip into a failure. CI sets it. The
    result: locally you get an honest "not verified", and on Linux those rules
    are actually exercised on every push.

    A skip that nobody notices is indistinguishable from a pass. This one is
    counted, printed, and fatal where it should be.

Run it directly:  python test_fixtures.py
Exit code is 0 on pass, 1 on failure, so it drops into CI unchanged.
"""

import os
import sys

import scanner
from engines import config as config_engine
from engines import dependencies as dependencies_engine
from engines import secrets as secrets_engine

REQUIRE_SEMGREP = os.environ.get("SAFESHIP_REQUIRE_SEMGREP") == "1"

# Files inside the secrets fixture that must produce nothing: a template full of
# placeholders, and a config holding a Stripe key that is meant to ship.
SILENT_SECRET_FILES = (".env.example", "safe_config.py")


def short_id(finding):
    """Semgrep prefixes rule ids with the config path; keep the rule's own name."""
    return finding.get("check_id", "").rsplit(".", 1)[-1]


def count(findings, prefix, exclude=None):
    ids = {short_id(f) for f in findings if short_id(f).startswith(prefix)}
    if exclude:
        ids = {i for i in ids if not i.startswith(exclude)}
    return ids


# --------------------------------------------------------------------------
# Pure-Python engines: no network except dependencies, no Semgrep, no API key.
# --------------------------------------------------------------------------

def check_secrets(failures, skips):
    findings = secrets_engine.scan("test_targets/secrets")
    if len(findings) != 16:
        failures.append(f"secrets: expected 16 planted credentials, got {len(findings)}")

    noisy = [f for f in findings
             if os.path.basename(f["path"]) in SILENT_SECRET_FILES]
    if noisy:
        where = ", ".join(f'{os.path.basename(f["path"])}:{f["start"]["line"]}' for f in noisy)
        failures.append(
            f"secrets: {len(noisy)} finding(s) in files that must stay silent ({where}). "
            "A placeholder or a publishable key reported as a leak is the failure "
            "this tool is built to avoid"
        )


def check_config(failures, skips):
    bad = config_engine.scan("test_targets/config/bad")
    if len(bad) != 22:
        failures.append(f"config/bad: expected 22 issues, got {len(bad)}")

    good = config_engine.scan("test_targets/config/good")
    if good:
        where = ", ".join(f'{os.path.basename(f["path"])}:{f["start"]["line"]}' for f in good)
        failures.append(f"config/good: expected zero findings, got {len(good)} ({where})")


def check_dependencies(failures, skips):
    try:
        findings = dependencies_engine.scan("test_targets/deps")
    except dependencies_engine.DependencyScanError as exc:
        # OSV.dev is the only network call in the whole suite. A blip there is
        # not a regression in this repo, so it is a skip -- but a counted one.
        skips.append(f"dependencies: OSV.dev unreachable ({exc})")
        return
    if len(findings) != 9:
        failures.append(f"dependencies: expected 9 vulnerable packages, got {len(findings)}")


# --------------------------------------------------------------------------
# Semgrep rules. These are the ones that go unverified when the OS blocks it.
# --------------------------------------------------------------------------

def semgrep_available():
    """Actually run it. `find_semgrep` succeeding does not mean it can execute.

    On Windows the policy has blocked the child process (`pysemgrep`) while the
    parent launched fine, so a presence check passes and the scan still dies.
    """
    try:
        scanner.scan("test_targets/js/safe.js", config="rules/")
        return True, None
    except scanner.ScannerError as exc:
        return False, str(exc).strip().splitlines()[0]


def check_rules(failures, skips):
    available, why = semgrep_available()
    if not available:
        message = f"semgrep rules: not verified -- {why}"
        if REQUIRE_SEMGREP:
            failures.append(message + " (SAFESHIP_REQUIRE_SEMGREP=1)")
        else:
            skips.append(message)
        return

    python_rules = count(scanner.scan("test_targets/vulnerable.py", config="rules/"),
                         "vibe-", exclude="vibe-js-")
    if len(python_rules) != 7:
        failures.append(
            f"rules: expected all 7 Python pattern rules to fire on vulnerable.py, "
            f"got {len(python_rules)} ({sorted(python_rules)})"
        )

    js = scanner.scan("test_targets/js/vulnerable.js", config="rules/")
    js_hits = [f for f in js if short_id(f).startswith("vibe-js-")]

    # Distinct (line, rule), not raw count. Two of the JS rules list both
    # `const $NAME = $VALUE` and a bare `$NAME = $VALUE` in the same
    # pattern-either, and Semgrep matches a const declaration with both -- so
    # lines 13 and 17 are each reported twice. Harmless downstream, because
    # analyze.py dedupes on (path, line) and the user never sees it, but it
    # means the raw number is 13 and the number of planted vulns is 11.
    # Asserting the raw count would pin a quirk instead of the contract.
    js_locations = {(f["start"]["line"], short_id(f)) for f in js_hits}
    if len(js_locations) != 11:
        failures.append(
            f"rules: expected 11 distinct JS findings on vulnerable.js, "
            f"got {len(js_locations)}"
        )

    js_rules = {short_id(f) for f in js_hits}
    if len(js_rules) != 7:
        failures.append(
            f"rules: expected all 7 JS pattern rules to fire on vulnerable.js, "
            f"got {len(js_rules)} ({sorted(js_rules)})"
        )

    # The good fixtures. These are the ones worth having.
    safe_js = scanner.scan("test_targets/js/safe.js", config="rules/")
    if safe_js:
        failures.append(
            f"rules: js/safe.js must be silent, got {len(safe_js)} "
            f"({sorted(short_id(f) for f in safe_js)})"
        )

    taint_on_safe = scanner.scan("test_targets/safe_but_flagged.py",
                                 config="rules/taint_flows.yaml")
    if taint_on_safe:
        failures.append(
            f"taint: safe_but_flagged.py must be silent, got {len(taint_on_safe)}. "
            "The declared sanitizers are what keep it that way"
        )


CHECKS = (
    ("secrets: 16 found, safe files silent", check_secrets),
    ("config: 22 bad, 0 good", check_config),
    ("dependencies: 9 vulnerable packages", check_dependencies),
    ("semgrep rules: 7 Python, 11 JS, 0 on both safe fixtures", check_rules),
)


def main():
    failures, skips = [], []
    for label, check in CHECKS:
        before_f, before_s = len(failures), len(skips)
        try:
            check(failures, skips)
        except Exception as exc:  # noqa: BLE001 -- a crashing check is a failing check
            failures.append(f"{label}: check itself crashed -- {type(exc).__name__}: {exc}")
        if len(failures) > before_f:
            print(f"  FAIL  {label}")
        elif len(skips) > before_s:
            print(f"  skip  {label}")
        else:
            print(f"  ok    {label}")

    for skip in skips:
        print(f"\n  SKIPPED: {skip}")
        print("  Nothing was checked there. Not a pass.")

    if failures:
        print(f"\nFAIL ({len(failures)} problem(s))")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    verified = len(CHECKS) - len(skips)
    print(f"\nPASS  {verified}/{len(CHECKS)} fixture contracts verified")
    if skips:
        print("      set SAFESHIP_REQUIRE_SEMGREP=1 to make the skip fatal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
