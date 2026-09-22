"""
test_degradation.py -- proves one engine failing costs you that engine, and
nothing else.

WHY THIS TEST EXISTS
    CLAUDE.md claimed "one engine failing degrades the scan; it does not end
    it" for eight months while the code did the opposite. Three separate bugs
    were hiding behind that sentence, and all three survived because the
    engines kept working: this code path only runs when one stops, and nothing
    ever stopped one on purpose.

        1. scanner.py caught TimeoutExpired and JSONDecodeError but not
           OSError, so Windows Application Control (WinError 4551) never became
           a ScannerError -- the one type the degradation path recognised.
        2. The engine loop in analyze.py caught only each engine's DECLARED
           exception type. That is the bug the loop exists to prevent,
           reintroduced by being too specific: the failure nobody anticipated
           is exactly the one a narrow `except` lets through.
        3. --no-explain returned without the NOT SCANNED warning, which went to
           stderr only and vanishes under `> report.txt`. That is the path used
           when there is no API key, so it was the likeliest of all to be read
           as a clean bill of health.

    The lesson was not "add error handling". It was that the degradation path
    needs a test that actually breaks an engine. This is that test.

    The failure it guards against is the worst one a security tool has: a
    report that looks clean because nobody looked.

Run it directly:  python test_degradation.py
Exit code is 0 on pass, 1 on failure, so it drops into CI unchanged.
"""

import contextlib
import io
import sys

import analyze
import scanner
from engines import config as config_engine
from engines import secrets as secrets_engine

# A fixture with plenty for the config engine to find, so "the other engines
# still reported" is a claim with evidence behind it rather than an empty list.
TARGET = "test_targets/config/bad"

# Offline and modelless: this test is about the failure path, not the network.
OFFLINE = ["--no-semgrep", "--no-deps", "--no-explain"]


class Boom(Exception):
    """An exception type no engine declares.

    That is the entire point. A test that raises the declared exception only
    proves the `except` clause someone already wrote still works.
    """


def explode(*args, **kwargs):
    raise Boom("simulated engine failure")


def run_analyze(argv):
    """Call the real main() with argv, capturing both streams.

    Returns (systemexit_or_None, stdout, stderr). Driving main() rather than
    re-implementing the loop is deliberate -- a test that models the code
    cannot catch the code diverging from the model.
    """
    out, err = io.StringIO(), io.StringIO()
    saved_argv = sys.argv
    sys.argv = ["analyze.py"] + argv
    exit_exc = None
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            analyze.main()
    except SystemExit as exc:
        exit_exc = exc
    finally:
        sys.argv = saved_argv
    return exit_exc, out.getvalue(), err.getvalue()


def check_scanner_converts_oserror(failures):
    """Bug 1: a raw OSError must not escape scanner.scan().

    find_semgrep is stubbed so the test does not depend on Semgrep being
    installed, or runnable -- which on Windows is exactly what is in doubt.
    """
    saved_find = scanner.find_semgrep
    saved_run = scanner.subprocess.run

    def blocked_by_policy(*args, **kwargs):
        raise OSError(4551, "An Application Control policy has blocked this file")

    scanner.find_semgrep = lambda: ("semgrep", {"PATH": ""})
    scanner.subprocess.run = blocked_by_policy
    try:
        scanner.scan(TARGET)
    except scanner.ScannerError:
        pass  # Correct: converted into the type analyze.py degrades on.
    except OSError as exc:
        failures.append(
            f"scanner.scan let a raw OSError escape ({exc!r}); analyze.py's "
            "engine loop keys on ScannerError, so this ends the whole scan"
        )
    except Exception as exc:  # noqa: BLE001 -- reporting an unexpected type is the job
        failures.append(f"scanner.scan raised {type(exc).__name__}, expected ScannerError")
    else:
        failures.append("scanner.scan did not raise at all when the process could not start")
    finally:
        scanner.find_semgrep = saved_find
        scanner.subprocess.run = saved_run


def check_undeclared_failure_keeps_other_engines(failures):
    """Bugs 2 and 3: an unanticipated exception costs one engine, loudly."""
    saved = secrets_engine.scan
    secrets_engine.scan = explode
    try:
        exit_exc, out, err = run_analyze([TARGET] + OFFLINE)
    finally:
        secrets_engine.scan = saved

    if exit_exc is not None:
        failures.append(
            f"one engine raising {Boom.__name__} ended the whole scan "
            f"(SystemExit: {exit_exc})"
        )
        return

    # Bug 3: the warning must reach stdout. stderr alone is lost to a redirect.
    if "NOT SCANNED" not in out:
        where = "stderr only" if "skipped" in err else "nowhere"
        failures.append(
            f"--no-explain did not print NOT SCANNED to stdout ({where}); "
            "`safeship scan --no-explain > report.txt` then reads as clean"
        )

    # The type must be named, or the message says nothing actionable.
    if Boom.__name__ not in out and Boom.__name__ not in err:
        failures.append("the skipped-engine message does not name the exception type")

    # The surviving engine must still have reported.
    config_findings = [line for line in out.splitlines() if "config." in line]
    if not config_findings:
        failures.append(
            "no config findings survived -- one engine failing threw away the "
            "engines that worked, which is the bug this whole path exists for"
        )


def check_declared_failure_still_handled(failures):
    """The narrow path must keep working; broadening it must not replace it."""
    saved = secrets_engine.scan

    def declared_failure(*args, **kwargs):
        raise secrets_engine.SecretScanError("simulated declared failure")

    secrets_engine.scan = declared_failure
    try:
        exit_exc, out, _ = run_analyze([TARGET] + OFFLINE)
    finally:
        secrets_engine.scan = saved

    if exit_exc is not None:
        failures.append("a declared SecretScanError ended the scan")
    elif "NOT SCANNED" not in out:
        failures.append("a declared SecretScanError was not reported as skipped")


def check_total_failure_is_loud(failures):
    """Nothing scanned must never be reported as nothing found.

    These two outcomes look identical in a report and mean opposite things.
    Confusing them is how a security tool tells you that you are safe.
    """
    saved_secrets, saved_config = secrets_engine.scan, config_engine.scan
    secrets_engine.scan = explode
    config_engine.scan = explode
    try:
        exit_exc, out, err = run_analyze([TARGET] + OFFLINE)
    finally:
        secrets_engine.scan = saved_secrets
        config_engine.scan = saved_config

    if exit_exc is None:
        failures.append("every engine failed and the run still exited successfully")
    elif "nothing was scanned" not in str(exit_exc).lower():
        failures.append(f"the total-failure message is unclear: {exit_exc!r}")

    if "No findings" in out:
        failures.append(
            "every engine failed and the report said 'No findings' -- the exact "
            "false clean bill of health this path exists to prevent"
        )


CHECKS = (
    ("scanner converts OSError into ScannerError", check_scanner_converts_oserror),
    ("an undeclared failure costs one engine only", check_undeclared_failure_keeps_other_engines),
    ("a declared failure is still handled", check_declared_failure_still_handled),
    ("total failure is loud, not 'No findings'", check_total_failure_is_loud),
)


def main():
    failures = []
    for label, check in CHECKS:
        before = len(failures)
        try:
            check(failures)
        except Exception as exc:  # noqa: BLE001 -- a crashing check is a failing check
            failures.append(f"{label}: check itself crashed -- {type(exc).__name__}: {exc}")
        if len(failures) == before:
            print(f"  ok    {label}")
        else:
            print(f"  FAIL  {label}")

    if failures:
        print(f"\nFAIL ({len(failures)} problem(s))")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"\nPASS  {len(CHECKS)} degradation contracts hold")
    print("      each one broke a real engine rather than simulating the loop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
