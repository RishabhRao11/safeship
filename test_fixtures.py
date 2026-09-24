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
import subprocess
import sys
import tempfile

import analyze
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


def check_transitive_dependencies(failures, skips):
    """The resolved tree is scanned, not just what package.json asked for.

    Benchmarking showed this was the one axis where npm audit and pip-audit were
    simply better: a CVE in a package you never chose is just as exploitable as
    one you did. On a generated lockfile for a four-dependency Express app,
    SafeShip and npm audit now report the same ten packages.

    Parsing only, deliberately -- no OSV call. This checks the code written
    here, and it stays deterministic and offline. Whether lodash 4.17.15 has an
    advisory is OSV's business and changes over time.
    """
    import json as _json

    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as fh:
            _json.dump({"dependencies": {"express": "4.17.1"}}, fh)
        with open(os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8") as fh:
            _json.dump({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/express": {"version": "4.17.1"},
                    "node_modules/qs": {"version": "6.7.0"},
                },
            }, fh)

        deps = {d.name: d for d in
                dependencies_engine.parse_package_json(os.path.join(tmp, "package.json"))}

        if "qs" not in deps:
            failures.append(
                "transitive: a package present only in package-lock.json was not "
                "scanned -- this is the gap npm audit was filling"
            )
        elif deps["qs"].direct:
            failures.append(
                "transitive: qs is not in package.json but was marked direct, so "
                "the fix advice will tell the user to edit a file that does not "
                "mention it"
            )
        if "express" not in deps or not deps["express"].direct:
            failures.append("transitive: a declared dependency lost its `direct` mark")

    # lockfileVersion 1 nests the tree. Reading only the top level found the
    # direct dependencies and silently ignored everything underneath.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as fh:
            _json.dump({"dependencies": {"express": "4.17.1"}}, fh)
        with open(os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8") as fh:
            _json.dump({
                "lockfileVersion": 1,
                "dependencies": {
                    "express": {"version": "4.17.1",
                                "dependencies": {"qs": {"version": "6.7.0"}}},
                },
            }, fh)
        names = {d.name for d in
                 dependencies_engine.parse_package_json(os.path.join(tmp, "package.json"))}
        if "qs" not in names:
            failures.append(
                "transitive: a nested lockfileVersion 1 dependency was missed; "
                "for a v1 lockfile that is most of what is installed"
            )

    # Pipfile.lock is a fully resolved tree, dev section included -- a
    # vulnerable dev tool still runs on your machine and in CI.
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "Pipfile.lock"), "w", encoding="utf-8") as fh:
            _json.dump({"default": {"flask": {"version": "==0.12.2"}},
                        "develop": {"pyyaml": {"version": "==5.1"}}}, fh)
        found = {d.name: d.version for d in
                 dependencies_engine.parse_pipfile_lock(os.path.join(tmp, "Pipfile.lock"))}
        if found != {"flask": "0.12.2", "pyyaml": "5.1"}:
            failures.append(f"transitive: Pipfile.lock parsed as {found}")


def _git_repo(directory, steps):
    """Build a throwaway repo. `steps` is a list of ({path: text}, message)."""
    run = lambda *a: subprocess.run(["git", "-C", directory] + list(a),
                                    capture_output=True, check=True)
    run("init", "-q", ".")
    run("config", "user.email", "test@example.invalid")
    run("config", "user.name", "Fixture")
    shas = []
    for files, message in steps:
        for name, text in files.items():
            with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
                handle.write(text)
        run("add", "-A")
        run("commit", "-q", "-m", message)
        shas.append(subprocess.run(["git", "-C", directory, "rev-parse", "--short", "HEAD"],
                                   capture_output=True, text=True).stdout.strip())
    return shas


def check_history_scan(failures, skips):
    """Credentials that were committed and later deleted are still leaked.

    Removing a key from a file and committing the removal looks like a fix. The
    old blob stays in the object store and in every clone, and the working-tree
    scan cannot see it -- which is exactly why people are sure it is gone.

    Built at runtime rather than committed as a fixture: a nested .git inside
    this repository would not survive being cloned.
    """
    key = "AKIA3XQ7NVBW2LFDR5TC"

    with tempfile.TemporaryDirectory() as tmp:
        deleted = os.path.join(tmp, "deleted")
        still = os.path.join(tmp, "still")
        plain = os.path.join(tmp, "plain")
        for d in (deleted, still, plain):
            os.makedirs(d)

        added, _removed = _git_repo(deleted, [
            ({".env": f"AWS_ACCESS_KEY_ID={key}\nPORT=3000\n"}, "add the key"),
            ({".env": "PORT=3000\n"}, "remove it, which looks like a fix"),
        ])
        # The key stays, but the FILE changes -- so an old blob exists that
        # still contains it. A single-commit repo would not test this at all:
        # with no historical-only blob there is nothing to suppress, and the
        # check passes whether or not the suppression works. Mutation testing
        # is what exposed that; the first version of this fixture was useless.
        _git_repo(still, [
            ({".env": f"AWS_ACCESS_KEY_ID={key}\nPORT=3000\n"}, "key and a port"),
            ({".env": f"AWS_ACCESS_KEY_ID={key}\nPORT=4000\n"}, "change the port only"),
        ])

        # 1. The deleted credential must be found, and the working-tree scan
        #    must NOT find it -- that contrast is the whole justification.
        if secrets_engine.scan(deleted):
            failures.append("history: the working-tree scan sees a deleted key; "
                            "the fixture is not testing what it claims to")
        found = secrets_engine.scan_history(deleted)
        if len(found) != 1:
            failures.append(
                f"history: expected 1 finding for a committed-then-deleted key, "
                f"got {len(found)}"
            )
            return

        # 2. Naming the commit that REMOVED it sends someone to the wrong place.
        named = found[0]["extra"]["metadata"].get("history_commit")
        if named != added:
            failures.append(
                f"history: named commit {named}, but {added} is the one that "
                "added the key -- git log --find-object lists newest first"
            )

        # 3. A credential still in the working tree belongs to the other scan.
        #    Reporting it twice under a 'deleted' heading trains people to skim.
        if secrets_engine.scan_history(still):
            failures.append(
                "history: re-reported a credential that is still at HEAD, which "
                "the working-tree scan already covers"
            )

        # 4. No history is not the same as a check that failed.
        try:
            if secrets_engine.scan_history(plain) != []:
                failures.append("history: a directory with no git repo produced findings")
        except secrets_engine.SecretScanError as exc:
            failures.append(
                f"history: a non-git directory raised instead of returning [] ({exc}); "
                "that cries wolf on the NOT SCANNED warning"
            )


def check_dedupe_precedence(failures, skips):
    """A shared line is reported by whichever engine actually answered it.

    Severity alone could not decide this. A registry rule and the secrets engine
    both call a leaked AWS key ERROR, so the tie fell to insertion order, and
    Semgrep is collected first -- four of the seven credentials in
    test_targets/secrets/.env were reported by the registry, at `high` instead
    of `critical`, with the redaction, the git-exposure note and the
    provider-specific remediation all replaced by a generic message and the
    literal string "requires login" where the code should be.

    Unit-level rather than pipeline-level on purpose: no Semgrep, no network,
    and it states the contract directly instead of inferring it from counts.
    """
    def finding(check_id, severity, engine=None, taint=False):
        metadata = {}
        if engine:
            metadata["engine"] = engine
        if taint:
            metadata["analysis"] = "taint"
        return {"check_id": check_id, "path": "x.env", "start": {"line": 1},
                "extra": {"severity": severity, "metadata": metadata}}

    registry = finding("detected-aws-access-key-id-value", "ERROR")
    answered = finding("safeship.secrets.aws-access-key-id", "ERROR", engine="secrets")

    # The real bug was order dependence, so both orders are checked.
    for label, order in (("registry first", [registry, answered]),
                         ("engine first", [answered, registry])):
        survivor = analyze.deduplicate([dict(f) for f in order])[0]
        if survivor["check_id"] != answered["check_id"]:
            failures.append(
                f"dedupe ({label}): a registry rule outranked the secrets engine "
                f"on the same line -- kept {survivor['check_id']}"
            )
        if survivor["check_id"] in survivor.get("_also_matched", []):
            failures.append(
                f"dedupe ({label}): the survivor lists itself in also_matched, "
                "so the report overstates how many rules agreed"
            )

    # Tier must outrank severity, or the engine's own calibration is overridden
    # by a scale that means something different.
    survivor = analyze.deduplicate([
        dict(finding("safeship.secrets.generic", "WARNING", engine="secrets")),
        dict(finding("detected-generic-secret", "ERROR")),
    ])[0]
    if not survivor["check_id"].startswith("safeship.secrets"):
        failures.append(
            "dedupe: a registry ERROR outranked an engine WARNING; severity is "
            "only comparable within a tier"
        )

    # A proven dataflow outranks a shape match.
    survivor = analyze.deduplicate([
        dict(finding("rules.vibe-js-sql-string-building", "ERROR")),
        dict(finding("rules.taint-js-sql-injection", "ERROR", taint=True)),
    ])[0]
    if "taint" not in survivor["check_id"]:
        failures.append(
            f"dedupe: a pattern match outranked a proven dataflow -- kept "
            f"{survivor['check_id']}"
        )


CHECKS = (
    ("secrets: 16 found, safe files silent", check_secrets),
    ("dedupe keeps the engine that answered", check_dedupe_precedence),
    ("history: deleted credentials are still leaked", check_history_scan),
    ("config: 22 bad, 0 good", check_config),
    ("dependencies: 9 vulnerable packages", check_dependencies),
    ("transitive: the resolved tree, not just the manifest", check_transitive_dependencies),
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
