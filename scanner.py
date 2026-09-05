"""
scanner.py -- the static-analysis half of SafeShip.

WHAT THIS DOES
    Runs Semgrep against a target file (or directory) and hands back the findings
    as a plain Python list of dictionaries. That's it. It does no explaining, no
    formatting, no API calls -- it is purely "point Semgrep at code, get structured
    findings back."

WHY IT'S A SEPARATE FILE
    Two very different kinds of failure live in this pipeline: "the static analyzer
    misbehaved" and "the LLM misbehaved." Keeping them in separate modules means
    when a scan comes back empty you know exactly which half to go debug.

HOW SEMGREP ACTUALLY GETS INVOKED (this machine, specifically)
    The project notes said to use `python -m semgrep`. That advice is stale. Semgrep
    deprecated the `python -m semgrep` entrypoint in version 1.38.0, and by 1.173.0
    (what's installed here) it no longer runs a scan at all -- it prints a deprecation
    warning and exits with code 2.

    The working invocation is the `semgrep` executable. There's a wrinkle: on Windows,
    `semgrep.exe` is a thin launcher that immediately shells out to a *second*
    executable called `pysemgrep`. Both live in Python's "Scripts" directory. If that
    directory isn't on PATH, you get one of two confusing errors:
        - "semgrep: command not found"        (the launcher itself wasn't found)
        - "executing pysemgrep failed ... No such file or directory"
          (the launcher was found, but it couldn't find its own helper)

    So find_semgrep() below locates that Scripts directory and makes sure it's on
    PATH for the subprocess. That fixes both errors at once.
"""

import json
import os
import shutil
import subprocess
import sys
import sysconfig


class ScannerError(Exception):
    """Raised when Semgrep can't be found or the scan itself fails.

    A dedicated exception type (rather than a bare Exception) lets analyze.py
    catch *scanner* problems specifically and print something useful, instead of
    swallowing every error in the program and pretending the file was clean.
    A scan that fails silently is worse than no scan -- it tells you you're safe
    when nobody actually looked.
    """


def _script_dirs():
    """Return the directories where pip installs command-line executables.

    There are two of them and which one gets used depends on how the package was
    installed:
        - the "system" scheme  -> e.g. C:\\Python314\\Scripts
        - the "user" scheme    -> e.g. C:\\Users\\you\\AppData\\Roaming\\Python\\Python314\\Scripts
                                  (this is where `pip install --user` puts things,
                                  and it is where semgrep lives on this machine)

    sysconfig knows both paths without us hardcoding a username or Python version,
    so this keeps working if either changes.
    """
    dirs = []

    # The user-scheme name is platform-dependent: "nt_user" on Windows,
    # "posix_user" on Linux/macOS. os.name gives us "nt" or "posix".
    for scheme in (f"{os.name}_user", sysconfig.get_default_scheme()):
        try:
            path = sysconfig.get_path("scripts", scheme)
        except KeyError:
            # This scheme doesn't exist on this platform -- skip it rather than crash.
            continue
        if path and path not in dirs:
            dirs.append(path)

    # Belt and braces: the Scripts dir sitting next to the running interpreter.
    # Covers virtualenvs, where sys.executable is the authoritative location.
    exe_dir = os.path.dirname(sys.executable)
    for candidate in (os.path.join(exe_dir, "Scripts"), exe_dir):
        if os.path.isdir(candidate) and candidate not in dirs:
            dirs.append(candidate)

    return dirs


def find_semgrep():
    """Locate the semgrep executable and build an environment it can run in.

    Returns a (executable_path, environment_dict) tuple.

    The environment matters as much as the path here. Remember: semgrep.exe needs
    to find pysemgrep at runtime. So we don't just locate semgrep -- we return a
    PATH that contains its whole neighborhood, and hand that to subprocess.
    """
    # Start from the current environment and prepend the script directories.
    # os.environ.copy() rather than mutating os.environ directly: we don't want a
    # library import to permanently rewrite PATH for the whole calling program.
    env = os.environ.copy()
    extra = [d for d in _script_dirs() if os.path.isdir(d)]
    if extra:
        env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])

    # shutil.which() does what the shell does: walk PATH looking for the name,
    # honouring .exe/.bat extensions on Windows. We search using our *augmented*
    # PATH so a Scripts-dir-only install is still found.
    exe = shutil.which("semgrep", path=env["PATH"])
    if exe:
        return exe, env

    raise ScannerError(
        "Could not find the 'semgrep' executable.\n"
        "Looked in: " + (", ".join(extra) if extra else "(no script dirs found)") + "\n"
        "Install it with:  python -m pip install semgrep\n"
        "Note: `python -m semgrep` does NOT work on semgrep >= 1.38 -- it only prints "
        "a deprecation notice and exits. The executable is what you want."
    )


def scan(target, config="auto", timeout=300):
    """Run Semgrep on `target` and return its findings as a list of dicts.

    Args:
        target:  path to the file or directory to scan.
        config:  which ruleset to use. "auto" pulls Semgrep's curated default rules
                 (requires network access). Pass a path like "rules/vibe_patterns.yaml"
                 to run only our custom rules instead.
        timeout: seconds to wait before giving up. `--config auto` downloads rules on
                 first use, so the initial run is slower than later ones.

    Returns:
        A list of finding dicts, straight from Semgrep's JSON. Each one has at least:
            check_id         -- the rule that fired, e.g. "python.lang.security...."
            path             -- file the finding is in
            start / end      -- dicts with a "line" key (1-indexed)
            extra.message    -- Semgrep's description of the problem
            extra.severity   -- "ERROR" | "WARNING" | "INFO"
                                (note: Semgrep's own words, NOT the critical/high/
                                medium/low scale the explainer produces. Don't
                                conflate the two.)

        Returns an empty list when the file is clean. An empty list is a real,
        successful result -- failures raise ScannerError instead, so the caller can
        always tell "nothing found" apart from "nothing ran."
    """
    if not os.path.exists(target):
        raise ScannerError(f"Target does not exist: {target}")

    exe, env = find_semgrep()

    cmd = [
        exe,
        "--config", config,
        "--json",     # machine-readable output instead of the pretty terminal report
        "--quiet",    # suppress progress bars/banners so stdout is pure JSON
        target,
    ]

    try:
        # We capture stdout and stderr separately: JSON comes out of stdout, and
        # any diagnostics go to stderr. Merging them would corrupt the JSON.
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,       # decode bytes -> str for us
            env=env,         # the PATH-augmented environment from find_semgrep()
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ScannerError(
            f"Semgrep timed out after {timeout}s on {target}. "
            "If this was the first run with --config auto, it was probably still "
            "downloading rules -- try again, or raise the timeout."
        )

    # Semgrep's exit codes:
    #   0 = ran successfully (findings may or may not exist -- 0 does NOT mean clean)
    #   1 = findings present AND --error was passed (we don't pass it, so we won't see this)
    #   2 = something actually went wrong: bad config, parse failure, crash
    #
    # We check stdout for JSON before trusting the exit code, because Semgrep can
    # return a nonzero code for partial failures while still emitting valid results.
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise ScannerError(
            f"Semgrep did not return valid JSON (exit code {proc.returncode}).\n"
            f"stderr: {proc.stderr.strip()[:1000]}\n"
            f"stdout: {proc.stdout.strip()[:500]}"
        )

    # Semgrep reports per-file problems (unparseable files, rule errors) in an
    # "errors" list while still succeeding overall. Surface them as warnings rather
    # than raising -- a rule that failed to load shouldn't discard the findings from
    # the rules that did load. But you should still SEE it, because a silently
    # dropped rule is a silently missed vulnerability.
    for err in payload.get("errors", []):
        msg = err.get("message") or err.get("long_msg") or str(err)
        print(f"[scanner warning] {msg}", file=sys.stderr)

    # The "results" key holds the actual findings. .get() with a default keeps us
    # safe if Semgrep ever changes its output shape.
    return payload.get("results", [])


# ---------------------------------------------------------------------------
# Running this file directly gives you a quick smoke test:
#     python scanner.py test_targets/vulnerable.py
# It prints one line per finding so you can confirm the scanner works on its own,
# before any of the LLM machinery is involved.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python scanner.py <file-or-directory> [semgrep-config]")
        sys.exit(1)

    target_arg = sys.argv[1]
    config_arg = sys.argv[2] if len(sys.argv) > 2 else "auto"

    try:
        findings = scan(target_arg, config=config_arg)
    except ScannerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"type: {type(findings).__name__}, count: {len(findings)}\n")
    for f in findings:
        line = f.get("start", {}).get("line", "?")
        severity = f.get("extra", {}).get("severity", "?")
        print(f"  [{severity}] line {line}: {f.get('check_id')}")
