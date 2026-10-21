# Changelog

## 0.3.0 — 2026-10-21

Every gap found by benchmarking against gitleaks, detect-secrets, npm audit and
pip-audit is closed in this release, along with two bugs in the default command.

### Breaking

**Python 3.10 or newer is required** (was 3.9). Semgrep itself requires 3.10:
on 3.9, pip quietly installs an older Semgrep that matches rules differently, so
3.9 "worked" and found different things. That was never really support.

**`--json` is now an object, not a bare list.** It records which engines ran
and which did not, the SafeShip and Semgrep versions, and whether AI
explanations ran. The findings are under `findings`. Anything that parsed the
old list needs one change; `python report.py` reads both shapes.

### Added

**Git history scanning.** A credential deleted from a file and committed is
still in every clone of the repository. SafeShip now finds credentials that
exist in history but no longer in the working tree, and names the commit that
added them. On by default; `--no-history` to skip.

**Transitive dependencies.** `package-lock.json` (all versions) and
`Pipfile.lock` are read, so vulnerable packages you never installed directly are
found too. On a real four-dependency Express app, SafeShip and `npm audit`
report the same ten packages; 0.2.0 found four. Fix advice says when a package
is not in your `package.json` and suggests `npm audit fix` or an override,
instead of telling you to edit a file that does not mention it.

**Versions in `--json`**, so a result can be reproduced: the same rules give
different counts on a different Semgrep.

### Fixed

**No API key no longer throws the scan away.** In 0.2.0, plain
`npx safeship scan` without `ANTHROPIC_API_KEY` ran every engine, then exited at
the first Semgrep finding before writing the report. It now falls back to
unexplained findings and says so. A *malformed* key still stops the run, but now
before scanning, so nothing is lost.

**`--secrets-only` and `--no-explain` work without the anthropic package
installed.** They needed it anyway because of an import at the top of a file.

**Windows: the CLI picks a Python that can actually run the tool.** `py -3` and
the `python` on PATH are often different installs. 0.2.0 checked the version of
one and found Semgrep in the other, reported "everything safeship needs is
present", and then crashed on import.

**SafeShip's own findings are no longer hidden behind generic ones.** When a
Semgrep registry rule and a SafeShip engine flagged the same line, the registry
rule usually won, so a leaked AWS key was shown at *high* instead of
*critical*, with a generic message and the literal text "requires login" where
the code should be.

**"+N other rules matched here" no longer counts the finding itself.**

**`python report.py findings.json` keeps the "Incomplete scan" banner.** It
used to drop it, so a report rendered from saved results could look complete
when an engine had not run.

## 0.2.0 — 2026-09-21

### Added

**Dataflow (taint) rules — `rules/taint_flows.yaml`.** Six rules across Python
and JavaScript/TypeScript covering SQL injection, command injection, and code
execution. These ask a different question from the pattern rules: not "does this
line look dangerous" but "can attacker input actually reach here, and was it
neutralised on the way".

Because `int()`, `parseInt()`, `.isdigit()` and allowlist membership are declared
as *sanitizers*, a proven flow needs no AI judgment — the analysis already
answered it. On a fixture of genuinely safe code that Semgrep's registry flags 9
times, the taint rules report **0**.

They do not replace the pattern rules. Taint misses injections in plain helper
functions where nothing marks a parameter as attacker-controlled, so both layers
run. Over-firing annoys people; silently missing is worse and feels better.

### Fixed

**False positives on real code cut from 20 to 1.** Measured over 13,107 files of
installed third-party libraries — code the scanner was not written against. Four
new filters on the generic credential rule, each written against a line actually
read rather than imagined:

| Shape | Example | Why it is not a credential |
|---|---|---|
| numeric dotted | `szOID_RSA_challengePwd = "1.2.840.113549.1.9.7"` | an X.509 OID |
| separator-joined words | `token_endpoint_auth_method="private_key_jwt"` | a method name |
| brace interpolation | `f"AccessToken(token='{masked}')"` | an f-string template |
| PEM header, no body | `_SK_START = b"-----BEGIN OPENSSH PRIVATE KEY-----"` | the delimiter a parser looks *for* |

Detection of real credentials is unchanged: 16/16 on the fixture, and both
files of correct code still report nothing.

**A blocked engine no longer ends the whole scan.** On Windows, an Application
Control policy blocking Semgrep's native binary raised a bare `OSError` that
escaped the per-engine error handling, so the run exited with an empty report
*after* the credential, dependency, and configuration scans had already
succeeded. Any engine can now fail without costing you the other three.

**`--no-explain` now says when an engine did not run.** The warning went to
stderr only, so `safeship scan --no-explain > report.txt` produced a file that
looked like a clean bill of health for checks nobody performed. This is the path
used when there is no API key, so it was the likeliest of all to be misread.

## 0.1.0 — 2026-09-08

First release. Four engines — credentials, dependencies, configuration, static
analysis — one HTML report, nothing uploaded.
