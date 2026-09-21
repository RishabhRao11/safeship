# Changelog

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
