# VibeSec — AI Security Scanner for Vibe-Coded Projects

Scans AI-generated Python for security bugs by combining Semgrep (finds the pattern)
with the Claude API (explains it in plain English). Rishabh is learning security by
building the tool and then attacking it.

**Heavy comments throughout — this is a learning tool, not just a working one.**

---

## Read this before suggesting anything

Two facts cost us a lot of time. Don't rediscover them.

**1. `python -m semgrep` does not work.** Deprecated in 1.38.0; this machine has
1.173.0, where it prints a warning and exits 2 without scanning. Use the `semgrep`
executable. On Windows it shells out to a separate `pysemgrep`, and both live in
`C:\Users\rishi\AppData\Roaming\Python\Python314\Scripts`. `scanner.py` already finds
them via `sysconfig` — you don't need to touch PATH.

**2. A Claude Pro subscription does NOT include Anthropic API credits.** They are
separate products with separate billing. Pro covers claude.ai and Claude Code; a
`sk-ant-` key billed pay-as-you-go covers your own scripts. The API key is set at
User scope and is valid — the account balance is zero, so every request returns
`400 invalid_request_error: credit balance is too low`. **This is the only thing
blocking the project.** $5 is the minimum top-up; a full 14-finding run costs cents.

Note: Claude Code's own process may not inherit the User-scope key. To use it in a
command without exposing the value:
`$env:ANTHROPIC_API_KEY = [Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY","User")`

---

## Environment

Windows 11 · Python 3.14.2 · Semgrep 1.173.0 · anthropic SDK 0.122.0 ·
model `claude-sonnet-5` (set in `explainer.py`; Sonnet 4.6 lacks structured outputs)

---

## What works, verified

| File | State |
|---|---|
| `scanner.py` | **Works.** Runs Semgrep, returns parsed findings. |
| `test_targets/vulnerable.py` | **Done.** 7 planted vulns, each commented with why LLMs write it. |
| `rules/vibe_patterns.yaml` | **Works.** 7 custom rules, all firing. |
| `analyze.py` | **Scan path works** (`--no-explain`). Explain path never run. |
| `explainer.py` | **Never run.** Blocked on credits. |

Measured: `--config auto` alone catches 4 of 7 planted vulns. Adding the custom rules
catches 7 of 7 (31 raw findings → 14 locations after dedupe).

Run the working half with:
`python analyze.py test_targets/vulnerable.py --config auto --config rules/vibe_patterns.yaml --no-explain`

---

## Two real findings so far

**False positives (Test 2 — passed).** `test_targets/safe_but_flagged.py` contains
three genuinely safe patterns. Semgrep raises 11 findings on it. An LLM given the
prompt correctly dismissed all 5 deduped locations. This is the clearest evidence the
LLM layer earns its place.

**False negative (Test 3).** `test_targets/mass_assignment.py` has a mass-assignment
privilege-escalation bug — `is_admin` arrives in the request body, so a user promotes
themselves with `{"is_admin": true}`. Semgrep raises 5 findings on that line, all
labelled SQL injection. Nothing detects the actual worst bug, because there is no
dangerous *function* to match. Whether the LLM catches it is still untested.

**Known bug found while testing this:** `CONTEXT_LINES = 5` in `analyze.py` clips the
function signature and the line where the request body is read, so the LLM is asked
"is this attacker-reachable?" without seeing where the input comes from. Should extend
to the enclosing function instead of a fixed line count. Not yet fixed.

---

## Next step, in order

1. Add $5 of API credits at console.anthropic.com → Plans & Billing.
2. `python explainer.py` — one request, one cent, proves the LLM path works.
3. `python analyze.py test_targets/vulnerable.py --config auto --config rules/vibe_patterns.yaml`
4. Then Test 1 (prompt injection) and Test 4 (Snyk, free tier).

---

## How to work on this

- **One step at a time.** Do not write the next file until the last one has actually
  run. Untested code is not progress.
- **Rishabh runs it and judges the output.** If Claude both writes the tool and grades
  its answers, he learns nothing. The judgment is the point.
- **Ask before adding files.** This repo accumulated scaffolding fast.

Disposable, safe to delete: `diagnose.py`, `manual_review.py`, `RED_TEAM.md`, and any
`*_prompts.md`. Core is `scanner.py`, `explainer.py`, `analyze.py`, `rules/`,
`test_targets/`.

## Not yet

Not a web app. Not scanning GitHub URLs. Python only. Not production-ready.
