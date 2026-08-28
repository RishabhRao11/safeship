# VibeSec — security scanner for vibe-coded projects

Scans a project with four independent engines and prints one report. Built for
non-technical developers shipping AI-generated code, so the governing constraint
is **a false positive costs more than a missed finding**: a user who gets twenty
fake criticals stops running the tool at all.

Target audience is the vibecoder. Rishabh runs it, judges the output, and attacks
it. Code is production-shaped — clean modules, real error handling for other
people's messy repos — not a tutorial.

---

## Read this before suggesting anything

Three facts that cost real time. Don't rediscover them.

**1. `python -m semgrep` does not work.** Deprecated in 1.38.0; this machine has
1.173.0, where it prints a warning and exits 2 without scanning. Use the `semgrep`
executable. On Windows it shells out to a separate `pysemgrep`; both live in
`C:\Users\rishi\AppData\Roaming\Python\Python314\Scripts`. `scanner.py` already
finds them via `sysconfig` — you don't need to touch PATH.

**2. A Claude Pro subscription does NOT include Anthropic API credits.** Separate
products, separate billing. The `sk-ant-` key is set at User scope and is valid;
the balance is zero, so every request returns `400 credit balance is too low`.
$5 is the minimum top-up. This blocks **only** `explainer.py` now — three of four
engines need no API key at all.

To use the key in a command without exposing it:
`$env:ANTHROPIC_API_KEY = [Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY","User")`

**3. Don't parse Python with regex.** `engines/config.py` needs to skip
docstrings (prose describing bad config is not bad config). A hand-rolled
triple-quote state machine was tried and silently inverted itself: this very file
contains `re.compile(r'"""|...')`, whose `"""` inside a single-quoted string
flipped the flag with no matching close, so every docstring below it was treated
as code. Use `tokenize`. It knows the difference.

---

## Environment

Windows 11 · Python 3.14.2 · Semgrep 1.173.0 · anthropic SDK 0.122.0 ·
model `claude-sonnet-5` (set in `explainer.py`; Sonnet 4.6 lacks structured outputs)

Runtime dependencies are still just `semgrep` and `anthropic`. The three new
engines use only the standard library — `urllib`, `json`, `re`, `tokenize`.

---

## Architecture

Every engine exposes `scan(target) -> list[finding]` and returns the **same
Semgrep-shaped dict**, so `analyze.py` merges them without knowing who produced
what:

```python
{"check_id", "path", "start": {"line", "col"}, "end": {...},
 "extra": {"message", "severity",            # ERROR | WARNING | INFO
           "lines", "metadata": {"engine", ...}}}
```

| File | What it does | State |
|---|---|---|
| `scanner.py` | Runs Semgrep, returns parsed findings | Works |
| `engines/secrets.py` | Credentials in **any** text file | Works, 15/15 on fixtures |
| `engines/dependencies.py` | OSV.dev CVE lookup, pip + npm | Works, 9/9 on fixtures |
| `engines/config.py` | Insecure config, 22 rules + 2 absence checks | Works, 22/22 on fixtures |
| `analyze.py` | Orchestrates, dedupes, reports | Works |
| `report.py` | Findings → one self-contained HTML file | Works |
| `rules/vibe_patterns.yaml` | 7 Python rules | Works, 7/7 |
| `rules/vibe_patterns_js.yaml` | 7 JS/TS rules | Works, 11/11 |
| `explainer.py` | Claude explains a Semgrep finding | **Never run — needs credits** |

Measured on `test_targets/`: 87 raw findings → 72 locations.

Custom rules vs the registry alone, per language:

| Fixture | `--config auto` | plus `rules/` |
|---|---|---|
| `test_targets/vulnerable.py` | 4/7 | 7/7 |
| `test_targets/js/vulnerable.js` | 2/11 | 11/11 |

---

## Design decisions, and why

**Only Semgrep findings go to Claude.** The explainer answers "is this pattern
actually exploitable here?" — a question that needs judgment. The other three
engines already carry their answer:

- *Secrets* — explaining a leaked key means sending the lines containing that key
  to a third party. The tool would be doing the exact thing it warns about.
- *Dependencies* — answering "does this CVE affect you" honestly needs whole-program
  reachability analysis we don't do. A published advisory beats a confident guess.
- *Config* — this one is the closest call, and is the obvious next improvement.
  Presence checks would benefit from judgment; **absence checks never should**,
  because there is no code at the location to reason about.

**No generic high-entropy detection.** It's the largest false-positive source in
every scanner that ships it — git SHAs, base64 images, minified bundles, integrity
hashes. Entropy is used only as a *filter* on the medium-confidence rule, never as
a detector. If it's ever added, it belongs behind `--entropy`, off by default.

**Absence checks require three-part evidence.** "Missing rate limiting" fires only
if a web framework was found AND an auth-shaped route was found AND no rate-limit
library exists anywhere. All three, or silence. Capped at WARNING, and the message
says a proxy or CDN doing the job makes the finding expected.

**Absence facts are scoped per project, not per scan.** A directory counts as a
project when it holds a `package.json`, `requirements.txt`, `manage.py`, or
similar marker; each gets its own fact set. Without this, one service's
`import helmet` in a monorepo marks the fact true and silently clears the service
next door that has none.

**Severity means different things per engine, deliberately.** The secrets engine
downgrades on git exposure — a credential's risk really is a function of whether it
reached your history. The config engine does *not*, because that would conflate
"in version control" with "deployed": `DEBUG = True` is just as dangerous in an
untracked `settings.py` if that file is what ships.

**The HTML report escapes everything, and that is a security control.** It
embeds file paths, source lines, credential values, and model output — and model
output is steerable by a prompt injection in the scanned code. Unescaped, that
chain ends with the report running an attacker's JavaScript when the analyst
opens it. `report.py` has no raw-HTML path, and `test_report_escaping.py` exists
to keep it that way. Run it after any template change.

**Stripe `pk_live_` is deliberately not a secret pattern.** Publishable keys are
meant to ship in client code. `test_targets/secrets/safe_config.py` contains one
specifically to prove we don't flag it.

---

## Running it

```bash
# Everything. Needs an API key only for the Semgrep findings.
python analyze.py myproject/ --config auto --config rules/

# No API key, no network, fast:
python analyze.py myproject/ --no-semgrep --no-deps

# Shareable single-file report, opens from disk, no network:
python analyze.py myproject/ --html report.html

# Any engine standalone, for isolating which layer misbehaved:
python engines/secrets.py myproject/ --json
python engines/dependencies.py myproject/ --json
python engines/config.py myproject/ --json
```

Flags: `--no-semgrep` `--no-secrets` `--no-config` `--no-deps` `--secrets-only`
`--no-explain` `--no-dedupe` `--json` `--html PATH`

`report.py` also runs standalone against `--json` output, so the report can be
iterated on without re-scanning:
`python analyze.py proj/ --json > f.json && python report.py f.json out.html`

---

## Fixtures

Every engine has a paired **bad** and **good** fixture. The good ones matter more:
they are how false-positive regressions get caught.

| Fixture | Expect |
|---|---|
| `test_targets/vulnerable.py` | 7 planted vulns, all 7 custom rules fire |
| `test_targets/safe_but_flagged.py` | Semgrep over-fires; the LLM should dismiss |
| `test_targets/mass_assignment.py` | Known false negative — no dangerous *function* to match |
| `test_targets/secrets/` | 15 planted credentials; `.env.example` + `safe_config.py` must stay silent |
| `test_targets/deps/` | 9 vulnerable packages; unpinned + current ones ignored |
| `test_targets/config/bad/` | 22 issues across Django/Flask/Express/Next.js/Docker |
| `test_targets/config/good/` | **Zero findings.** Includes commented-out traps and a committed `.env.example` |
| `test_targets/js/vulnerable.js` | 11 planted vulns, all 7 JS rules fire |
| `test_targets/js/safe.js` | **Zero findings.** Parameterised query, non-SQL template literal, `eval` on a literal, `pk_live_` |

Fixture credentials are fake but format-valid. GitHub push protection may block a
push on pattern shape alone — allowlist the paths rather than weakening them.

---

## Known gaps

- **`explainer.py` has never run.** The only untested path in the pipeline.
- **`CONTEXT_LINES = 5` in `analyze.py` clips context.** On
  `test_targets/mass_assignment.py` it cuts the function signature and the line
  reading the request body, so the model is asked "is this attacker-reachable?"
  without seeing where input comes from. Should extend to the enclosing function.
- **`metavariable-regex` matches in FULL, it does not search.** A bare
  `(select|insert)` silently matches nothing; it needs wrapping `.*`. This
  cost real time — the rule loaded, ran, and quietly found less than it should.
  Every regex in both rule files is anchored or `.*`-wrapped for this reason.

---

## How to work on this

- **One step at a time.** Do not write the next file until the last one has run.
  Untested code is not progress.
- **Rishabh runs it and judges the output.** If Claude both writes the tool and
  grades its answers, he learns nothing. The judgment is the point.
- **Every new rule needs a good fixture too**, not just a bad one. A rule with no
  negative test is a false positive waiting to ship.
- **Ask before adding files.** This repo accumulated scaffolding fast once before.

## Phase 2 status

Item 4 (report) is done as a single self-contained HTML file rather than React +
a backend endpoint: with no server there is no endpoint to build, and a file a
user can email is more useful to this audience than one needing `npm install`.
It deviates from the spec in one way worth remembering — "an AI-generated
explanation for every issue" is not literally true, because three of four engines
answer without the model.

Item 5 (`npx vibesec scan`) is unstarted, and needs a decision first: an npx CLI
driving a Python tool means two runtimes and `npx` users hitting "Python not
found". A Python entry point (`pipx install vibesec` → `vibesec scan`) is the
honest packaging; the npx wrapper is worth it only if reaching Node-first users
beats install simplicity.

Not a web app, not a hosted service, not scanning GitHub URLs. Local-only by
design.
