# SafeShip — security scanner for vibe-coded projects

Scans a project with four independent engines and prints one report. Built for
non-technical developers shipping AI-generated code, so the governing constraint
is **a false positive costs more than a missed finding**: a user who gets twenty
fake criticals stops running the tool at all.

Target audience is the vibecoder. Whoever runs it judges the output and attacks
it. Code is production-shaped — clean modules, real error handling for other
people's messy repos — not a tutorial.

---

## Read this before suggesting anything

Three facts that cost real time. Don't rediscover them.

**1. `python -m semgrep` does not work.** Deprecated in 1.38.0; this machine has
1.173.0, where it prints a warning and exits 2 without scanning. Use the `semgrep`
executable. On Windows it shells out to a separate `pysemgrep`; both live in
the Python user-scheme `Scripts` directory. `scanner.py` already
finds them via `sysconfig` — you don't need to touch PATH.

**2. A Claude Pro subscription does NOT include Anthropic API credits.** Separate
products, separate billing: a valid `sk-ant-` key with no balance returns
`400 credit balance is too low` on every request, which reads like a broken key
and is not one. $5 is the minimum top-up. This affects **only** `explainer.py` —
three of four engines need no API key at all.

The key now lives in `.env` beside `analyze.py` (gitignored; `.env.example` is
the committed template). `analyze.py` has a twenty-line stdlib `load_dotenv()` --
no python-dotenv, the dependency count stays at two. It reads **only SafeShip's
own .env**, never the scanned project's: pulling a stranger's credentials into
our process environment, which every subprocess inherits, as a side effect of
scanning their code is precisely what this tool exists to warn about. A real
environment variable still wins over the file.

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
| `engines/secrets.py` | Credentials in **any** text file | Works, 16/16 on fixtures |
| `engines/dependencies.py` | OSV.dev CVE lookup, pip + npm | Works, 9/9 on fixtures |
| `engines/config.py` | Insecure config, 22 rules + 2 absence checks | Works, 22/22 on fixtures |
| `analyze.py` | Orchestrates, dedupes, reports | Works |
| `report.py` | Findings → one self-contained HTML file | Works |
| `bin/safeship.js` | npx CLI: preflight, then runs the scan locally | Works |
| `rules/vibe_patterns.yaml` | 7 Python rules | Works, 7/7 |
| `rules/vibe_patterns_js.yaml` | 7 JS/TS rules | Works, 11/11 |
| `rules/taint_flows.yaml` | 6 dataflow rules, Python + JS/TS | Works, 0 FPs on both safe fixtures |
| `explainer.py` | Claude explains a Semgrep finding | **Works** — first real run 2026-09-05 |

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

**The generic credential rule requires a quoted value in code.** Run over 12,775
files of real third-party libraries, the original rule produced 563 findings, 554
of them false: in a code file `api_key=resolved_api_key` and
`api_key_env_vars: Sequence[str]` are the *correct* pattern, not the bug. Quoted
values are matched everywhere; the unquoted form is scoped to config formats
(.env, YAML, INI, TOML, compose) where `NAME: value` really is a literal. Four
further filters — no whitespace, no SCREAMING_SNAKE, no leading `/` or `://`, no
all-letter words — removed the rest. Final: **17 findings on those 12,775 files**.
The fixtures never caught any of this, because every fixture was written as
`NAME = "literal"`. Fixtures test the shapes you thought of.

**Snippets extend to the enclosing function, not a fixed line count.**
`find_enclosing_start()` walks up from the finding to the first line that both
starts a scope and is indented less than the finding — true in Python, true in
practice for formatted JS — then absorbs any decorators above it, because
`@app.route(...)` is often the strongest clue that a handler is reachable at all.
Capped at `MAX_LOOKBACK = 40` so a long handler does not put 300 lines in every
prompt, and the window can only ever widen: `min(enclosing, fixed_window)` means
a finding on a function's first line still gets the old context.

Measured before and after on the same two fixtures:

| | before | after |
|---|---|---|
| `safe_but_flagged.py` (safe code) | 4/5 dismissed, **1 false positive** | **5/5 dismissed** |
| `mass_assignment.py` (real bug) | confirmed, but hedged — "*if* `data` comes from a request body" | confirmed, names the route: "an attacker POSTs to `/api/profile`" |

*Known limit:* it finds the enclosing **function**, so a module-level constant
the function references stays outside the window — `ALLOWED_SORT_COLUMNS` on line
47 of `safe_but_flagged.py` is still not included. It turned out not to matter:
the `if sort_column not in ALLOWED_SORT_COLUMNS` guard *inside* the function is
enough for the model to reason correctly. Resolving referenced names to their
definitions would be the next step, and is not obviously worth it.

**The LLM layer earns its place — measured, not assumed.** First real runs,
2026-09-05. On `safe_but_flagged.py` Semgrep raised 11 findings across 5
locations on genuinely safe code; Claude dismissed all 5 with correct
reasoning (`int()` casts mean no payload survives to the query; the allowlist
guard blocks the rest). On `mass_assignment.py` it confirmed the real bug with
concrete payloads and an allowlist fix. Roughly two cents per run at Sonnet 5.

**Three confidence tiers, not one.** Findings differ in how much is *known*
about them, and the pipeline routes them accordingly:

| Tier | What it means | Goes to the model? |
|---|---|---|
| Engine-answered | A credential, a CVE, a config line — the answer is a fact | No |
| **Dataflow (taint)** | Input provably reaches a sink, no sanitizer between | **No** |
| Pattern match | This shape is suspicious; reachability unknown | Yes |

`rules/taint_flows.yaml` asks a different question from `vibe_patterns.yaml`:
not "does this line look dangerous" but "can attacker input actually arrive
here, and was it neutralised on the way". Declaring `int()`, `float()`,
`.isdigit()` and allowlist-membership as **sanitizers** encodes in the rule what
the model previously had to re-derive on every run.

Measured on `test_targets/safe_but_flagged.py`, genuinely safe code:

| | findings | cost to clear |
|---|---|---|
| Semgrep registry (`auto`) | 9 | 9 API calls |
| `vibe_patterns.yaml` | 2 | 2 API calls |
| `taint_flows.yaml` | **0** | **nothing — the rule knows** |

**Taint does NOT replace the pattern rules, and running only taint is a
downgrade.** The two fail in opposite directions. On `vulnerable.py` the pattern
rules catch 3 of 3 SQL injections; taint catches 1, because the other two sit in
plain helpers (`def get_user(user_id):`) with no decorator and no request call —
nothing in the file says that parameter is attacker-controlled, so there is no
source to start from. Over-firing annoys people; silently missing is worse and
feels better. Keep both.

Three bugs found writing these, all worth not repeating:

- **A bare `$REQ.query` matches any object's `.query`** — including `db.query`,
  which made the sink its own source and flagged every constant query. Constrain
  the metavariable with `metavariable-regex`.
- **`subprocess.run(...)` as a sink flags the fix.** `subprocess.run(["ping",
  host])` has no shell to inject into; only `shell=True` is the sink.
- **`focus-metavariable` is what separates a parameterised query from an
  injection.** Without it, `db.query('... WHERE id = ?', [req.query.id])` — the
  recommended form — is flagged, because the value does reach the call. It
  reaches the *parameter array*, not the statement.

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
# As a user would, once published:
npx safeship scan            # scan .
npx safeship doctor          # check Python + Semgrep are present

# Locally, before publishing:
node bin/safeship.js scan ./someproject --no-explain
```

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
| `test_targets/secrets/` | 16 planted credentials; `.env.example` + `safe_config.py` must stay silent |
| `test_targets/deps/` | 9 vulnerable packages; unpinned + current ones ignored |
| `test_targets/config/bad/` | 22 issues across Django/Flask/Express/Next.js/Docker |
| `test_targets/config/good/` | **Zero findings.** Includes commented-out traps and a committed `.env.example` |
| `test_targets/js/vulnerable.js` | 11 planted vulns, all 7 JS rules fire |
| `test_targets/js/safe.js` | **Zero findings.** Parameterised query, non-SQL template literal, `eval` on a literal, `pk_live_` |

Fixture credentials are fake but format-valid. GitHub push protection may block a
push on pattern shape alone — allowlist the paths rather than weakening them.

---

**One engine failing degrades the scan; it does not end it.** Found by running
this on real projects, where Windows blocked Semgrep's native binary with an
application-control policy and the whole run exited — throwing away three working
engines. Every engine is now collected in `skipped` and named at the top of the
report, and in the zero-findings path first of all: "no findings" plus a silently
absent engine reads as a clean bill of health for checks nobody performed.

## Known gaps

- **Semgrep intermittently dies under Windows Application Control.**
  `OSError: [WinError 4551] An Application Control policy has blocked this file`,
  raised when semgrep shells out to its native `osemgrep`. Seen mid-session on
  2026-09-04, cleared by itself on 2026-09-05 — so treat it as flaky, not fixed.
  Nothing in SafeShip can prevent it; the scan degrades to the three pure-Python
  engines and says which engine did not run.
- **`metavariable-regex` matches in FULL, it does not search.** A bare
  `(select|insert)` silently matches nothing; it needs wrapping `.*`. This
  cost real time — the rule loaded, ran, and quietly found less than it should.
  Every regex in both rule files is anchored or `.*`-wrapped for this reason.

---

## How to work on this

- **One step at a time.** Do not write the next file until the last one has run.
  Untested code is not progress.
- **Whoever runs it judges the output.** If the model both writes the tool and
  grades its own answers, nobody learns anything. The judgment is the point.
- **Every new rule needs a good fixture too**, not just a bad one. A rule with no
  negative test is a false positive waiting to ship.
- **Ask before adding files.** This repo accumulated scaffolding fast once before.

## The npx wrapper

`npx` reaches the audience that ships AI-built products — Next.js and Express —
and needs no install step. The core is Python because Semgrep is Python, and
that combination has exactly one honest failure mode: npx promises zero-install
and then hits a missing interpreter. So `bin/safeship.js` checks Python (3.9+,
trying `py -3` first on Windows) and Semgrep before doing anything, and names
what to install. `safeship doctor` runs the same checks alone.

Two things that were wrong and are easy to reintroduce:

- **Do not set `cwd` on the spawn.** An earlier version used `cwd: ROOT`, which
  made `npx safeship scan .` scan the installed package instead of the user's
  project. Python puts the script's own directory on `sys.path`, so imports
  resolve without it. The target is resolved to an absolute path for the same
  reason.
- **`files` in package.json is an allowlist, but a listed directory pulls in
  everything under it** — including `__pycache__`. `test_targets/` is excluded
  on purpose: it holds format-valid fake credentials that must never ship.

## Phase 2 status

Item 4 (report) is done as a single self-contained HTML file rather than React +
a backend endpoint: with no server there is no endpoint to build, and a file a
user can email is more useful to this audience than one needing `npm install`.
It deviates from the spec in one way worth remembering — "an AI-generated
explanation for every issue" is not literally true, because three of four engines
answer without the model.

Item 5 (`npx safeship scan`) is done, minus publishing. It runs the scan locally
rather than zipping and uploading, because there is no server by design — and for
a tool that hunts credentials, not transmitting your source is a feature.

Still open: nothing is published to npm, and there is no `pyproject.toml`, so
`pip install safeship` does not exist either. Publishing needs a license decision
and a name check on the registry.

Not a web app, not a hosted service, not scanning GitHub URLs. Local-only by
design.
