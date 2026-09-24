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
| `engines/secrets.py` | Credentials in **any** text file, plus git history | Works, 16/16 on fixtures, 1 FP on 13,107 real files |
| `engines/dependencies.py` | OSV.dev CVE lookup, pip + npm, transitive via lockfiles | Works, 9/9 on fixtures; matches `npm audit` 10/10 on a real tree |
| `engines/config.py` | Insecure config, 22 rules + 2 absence checks | Works, 22/22 on fixtures |
| `analyze.py` | Orchestrates, dedupes, reports | Works |
| `report.py` | Findings → one self-contained HTML file | Works |
| `bin/safeship.js` | npx CLI: preflight, then runs the scan locally | Works |
| `rules/vibe_patterns.yaml` | 7 Python rules | Works, 7/7 |
| `rules/vibe_patterns_js.yaml` | 7 JS/TS rules | Works, 11/11 |
| `rules/taint_flows.yaml` | 6 dataflow rules, Python + JS/TS | Works, 0 FPs on both safe fixtures |
| `explainer.py` | Claude explains a Semgrep finding | **Works** — first real run 2026-09-05 |

Measured on `test_targets/` (2026-09-24, all four engines): **151 raw
findings → 88 locations**.

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

Benchmarking against `detect-secrets` forced a second round on the same corpus
(13,107 files after installing the benchmark tools), where 19 of 20 remaining
findings were still false. Four more filters, each written against a line that
was actually read rather than imagined:

| Shape | Real example | Why it is not a credential |
|---|---|---|
| numeric dotted | `szOID_RSA_challengePwd = "1.2.840.113549.1.9.7"` | an X.509 OID |
| separator-joined words | `token_endpoint_auth_method="private_key_jwt"` | a method name |
| braces | `f"AccessToken(token='{masked}')"` | an f-string template |
| PEM header, no body | `_SK_START = b"-----BEGIN OPENSSH PRIVATE KEY-----"` | the delimiter a parser looks *for* |

**Result: 20 → 1 on the corpus, 16/16 recall unchanged.** The survivor is a
genuine JWT in PyJWT's own README — a correct detection that is not actionable,
and deliberately left alone rather than special-cased.

Two details in there are load-bearing. The separator requirement is what keeps
`private_key_jwt` filtered while `8f4c2e9a7b1d6350fae82c94d17b0e63` still fires:
drop it and the filter eats genuine lowercase hex secrets. And the PEM check
needs a *lookahead* for base64 body, because the header alone was the only
**critical** false positive in the whole corpus — the most expensive kind, since
critical is the one a user drops everything to act on.

Worth noting what did **not** need fixing: across all 13,107 files the 22
provider-format patterns (AWS, Stripe, GitHub, Slack, Google, OpenAI) produced
**zero** false positives. Every one came from the single generic catch-all rule.
That is the argument against generic high-entropy detection, restated as data.

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

**Transitive dependencies are scanned, from the lockfile.** The manifest
records what you asked for; the lockfile records what is actually installed,
which is usually ten times more packages. A CVE in something you never chose is
just as exploitable as one you did.

Added because the benchmark showed this was the one axis where `npm audit` and
`pip-audit` were simply better. Verified by generating a lockfile for a
four-dependency Express app and running both:

| | packages reported |
|---|---|
| `npm audit` | axios, body-parser, cookie, express, jsonwebtoken, lodash, path-to-regexp, qs, send, serve-static |
| SafeShip | the same ten — 4 direct, 6 transitive |

Before the change it found 4. Sources: `package-lock.json` (v1 nested and v2/v3
flat) and `Pipfile.lock`. A `requirements.txt` produced by `pip freeze` is
already flat, so pip users were mostly covered by accident.

**The fix advice differs, and that is the point of tracking `direct`.** Telling
someone to "upgrade lodash to 4.17.21" when lodash is not in their package.json
is advice they cannot follow: it sends them to edit a file that does not mention
the package, and when that fails the natural conclusion is that the tool is
wrong. Transitive findings say so explicitly and suggest `npm audit fix` or an
`overrides` entry, with the warning that an override forces a version the parent
did not choose.

*Severity is not downgraded for being transitive.* Actionability and
exploitability are different things, and quietly rating a real CVE lower because
it is inconvenient to fix would be inventing a judgment the data does not
support.

**Known gaps, all for the same reason:** `poetry.lock` and `uv.lock` are TOML,
and `tomllib` arrived in 3.11 while `MIN_PYTHON` is 3.10 — parsing them means
either a dependency or a hand-rolled parser, and this file already has a section
on why hand-rolled parsers are a bad idea. `yarn.lock` is a bespoke format and
`pnpm-lock.yaml` is YAML, which has no stdlib parser either.

**Git history is scanned, because deleting a key is not revoking it.**
`scan_history()` in `engines/secrets.py`. Removing a credential from a file and
committing the removal *looks* like a fix: the file is clean, the working-tree
scan says nothing, and the person is now confident. The old blob is still in the
object store, still in every clone and fork, and `git show` brings it back in one
command.

Added after benchmarking against gitleaks, whose primary mode is history
scanning and ours was nothing. On by default, `--no-history` to skip; 0.74s
across this repo's 22 commits, so it does not need to be opt-in.

Four things were wrong on the way, and all four are the kind that look fine:

- **Excluding by blob is not enough — exclude by credential value.** A file that
  was reformatted, or had one unrelated line changed, leaves an old blob holding
  a secret that is *still in HEAD*. Measured on this repo: **13 findings, 12 of
  them still live**, reported under a heading that says they were deleted. The
  unit that matters is the credential, not the object that carried it. After
  the fix: 2, and both genuine — the rename left `postgresql://vibesec:...`
  connection strings in history while HEAD says `safeship:`.
- **`git log --find-object` lists newest first**, so taking the first entry names
  the commit that *removed* the credential. Sending someone to the deletion
  commit is worse than saying nothing: it makes the tool look wrong about the
  thing it is warning them about. Take the oldest.
- **Blob paths are relative to the repo root, not to the scan target.** Handed
  straight to the report they rendered as `../../../../../../.env`, and scanning
  one subdirectory of a monorepo reported credentials from every other project
  in it. Make them absolute, then filter to the target.
- **A directory that is not a git repository returns `[]`, it does not raise.**
  There is no history, so nothing went unchecked. A `NOT SCANNED` warning for a
  folder that never had commits cries wolf on the one warning that has to stay
  meaningful.

Contract in `test_fixtures.py`, building throwaway repos at runtime because a
nested `.git` would not survive being cloned. **Mutation testing earned its keep
here**: the first version of the "still present at HEAD" fixture had a single
commit, so there was no historical blob at all and the check passed whether or
not the suppression worked. Dropping the exclusion did not turn it red. The
fixture now changes the file while keeping the key, which is the real case.

**At a shared line, the engine that answered wins — tier before severity.**
Two rules on one line are usually describing the same thing, and dedupe has to
pick which description to keep. Severity alone could not decide it: a registry
rule and the secrets engine both call a leaked AWS key `ERROR`, so the tie fell
to insertion order, and Semgrep is collected first.

On `test_targets/secrets/.env` that cost four of the seven credentials. What was
lost is not a label:

| | kept before | kept after |
|---|---|---|
| rule | `detected-aws-access-key-id-value` | `secrets.aws-access-key-id` |
| severity | high | **critical** |
| snippet | `"requires login"` | `AWS_ACCESS_KEY_ID=AKIA...R5TC (20 chars)` |
| remediation | generic | "Deactivate the key in IAM, then create a new one" |
| git exposure | absent | "committed" |

That snippet is not a typo. Semgrep's registry gates rule *content* behind a
login, so an unauthenticated run gets the literal string `requires login` where
the code should be. The winner was strictly less useful than the loser, and
rated it lower too.

`_survivor_rank()` now sorts on `(tier, severity)`, using the same three tiers
the pipeline already routes on: engine-answered, dataflow, pattern. Measured on
`test_targets/`, 18 locations changed owner and **every one** moved from a
generic registry rule to a purpose-built finding — 10 credentials to the secrets
engine, 6 injections to the taint rules, 2 to the config engine. Locations went
78 → 79, because two adjacent secrets on `js/vulnerable.js:13-14` stopped being
merged as one rule and are now correctly two.

*Ranking by tier first also fixes a comparison that was never meaningful.*
Severity scales differ per engine by design (see below), so comparing a config
`WARNING` against a registry `ERROR` was comparing different units. Tier-first
means severity is only ever compared within a tier.

A second bug surfaced while fixing this: the survivor listed **itself** in
`_also_matched`, because the challenger was appended before deciding who won.
The report said "+2 other rules here" when one other rule had matched. Rare while
promotions only happened on a severity difference; routine once tier decides.

Both are contracts in `test_fixtures.py`, both mutation-verified — including
**both insertion orders**, since order dependence was the actual bug.

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

Flags: `--no-semgrep` `--no-secrets` `--no-config` `--no-deps` `--no-history`
`--secrets-only` `--no-explain` `--no-dedupe` `--json` `--html PATH`

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

## Tests

Three, all standalone, all exit 0/1:

```bash
python test_fixtures.py          # every count in this file, plus dedupe precedence
python test_degradation.py       # failure paths: 5 contracts, all mutation-verified
                                 # (breaking every engine means every one, history included)
python test_report_escaping.py   # the HTML report cannot be made to execute code
```

Each exists because of a real failure, not for coverage.

`test_fixtures.py` **skips** the Semgrep checks when Semgrep cannot run, and
`SAFESHIP_REQUIRE_SEMGREP=1` makes that skip fatal. CI sets it. This is the
answer to the Application Control gap below: locally you get an honest "not
verified", and on Linux the rules are actually exercised on every push. A skip
nobody notices is indistinguishable from a pass, so it is counted and printed.

## CI

`.github/workflows/ci.yml` — push, PR, and **weekly**. The schedule is not
decoration: OSV.dev publishes new advisories and Semgrep releases change how
rules match, so a green build in September is not evidence about October.

Two jobs. `tests` runs all three suites on Python 3.10 and 3.13. `cli` runs
`bin/safeship.js` on ubuntu **and windows** -- Windows because the interpreter
probe tries `py -3` first and that branch never runs on Linux -- scanning a
throwaway project created *outside* the repo, which is the only arrangement that
can catch the `cwd` bug coming back.

**The first CI run went red, and both failures were real.** That is the argument
for having it.

- **Python 3.9 was never actually supported.** The README promised 3.9+ and the
  CLI enforced it, but Semgrep requires >=3.10 as of 1.137 -- so on 3.9 pip
  quietly resolves semgrep to ~1.136, a different engine whose rule matching
  moves the fixture counts. "Supported" meant "installs, and silently finds
  other things". The floor is now 3.10 in `bin/safeship.js`, the README, and the
  matrix. The three pure-Python engines would still run on 3.9; Semgrep is what
  sets the floor, and claiming otherwise was the bug.

- **The windows CLI job failed for a second, unrelated reason, and it took
  three runs to read.** Downloading Actions logs returns 403 "Must have admin
  rights to Repository" even on a public repo, so the step now publishes its own
  diagnosis as an `::error::` annotation -- annotations are served by the API to
  anyone. Keep that. A red build nobody can read is barely better than no build.

  What it said:

      python (PATH): hostedtoolcache/Python/3.13.15  ->  anthropic 1.8.0
      py -3:         hostedtoolcache/Python/3.14.7   ->  ModuleNotFoundError

  `py -3` resolves through the Windows registry; pip installs into whatever is
  on PATH. They are routinely different interpreters. The preflight checked the
  *version* of the one it picked and the *presence* of semgrep found via PATH --
  from the other interpreter -- printed "Everything safeship needs is present",
  and then `analyze.py` died on import before a single engine ran.

  Two fixes, and the second one matters more:

  1. `findPython()` now **prefers** a candidate that can `import anthropic`
     rather than taking the first that satisfies the version check. Importing
     the SDK is the best available proxy for "this is the Python the user
     actually ran pip install with". It still falls back to a version-valid
     interpreter and warns, because three engines need no SDK at all.
  2. `analyze.py` no longer imports `explainer` at module scope. It imports the
     anthropic SDK at *its* module scope, so one top-level import made the SDK
     mandatory for every run -- including `--secrets-only`, which the README
     calls the offline path. **The key was optional; the package was not.**
     `anthropic_client()` had already deferred its own import for this reason;
     the top-level `import explainer` silently defeated it.

  This is the fifth contract in `test_degradation.py`, and it runs in a
  subprocess because the failure was at import time and a test that has already
  imported `analyze` cannot observe it. Mutation-verified: putting the
  top-level import back turns it red.

---

**One engine failing degrades the scan; it does not end it.** Found by running
this on real projects, where Windows blocked Semgrep's native binary with an
application-control policy and the whole run exited — throwing away three working
engines. Every engine is now collected in `skipped` and named at the top of the
report, and in the zero-findings path first of all: "no findings" plus a silently
absent engine reads as a clean bill of health for checks nobody performed.

**That claim was false for eight months, and a benchmark run caught it.** On
2026-09-20 the Application Control block returned and `analyze.py` exited 1 with
an empty report, after the credential, dependency and config scans had already
succeeded. Two causes, both fixed:

- `scanner.py` caught `TimeoutExpired` and `JSONDecodeError` but not `OSError`,
  so `WinError 4551` never became a `ScannerError` — the one type the degradation
  path recognises. Converting it is the entire reason that exception class exists.
- The `planned` loop caught only each engine's **declared** exception type. That
  is the bug the table was built to prevent, reintroduced by being too specific:
  an unanticipated failure is exactly the one that escapes a narrow `except`.
  It now also catches `Exception`, names the type, and keeps going.

A third gap surfaced while verifying: `--no-explain` printed its compact listing
and returned **without** the `NOT SCANNED` warning, which went to stderr only and
vanishes under a redirect. That is the path the README sends people to when they
have no API key — the likeliest of all to be misread as a clean bill of health.

The lesson is narrower than "add error handling": *the degradation path needs a
test that actually breaks an engine.* All three of these survived because the
engines kept working, and the path only runs when one stops.

**`test_degradation.py` is that test**, written 2026-09-22. It monkeypatches a
real engine to raise, then drives the real `main()` -- not a copy of the loop,
because a test that models the code cannot catch the code diverging from the
model. Four contracts:

| Contract | Guards |
|---|---|
| `scanner.scan` converts `OSError` into `ScannerError` | bug 1 |
| An **undeclared** exception costs one engine, and names the type | bug 2 |
| A **declared** exception is still handled | that broadening did not replace the narrow path |
| Total failure raises, and never prints "No findings" | the false clean bill of health |

The third one matters as much as the second. Widening an `except` is exactly the
kind of change that silently swallows the specific handler it was meant to
supplement.

**Every check was verified by putting the bug back.** Each fix was deleted in
turn and the suite re-run; all three mutations were caught, and the `--no-explain`
one produced the diagnosis in words -- "stderr only; `safeship scan --no-explain
> report.txt` then reads as clean". A green test proves nothing until you have
watched it go red. If you add a fifth contract here, mutate the code it covers
before believing it.

## Known gaps

- **Semgrep intermittently dies under Windows Application Control.**
  `OSError: [WinError 4551] An Application Control policy has blocked this file`,
  raised when semgrep shells out to its native `osemgrep`. Seen mid-session on
  2026-09-04, cleared by itself on 2026-09-05, back on 2026-09-20 — so treat it
  as flaky, not fixed. Nothing in SafeShip can prevent it; the scan degrades to
  the three pure-Python engines and says which engine did not run.

  **It has a second face, and it looks like a packaging bug.** On 2026-09-21 the
  same policy blocked `pysemgrep.exe` instead of `osemgrep`. `semgrep.exe` then
  starts fine, fails to spawn its child, and reports

      exit code 127 -- executing pysemgrep failed: No such file or directory

  which reads as a missing file or a broken PATH. It is neither. `scanner.py`
  locates both shims and hands subprocess a PATH containing them; verify with

      python -c "import scanner,shutil; e,v=scanner.find_semgrep(); print(shutil.which('pysemgrep',path=v['PATH']))"

  If that prints a path, SafeShip has done its job and the policy is the cause.
  Running the shim directly confirms it — `pysemgrep.exe --version` returns
  "Permission denied". Diagnosed once while checking a release; do not go
  rewriting PATH handling over it.
- **`metavariable-regex` matches in FULL, it does not search.** A bare
  `(select|insert)` silently matches nothing; it needs wrapping `.*`. This
  cost real time — the rule loaded, ran, and quietly found less than it should.
  Every regex in both rule files is anchored or `.*`-wrapped for this reason.

---

## Benchmarked against other tools

Run 2026-09-20, gitleaks added 2026-09-24. Every number before this was
self-generated, which is worth exactly as much as a fixture you wrote yourself.

**Dependencies**, on `test_targets/deps/` — 6 vulnerable PyPI, 3 npm:

| | PyPI | npm | FPs |
|---|---|---|---|
| `pip-audit` 2.10.1 | **0/6 — errored out** | n/a | — |
| `npm audit` 11.6.2 | n/a | 3/3 | 0 |
| SafeShip | 6/6 | 3/3 | 0 |

`pip-audit` audits an environment it must first *resolve*, and failed twice for
different reasons: `cryptography==2.3` has no Python 3.14 wheel and fails to
build, and with it removed `requests==2.19.1` pins `urllib3<1.24` against the
pinned `urllib3==1.24.1` → `ResolutionImpossible`. It is not broken — it reported
6 advisories for `jinja2==2.10` alone. The point is structural: **a
requirements.txt written by an AI from memory is often unresolvable, and that is
precisely this tool's input.** Reading the file and querying OSV needs no resolve.

Fair to both: `pip-audit` and `npm audit` cover **transitive** dependencies.
That was a real gap in their favour and is now closed -- on a generated lockfile
for a four-dependency Express app, SafeShip and `npm audit` report the same ten
packages. `npm audit` still needs a lockfile it can resolve; SafeShip reads
whichever of `package-lock.json` or `Pipfile.lock` is present and falls back to
the manifest when neither is.

**Secrets**, on `test_targets/secrets/` — 16 planted credentials:

| | recall | FPs |
|---|---|---|
| `detect-secrets` 1.5.0 | 8/16 | 4 |
| `gitleaks` 8.30.1 | 13/16 | 1 |
| SafeShip | 16/16 | 0 |

All four of `detect-secrets`' unique findings are false, and the inversion is
almost too neat: it flagged `AKIAIOSFODNN7EXAMPLE` in `.env.example` and
**missed the real AWS key in `.env`**. It also flagged both `pk_live_`
publishable keys, which are designed to ship, and missed the `sk_live_` secret
key and the Slack token entirely.

`gitleaks` is the better of the two by a wide margin, and stays silent on
`.env.example` where `detect-secrets` does not. Its three misses are one shape:
**credentials embedded in a URL**. `postgresql://user:PASSWORD@host/db` in both
`.env` and `docker-compose.yml`, plus the GCP `service_account` block. Its one
false positive is the `pk_live_` trap — same one `detect-secrets` fell into, and
the reason that line exists.

A fourth gitleaks row is not a false positive but worth knowing: its
`generic-api-key` regex spans the newline, so the JWT on `deploy_notes.txt:14`
is reported twice, once anchored to the prose line above it.

**Secrets, on code neither tool was written for** — 13,107 files of installed
third-party libraries. This is the run that matters, and before the filter work
it went the other way:

| | findings | all false? |
|---|---|---|
| `detect-secrets` 1.5.0 | **0** | — |
| `gitleaks` 8.30.1 | **220** | yes |
| SafeShip, before the filters | **20** | 19 of 20 |
| SafeShip, after | **1** | no — a real JWT in PyJWT's README |

Losing 20–0 to `detect-secrets` on the tool's own stated governing constraint is
the most useful thing the benchmark produced. Keep re-running both halves; the
corpus is just `site-packages`, and it grows on its own as you install things.

**Be fair to gitleaks about that 220.** Two hundred of them come from a single
file — `license_expression/data/scancode-licensedb-index.json`, where
`"license_key": "gfdl-1.3-invariants-or-later"` matches `generic-api-key`.
Excluding that one file it is 20, across 9 files, and those are also all false:
`private_key: x25519.X25519PrivateKey` (a type annotation), `cv.gapi.CV_UINT64:
'cv.gapi.CV_UINT64'` (an enum mapping), `Ed25519PrivateKey` (a class name),
`key_sha256": "bb1636..."` (a test vector).

Every one is the same catch-all-rule problem SafeShip had, and several are
exactly the shapes the four filters now handle. gitleaks also ships
`.gitleaksignore` as the intended answer, which makes a raw count less damning
than it looks in its own workflow.

**Two things gitleaks does better, stated plainly.** It scanned 516 MB in
**9.8 seconds** against SafeShip's 70, because it is Go and we are Python. And
its primary mode is `gitleaks git` — scanning history for credentials that were
committed and later removed — which SafeShip does not do at all. A key deleted
in the working tree but alive in the reflog is still leaked, and we would miss
it entirely.

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
and then hits a missing interpreter. So `bin/safeship.js` checks Python (3.10+,
trying `py -3` first on Windows) and Semgrep before doing anything, and names
what to install. `safeship doctor` runs the same checks alone.

`MIN_PYTHON` is **3.10**, and it is Semgrep's floor rather than ours -- see the
CI section. Do not lower it back to 3.9 to be generous: pip will happily install
an old semgrep there and the scan will quietly find different things.

**A version check is not a usability check.** `findPython()` prefers an
interpreter that can `import anthropic`, because on Windows `py -3` and the
`python` on PATH are frequently different installs and only one of them has the
dependencies. Picking by version alone produced a preflight that said everything
was present and a scan that died on import.

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

Published to npm: `safeship@0.1.0` on 2026-09-08, `0.2.0` on 2026-09-21. The
version bump is a **minor**, not a patch, because `rules/taint_flows.yaml` is new
detection capability rather than a fix. `CHANGELOG.md` is the record and ships
with the package.

Verify a release the way the last one was verified: `npm pack`, install the
tarball into a scratch directory, and run the CLI from there against a project
somewhere else entirely. That is what proves the `cwd` bug has not come back —
running it from inside the repo cannot, because both paths happen to work.

Still open: there is no `pyproject.toml`, so `pip install safeship` does not
exist. Nothing else blocks it.

Not a web app, not a hosted service, not scanning GitHub URLs. Local-only by
design.
