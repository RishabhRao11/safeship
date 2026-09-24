# SafeShip

[![CI](https://github.com/RishabhRao11/safeship/actions/workflows/ci.yml/badge.svg)](https://github.com/RishabhRao11/safeship/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/safeship)](https://www.npmjs.com/package/safeship)

Security scanner for vibe-coded projects — the ones written mostly by an AI, shipped
mostly on trust.

```bash
npx safeship scan
```

It reads your project, writes a single HTML report you can open or forward, and
uploads nothing. Everything runs on your machine.

![A SafeShip report: severity tallies, filters by severity and engine, and a SQL
injection finding expanded to show the attack and the fix](docs/report.png)

*An actual report from a small Express app — 33 findings across 21 locations. Each
finding expands to show why it matters and the code that fixes it.*

## What it looks for

Four engines run over the same target and land in one report.

| Engine | Finds |
|---|---|
| **Credentials** | API keys, tokens, private keys, and database URLs — in **any** text file, including `.env`, `config.json`, `docker-compose.yml`, and README files that a code scanner never opens. Also **git history**, for keys you deleted but never revoked |
| **Dependencies** | Known CVEs in `requirements.txt` and `package.json`, with CVSS scores and the version that fixes them, via [OSV.dev](https://osv.dev) |
| **Configuration** | Debug mode on in production, CORS opened to the internet, TLS verification disabled, `.env` committed to git, secrets published to the browser via `NEXT_PUBLIC_` |
| **Static analysis** | SQL injection, command injection, `eval` on user input, and unauthenticated debug routes — Semgrep plus custom rules for the mistakes AI-generated code actually makes |

Those custom rules are the point. Against Semgrep's default registry alone:

| Fixture | registry only | with SafeShip's rules |
|---|---|---|
| Python | 4/7 | **7/7** |
| JavaScript | 2/11 | **11/11** |

## Measured against other tools

Not self-reported fixture scores — the same inputs, run through the tools people
actually use.

**Credentials**, on a fixture of 16 planted secrets plus two files of correct code
that must stay silent:

| | found | false positives |
|---|---|---|
| `detect-secrets` 1.5.0 | 8/16 | 4 |
| `gitleaks` 8.30.1 | 13/16 | 1 |
| **SafeShip** | **16/16** | **0** |

`detect-secrets` flagged the AWS key in `.env.example` and missed the real one in
`.env`. Both it and `gitleaks` flagged a Stripe *publishable* key, which is
designed to ship. `gitleaks` missed every credential embedded in a URL —
`postgresql://user:password@host/db` in two files — plus a GCP service account.

On **13,107 files of installed third-party libraries**, code none of these tools
was written against, the false-positive counts are `gitleaks` 220,
`detect-secrets` 0, SafeShip 1.

**Dependencies**, on 6 vulnerable PyPI and 3 vulnerable npm packages:

| | found |
|---|---|
| `pip-audit` 2.10.1 | 0/6 — could not resolve the file |
| `npm audit` 11.6.2 | 3/3 |
| **SafeShip** | **9/9** |

`pip-audit` has to resolve and build an environment before it can audit one. A
`requirements.txt` an AI wrote from memory often cannot be resolved at all — here
two pinned versions contradicted each other — and you get an error instead of
findings. SafeShip reads the file and asks OSV.

**Where they beat SafeShip:** `pip-audit` and `npm audit` both check
**transitive** dependencies — SafeShip only reads what you declared. `gitleaks`
is about seven times faster, being Go rather than Python, and walks every commit
where SafeShip compares against your current one — so it will still catch a key
added and removed inside a branch that was later squashed. And `detect-secrets`
reports 0 false positives on those 13,107 library files to SafeShip's 1 — that
gap used to be 0 to 20, and closing it is what [CLAUDE.md](CLAUDE.md) spends its
longest section on.

Git history scanning exists *because* of this benchmark: gitleaks had it, we did
not, and a credential you deleted from a file is still in every clone of your
repository.

## Design decisions worth knowing

**Your source never leaves your machine.** There is no upload, no account, no
server. The report is one HTML file with inline CSS and JS that makes no network
requests — you can read the whole thing before you trust it.

**Your credentials are never sent to an AI.** Static-analysis findings are sent to
Claude to judge whether they are genuinely exploitable, which is a real judgment
call. Leaked keys are not: explaining one would mean transmitting it to a third
party, which is the exact thing the finding is warning you about. Credential,
dependency, and configuration findings are answered by the engines themselves —
so three of the four engines need **no API key at all**.

**False positives are treated as the expensive failure.** A report with twenty
fake criticals gets closed and never reopened. Every rule ships with a fixture of
correct code that it must stay silent on: parameterised queries, `process.env`
lookups, `.env.example` templates, and Stripe *publishable* keys are all left
alone on purpose.

## Usage

```bash
npx safeship scan                     # scan the current directory
npx safeship scan ./apps/web          # scan somewhere specific
npx safeship scan --secrets-only      # credentials only: no network, no API key
npx safeship scan --json > out.json   # machine-readable
npx safeship doctor                   # check the toolchain is installed
```

| Option | |
|---|---|
| `--html <path>` | where to write the report (default `safeship-report.html`) |
| `--no-html` | skip the report |
| `--json` | JSON on stdout |
| `--secrets-only` | fastest path: offline, no API key |
| `--no-deps` | skip the dependency check, the only engine that uses the network |
| `--no-history` | skip the git-history sweep for deleted-but-committed keys |
| `--no-explain` | skip the AI explanations |

## Requirements

Node 16+, and **Python 3.10+** — the scanning core is Python because Semgrep is,
and Semgrep itself requires 3.10 or newer.
`npx safeship doctor` checks both and tells you exactly what to install. If Semgrep
is missing:

```bash
python -m pip install -r requirements.txt
```

An `ANTHROPIC_API_KEY` is optional. Without one, use `--no-explain` or
`--secrets-only`; you still get every credential, dependency, and configuration
finding. The `anthropic` package is optional on the same terms -- those paths
run without it installed at all.

## Status

Early. Python and JavaScript/TypeScript only. Not a hosted service, and it does
not scan GitHub URLs.
