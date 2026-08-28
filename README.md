# VibeSec

Security scanner for vibe-coded projects — the ones written mostly by an AI, shipped
mostly on trust.

```bash
npx vibesec scan
```

It reads your project, writes a single HTML report you can open or forward, and
uploads nothing. Everything runs on your machine.

## What it looks for

Four engines run over the same target and land in one report.

| Engine | Finds |
|---|---|
| **Credentials** | API keys, tokens, private keys, and database URLs — in **any** text file, including `.env`, `config.json`, `docker-compose.yml`, and README files that a code scanner never opens |
| **Dependencies** | Known CVEs in `requirements.txt` and `package.json`, with CVSS scores and the version that fixes them, via [OSV.dev](https://osv.dev) |
| **Configuration** | Debug mode on in production, CORS opened to the internet, TLS verification disabled, `.env` committed to git, secrets published to the browser via `NEXT_PUBLIC_` |
| **Static analysis** | SQL injection, command injection, `eval` on user input, and unauthenticated debug routes — Semgrep plus custom rules for the mistakes AI-generated code actually makes |

Those custom rules are the point. Against Semgrep's default registry alone:

| Fixture | registry only | with VibeSec's rules |
|---|---|---|
| Python | 4/7 | **7/7** |
| JavaScript | 2/11 | **11/11** |

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
npx vibesec scan                     # scan the current directory
npx vibesec scan ./apps/web          # scan somewhere specific
npx vibesec scan --secrets-only      # credentials only: no network, no API key
npx vibesec scan --json > out.json   # machine-readable
npx vibesec doctor                   # check the toolchain is installed
```

| Option | |
|---|---|
| `--html <path>` | where to write the report (default `vibesec-report.html`) |
| `--no-html` | skip the report |
| `--json` | JSON on stdout |
| `--secrets-only` | fastest path: offline, no API key |
| `--no-deps` | skip the dependency check, the only engine that uses the network |
| `--no-explain` | skip the AI explanations |

## Requirements

Node 16+, and **Python 3.9+** — the scanning core is Python because Semgrep is.
`npx vibesec doctor` checks both and tells you exactly what to install. If Semgrep
is missing:

```bash
python -m pip install -r requirements.txt
```

An `ANTHROPIC_API_KEY` is optional. Without one, use `--no-explain` or
`--secrets-only`; you still get every credential, dependency, and configuration
finding.

## Status

Early. Python and JavaScript/TypeScript only. Not a hosted service, and it does
not scan GitHub URLs.
