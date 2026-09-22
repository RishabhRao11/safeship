#!/usr/bin/env node
'use strict';

/*
 * safeship -- npx entry point.
 *
 * WHAT THIS IS NOT
 *   The original spec had this zip the codebase, upload it to an API, stream
 *   back status, and print a dashboard link. SafeShip is local-only by design, so
 *   there is no endpoint to upload to -- and for a tool whose whole job is
 *   finding your credentials, not transmitting your source anywhere is a feature
 *   rather than a limitation. This runs the scan on your machine and writes a
 *   report you can open, keep, or forward.
 *
 * WHY A NODE WRAPPER AROUND A PYTHON TOOL
 *   Most people shipping AI-generated products are shipping Next.js and Express,
 *   and `npx safeship scan` needs no install step. The scanning core is Python
 *   because Semgrep is Python.
 *
 *   That combination has one honest failure mode: npx promises zero-install and
 *   then hits a missing Python. So this checks the whole toolchain up front and
 *   says exactly what to install, rather than surfacing a stack trace from a
 *   subprocess three layers down. `safeship doctor` runs those same checks on
 *   their own.
 */

const { spawnSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const ROOT = path.resolve(__dirname, '..');
// Semgrep requires >=3.10 as of 1.137. On 3.9 pip silently resolves to
// semgrep ~1.136, a different engine that matches rules differently --
// so "supported" would mean "installs, and quietly finds other things".
// CI caught this: the 3.9 job failed the fixture counts, not an import.
const MIN_PYTHON = [3, 10];
const DEFAULT_REPORT = 'safeship-report.html';

// Candidate interpreters, best first. `py -3` is the Windows launcher, which is
// present far more often than a `python3` on PATH.
const PYTHON_CANDIDATES = process.platform === 'win32'
  ? [['py', ['-3']], ['python', []], ['python3', []]]
  : [['python3', []], ['python', []]];

const bold = (s) => (process.stdout.isTTY ? `\x1b[1m${s}\x1b[0m` : s);
const dim = (s) => (process.stdout.isTTY ? `\x1b[2m${s}\x1b[0m` : s);
const red = (s) => (process.stdout.isTTY ? `\x1b[31m${s}\x1b[0m` : s);
const green = (s) => (process.stdout.isTTY ? `\x1b[32m${s}\x1b[0m` : s);
const yellow = (s) => (process.stdout.isTTY ? `\x1b[33m${s}\x1b[0m` : s);

function run(cmd, args, opts) {
  return spawnSync(cmd, args, { encoding: 'utf8', ...opts });
}

/* ---------------------------------------------------------------------- */
/* Preflight                                                              */
/* ---------------------------------------------------------------------- */

// Can this interpreter import the optional SDK? Used as a tie-break, because
// it is the best available signal for "this is the Python the user actually
// ran pip install with".
function hasSdk(python) {
  return run(python.cmd, [...python.baseArgs, '-c', 'import anthropic']).status === 0;
}

function findPython() {
  // WHY THIS PREFERS RATHER THAN TAKES THE FIRST MATCH
  //   On Windows `py -3` resolves through the registry while pip installs into
  //   whichever interpreter is on PATH. Those are often not the same one. CI
  //   caught it on a clean runner:
  //
  //     python (PATH): hostedtoolcache/Python/3.13.15  ->  anthropic 1.8.0
  //     py -3:         hostedtoolcache/Python/3.14.7   ->  ModuleNotFoundError
  //
  //   The old code took `py -3` because it came first and satisfied the version
  //   check, reported "everything safeship needs is present", and then died on
  //   an import. Version is not the only thing that makes an interpreter usable.
  let fallback = null;
  for (const [cmd, baseArgs] of PYTHON_CANDIDATES) {
    const probe = run(cmd, [
      ...baseArgs, '-c', 'import sys;print("%d.%d" % sys.version_info[:2])',
    ]);
    if (probe.status !== 0 || !probe.stdout) continue;

    const [major, minor] = probe.stdout.trim().split('.').map(Number);
    if (major > MIN_PYTHON[0]
        || (major === MIN_PYTHON[0] && minor >= MIN_PYTHON[1])) {
      const candidate = { cmd, baseArgs, version: `${major}.${minor}` };
      if (hasSdk(candidate)) return candidate;
      // Usable for the three engines that need no SDK. Keep it, but keep
      // looking for one that is equipped for everything.
      if (!fallback) fallback = candidate;
      continue;
    }
    // Found, but too old. Keep looking -- a newer one may be further down the
    // list -- and remember this so the error can name the version we saw.
    findPython.tooOld = `${cmd} (Python ${major}.${minor})`;
  }
  return fallback;
}

function checkSemgrep(python) {
  // Reuse scanner.find_semgrep() rather than probing PATH here: it already
  // handles the Windows case where semgrep.exe lives in a Scripts directory
  // that is not on PATH and shells out to a separate pysemgrep.
  const probe = run(python.cmd, [
    ...python.baseArgs, '-c',
    'import sys; sys.path.insert(0, sys.argv[1]); import scanner;'
    + ' print(scanner.find_semgrep()[0])',
    ROOT,
  ]);
  return probe.status === 0 ? probe.stdout.trim() : null;
}

function installHint(python) {
  const py = python ? [python.cmd, ...python.baseArgs].join(' ') : 'python';
  return `  ${py} -m pip install -r "${path.join(ROOT, 'requirements.txt')}"`;
}

function preflight({ quiet } = {}) {
  const python = findPython();
  if (!python) {
    console.error(red('safeship needs Python 3.10 or newer, and could not find it.'));
    if (findPython.tooOld) {
      console.error(`Found ${findPython.tooOld}, which is too old.`);
    }
    console.error('\nSafeShip scans with Semgrep, which is a Python tool. Install');
    console.error('Python from https://python.org/downloads (tick "Add to PATH"');
    console.error('on Windows), then run this command again.');
    return null;
  }
  if (!quiet) console.log(dim(`python ${python.version} via ${python.cmd}`));

  const semgrep = checkSemgrep(python);
  if (!semgrep) {
    console.error(red('safeship found Python but not Semgrep.'));
    console.error('\nInstall the dependencies with:\n');
    console.error(installHint(python));
    console.error('\nNote: `python -m semgrep` does not work on semgrep 1.38 or');
    console.error('newer -- it prints a deprecation notice and exits. SafeShip');
    console.error('locates the executable itself, so you only need the install.');
    return null;
  }
  if (!quiet) console.log(dim(`semgrep at ${semgrep}`));

  // Not fatal: three of four engines never touch the SDK, and --no-explain and
  // --secrets-only are the documented paths for exactly this. But saying
  // nothing is how a run gets all the way through a scan and then dies on an
  // import, throwing the results away.
  if (!hasSdk(python)) {
    console.error(yellow('\nThe anthropic SDK is not installed for this Python.'));
    console.error('AI explanations need it. Everything else -- credentials,');
    console.error('dependencies, configuration -- does not.\n');
    console.error(installHint(python));
    console.error('\nOr run with --no-explain to skip the explanations.');
  }

  return python;
}

/* ---------------------------------------------------------------------- */
/* Commands                                                               */
/* ---------------------------------------------------------------------- */

function doctor() {
  console.log(bold('safeship doctor\n'));
  const python = preflight({});
  if (!python) {
    process.exit(1);
  }
  const analyze = path.join(ROOT, 'analyze.py');
  const ok = fs.existsSync(analyze);
  console.log(dim(`analyze.py ${ok ? 'found' : 'MISSING'} at ${analyze}`));
  if (!ok) {
    console.error(red('\nThe Python half of safeship is missing from this package.'));
    process.exit(1);
  }
  console.log(green('\nEverything safeship needs is present.'));
}

function scan(argv) {
  const passthrough = [];
  let target = null;
  let html = DEFAULT_REPORT;
  let wantsJson = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--html') { html = argv[++i]; continue; }
    if (arg === '--no-html') { html = null; continue; }
    if (arg === '--json') { wantsJson = true; passthrough.push(arg); continue; }
    if (arg.startsWith('-')) {
      passthrough.push(arg);
      // Flags that take a value need it carried across too.
      if (arg === '--config' && argv[i + 1]) passthrough.push(argv[++i]);
      continue;
    }
    if (target === null) target = arg;
  }
  target = target || '.';

  if (!fs.existsSync(target)) {
    console.error(red(`No such file or directory: ${target}`));
    process.exit(1);
  }

  const python = preflight({ quiet: wantsJson });
  if (!python) process.exit(1);

  // Absolute, because the child does NOT run in this directory and a bare "."
  // would otherwise resolve against the installed package rather than the
  // user's project -- scanning safeship itself and reporting it as their code.
  const absTarget = path.resolve(target);

  const args = [
    ...python.baseArgs,
    path.join(ROOT, 'analyze.py'),
    absTarget,
  ];
  // Default to both rule sets unless the caller chose their own. Passing the
  // directory loads the Python and the JavaScript rules together.
  if (!passthrough.includes('--config')) {
    args.push('--config', 'auto', '--config', path.join(ROOT, 'rules'));
  }
  if (html && !wantsJson) args.push('--html', html);
  args.push(...passthrough);

  // analyze.py announces the target itself on stderr; printing it here too just
  // said the same thing twice.

  // stdio inherited so progress on stderr streams live and the report on stdout
  // stays pipeable: `npx safeship scan --json > findings.json` works unchanged.
  //
  // cwd is deliberately left as the user's directory rather than the package's.
  // Python puts the script's own directory on sys.path, so `from engines import
  // ...` resolves regardless -- while cwd:ROOT would quietly drop a relative
  // --html report inside the installed package, where nobody would find it.
  const child = spawn(python.cmd, args, { stdio: 'inherit' });

  child.on('error', (err) => {
    console.error(red(`Could not start Python: ${err.message}`));
    process.exit(1);
  });

  child.on('close', (code) => {
    // Checked, not assumed. This printed a path to a file that was never written
    // whenever --no-explain was passed, because analyze.py used to return before
    // reaching the report writer.
    if (code === 0 && html && !wantsJson && fs.existsSync(path.resolve(html))) {
      console.log(`\n${green('Report:')} ${path.resolve(html)}`);
      console.log(dim('Open it in a browser. It is a single file with no network calls,'));
      console.log(dim('so you can email it or attach it to a ticket as-is.'));
    }
    process.exit(code === null ? 1 : code);
  });
}

function usage() {
  console.log(`
${bold('safeship')} — security scanner for vibe-coded projects

  ${bold('npx safeship scan')} [path]        scan a directory (default: .)
  ${bold('npx safeship doctor')}             check that the toolchain is installed

Options for ${bold('scan')}:
  --html <path>     where to write the report (default: ${DEFAULT_REPORT})
  --no-html         skip the HTML report
  --json            machine-readable output on stdout
  --secrets-only    credentials only: no network, no API key, fastest
  --no-deps         skip the dependency check (the only networked engine)
  --no-explain      skip the AI explanations
  --config <cfg>    override the Semgrep rulesets

Everything runs on your machine. No source code is uploaded anywhere.
`);
}

/* ---------------------------------------------------------------------- */

function main() {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (!command || command === '-h' || command === '--help' || command === 'help') {
    usage();
    return;
  }
  if (command === '-v' || command === '--version') {
    console.log(require(path.join(ROOT, 'package.json')).version);
    return;
  }
  if (command === 'doctor') return doctor();
  if (command === 'scan') return scan(argv.slice(1));

  // `npx safeship ./myproject` with no subcommand is what people will type.
  if (!command.startsWith('-')) return scan(argv);

  console.error(red(`Unknown command: ${command}`));
  usage();
  process.exit(1);
}

main();
