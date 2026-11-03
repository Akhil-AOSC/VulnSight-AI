'use strict';

const path = require('path');
const { initEnv } = require('./env');
initEnv();
const { detectProjects, loadProject } = require('./detect');
const { scanProjects, applyThreshold } = require('./scanner');
const { renderText, renderJson } = require('./report');
const { startServer } = require('./server');
const { isGitUrl, cloneRepository } = require('./git');
const pkg = require('../package.json');

// Exit codes follow the same convention as other scanners so CI can rely on them.
const EXIT = { OK: 0, ISSUES: 1, ERROR: 2, NO_PROJECTS: 3 };
const THRESHOLDS = ['low', 'medium', 'high', 'critical'];

const HELP = `VulnSight-AI ${pkg.version} - open-source dependency vulnerability scanner (data: OSV.dev)

Usage:
  vulnsight test [path|url] [options]  Scan local [path] or remote Git [url] (default: current directory)
  vulnsight ui [path] [--port=4321]    Open the web dashboard at http://localhost:4321

Options:
  --file=<lockfile>             Scan one file instead of auto-detecting
  --severity-threshold=<level>  Only report issues at or above low|medium|high|critical
  --dev                         Include development dependencies
  --json                        Print results as JSON
  --no-color                    Disable colored output
  -h, --help                    Show this help
  -v, --version                 Show the version

Supported files:
  npm      package-lock.json, npm-shrinkwrap.json
  Python   requirements*.txt, poetry.lock, Pipfile.lock

Exit codes:
  0 no issues found   1 issues found   2 error   3 no supported files found`;

class UsageError extends Error {}

function parseArgs(argv) {
  const opts = { command: null, target: null, json: false, dev: false, threshold: 'low', file: null, color: undefined, port: 4321 };
  for (const arg of argv) {
    if (arg === '--json') opts.json = true;
    else if (arg === '--dev') opts.dev = true;
    else if (arg === '--no-color') opts.color = false;
    else if (arg === '-h' || arg === '--help') opts.command = 'help';
    else if (arg === '-v' || arg === '--version') opts.command = 'version';
    else if (arg.startsWith('--severity-threshold=')) opts.threshold = arg.split('=')[1].toLowerCase();
    else if (arg.startsWith('--file=')) opts.file = arg.slice('--file='.length);
    else if (arg.startsWith('--port=')) {
      opts.port = Number(arg.slice('--port='.length));
      if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) throw new UsageError(`Invalid --port "${arg}"`);
    }
    else if (arg.startsWith('-')) throw new UsageError(`Unknown option: ${arg}`);
    else if (!opts.command) opts.command = arg;
    else if (!opts.target) opts.target = arg;
    else throw new UsageError(`Unexpected argument: ${arg}`);
  }
  if (!THRESHOLDS.includes(opts.threshold)) {
    throw new UsageError(`Invalid --severity-threshold "${opts.threshold}". Use one of: ${THRESHOLDS.join(', ')}`);
  }
  return opts;
}

async function runTest(opts, { scan = scanProjects, stdout = console.log, stderr = console.error } = {}) {
  const rawTarget = opts.target || '.';
  let dir;
  let cleanup = null;
  let isRemote = false;

  if (isGitUrl(rawTarget)) {
    isRemote = true;
    stdout(`Cloning ${rawTarget}...`);
    try {
      const cloned = await cloneRepository(rawTarget);
      dir = cloned.dir;
      cleanup = cloned.cleanup;
    } catch (err) {
      stderr(`Error: ${err.message}`);
      return EXIT.ERROR;
    }
  } else {
    dir = path.resolve(rawTarget);
  }

  try {
    const { projects, warnings } = opts.file
      ? { projects: [loadProject(path.resolve(dir, opts.file), opts)], warnings: [] }
      : detectProjects(dir, opts);

    if (!projects.length) {
      for (const w of warnings) stderr(`Warning: ${w}`);
      stderr(`No supported dependency files found in ${rawTarget}. Run "vulnsight --help" to see supported files.`);
      return EXIT.NO_PROJECTS;
    }

    if (isRemote) {
      for (const p of projects) {
        p.file = path.relative(dir, p.file) || path.basename(p.file);
      }
    }

    const results = applyThreshold(await scan(projects), opts.threshold);

    const color = opts.color ?? (Boolean(process.stdout.isTTY) && !process.env.NO_COLOR);
    stdout(opts.json ? renderJson(results, warnings) : renderText(results, warnings, { color }));
    return results.some((r) => r.issues.length) ? EXIT.ISSUES : EXIT.OK;
  } finally {
    if (cleanup) cleanup();
  }
}

// Runs until the process is stopped (Ctrl+C).
async function runUi(opts) {
  let server;
  try {
    server = await startServer({ port: opts.port, defaultTarget: path.resolve(opts.target || '.') });
  } catch (err) {
    const reason = err.code === 'EADDRINUSE' ? `port ${opts.port} is already in use. Try --port=<other>` : err.message;
    console.error(`Error: could not start the dashboard: ${reason}`);
    return EXIT.ERROR;
  }
  console.log(`VulnSight-AI dashboard running at http://localhost:${opts.port}  (press Ctrl+C to stop)`);
  await new Promise((resolve) => server.on('close', resolve));
  return EXIT.OK;
}

async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(err.message);
    console.error('Run "vulnsight --help" for usage.');
    return EXIT.ERROR;
  }

  if (!opts.command || opts.command === 'help') {
    console.log(HELP);
    return EXIT.OK;
  }
  if (opts.command === 'version') {
    console.log(pkg.version);
    return EXIT.OK;
  }
  if (opts.command === 'ui') return runUi(opts);
  if (opts.command !== 'test') {
    console.error(`Unknown command: ${opts.command}. Run "vulnsight --help" for usage.`);
    return EXIT.ERROR;
  }

  try {
    return await runTest(opts);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    return EXIT.ERROR;
  }
}

module.exports = { main, parseArgs, runTest, EXIT };
