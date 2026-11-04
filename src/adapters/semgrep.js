'use strict';

const fs = require('fs');
const path = require('path');
const { execTool } = require('./runner');
const { createFinding } = require('../findings');
const { ensureOpengrep, resolveSastEngine } = require('./tools');
const { scanBuiltinSast } = require('./builtin-sast');
const { scanEslint } = require('./eslint-sast');

const DEFAULT_CONFIG = path.join(__dirname, 'sast-rules', 'vulnsight.yml');
const DEFAULT_EXCLUDES = [
  '--exclude=node_modules', '--exclude=dist', '--exclude=build', '--exclude=vendor',
  '--exclude=.git', '--exclude=coverage', '--exclude=.next', '--exclude=out',
  '--exclude=.vulnsight-data', '--exclude=.vulnsight-tools',
];
const SEVERITY = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };

const asList = (v) => (Array.isArray(v) ? v : v ? [v] : []);

function cweIds(metadata) {
  return asList(metadata.cwe).map((c) => (String(c).match(/CWE-\d+/i) || [])[0]).filter(Boolean).map((c) => c.toUpperCase());
}

const SECRET_RULE = /secret|token|password|passwd|credential|api[-_]?key|private[-_]?key/i;

function toFinding(result, root, version) {
  const extra = result.extra || {};
  const metadata = extra.metadata || {};
  const ruleId = result.check_id;
  const file = path.relative(root, path.resolve(root, result.path || '')).split(path.sep).join('/');
  const refs = asList(metadata.references);

  return createFinding({
    category: 'sast',
    scanner: { name: 'semgrep', version, ruleId },
    title: (extra.message || ruleId).split('\n')[0].slice(0, 200),
    description: extra.message || null,
    severity: SEVERITY[String(extra.severity).toUpperCase()] || 'unknown',
    identifiers: { primary: ruleId, aliases: [], cwe: cweIds(metadata) },
    location: {
      file,
      line: result.start ? result.start.line : null,
      endLine: result.end ? result.end.line : null,
    },
    remediation: { advice: extra.fix || null },
    evidence: extra.lines && extra.lines !== 'requires login' && !SECRET_RULE.test(ruleId) && String(metadata.category).toLowerCase() !== 'secrets' ? extra.lines : null,
    url: refs[0] || null,
  });
}

function parseSemgrep(stdout, root, version) {
  const data = JSON.parse(stdout);
  const findings = (data.results || []).map((r) => toFinding(r, root, version));
  const errors = (data.errors || []).map((e) => (e.message || e.long_msg || 'Semgrep error').toString().slice(0, 300));
  return { findings, errors };
}

async function toolVersion(exec, bin) {
  const { stdout } = await exec(bin, ['--version']);
  return stdout.trim().split('\n').pop();
}

function grepArgs(kind, config, extraArgs) {
  const args = ['scan', '--json', '--quiet', '--config', config, ...DEFAULT_EXCLUDES, ...extraArgs, '.'];
  if (kind === 'semgrep') args.splice(3, 0, '--metrics=off', '--disable-version-check');
  return args;
}

function findingKey(f) {
  const id = String((f.identifiers && f.identifiers.primary) || '').split('.').pop();
  return `${f.location && f.location.file}:${f.location && f.location.line}:${id}`;
}

function mergeFindings(...lists) {
  const seen = new Set();
  const out = [];
  for (const list of lists) {
    for (const f of list || []) {
      const key = findingKey(f);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
  }
  return out;
}

function labeledVersion(kind, verRaw, labeled) {
  return labeled ? `${kind} ${verRaw}` : verRaw;
}

async function runGrep(exec, engine, target, { config, extraArgs, signal, labeled = true }) {
  const verRaw = await toolVersion(exec, engine.bin);
  const version = labeledVersion(engine.kind, verRaw, labeled);
  const { stdout } = await exec(engine.bin, grepArgs(engine.kind, config, extraArgs), {
    cwd: target.path, signal, okCodes: [0, 1],
  });
  const { findings, errors } = parseSemgrep(stdout, target.path, version);
  return { findings, raw: { errors, config, engine: engine.kind }, version };
}

async function runEslintEngine(exec, engine, target, signal) {
  const verRaw = await toolVersion(exec, engine.bin);
  const version = labeledVersion(engine.kind, verRaw, true);
  const out = await scanEslint(target.path, {
    bin: engine.bin, version, exec, signal, useApi: exec === execTool,
  });
  return { ...out, version };
}

function builtinResult(target, config) {
  return {
    findings: scanBuiltinSast(target.path, { version: 'builtin-rules' }),
    raw: { engine: 'builtin-rules', config },
    version: 'builtin-rules',
  };
}

// Code scanning via Opengrep (downloaded like Gitleaks). Custom exec/command still
// talks Semgrep JSON. Built-in rules are only used if Opengrep cannot run.
function createSemgrepAdapter({
  config = DEFAULT_CONFIG,
  command = 'semgrep',
  exec = execTool,
  extraArgs = [],
  fallback = exec === execTool && command === 'semgrep',
  resolveEngine,
  ensure = ensureOpengrep,
} = {}) {
  async function engineFor(cwd) {
    if (!fallback) return { kind: 'semgrep', bin: command, labeled: false };
    if (resolveEngine) {
      const picked = resolveEngine({ cwd });
      return picked && picked.bin ? picked : null;
    }
    try {
      return { kind: 'opengrep', bin: await ensure('opengrep') };
    } catch {
      return null;
    }
  }

  return {
    name: 'semgrep',
    category: 'sast',
    async version() {
      const engine = await engineFor();
      if (!engine) return 'builtin-rules';
      try {
        const ver = await toolVersion(exec, engine.bin);
        return engine.labeled === false ? ver : labeledVersion(engine.kind, ver, true);
      } catch (err) {
        if (fallback && /not installed/i.test(err.message)) return 'builtin-rules';
        throw err;
      }
    },
    async supports(target) {
      return !!target.path && fs.existsSync(target.path) && fs.statSync(target.path).isDirectory();
    },
    async run(target, { signal } = {}) {
      const engine = await engineFor(target.path);
      if (!engine) return builtinResult(target, config);
      try {
        if (engine.kind === 'eslint') {
          const eslint = await runEslintEngine(exec, engine, target, signal);
          return { ...eslint, findings: mergeFindings(eslint.findings, scanBuiltinSast(target.path, { version: eslint.version })) };
        }
        const grep = await runGrep(exec, engine, target, {
          config, extraArgs, signal, labeled: engine.labeled !== false,
        });
        return {
          ...grep,
          findings: mergeFindings(grep.findings, scanBuiltinSast(target.path, { version: grep.version })),
        };
      } catch (err) {
        if (!fallback) throw err;
        return builtinResult(target, config);
      }
    },
  };
}

module.exports = { createSemgrepAdapter, parseSemgrep, DEFAULT_CONFIG, resolveSastEngine };
