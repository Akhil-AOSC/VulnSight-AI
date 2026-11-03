'use strict';

const fs = require('fs');
const path = require('path');
const { execTool } = require('./runner');
const { createFinding } = require('../findings');
const { resolveSastEngine, resolveOpengrep, resolveSemgrep, resolveEslint } = require('./tools');
const { scanBuiltinSast } = require('./builtin-sast');
const { scanEslint } = require('./eslint-sast');

const DEFAULT_CONFIG = path.join(__dirname, 'sast-rules', 'vulnsight.yml');
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
  const args = ['scan', '--json', '--quiet', '--config', config, ...extraArgs, '.'];
  if (kind === 'semgrep') args.splice(3, 0, '--metrics=off', '--disable-version-check');
  return args;
}

function installedEngines(cwd, resolveEngine) {
  if (resolveEngine) {
    const engine = resolveEngine({ cwd });
    return engine && engine.kind !== 'builtin' && engine.bin ? [engine] : [];
  }
  return [
    { kind: 'opengrep', bin: resolveOpengrep() },
    { kind: 'semgrep', bin: resolveSemgrep() },
    { kind: 'eslint', bin: resolveEslint(cwd) },
  ].filter((e) => e.bin);
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

// SAST: Opengrep, then Semgrep, then ESLint when installed; otherwise built-in rules.
// Default --config is the local rule pack (not the Semgrep registry).
function createSemgrepAdapter({
  config = DEFAULT_CONFIG,
  command = 'semgrep',
  exec = execTool,
  extraArgs = [],
  fallback = exec === execTool && command === 'semgrep',
  resolveEngine,
} = {}) {
  return {
    name: 'semgrep',
    category: 'sast',
    async version() {
      if (!fallback) return toolVersion(exec, command);
      const [engine] = installedEngines(undefined, resolveEngine);
      if (!engine) return 'builtin-rules';
      try {
        return `${engine.kind} ${await toolVersion(exec, engine.bin)}`;
      } catch (err) {
        if (/not installed/i.test(err.message)) return 'builtin-rules';
        throw err;
      }
    },
    async supports(target) {
      return !!target.path && fs.existsSync(target.path) && fs.statSync(target.path).isDirectory();
    },
    async run(target, { signal } = {}) {
      if (!fallback) {
        return runGrep(exec, { kind: 'semgrep', bin: command }, target, { config, extraArgs, signal, labeled: false });
      }

      const queue = installedEngines(target.path, resolveEngine);
      for (const engine of queue) {
        try {
          if (engine.kind === 'eslint') return await runEslintEngine(exec, engine, target, signal);
          return await runGrep(exec, engine, target, { config, extraArgs, signal });
        } catch (err) {
          if (!fallback) throw err;
        }
      }
      return builtinResult(target, config);
    },
  };
}

module.exports = { createSemgrepAdapter, parseSemgrep, DEFAULT_CONFIG, resolveSastEngine };
