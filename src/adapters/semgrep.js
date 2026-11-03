'use strict';

const fs = require('fs');
const path = require('path');
const { execTool } = require('./runner');
const { createFinding } = require('../findings');

const SEVERITY = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };

const asList = (v) => (Array.isArray(v) ? v : v ? [v] : []);

// "CWE-79: Improper Neutralization..." -> "CWE-79"
function cweIds(metadata) {
  return asList(metadata.cwe).map((c) => (String(c).match(/CWE-\d+/i) || [])[0]).filter(Boolean).map((c) => c.toUpperCase());
}

// Rules that detect credentials return the matching source line, which contains the secret.
// Such findings never carry evidence, so a secret cannot reach stored findings, exports or AI prompts.
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
    // Semgrep returns "requires login" for lines in the unauthenticated CLI; don't show that as evidence.
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

// SAST via the Semgrep CLI. `config` is passed through as --config (default: the public registry
// ruleset); pass a local rules path for fully offline scans. Metrics are always disabled.
function createSemgrepAdapter({ config = 'p/default', command = 'semgrep', exec = execTool, extraArgs = [] } = {}) {
  return {
    name: 'semgrep',
    category: 'sast',
    async version() {
      const { stdout } = await exec(command, ['--version']);
      return stdout.trim().split('\n').pop();
    },
    async supports(target) {
      return !!target.path && fs.existsSync(target.path) && fs.statSync(target.path).isDirectory();
    },
    async run(target, { signal } = {}) {
      const version = await this.version();
      const args = ['scan', '--json', '--quiet', '--metrics=off', '--disable-version-check', '--config', config, ...extraArgs, '.'];
      const { stdout } = await exec(command, args, { cwd: target.path, signal });
      const { findings, errors } = parseSemgrep(stdout, target.path, version);
      return { findings, raw: { errors, config } };
    },
  };
}

module.exports = { createSemgrepAdapter, parseSemgrep };
