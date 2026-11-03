'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execTool } = require('./runner');
const { createFinding } = require('../findings');
const { ensureGitleaks } = require('./tools');
const { scanBuiltinSecrets } = require('./builtin-secrets');

const MASK = '[REDACTED]';

// Removes the secret from any text. Gitleaks is also run with --redact, so this is a second layer:
// a raw secret must never reach stored findings, logs, reports or AI prompts.
function mask(text, secret) {
  if (!text) return null;
  let out = String(text);
  if (secret && secret !== 'REDACTED') out = out.split(secret).join(MASK);
  return out.slice(0, 300);
}

function toFinding(leak, root, version) {
  const file = path.relative(root, path.resolve(root, leak.File || '')).split(path.sep).join('/');
  return createFinding({
    category: 'secret',
    scanner: { name: 'gitleaks', version, ruleId: leak.RuleID },
    title: leak.Description || `Secret detected (${leak.RuleID})`,
    description: `A possible secret matching rule "${leak.RuleID}" was found in the source.`,
    // A committed credential is treated as high until a human or validation says otherwise.
    severity: 'high',
    identifiers: { primary: leak.RuleID, aliases: [], cwe: ['CWE-798'] },
    location: { file, line: leak.StartLine || null, endLine: leak.EndLine || null },
    remediation: { advice: 'Revoke and rotate this credential, then remove it from the code and Git history. Load secrets from the environment or a secret manager.' },
    evidence: mask(leak.Match, leak.Secret),
  });
}

function parseGitleaks(stdout, root, version) {
  const text = stdout.trim();
  if (!text || text === 'null') return [];
  return JSON.parse(text).map((leak) => toFinding(leak, root, version));
}

// Secret scanning via the Gitleaks CLI over the working tree (no Git history).
function createGitleaksAdapter({ command = 'gitleaks', exec = execTool, extraArgs = [], fallback = exec === execTool && command === 'gitleaks' } = {}) {
  async function binary() {
    if (!fallback) return command;
    try {
      return await ensureGitleaks(command);
    } catch {
      return command;
    }
  }

  return {
    name: 'gitleaks',
    category: 'secret',
    async version() {
      try {
        const { stdout } = await exec(await binary(), ['version']);
        return stdout.trim().split('\n').pop().replace(/^v/, '');
      } catch (err) {
        if (fallback && /not installed/i.test(err.message)) return 'builtin-rules';
        throw err;
      }
    },
    async supports(target) {
      return !!target.path && fs.existsSync(target.path) && fs.statSync(target.path).isDirectory();
    },
    async run(target, { signal } = {}) {
      const version = await this.version();
      if (version === 'builtin-rules') {
        return { findings: scanBuiltinSecrets(target.path, { version }), raw: { engine: 'builtin-rules' } };
      }
      // Gitleaks (verified on 8.21.2) does not treat "--report-path -" as stdout: it creates a file
      // named "-" in the working directory, and the scan then looks clean. The report goes to a
      // private temp directory outside the scanned tree instead, and is deleted afterwards.
      const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-gl-'));
      const reportPath = path.join(reportDir, 'report.json');
      try {
        const args = [
          'detect', '--no-git', '--source', '.',
          '--report-format', 'json', '--report-path', reportPath,
          '--redact', '--exit-code', '0', '--no-banner', '--log-level', 'error',
          ...extraArgs,
        ];
        await exec(await binary(), args, { cwd: target.path, signal });
        // A missing report means gitleaks did not run properly: fail loudly, never report "clean".
        if (!fs.existsSync(reportPath)) throw new Error('gitleaks did not produce a report');
        return { findings: parseGitleaks(fs.readFileSync(reportPath, 'utf8'), target.path, version), raw: null };
      } finally {
        fs.rmSync(reportDir, { recursive: true, force: true });
      }
    },
  };
}

module.exports = { createGitleaksAdapter, parseGitleaks, mask };
