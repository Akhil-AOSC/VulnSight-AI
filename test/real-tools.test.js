'use strict';

// Runs the adapters against the REAL scanners and the deliberately insecure fixtures in
// examples/. Skipped automatically unless the tools are available. To run:
//   VULNSIGHT_TOOLS_DIR=<dir with gitleaks, trivy (and venv/Scripts/semgrep)>
//   VULNSIGHT_CHECKOV_PYTHON=<python that has checkov installed>
//   npm test
// SAST uses local rules (Opengrep/Semgrep/ESLint/builtin). Trivy still needs a vulnerability DB.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { runAdapter } = require('../src/adapters/runner');
const { createSemgrepAdapter } = require('../src/adapters/semgrep');
const { createGitleaksAdapter } = require('../src/adapters/gitleaks');
const { createTrivyAdapter } = require('../src/adapters/trivy');
const { createCheckovAdapter } = require('../src/adapters/checkov');

const DIR = process.env.VULNSIGHT_TOOLS_DIR;
const SKIP = DIR ? false : 'set VULNSIGHT_TOOLS_DIR to run against the real scanners';
if (DIR) {
  process.env.PATH = [DIR, path.join(DIR, 'venv', 'Scripts'), path.join(DIR, 'venv', 'bin'), process.env.PATH].join(path.delimiter);
}
process.env.PYTHONUTF8 = '1';

const INSECURE = { path: path.join(__dirname, '..', 'examples', 'insecure-app') };
const NPM_APP = { path: path.join(__dirname, '..', 'examples', 'npm-app') };
const TIMEOUT = { timeoutMs: 240000 };
const has = (findings, pred) => findings.some(pred);

test('real gitleaks finds the fixture secrets, redacted, and leaves the tree untouched', { skip: SKIP }, async () => {
  const before = fs.readdirSync(INSECURE.path).sort();
  const r = await runAdapter(createGitleaksAdapter(), INSECURE, TIMEOUT);
  assert.equal(r.status, 'ok', r.error);
  assert.match(r.version, /^\d+\.\d+\.\d+/);
  assert.ok(has(r.findings, (f) => f.identifiers.primary === 'github-pat' && f.location.file === 'config.js' && f.location.line === 3));
  assert.ok(has(r.findings, (f) => f.identifiers.primary === 'slack-webhook-url'));
  assert.ok(!JSON.stringify(r.findings).includes('ghp_7Xq2'), 'raw secret never reaches a finding');
  assert.deepEqual(fs.readdirSync(INSECURE.path).sort(), before, 'no files written into the scanned folder');

  const clean = await runAdapter(createGitleaksAdapter(), NPM_APP, TIMEOUT);
  assert.equal(clean.status, 'ok');
  assert.equal(clean.findings.length, 0);
});

test('real semgrep finds XSS, command injection and eval in the fixture', { skip: SKIP }, async () => {
  const r = await runAdapter(createSemgrepAdapter(), INSECURE, TIMEOUT);
  assert.equal(r.status, 'ok', r.error);
  const rules = r.findings.map((f) => f.identifiers.primary).join('\n');
  assert.match(rules, /xss|raw-html-format/);
  assert.match(rules, /detect-child-process/);
  assert.match(rules, /eval/);
  assert.ok(has(r.findings, (f) => f.location.file === 'app.js' && f.severity === 'high'));
  assert.ok(r.findings.every((f) => f.category === 'sast' && f.location.line > 0));
  assert.ok(!JSON.stringify(r.findings).includes('ghp_7Xq2'));
});

test('real trivy finds lockfile vulnerabilities and IaC misconfigurations', { skip: SKIP }, async () => {
  const vulns = await runAdapter(createTrivyAdapter({ mode: 'fs' }), NPM_APP, TIMEOUT);
  assert.equal(vulns.status, 'ok', vulns.error);
  assert.ok(has(vulns.findings, (f) => f.category === 'sca' && f.location.package === 'lodash' && f.location.ecosystem === 'npm' && f.remediation.fixedIn));
  assert.ok(has(vulns.findings, (f) => f.location.package === 'minimist' && f.severity === 'critical'));

  const iac = await runAdapter(createTrivyAdapter({ mode: 'fs' }), INSECURE, TIMEOUT);
  assert.equal(iac.status, 'ok', iac.error);
  assert.ok(has(iac.findings, (f) => f.category === 'iac' && f.location.file === 'main.tf' && f.location.line > 0));
  assert.ok(has(iac.findings, (f) => f.location.file === 'Dockerfile'));
});

const CHECKOV_SKIP = SKIP || (process.env.VULNSIGHT_CHECKOV_PYTHON ? false : 'set VULNSIGHT_CHECKOV_PYTHON to a python with checkov');
test('real checkov finds Terraform misconfigurations', { skip: CHECKOV_SKIP }, async () => {
  const adapter = createCheckovAdapter({ command: process.env.VULNSIGHT_CHECKOV_PYTHON, commandArgs: ['-m', 'checkov.main'] });
  const r = await runAdapter(adapter, INSECURE, TIMEOUT);
  assert.equal(r.status, 'ok', r.error);
  assert.ok(has(r.findings, (f) => f.identifiers.primary === 'CKV_AWS_20' && f.location.file === 'main.tf'));
  assert.ok(r.findings.every((f) => f.category === 'iac'));
});

test('a missing tool is an error status and an unreadable target is skipped', { skip: SKIP }, async () => {
  const missing = await runAdapter(createGitleaksAdapter({ command: 'gitleaks-does-not-exist' }), INSECURE, TIMEOUT);
  assert.equal(missing.status, 'error');
  assert.match(missing.error, /not installed/);
  const skipped = await runAdapter(createSemgrepAdapter(), { path: path.join(INSECURE.path, 'no-such-dir') }, TIMEOUT);
  assert.equal(skipped.status, 'skipped');
});
