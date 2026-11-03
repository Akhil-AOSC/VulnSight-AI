'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { scanBuiltinSast } = require('../src/adapters/builtin-sast');
const { scanBuiltinSecrets } = require('../src/adapters/builtin-secrets');
const { createSemgrepAdapter } = require('../src/adapters/semgrep');
const { runAdapter } = require('../src/adapters/runner');

const INSECURE = path.join(__dirname, '..', 'examples', 'insecure-app');

test('builtin SAST finds XSS, command injection and eval in the fixture', () => {
  const findings = scanBuiltinSast(INSECURE);
  const ids = findings.map((f) => f.identifiers.primary).join('\n');
  assert.match(ids, /xss|direct-response-write/);
  assert.match(ids, /child-process/);
  assert.match(ids, /eval/);
  assert.ok(findings.every((f) => f.category === 'sast' && f.location.file === 'app.js' && f.location.line > 0));
  assert.ok(findings.every((f) => f.evidence));
});

test('builtin secrets finds the fixture tokens and redacts them', () => {
  const findings = scanBuiltinSecrets(INSECURE);
  assert.ok(findings.some((f) => f.identifiers.primary === 'github-pat' && f.location.file === 'config.js'));
  assert.ok(findings.some((f) => f.identifiers.primary === 'slack-webhook-url'));
  assert.ok(!JSON.stringify(findings).includes('ghp_7Xq2'));
  assert.ok(findings.every((f) => f.category === 'secret' && f.evidence.includes('[REDACTED]')));
});

test('semgrep adapter falls back to builtin rules when the CLI is missing', async () => {
  const r = await runAdapter(createSemgrepAdapter(), { path: INSECURE });
  assert.equal(r.status, 'ok', r.error);
  assert.ok(r.findings.some((f) => f.category === 'sast' && /xss|direct-response-write|eval|child-process/.test(f.identifiers.primary)));
});
