'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {
  generateVerificationToken,
  verifyViaHttpToken,
  checkOwnership,
} = require('../src/platform/dast-verifier');

test('generateVerificationToken produces a unique vs-verify- token', () => {
  const t1 = generateVerificationToken('web_1', 'org_1');
  const t2 = generateVerificationToken('web_1', 'org_1');

  assert.ok(t1.startsWith('vs-verify-'));
  assert.equal(t1.length, 'vs-verify-'.length + 32);
  assert.notEqual(t1, t2);
});

test('verifyViaHttpToken validates token presence or returns clear error', async () => {
  // Test with a non-existent public URL or malformed target
  const res = await verifyViaHttpToken('https://invalid-non-existent-domain-404-xyz.com', 'vs-verify-token123');
  assert.equal(res.verified, false);
  assert.ok(res.error);
});

test('checkOwnership checks DNS and HTTP verification endpoints', async () => {
  const res = await checkOwnership('non-existent-site-test-123.org', 'https://non-existent-site-test-123.org', 'vs-verify-sample');
  assert.equal(res.verified, false);
  assert.ok(res.error.includes('Domain ownership verification failed'));
});
