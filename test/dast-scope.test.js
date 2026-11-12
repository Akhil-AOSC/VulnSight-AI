'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeUrl, urlInScope, normalizeProfile, normalizeLimits, normalizeScope, isStateChangingMethod,
} = require('../src/adapters/dast/scope');
const { sanitizeHeaders, redactEvidence } = require('../src/adapters/dast/safe-fetch');

test('normalizeUrl drops hash, default ports and sorts query keys', () => {
  const a = normalizeUrl('https://app.example.com:443/b?z=2&a=1#frag');
  const b = normalizeUrl('https://app.example.com/b?a=1&z=2');
  assert.equal(a.href, b.href);
  assert.equal(a.searchParams.get('a'), '1');
});

test('urlInScope rejects other hosts, credentials and odd ports', () => {
  const scope = normalizeScope('app.example.com', { allowPaths: ['/app'] });
  assert.equal(urlInScope(normalizeUrl('https://app.example.com/app/x'), scope), true);
  assert.equal(urlInScope(normalizeUrl('https://evil.example.com/app'), scope), false);
  assert.equal(urlInScope(normalizeUrl('https://app.example.com/other'), scope), false);
  assert.equal(urlInScope(new URL('https://user:pass@app.example.com/app'), scope), false);
});

test('normalizeProfile maps aliases and gates ascan', () => {
  assert.equal(normalizeProfile('standard'), 'standard');
  assert.equal(normalizeProfile('crawl'), 'discovery');
  assert.equal(normalizeProfile('public_assessment'), 'public');
  assert.equal(normalizeProfile('PUBLIC_ASSESSMENT'), 'public');
  assert.throws(() => normalizeProfile('deep'), /authorizeActiveTesting/);
  assert.equal(normalizeProfile('ascan', { allowAscan: true }), 'deep');
});

test('limits are clamped', () => {
  const limits = normalizeLimits({ maxPages: 9999, maxDepth: 0, maxRps: 99 });
  assert.equal(limits.maxPages, 200);
  assert.equal(limits.maxDepth, 1);
  assert.equal(limits.maxRps, 5);
});

test('state-changing methods are detected', () => {
  assert.equal(isStateChangingMethod('POST'), true);
  assert.equal(isStateChangingMethod('GET'), false);
});

test('normalizeScope drops extra hosts that are not verified subdomains', () => {
  const scope = normalizeScope('app.example.com', {
    allowHosts: ['app.example.com', 'victim.org'],
    extraHosts: ['cdn.app.example.com', 'evil.com'],
  });
  assert.deepEqual(scope.allowHosts.sort(), ['app.example.com']);
  assert.deepEqual(scope.extraHosts, ['cdn.app.example.com']);
});

test('headers and evidence redact secrets', () => {
  const headers = sanitizeHeaders({ 'Set-Cookie': 'sid=abc', 'content-type': 'text/html' });
  assert.equal(headers['set-cookie'], '[redacted]');
  assert.equal(headers['content-type'], 'text/html');
  assert.match(redactEvidence('Authorization: Bearer secret-token leftover'), /\[redacted\]/);
});
