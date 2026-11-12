'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mapZapAlert, runZapActiveScan } = require('../src/adapters/dast/zap-ascan');
const { resetZapSession, flattenZapList, pickTreeUrl } = require('../src/adapters/dast/zap-client');

test('mapZapAlert promotes ZAP high SQL injection to critical and redacts evidence', () => {
  const finding = mapZapAlert({
    risk: 'High',
    alert: 'SQL Injection',
    description: 'The page is vulnerable',
    pluginId: '40018',
    cweid: '89',
    url: 'https://example.com/search',
    param: 'q',
    evidence: 'Authorization: Bearer secret-token',
    solution: 'Use parameterised queries',
  });
  assert.equal(finding.severity, 'critical');
  assert.equal(finding.scanner.name, 'owasp-zap-ascan');
  assert.equal(finding.location.parameter, 'q');
  assert.match(finding.evidence, /\[redacted\]/);
});

test('mapZapAlert keeps distinct ZAP alerts of the same plugin', () => {
  const a = mapZapAlert({
    id: '11', risk: 'Medium', alert: 'Absence of Anti-CSRF Tokens', pluginId: '10202',
    url: 'https://example.com/a', param: 'x', evidence: 'form-a',
  });
  const b = mapZapAlert({
    id: '12', risk: 'Medium', alert: 'Absence of Anti-CSRF Tokens', pluginId: '10202',
    url: 'https://example.com/a', param: 'x', evidence: 'form-b',
  });
  assert.notEqual(a.id, b.id);
});

test('mapZapAlert promotes CSRF, IDOR and SSRF into high or critical', () => {
  const csrf = mapZapAlert({
    risk: 'Medium', alert: 'Absence of Anti-CSRF Tokens', pluginId: '10202', cweid: '352',
    url: 'https://example.com/form',
  });
  const idor = mapZapAlert({
    risk: 'High', alert: 'Insecure Direct Object References', pluginId: '40003', cweid: '639',
    url: 'https://example.com/orders/1',
  });
  const ssrf = mapZapAlert({
    risk: 'High', alert: 'Server Side Request Forgery', pluginId: '40046', cweid: '918',
    url: 'https://example.com/fetch', param: 'url',
  });
  assert.equal(csrf.severity, 'high');
  assert.equal(idor.severity, 'critical');
  assert.equal(ssrf.severity, 'critical');
});

test('mapZapAlert drops User Agent Fuzzer and Modern Web Application noise', () => {
  assert.equal(mapZapAlert({ risk: 'Low', alert: 'User Agent Fuzzer', pluginId: '10104', url: 'https://example.com' }), null);
  assert.equal(mapZapAlert({ risk: 'Low', alert: 'Modern Web Application', pluginId: '10109', url: 'https://example.com' }), null);
});

test('mapZapAlert keeps ZAP high XSS as high', () => {
  const finding = mapZapAlert({
    risk: 'High',
    alert: 'Cross Site Scripting (Reflected)',
    cweid: '79',
    pluginId: '40012',
    url: 'https://example.com/q',
  });
  assert.equal(finding.severity, 'high');
});

function mockZapFetch(calls, extra = {}) {
  return async (url, init) => {
    calls.push({ url: String(url), headers: (init && init.headers) || {}, signal: init && init.signal });
    const path = String(url);
    const json = (body) => ({ ok: true, json: async () => body });
    if (path.includes('newSession')) return json({});
    if (path.includes('newContext')) return json({ contextId: '9' });
    if (path.includes('includeInContext')) return json({});
    if (path.includes('setOption')) return json({});
    if (path.includes('/context/view/context')) return json({ context: { id: '9' } });
    if (path.includes('accessUrl')) return json({});
    if (path.includes('core/view/urls')) return json({ urls: extra.urls || ['https://example.com'] });
    if (path.includes('core/view/sites')) return json({ sites: extra.sites || ['https://example.com'] });
    if (path.includes('spider/view/allUrls')) return json({ allUrls: extra.urls || ['https://example.com'] });
    if (path.includes('ascan/action/scan')) return json({ scan: '1' });
    if (path.includes('ascan/view/status')) return json({ status: '100' });
    if (path.includes('core/view/alerts')) return json({ alerts: [] });
    return json({});
  };
}

test('flattenZapList unwraps ZAP JSON list wrappers', () => {
  assert.deepEqual(flattenZapList({ url: ['https://a.example', 'https://b.example'] }), [
    'https://a.example',
    'https://b.example',
  ]);
  assert.equal(pickTreeUrl(['https://www.example.com/app'], 'https://example.com'), 'https://www.example.com/app');
});

test('runZapActiveScan uses header API key, newSession, contextId and timeouts', async () => {
  resetZapSession();
  const prevUrl = process.env.ZAP_API_URL;
  const prevKey = process.env.ZAP_API_KEY;
  process.env.ZAP_API_URL = 'http://127.0.0.1:18080';
  process.env.ZAP_API_KEY = 'test-key';
  const calls = [];
  const orig = global.fetch;
  global.fetch = mockZapFetch(calls);
  try {
    const { normalizeScope } = require('../src/adapters/dast/scope');
    await runZapActiveScan('https://example.com', { scope: normalizeScope('example.com'), maxDurationSec: 1, allowActive: true });
    assert.ok(calls.some((c) => c.headers['X-ZAP-API-Key'] === 'test-key'));
    assert.ok(calls.every((c) => !c.url.includes('apikey=')));
    assert.ok(calls.some((c) => c.url.includes('newSession')));
    assert.ok(calls.some((c) => c.url.includes('newContext')));
    assert.ok(calls.some((c) => c.url.includes('contextId=9')));
    assert.ok(calls.some((c) => c.url.includes('ascan/action/enableAllScanners')));
    assert.ok(calls.some((c) => c.url.includes('ascan/action/enableScanners') && c.url.includes('40046')));
    assert.ok(calls.every((c) => c.signal));
  } finally {
    global.fetch = orig;
    resetZapSession();
    if (prevUrl) process.env.ZAP_API_URL = prevUrl; else delete process.env.ZAP_API_URL;
    if (prevKey) process.env.ZAP_API_KEY = prevKey; else delete process.env.ZAP_API_KEY;
  }
});

test('runZapActiveScan reuses an existing ZAP session and does not call newSession', async () => {
  resetZapSession();
  const prevUrl = process.env.ZAP_API_URL;
  const prevKey = process.env.ZAP_API_KEY;
  process.env.ZAP_API_URL = 'http://127.0.0.1:18080';
  process.env.ZAP_API_KEY = 'test-key';
  const calls = [];
  const orig = global.fetch;
  global.fetch = mockZapFetch(calls, { urls: ['https://www.example.com/'] });
  try {
    await runZapActiveScan('https://example.com', {
      zapSession: { contextName: 'vs-ctx', contextId: '4' },
      seedUrls: ['https://www.example.com/'],
      maxDurationSec: 1,
      allowActive: true,
    });
    assert.ok(calls.every((c) => !c.url.includes('newSession')));
    assert.ok(calls.some((c) => c.url.includes('ascan/action/scan') && c.url.includes('url=')));
    assert.ok(calls.some((c) => c.url.includes('contextId=4')));
  } finally {
    global.fetch = orig;
    resetZapSession();
    if (prevUrl) process.env.ZAP_API_URL = prevUrl; else delete process.env.ZAP_API_URL;
    if (prevKey) process.env.ZAP_API_KEY = prevKey; else delete process.env.ZAP_API_KEY;
  }
});

test('runZapActiveScan refuses to run without stored active permission', async () => {
  await assert.rejects(
    () => runZapActiveScan('https://example.com', { allowActive: false }),
    /allowActiveTesting/
  );
});

test('runZapActiveScan refuses to run without ZAP_API_URL', async () => {
  const prev = process.env.ZAP_API_URL;
  delete process.env.ZAP_API_URL;
  await assert.rejects(
    () => runZapActiveScan('https://example.com', { allowActive: true }),
    (err) => err.message.includes('OWASP ZAP')
  );
  if (prev) process.env.ZAP_API_URL = prev;
});
