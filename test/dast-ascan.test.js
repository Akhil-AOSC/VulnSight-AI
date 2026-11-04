'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mapZapAlert, runZapActiveScan } = require('../src/adapters/dast/zap-ascan');

test('mapZapAlert converts ZAP high alerts to high DAST findings with redacted evidence', () => {
  const finding = mapZapAlert({
    risk: 'High',
    alert: 'SQL Injection',
    description: 'The page is vulnerable',
    pluginId: '40018',
    url: 'https://example.com/search',
    param: 'q',
    evidence: 'Authorization: Bearer secret-token',
    solution: 'Use parameterised queries',
  });
  assert.equal(finding.severity, 'high');
  assert.equal(finding.scanner.name, 'owasp-zap-ascan');
  assert.equal(finding.location.parameter, 'q');
  assert.match(finding.evidence, /\[redacted\]/);
});

test('runZapActiveScan refuses to run without ZAP_API_URL', async () => {
  const prev = process.env.ZAP_API_URL;
  delete process.env.ZAP_API_URL;
  await assert.rejects(
    () => runZapActiveScan('https://example.com'),
    (err) => err.message.includes('OWASP ZAP')
  );
  if (prev) process.env.ZAP_API_URL = prev;
});
