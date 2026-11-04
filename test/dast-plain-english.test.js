'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { plainEnglishForFinding } = require('../src/adapters/dast/plain-english');

test('plainEnglishForFinding explains HSTS in everyday language', () => {
  const text = plainEnglishForFinding({
    severity: 'medium',
    title: 'Missing Strict-Transport-Security (HSTS) Header',
    description: 'HSTS header is absent.',
    location: { url: 'https://example.com/' },
    scanner: { name: 'vulnsight-passive', ruleId: 'header-strict-transport-security' },
    remediation: { advice: 'Add Strict-Transport-Security.' },
  }, 'https://example.com');
  assert.match(text, /HTTPS/i);
  assert.match(text, /https:\/\/example.com\//);
  assert.match(text, /moderate/i);
});
