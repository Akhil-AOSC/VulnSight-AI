'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseDeepScanOptions, redactDeepLimits, mergeSeedUrls, parseHeaderLine,
} = require('../src/adapters/dast/deep-options');

test('Deep options require authorized Deep and stay on the registered host', () => {
  assert.throws(
    () => parseDeepScanOptions({ sessionCookie: 'sid=1' }, { siteHostname: 'zango.com.au', authorizedDeep: false }),
    /authorized Deep/,
  );
  const ok = parseDeepScanOptions({
    sessionCookie: 'sid=abc',
    sessionHeader: 'Authorization: Bearer tok',
    seedUrls: 'https://zango.com.au/api/users\nhttps://evil.example/x',
    originUrl: 'https://app.zango.com.au/',
  }, { siteHostname: 'zango.com.au', authorizedDeep: true });
  assert.equal(ok.sessionCookie, 'sid=abc');
  assert.deepEqual(ok.sessionHeader, { name: 'Authorization', value: 'Bearer tok' });
  assert.deepEqual(ok.seedUrls, ['https://zango.com.au/api/users']);
  assert.equal(ok.originUrl, 'https://app.zango.com.au/');
  assert.throws(
    () => parseDeepScanOptions({ originUrl: 'https://other.azurecontainerapps.io' }, { siteHostname: 'zango.com.au', authorizedDeep: true }),
    /subdomain/,
  );
});

test('redactDeepLimits strips cookie values from API documents', () => {
  const out = redactDeepLimits({ maxPages: 40, sessionCookie: 'sid=secret', seedUrls: ['https://zango.com.au/a'] });
  assert.equal(out.hasSessionCookie, true);
  assert.equal(out.sessionCookie, undefined);
  assert.deepEqual(out.seedUrls, ['https://zango.com.au/a']);
});

test('parseHeaderLine rejects hop-by-hop names', () => {
  assert.equal(parseHeaderLine('Host: evil'), null);
  assert.equal(parseHeaderLine('Bearer abc').name, 'Authorization');
});

test('mergeSeedUrls puts API seeds first', () => {
  const urls = mergeSeedUrls(['https://zango.com.au/'], ['https://zango.com.au/api/me'], {
    allowHosts: ['zango.com.au'],
    extraHosts: [],
    allowPaths: ['/'],
    denyPaths: [],
  }, 10);
  assert.equal(urls[0], 'https://zango.com.au/api/me');
});
