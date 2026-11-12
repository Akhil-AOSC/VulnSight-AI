'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseDeepScanOptions, redactDeepLimits, mergeSeedUrls, parseHeaderLine,
  sealDeepLimits, openDeepLimits,
} = require('../src/adapters/dast/deep-options');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');

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
    /listed on the site grant/,
  );
  const origin = parseDeepScanOptions(
    { originUrl: 'https://other.azurecontainerapps.io/' },
    {
      siteHostname: 'zango.com.au',
      authorizedDeep: true,
      allowedHosts: ['other.azurecontainerapps.io'],
    },
  );
  assert.equal(origin.originUrl, 'https://other.azurecontainerapps.io/');
});

test('redactDeepLimits strips cookie values from API documents', () => {
  const out = redactDeepLimits({ maxPages: 40, sessionCookie: 'sid=secret', seedUrls: ['https://zango.com.au/a'] });
  assert.equal(out.hasSessionCookie, true);
  assert.equal(out.sessionCookie, undefined);
  assert.deepEqual(out.seedUrls, ['https://zango.com.au/a']);
});

test('sealDeepLimits encrypts session material for durable storage', () => {
  const box = createSecretBox(generateMasterKey());
  const sealed = sealDeepLimits({
    maxPages: 40,
    sessionCookie: 'sid=secret',
    sessionHeader: { name: 'Authorization', value: 'Bearer tok' },
  }, box);
  assert.equal(sealed.sessionCookie, undefined);
  assert.equal(sealed.sessionHeader, undefined);
  assert.ok(sealed.sessionCookieEnc);
  assert.ok(sealed.sessionHeaderEnc);
  const opened = openDeepLimits(sealed, box);
  assert.equal(opened.sessionCookie, 'sid=secret');
  assert.deepEqual(opened.sessionHeader, { name: 'Authorization', value: 'Bearer tok' });
  const redacted = redactDeepLimits(sealed);
  assert.equal(redacted.hasSessionCookie, true);
  assert.equal(redacted.sessionCookieEnc, undefined);
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
