'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('node:dns');
const { isPublicAddress, guardedLookup, detectBlock } = require('../src/adapters/dast/net-guard');

test('isPublicAddress rejects loopback, mapped, 6to4, Teredo, CGNAT and docs ranges', () => {
  const blocked = [
    '127.0.0.1',
    '10.0.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '192.0.2.1',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::127.0.0.1',
    '2002:7f00:1::1',
    '2001:0000:4136:e378:8000:63bf:3fff:fdd2',
    '2001:db8::1',
    'fc00::1',
    'fe80::1',
  ];
  for (const ip of blocked) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
  assert.equal(isPublicAddress('1.1.1.1'), true);
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
});

test('guardedLookup rejects a rebinding answer that includes a non-public address', async () => {
  const orig = dns.lookup;
  dns.lookup = (hostname, opts, cb) => {
    cb(null, [
      { address: '1.1.1.1', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
  };
  try {
    await assert.rejects(
      () => new Promise((resolve, reject) => {
        guardedLookup('evil.example', { all: true }, (err, addresses) => (err ? reject(err) : resolve(addresses)));
      }),
      (err) => err.code === 'ESSRFBLOCKED' && /127\.0\.0\.1/.test(err.message)
    );
  } finally {
    dns.lookup = orig;
  }
});

test('detectBlock recognises Cloudflare challenge pages', () => {
  const hit = detectBlock(403, { 'cf-mitigated': 'challenge' }, '<title>Just a moment...</title>');
  assert.equal(hit.blocked, true);
  assert.equal(hit.by, 'Cloudflare');
  const miss = detectBlock(200, { server: 'nginx' }, '<html>ok</html>');
  assert.equal(miss.blocked, false);
});
