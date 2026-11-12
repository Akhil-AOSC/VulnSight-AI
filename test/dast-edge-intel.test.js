'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { collectEdgeIntel, ipOwner, parseRay, nsHost, cookieNames } = require('../src/adapters/dast/edge-intel');

const cloudflareDns = {
  resolveNs: async () => ['kai.ns.cloudflare.com', 'michelle.ns.cloudflare.com'],
  resolve4: async () => ['172.67.74.168', '104.26.10.86', '104.26.11.86'],
  resolve6: async () => ['2606:4700:83b9:be7e:3f39:0:f03d:ca3c'],
};

test('ipOwner does not use a hardcoded vendor range list', () => {
  assert.equal(ipOwner('104.26.10.86'), null);
  assert.equal(ipOwner('172.67.74.168'), null);
  assert.equal(ipOwner('2606:4700:83b9::1'), null);
  assert.equal(ipOwner('8.8.8.8'), null);
  assert.equal(ipOwner('not-an-ip'), null);
});

test('parseRay reads id and location code from cf-ray without a city map', () => {
  assert.deepEqual(parseRay('8f3a1b2c4d5e6f7a-SYD'), { id: '8f3a1b2c4d5e6f7a', code: 'SYD', city: null });
  assert.equal(parseRay('8f3a1b2c4d5e6f7a-ZZZ').city, null);
  assert.equal(parseRay(undefined), null);
});

test('nsHost and cookieNames identify the DNS host and keep cookie names only', () => {
  assert.equal(nsHost(['kai.ns.cloudflare.com']), 'Cloudflare');
  assert.equal(nsHost(['ns-1.awsdns-01.com']), 'Amazon Route 53');
  assert.equal(nsHost(['ns1.example.net']), null);
  assert.deepEqual(cookieNames(['__cf_bm=SECRET; path=/', 'sid=abc']), ['__cf_bm', 'sid']);
});

test('a Cloudflare challenge is reported as edge evidence, with no cookie values', async () => {
  const edge = await collectEdgeIntel({
    hostname: 'zango.com.au',
    statusCode: 403,
    headers: {
      server: 'cloudflare',
      'cf-ray': '8f3a1b2c4d5e6f7a-SYD',
      'cf-mitigated': 'challenge',
      'set-cookie': ['__cf_bm=SECRETVALUE123; path=/; HttpOnly'],
    },
    body: '<html><head><title>Just a moment...</title></head></html>',
    block: { blocked: true, by: 'Cloudflare', reason: 'challenge', retryAfterSec: null },
    tls: { issuer: 'Google Trust Services', subject: 'zango.com.au', sans: 'DNS:zango.com.au, DNS:*.zango.com.au', protocol: 'TLSv1.3' },
    resolver: cloudflareDns,
  });

  assert.equal(edge.provider, 'Cloudflare');
  assert.equal(edge.confidence, 'confirmed');
  assert.equal(edge.dnsHost, 'Cloudflare');
  assert.equal(edge.originHidden, true);
  assert.equal(edge.dns.ipv4.length, 3);
  assert.ok(edge.dns.ipv4.every((r) => r.owner === null));
  assert.equal(edge.edgeHeaders.ray.code, 'SYD');
  assert.equal(edge.edgeHeaders.ray.city, null);
  assert.equal(edge.botProtection.challenged, true);
  assert.equal(edge.botProtection.kind, 'Managed challenge');
  assert.equal(edge.botProtection.pageTitle, 'Just a moment...');
  assert.deepEqual(edge.cookieNames, ['__cf_bm']);
  assert.ok(!JSON.stringify(edge).includes('SECRETVALUE123'), 'cookie values must never be stored');
  assert.deepEqual(edge.tls.sans, ['zango.com.au', '*.zango.com.au']);
});

test('a site that is only DNS-hosted on Cloudflare is not reported as behind Cloudflare', async () => {
  const edge = await collectEdgeIntel({
    hostname: 'grey-cloud.example',
    statusCode: 200,
    headers: { server: 'nginx' },
    resolver: { ...cloudflareDns, resolve4: async () => ['203.0.114.10'], resolve6: async () => [] },
  });
  assert.equal(edge.dnsHost, 'Cloudflare');
  assert.equal(edge.provider, null, 'DNS hosting alone does not prove traffic goes through the edge');
  assert.equal(edge.originHidden, false);
  assert.equal(edge.botProtection.challenged, false);
});

test('DNS failures never throw', async () => {
  const failing = {
    resolveNs: async () => { throw new Error('ESERVFAIL'); },
    resolve4: async () => { throw new Error('x'); },
    resolve6: async () => { throw new Error('x'); },
  };
  const edge = await collectEdgeIntel({ hostname: 'nowhere.example', resolver: failing });
  assert.equal(edge.provider, null);
  assert.deepEqual(edge.dns.ipv4, []);
});
