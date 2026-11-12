'use strict';

// A host firewall that bans the scanner IP drops packets: engines see timeouts, never an HTTP
// response. These tests pin down that such a scan is reported as blocked (never as "ok" with zero
// findings) and that the pipeline stops sending traffic once the host stops answering.

const test = require('node:test');
const assert = require('node:assert/strict');
const { runDastPipeline } = require('../src/adapters/dast/pipeline');
const { classifyNetworkError } = require('../src/adapters/dast/net-guard');

const site = {
  target_url: 'https://shop.example.com',
  hostname: 'shop.example.com',
  is_verified: 1,
  verification_method: 'http_token',
  verified_at: new Date().toISOString(),
};
const scan = {
  profile: 'ascan',
  authorizeActiveTesting: true,
  siteConfig: {},
  limits: {},
  grant: {
    status: 'active',
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    allowedProfiles: ['deep', 'standard', 'discovery'],
    allowActiveTesting: true,
    allowHosts: ['shop.example.com'],
    allowPaths: ['/'],
    denyPaths: [],
    ports: [80, 443],
  },
};

const okPage = (url) => ({ url, urlHash: url, statusCode: 200, contentType: 'text/html', depth: 0, title: 'Home' });
const okInventory = (engine) => ({
  engine, pages: [okPage('https://shop.example.com/')], endpoints: [], forms: [], links: [], findings: [],
  reachability: { attempted: 1, loaded: 1, failures: 0, lastError: null },
});

function engines(overrides = {}) {
  const calls = [];
  const track = (name, fn) => async (...args) => {
    calls.push(name);
    return fn(...args);
  };
  return {
    calls,
    deps: {
      dastPassive: track('passive', overrides.passive || (async () => ({ findings: [], inventory: okInventory('vulnsight-recon') }))),
      dastBrowser: track('browser', overrides.browser || (async () => okInventory('vulnsight-browser'))),
      dastCrawl: track('spider', overrides.spider || (async () => okInventory('zap-traditional'))),
      dastNuclei: track('nuclei', overrides.nuclei || (async () => ({ engine: 'nuclei', findings: [] }))),
      dastAscan: track('ascan', overrides.ascan || (async () => ({ engine: 'zap-ascan', findings: [] }))),
      probeReachable: overrides.probe || (async () => ({ ok: true, statusCode: 200 })),
    },
  };
}

const byName = (result, name) => result.engines.find((e) => e.name === name);

test('classifyNetworkError recognises dropped connections from Node, Chromium and ZAP', () => {
  assert.equal(classifyNetworkError(Object.assign(new Error('connect ETIMEDOUT 192.250.232.175:443'), { code: 'ETIMEDOUT' })), 'dropped');
  assert.equal(classifyNetworkError('page.goto: net::ERR_CONNECTION_TIMED_OUT at https://x'), 'dropped');
  assert.equal(classifyNetworkError('page.goto: Timeout 15000ms exceeded.'), 'dropped');
  assert.equal(classifyNetworkError('ZAP stored no responses from the host (no responses)'), 'dropped');
  assert.equal(classifyNetworkError(new Error('read ECONNRESET')), 'dropped');
  assert.equal(classifyNetworkError(new Error('connect ECONNREFUSED 1.2.3.4:443')), 'refused');
  assert.equal(classifyNetworkError(new Error('getaddrinfo ENOTFOUND nope.example')), 'unreachable');
  assert.equal(classifyNetworkError(Object.assign(new Error('x'), { code: 'ESSRFBLOCKED' })), 'ssrf');
});

test('passive timeout stops the scan: no crawl, no Nuclei, no attack payloads', async () => {
  const { calls, deps } = engines({
    passive: async () => { throw Object.assign(new Error('connect ETIMEDOUT 192.250.232.175:443'), { code: 'ETIMEDOUT' }); },
  });
  const result = await runDastPipeline(site, scan, deps);

  assert.deepEqual(calls, ['passive']);
  assert.equal(byName(result, 'vulnsight-passive').status, 'blocked');
  assert.match(byName(result, 'vulnsight-passive').error, /firewall/i);
  for (const name of ['vulnsight-browser', 'nuclei', 'owasp-zap-ascan']) {
    assert.equal(byName(result, name).status, 'skipped', name);
    assert.match(byName(result, name).error, /dropping connections/i, name);
  }
  assert.match(byName(result, 'owasp-zap-ascan').error, /No attack payloads were sent/);
  assert.equal(result.partial, true);
  assert.equal(result.blockedBy, 'host firewall');
  assert.match(result.story.readout, /dropping connections/i);
});

test('a browser crawl where no page loaded is blocked, not ok', async () => {
  const { calls, deps } = engines({
    browser: async () => ({
      engine: 'vulnsight-browser', pages: [], endpoints: [], forms: [], links: [], findings: [],
      reachability: { attempted: 2, loaded: 0, failures: 2, lastError: 'page.goto: net::ERR_CONNECTION_TIMED_OUT' },
    }),
  });
  const result = await runDastPipeline(site, scan, deps);

  assert.equal(byName(result, 'vulnsight-browser').status, 'blocked');
  assert.equal(byName(result, 'vulnsight-browser').blockReason, 'connection_dropped');
  assert.deepEqual(calls, ['passive', 'browser']);
  assert.equal(byName(result, 'nuclei').status, 'skipped');
  assert.equal(result.blockedBy, 'host firewall');
});

test('a ZAP spider that stored no responses does not report fake pages as ok', async () => {
  const { calls, deps } = engines({
    spider: async () => ({
      engine: 'zap-traditional', pages: [], endpoints: [], forms: [], links: [], findings: [],
      reachability: { attempted: 1, loaded: 0, failures: 1, lastError: 'ZAP stored no responses from the host (no responses)' },
    }),
  });
  const result = await runDastPipeline(site, scan, deps);

  const spider = result.engines.find((e) => e.name === 'owasp-zap-spider' || e.name === 'builtin-get');
  assert.equal(spider.status, 'blocked');
  assert.ok(!calls.includes('nuclei'));
  assert.ok(!calls.includes('ascan'));
  // The inventory still comes from the stages that did load pages.
  assert.equal(result.inventory.pages[0].statusCode, 200);
});

test('host that starts dropping connections during Nuclei marks Nuclei blocked and skips the active scan', async () => {
  let probes = 0;
  const { calls, deps } = engines({
    probe: async () => {
      probes += 1;
      // Browser and spider stages are fine; after Nuclei the host stops answering.
      return probes < 3 ? { ok: true, statusCode: 200 } : { ok: false, kind: 'dropped', message: 'The host stopped answering this machine (ETIMEDOUT).' };
    },
  });
  const result = await runDastPipeline(site, scan, deps);

  assert.deepEqual(calls, ['passive', 'browser', 'spider', 'nuclei']);
  assert.equal(byName(result, 'nuclei').status, 'blocked');
  assert.match(byName(result, 'nuclei').error, /results are incomplete/);
  assert.equal(byName(result, 'owasp-zap-ascan').status, 'skipped');
  assert.equal(result.blockedBy, 'host firewall');
});

test('a host that answers throughout runs every stage and reports ok', async () => {
  const { calls, deps } = engines();
  const result = await runDastPipeline(site, scan, deps);

  assert.deepEqual(calls, ['passive', 'browser', 'spider', 'nuclei', 'ascan']);
  for (const e of result.engines) assert.equal(e.status, 'ok', e.name);
  assert.equal(result.blockedBy, null);
});

const tlsFinding = {
  category: 'dast', severity: 'high', title: 'TLS Certificate Is Not Trusted',
  scanner: { name: 'vulnsight-passive', ruleId: 'tls-cert-untrusted' },
  identifiers: { primary: 'CWE-295', cwe: ['CWE-295'] }, location: { url: 'https://shop.example.com/' },
};

test('WAF challenge on passive recon names the provider and keeps TLS findings', async () => {
  // passive.js returns the provider both ways: blocked: { by } and blockedBy.
  const { deps } = engines({
    passive: async () => ({
      findings: [tlsFinding],
      blocked: { by: 'Cloudflare', reason: 'challenge', retryAfterSec: null },
      blockedBy: 'Cloudflare',
      inventory: null,
    }),
  });
  const result = await runDastPipeline(site, scan, deps);

  const passive = byName(result, 'vulnsight-passive');
  assert.equal(passive.status, 'blocked');
  assert.equal(passive.error, 'blocked by Cloudflare');
  assert.equal(result.blockedBy, 'Cloudflare');
  assert.ok(result.findings.some((f) => f.scanner.ruleId === 'tls-cert-untrusted'), 'TLS finding from the handshake is kept');
  const story = result.story.stages.find((s) => s.name === 'vulnsight-passive');
  assert.match(story.why, /firewall \(Cloudflare\)/);
  assert.match(story.why, /TLS results were kept/);
});

test('older passive results that only carry blocked.by still name the provider', async () => {
  const { deps } = engines({
    passive: async () => ({ findings: [], blocked: { by: 'Akamai', reason: 'challenge' }, inventory: null }),
  });
  const result = await runDastPipeline(site, scan, deps);
  assert.equal(result.blockedBy, 'Akamai');
  assert.equal(byName(result, 'vulnsight-passive').error, 'blocked by Akamai');
});

test('an active scan stopped by its time limit is partial, not ok', async () => {
  const { deps } = engines({
    ascan: async () => ({ engine: 'zap-ascan', findings: [tlsFinding], timedOut: true, percent: 30, maxDurationSec: 180 }),
  });
  const result = await runDastPipeline(site, scan, deps);

  const ascan = byName(result, 'owasp-zap-ascan');
  assert.equal(ascan.status, 'partial');
  assert.equal(ascan.findings, 1);
  assert.match(ascan.error, /Stopped at 30% when it reached its 180-second time limit/);
  assert.match(ascan.error, /up to 900 seconds/);
  assert.equal(result.partial, true);
  assert.equal(result.story.headline, 'Incomplete inspection');
  const story = result.story.stages.find((s) => s.name === 'owasp-zap-ascan');
  assert.match(story.why, /Stopped at 30%/);
});

test('ZAP active scan reporting no stored responses is shown as a firewall block', async () => {
  const { deps } = engines({
    ascan: async () => {
      throw Object.assign(new Error('The host shop.example.com stopped answering this machine (ZAP stored no responses from the host). No attack payloads were sent.'), { code: 'HOST_DROPPED' });
    },
  });
  const result = await runDastPipeline(site, scan, deps);

  const ascan = byName(result, 'owasp-zap-ascan');
  assert.equal(ascan.status, 'blocked');
  assert.equal(ascan.blockReason, 'connection_dropped');
  assert.match(ascan.error, /No attack payloads were sent/);
  assert.equal(result.blockedBy, 'host firewall');
});

test('a site verified only by the removed manual attestation cannot crawl or attack', async () => {
  const { calls, deps } = engines();
  const manual = { ...site, verification_method: 'manual_authorization' };
  const result = await runDastPipeline(manual, { profile: 'deep', siteConfig: {}, limits: {} }, deps);
  assert.deepEqual(calls, ['passive'], 'only the passive check ran; no crawl, Nuclei or attack payloads');
  assert.equal(result.partial, true);
  assert.equal(byName(result, 'owasp-zap-ascan').status, 'skipped');
  assert.match(byName(result, 'owasp-zap-ascan').error, /engagement policy|lab allowlist|DNS\/HTTP|authorization/i);
});
