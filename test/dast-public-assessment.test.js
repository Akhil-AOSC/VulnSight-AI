'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { runDastPipeline } = require('../src/adapters/dast/pipeline');
const { evaluateScanAuthorization } = require('../src/platform/authorization-policy');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue, createWorker } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');
const { validateTargetUrl } = require('../src/adapters/dast/passive');

const PASSWORD = 'Correct-Horse-9';
const site = {
  target_url: 'https://shop.example.com',
  hostname: 'shop.example.com',
  is_verified: 0,
  verification_method: null,
};

function engines() {
  const calls = [];
  const track = (name, fn) => async (...args) => {
    calls.push(name);
    return fn(...args);
  };
  return {
    calls,
    deps: {
      dastPassive: track('passive', async () => ({
        findings: [{ title: 'Missing CSP', severity: 'medium' }],
        inventory: { pages: [], endpoints: [], forms: [], links: [] },
      })),
      dastBrowser: track('browser', async (_url, opts) => {
        assert.equal(opts.publicMode, true);
        assert.ok(opts.maxPages <= 12);
        return {
          engine: 'vulnsight-browser',
          pages: [{ url: 'https://shop.example.com/', urlHash: 'a', statusCode: 200, depth: 0 }],
          endpoints: [],
          forms: [],
          links: [],
          findings: [],
          reachability: { attempted: 1, loaded: 1, failures: 0 },
        };
      }),
      dastCrawl: track('spider', async () => {
        throw new Error('ZAP spider must not run during public assessment');
      }),
      dastNuclei: track('nuclei', async () => {
        throw new Error('Nuclei must not run during public assessment');
      }),
      dastAscan: track('ascan', async () => {
        throw new Error('ZAP ascan must not run during public assessment');
      }),
    },
  };
}

test('public assessment does not require DNS/HTTP or a grant', () => {
  const access = evaluateScanAuthorization({
    site: { hostname: 'example.com', is_verified: 0, target_url: 'https://example.com/' },
    profile: 'public',
  });
  assert.equal(access.allowed, true);
  assert.equal(access.assessmentKind, 'public_assessment');
  assert.equal(access.allowActive, false);
  assert.equal(access.nucleiMode, null);
  assert.equal(access.evidenceRequired, false);
  assert.equal(access.grant, null);
  assert.equal(access.policy, null);
});

test('public assessment ignores a stored grant and never enables active testing', () => {
  const access = evaluateScanAuthorization({
    site: { hostname: 'example.com', is_verified: 0, target_url: 'https://example.com/' },
    profile: 'public',
    grant: {
      status: 'active',
      evidenceKind: 'engagement_id',
      evidenceRef: 'ENG-SHOULD-NOT-MATTER',
      allowActiveTesting: true,
      allowedProfiles: ['discovery', 'standard', 'deep'],
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    },
  });
  assert.equal(access.allowed, true);
  assert.equal(access.assessmentKind, 'public_assessment');
  assert.equal(access.allowActive, false);
  assert.equal(access.grant, null);
});

test('public assessment runs passive plus limited discovery and never calls ZAP ascan or Nuclei', async () => {
  const { calls, deps } = engines();
  const result = await runDastPipeline(site, { profile: 'public', siteConfig: {}, limits: {} }, deps);
  assert.deepEqual(calls, ['passive', 'browser']);
  assert.equal(byName(result, 'nuclei').status, 'skipped');
  assert.equal(byName(result, 'owasp-zap-ascan').status, 'skipped');
  assert.match(byName(result, 'nuclei').error, /Public Website Assessment/);
  assert.match(byName(result, 'owasp-zap-ascan').error, /Public Website Assessment/);
  assert.equal(result.partial, false);
  assert.equal(result.profile, 'public');
  assert.equal(result.findings.length, 1);
});

function byName(result, name) {
  return result.engines.find((e) => e.name === name);
}

test('public assessment with a WAF challenge is still a complete public profile', async () => {
  const { deps } = engines();
  deps.dastPassive = async () => ({
    findings: [{ title: 'Deprecated TLS Protocol Accepted (TLSv1.1)', severity: 'medium' }],
    blocked: true,
    blockedBy: 'Cloudflare',
    inventory: { pages: [], endpoints: [], forms: [], links: [] },
  });
  const result = await runDastPipeline(site, { profile: 'public', siteConfig: {}, limits: {} }, deps);
  assert.equal(result.partial, false);
  assert.equal(result.blockedBy, 'Cloudflare');
  assert.equal(byName(result, 'vulnsight-passive').status, 'blocked');
  assert.equal(byName(result, 'vulnsight-browser').status, 'ok');
  assert.equal(result.story.headline, 'Inspection finished');
});

test('public pipeline still skips ascan when authorizeActiveTesting is set on the scan record', async () => {
  const { calls, deps } = engines();
  const result = await runDastPipeline(
    site,
    { profile: 'public', authorizeActiveTesting: true, siteConfig: {}, limits: {} },
    deps,
  );
  assert.deepEqual(calls, ['passive', 'browser']);
  assert.equal(byName(result, 'owasp-zap-ascan').status, 'skipped');
  assert.equal(result.access && result.access.allowActive, false);
});

test('register and start public assessment without verification', async () => {
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const platform = createPlatform({
    db,
    queue,
    secretBox: createSecretBox(generateMasterKey()),
    dastPassive: async () => ({ findings: [], inventory: { pages: [], endpoints: [], forms: [], links: [] } }),
    dastBrowser: async () => ({ engine: 'vulnsight-browser', pages: [], endpoints: [], forms: [], links: [], findings: [] }),
    dastCrawl: async () => { throw new Error('spider'); },
    dastNuclei: async () => { throw new Error('nuclei'); },
    dastAscan: async () => { throw new Error('ascan'); },
  });
  const worker = createWorker({ queue, handlers: platform.handlers });
  const res = await platform.auth.signup({ email: 'pub@example.com', name: 'O', password: PASSWORD, orgName: 'Co' });
  const ctx = { userId: res.user.id, orgId: res.orgId };
  const created = await platform.websites.create(ctx, { url: 'https://example.com', name: 'Ex' });
  assert.equal(created.isVerified, false);
  const scan = platform.websites.startScan(ctx, created.id, { profile: 'public_assessment' });
  assert.equal(scan.profile, 'public');
  while (await worker.runOnce());
  const done = platform.websites.getScan(ctx, created.id, scan.id);
  assert.equal(done.status, 'completed');
  const nuclei = (done.summary.engines || []).find((e) => e.name === 'nuclei');
  const ascan = (done.summary.engines || []).find((e) => e.name === 'owasp-zap-ascan');
  assert.equal(nuclei.status, 'skipped');
  assert.equal(ascan.status, 'skipped');
  const grants = db.prepare('SELECT COUNT(*) AS n FROM dast_authorizations WHERE org_id = ?').get(ctx.orgId).n;
  const policies = db.prepare('SELECT COUNT(*) AS n FROM dast_org_policies WHERE org_id = ?').get(ctx.orgId).n;
  assert.equal(grants, 0);
  assert.equal(policies, 0);
  const row = db.prepare('SELECT authorize_active, authorization_id FROM website_scans WHERE id = ?').get(scan.id);
  assert.equal(row.authorize_active, 0);
  assert.equal(row.authorization_id, null);
});

test('self-attestation flags cannot mark a site verified or start deep ascan', async () => {
  const db = openDatabase(':memory:');
  const platform = createPlatform({
    db,
    queue: createQueue(db),
    secretBox: createSecretBox(generateMasterKey()),
    dastPassive: async () => ({ findings: [], inventory: { pages: [], endpoints: [], forms: [], links: [] } }),
    dastAscan: async () => { throw new Error('ascan must not run'); },
  });
  const res = await platform.auth.signup({ email: 'attest@example.com', name: 'O', password: PASSWORD, orgName: 'Co' });
  const ctx = { userId: res.user.id, orgId: res.orgId };
  const created = await platform.websites.create(ctx, { url: 'https://example.com', name: 'Ex' });
  await assert.rejects(
    () => platform.websites.verify(ctx, created.id, { manual: true }),
    /Manual verification is not allowed/,
  );
  assert.throws(
    () => platform.websites.startScan(ctx, created.id, {
      profile: 'deep',
      attestAuthorization: true,
      authorizeActiveTesting: true,
    }),
    (err) => /Self-attestation cannot authorize/i.test(err.message),
  );
  const row = db.prepare('SELECT is_verified, verification_method FROM websites WHERE id = ?').get(created.id);
  assert.equal(row.is_verified, 0);
  assert.equal(row.verification_method, null);
});

test('unauthorized deep assessment is blocked without engagement evidence', async () => {
  const db = openDatabase(':memory:');
  const platform = createPlatform({
    db,
    queue: createQueue(db),
    secretBox: createSecretBox(generateMasterKey()),
    dastPassive: async () => ({ findings: [], inventory: { pages: [], endpoints: [], forms: [], links: [] } }),
    dastAscan: async () => { throw new Error('ascan must not run'); },
  });
  const res = await platform.auth.signup({ email: 'act@example.com', name: 'O', password: PASSWORD, orgName: 'Co' });
  const ctx = { userId: res.user.id, orgId: res.orgId };
  const created = await platform.websites.create(ctx, { url: 'https://example.com', name: 'Ex' });
  assert.throws(
    () => platform.websites.startScan(ctx, created.id, { profile: 'deep', authorizeActiveTesting: true }),
    (err) => /allowActiveTesting|engagement|not authorized|requires/i.test(err.message),
  );
});

test('SSRF guards still block loopback and private targets', async () => {
  await assert.rejects(() => validateTargetUrl('http://127.0.0.1/'), /private|loopback|not allowed|public/i);
  await assert.rejects(() => validateTargetUrl('http://169.254.169.254/'), /metadata|private|not allowed|public/i);
});
