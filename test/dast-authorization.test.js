'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluateWebsiteAccess, validateGrantInput, intersectScope } = require('../src/platform/dast-authorization');
const { normalizeScope, urlInScope, normalizeUrl } = require('../src/adapters/dast/scope');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue, createWorker } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');

const PASSWORD = 'Correct-Horse-9';

function setup() {
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const platform = createPlatform({
    db,
    queue,
    secretBox: createSecretBox(generateMasterKey()),
    dastPassive: async () => ({ findings: [], inventory: { pages: [], endpoints: [], forms: [], links: [] } }),
    dastCrawl: async () => ({ engine: 'builtin-get', pages: [{ url: 'https://example.com/', urlHash: 'a', statusCode: 200 }], endpoints: [], forms: [], links: [], findings: [] }),
    dastBrowser: async () => ({ engine: 'vulnsight-browser', pages: [], endpoints: [], forms: [], links: [], findings: [] }),
    dastNuclei: async (_urls, opts) => ({ engine: 'nuclei', findings: [], mode: opts.mode }),
    dastAscan: async () => ({ engine: 'zap-ascan', findings: [] }),
  });
  const worker = createWorker({ queue, handlers: platform.handlers });
  const drain = async () => { while (await worker.runOnce()); };
  return { db, platform, drain };
}

async function orgAndSite(platform, email) {
  const res = await platform.auth.signup({ email, name: 'Owner', password: PASSWORD, orgName: 'Co' });
  const ctx = { userId: res.user.id, orgId: res.orgId };
  const site = await platform.websites.create(ctx, { url: 'https://example.com', name: 'Example' });
  return { ctx, site };
}

function future(hours) {
  return new Date(Date.now() + hours * 3600 * 1000).toISOString();
}

test('self-attestation and public URLs are rejected as grant evidence', () => {
  assert.match(validateGrantInput({
    allowedProfiles: ['discovery'],
    expiresAt: future(24),
    evidenceKind: 'engagement_id',
    evidenceRef: 'i own this',
    siteHostname: 'example.com',
  }), /Self-attestation|identifier/);
  assert.match(validateGrantInput({
    allowedProfiles: ['discovery'],
    expiresAt: future(24),
    evidenceKind: 'change_ticket',
    evidenceRef: 'https://example.com/ok',
    siteHostname: 'example.com',
  }), /not sufficient/);
});

test('unauthorized active scan is rejected without grant or ownership', async () => {
  const { platform } = setup();
  const { ctx, site } = await orgAndSite(platform, 'noauth@example.com');
  assert.throws(
    () => platform.websites.startScan(ctx, site.id, { profile: 'deep', authorizeActiveTesting: true }),
    /engagement policy|lab allowlist|authorization|ownership|DNS\/HTTP/
  );
});

test('client grant allows discovery without DNS and can be expired or revoked', async () => {
  const { platform, drain } = setup();
  const { ctx, site } = await orgAndSite(platform, 'grant@example.com');
  assert.throws(
    () => platform.websites.createAuthorization(ctx, site.id, {
      allowedProfiles: ['discovery'],
      expiresAt: future(24),
      evidenceKind: 'engagement_id',
      evidenceRef: 'confirmed',
    }),
    /Self-attestation|identifier|evidenceRef|sufficient/
  );
  const grant = await platform.websites.createAuthorization(ctx, site.id, {
    allowedProfiles: ['discovery', 'standard'],
    expiresAt: future(48),
    evidenceKind: 'engagement_id',
    evidenceRef: 'ENG-99421A',
    allowHosts: ['example.com'],
  });
  assert.equal(grant.status, 'active');
  const scan = platform.websites.startScan(ctx, site.id, { profile: 'discovery', authorizationId: grant.id });
  assert.equal(scan.profile, 'discovery');
  await drain();
  assert.equal(platform.websites.getScan(ctx, site.id, scan.id).status, 'completed');

  const expired = await platform.websites.createAuthorization(ctx, site.id, {
    allowedProfiles: ['discovery'],
    expiresAt: future(2),
    evidenceKind: 'change_ticket',
    evidenceRef: 'JIRA-44120',
  });
  const { db } = setup();
  void db;
  platform.websites.revokeAuthorization(ctx, site.id, grant.id, { reason: 'engagement ended' });
  assert.throws(
    () => platform.websites.startScan(ctx, site.id, { profile: 'discovery', authorizationId: grant.id }),
    /site grant|engagement policy|lab allowlist|DNS\/HTTP|authorization/
  );

  const { evaluateWebsiteAccess: ev } = require('../src/platform/dast-authorization');
  assert.throws(() => ev({
    site: { hostname: 'example.com', is_verified: 0 },
    profile: 'discovery',
    grant: { ...expired, expiresAt: new Date(Date.now() - 1000).toISOString(), status: 'expired', allowedProfiles: ['discovery'], allowHosts: ['example.com'] },
  }), /authorization grant|ownership/);
});

test('grant cannot authorize a foreign hostname or out-of-scope path', () => {
  assert.match(validateGrantInput({
    allowedProfiles: ['discovery'],
    expiresAt: future(24),
    evidenceKind: 'engagement_id',
    evidenceRef: 'ENG-123456',
    allowHosts: ['victim.org'],
    siteHostname: 'example.com',
  }), /outside the registered website hostname/);

  const scope = intersectScope(
    normalizeScope('example.com', { allowPaths: ['/'] }),
    { allowHosts: ['example.com'], allowPaths: ['/app'], denyPaths: ['/admin'], ports: [443] },
    'example.com',
  );
  assert.equal(urlInScope(normalizeUrl('https://example.com/app/x'), scope), true);
  assert.equal(urlInScope(normalizeUrl('https://example.com/secret'), scope), false);
  assert.equal(urlInScope(normalizeUrl('http://example.com/app'), scope), false);
});

test('deep ascan needs grant.allowActiveTesting or DNS ownership plus confirmation', async () => {
  const { platform } = setup();
  const { ctx, site } = await orgAndSite(platform, 'ascan@example.com');
  const grant = await platform.websites.createAuthorization(ctx, site.id, {
    allowedProfiles: ['deep'],
    expiresAt: future(24),
    evidenceKind: 'signed_document_sha256',
    evidenceRef: 'a'.repeat(64),
    allowActiveTesting: false,
  });
  assert.throws(
    () => platform.websites.startScan(ctx, site.id, { profile: 'deep', authorizeActiveTesting: true, authorizationId: grant.id }),
    /allowActiveTesting|active testing/
  );
  const active = await platform.websites.createAuthorization(ctx, site.id, {
    allowedProfiles: ['deep'],
    expiresAt: future(24),
    evidenceKind: 'engagement_id',
    evidenceRef: 'ENG-555001',
    allowActiveTesting: true,
  });
  const scan = platform.websites.startScan(ctx, site.id, {
    profile: 'deep',
    authorizationId: active.id,
  });
  assert.equal(scan.profile, 'deep');
  assert.equal(scan.authorizeActiveTesting, true);
});

test('worker revalidates authorization between stages and records a skip when revoked', async () => {
  let calls = 0;
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const platform = createPlatform({
    db,
    queue,
    secretBox: createSecretBox(generateMasterKey()),
    dastPassive: async () => ({ findings: [], inventory: { pages: [], endpoints: [], forms: [], links: [] } }),
    dastCrawl: async () => ({ engine: 'builtin-get', pages: [{ url: 'https://example.com/', urlHash: 'a' }], endpoints: [], forms: [], links: [], findings: [] }),
    dastBrowser: null,
    dastNuclei: async () => ({ engine: 'nuclei', findings: [] }),
    dastAscan: async () => ({ engine: 'zap-ascan', findings: [] }),
  });
  const orig = platform.handlers.website_scan;
  const worker = createWorker({
    queue,
    handlers: {
      website_scan: async (payload, job) => {
        calls += 1;
        return orig(payload, job);
      },
    },
  });
  const res = await platform.auth.signup({ email: 'rev@example.com', name: 'O', password: PASSWORD, orgName: 'Co' });
  const ctx = { userId: res.user.id, orgId: res.orgId };
  const site = await platform.websites.create(ctx, { url: 'https://example.com' });
  const grant = await platform.websites.createAuthorization(ctx, site.id, {
    allowedProfiles: ['discovery'],
    expiresAt: future(24),
    evidenceKind: 'engagement_id',
    evidenceRef: 'ENG-REVOKED1',
  });
  const scan = platform.websites.startScan(ctx, site.id, { profile: 'discovery', authorizationId: grant.id });
  platform.websites.revokeAuthorization(ctx, site.id, grant.id, { reason: 'stopped' });
  while (await worker.runOnce());
  const done = platform.websites.getScan(ctx, site.id, scan.id);
  assert.equal(done.status, 'completed');
  assert.equal(done.summary.partial, true);
  assert.ok(done.summary.engines.some((e) => e.status === 'skipped' && /revok|grant|policy|DNS\/HTTP|authorization/i.test(e.error || '')));
  assert.ok(calls >= 1);
});

test('evaluateWebsiteAccess forbids nuclei full / ascan without active permission', () => {
  const site = { hostname: 'example.com', is_verified: 0, verification_method: null };
  const grant = {
    status: 'active',
    expiresAt: future(24),
    allowedProfiles: ['deep'],
    allowActiveTesting: false,
    allowHosts: ['example.com'],
  };
  assert.throws(() => evaluateWebsiteAccess({
    site, profile: 'deep', authorizeActiveTesting: true, grant,
  }), /active testing/);
});
