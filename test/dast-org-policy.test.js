'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');
const {
  validatePolicyInput,
  isHostWithinApprovedScope,
  isAuthorizationExpired,
  isAuthorizationRevoked,
  evaluateScanAuthorization,
} = require('../src/platform/authorization-policy');

const PASSWORD = 'Correct-Horse-9';

function future(hours) {
  return new Date(Date.now() + hours * 3600 * 1000).toISOString();
}

function setup() {
  const db = openDatabase(':memory:');
  const platform = createPlatform({
    db,
    queue: createQueue(db),
    secretBox: createSecretBox(generateMasterKey()),
    dastPassive: async () => ({ findings: [], inventory: { pages: [], endpoints: [], forms: [], links: [] } }),
    dastCrawl: async () => ({ engine: 'builtin-get', pages: [], endpoints: [], forms: [], links: [], findings: [] }),
    dastBrowser: null,
    dastNuclei: null,
    dastAscan: null,
  });
  return { db, platform };
}

test('lab policies reject wildcards; engagement accepts a concrete parent host', () => {
  const base = {
    allowedProfiles: ['discovery', 'standard'],
    expiresAt: future(24),
    evidenceKind: 'engagement_id',
    evidenceRef: 'ENG-ORG-0001',
    allowHosts: ['*.example.com'],
  };
  assert.match(validatePolicyInput({ ...base, kind: 'lab' }), /explicit hostnames/);
  assert.equal(validatePolicyInput({ ...base, kind: 'engagement' }), null);
  assert.match(validatePolicyInput({
    ...base,
    kind: 'lab',
    allowHosts: ['staging.example.com'],
    evidenceRef: 'ok',
  }), /evidenceRef|identifier|Self-attestation/);
  assert.equal(validatePolicyInput({
    ...base,
    kind: 'lab',
    allowHosts: ['staging.example.com'],
  }), null);

  const lab = { kind: 'lab', allowHosts: ['staging.example.com'], denyHosts: [] };
  assert.equal(isHostWithinApprovedScope(lab, 'staging.example.com'), true);
  assert.equal(isHostWithinApprovedScope(lab, 'other.example.com'), false);

  const eng = { kind: 'engagement', allowHosts: ['example.com'], denyHosts: ['evil.example.com'] };
  assert.equal(isHostWithinApprovedScope(eng, 'shop.example.com'), true);
  assert.equal(isHostWithinApprovedScope(eng, 'evil.example.com'), false);
});

test('org engagement policy CRUD, expiry and revoke', async () => {
  const { platform } = setup();
  const res = await platform.auth.signup({ email: 'pol@example.com', name: 'O', password: PASSWORD, orgName: 'Co' });
  const ctx = { userId: res.user.id, orgId: res.orgId };
  const created = platform.dastPolicies.create(ctx, {
    kind: 'engagement',
    allowedProfiles: ['discovery', 'standard', 'deep'],
    allowActiveTesting: true,
    expiresAt: future(48),
    evidenceKind: 'engagement_id',
    evidenceRef: 'ENG-ORG-99881',
    allowHosts: ['example.com'],
    denyHosts: ['payroll.example.com'],
  });
  assert.equal(created.status, 'active');
  assert.equal(created.kind, 'engagement');
  assert.equal(platform.dastPolicies.list(ctx).length, 1);

  const revoked = platform.dastPolicies.revoke(ctx, created.id, { reason: 'ended' });
  assert.equal(revoked.status, 'revoked');
  assert.equal(isAuthorizationRevoked(revoked), true);
  assert.equal(isAuthorizationExpired({ expiresAt: new Date(Date.now() - 1000).toISOString() }), true);
});

test('evaluateScanAuthorization: deny overrides allow, deep needs stored active permission', () => {
  const site = { hostname: 'app.example.com', target_url: 'https://app.example.com/app' };
  const policy = {
    kind: 'engagement',
    status: 'active',
    startsAt: future(-1),
    expiresAt: future(24),
    allowedProfiles: ['discovery', 'standard', 'deep'],
    allowActiveTesting: false,
    allowHosts: ['example.com'],
    denyHosts: [],
    allowPaths: ['/'],
    denyPaths: ['/admin'],
    ports: [443],
  };
  const access = evaluateScanAuthorization({ site, profile: 'standard', orgPolicies: [policy] });
  assert.equal(access.allowed, true);
  assert.equal(access.source, 'org_engagement');
  assert.equal(access.allowActive, false);

  assert.throws(() => evaluateScanAuthorization({
    site, profile: 'deep', orgPolicies: [policy],
  }), /allowActiveTesting/);

  assert.throws(() => evaluateScanAuthorization({
    site: { hostname: 'app.example.com', target_url: 'https://app.example.com/admin' },
    profile: 'standard',
    orgPolicies: [policy],
  }), /denied/);

  const deniedHost = { ...policy, denyHosts: ['app.example.com'] };
  assert.throws(() => evaluateScanAuthorization({
    site, profile: 'standard', orgPolicies: [deniedHost],
  }), /denied/);
});

test('org engagement covers a new website without a per-site grant or per-scan confirm', async () => {
  const { platform } = setup();
  const res = await platform.auth.signup({ email: 'reuse@example.com', name: 'O', password: PASSWORD, orgName: 'Co' });
  const ctx = { userId: res.user.id, orgId: res.orgId };
  platform.dastPolicies.create(ctx, {
    kind: 'engagement',
    allowedProfiles: ['discovery', 'standard', 'deep'],
    allowActiveTesting: true,
    expiresAt: future(48),
    evidenceKind: 'engagement_id',
    evidenceRef: 'ENG-REUSE-1',
    allowHosts: ['example.com'],
  });
  const site = await platform.websites.create(ctx, { url: 'https://example.com', name: 'Shop' });
  const listed = await platform.websites.list(ctx);
  assert.equal(listed[0].authorization.status, 'authorized');
  const scan = platform.websites.startScan(ctx, site.id, { profile: 'standard' });
  assert.equal(scan.profile, 'standard');
  const deep = platform.websites.startScan(ctx, site.id, { profile: 'deep' });
  assert.equal(deep.authorizeActiveTesting, true);
});

test('lab allowlist does not cover sibling hosts; expired policy does not grant', () => {
  const site = { hostname: 'lab.example.com', target_url: 'https://lab.example.com/' };
  const lab = {
    kind: 'lab',
    status: 'active',
    expiresAt: future(24),
    allowedProfiles: ['standard'],
    allowActiveTesting: false,
    allowHosts: ['lab.example.com'],
    denyHosts: [],
    allowPaths: ['/'],
    denyPaths: [],
    ports: [443],
  };
  assert.equal(evaluateScanAuthorization({ site, profile: 'standard', orgPolicies: [lab] }).source, 'lab');
  assert.throws(() => evaluateScanAuthorization({
    site: { hostname: 'other.example.com', target_url: 'https://other.example.com/' },
    profile: 'standard',
    orgPolicies: [lab],
  }), /engagement policy|lab allowlist|DNS\/HTTP/);
  assert.throws(() => evaluateScanAuthorization({
    site,
    profile: 'standard',
    orgPolicies: [{ ...lab, expiresAt: new Date(Date.now() - 5000).toISOString(), status: 'expired' }],
  }), /engagement policy|lab allowlist|DNS\/HTTP/);
});
