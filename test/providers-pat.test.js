'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');
const { PROVIDERS } = require('../src/platform/providers');

function setup(opts = {}) {
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const platform = createPlatform({
    db,
    queue,
    secretBox: createSecretBox(generateMasterKey()),
    validateUrl: async (url) => ({ url, host: 'github.com', fullName: 'acme/repo', address: '140.82.112.3' }),
    fetchImpl: opts.fetchImpl,
  });
  return { db, platform };
}

async function signup(platform, email = 'dev@example.com') {
  const r = await platform.auth.signup({ email, name: 'Dev', password: 'Correct-Horse-9', orgName: 'Acme' });
  return { ...r, ctx: { userId: r.user.id, orgId: r.orgId } };
}

test('github.validate parses expiration header and scopes properly', async () => {
  const fetchImpl = async (url) => {
    return {
      ok: true,
      status: 200,
      headers: {
        get: (h) => {
          if (h === 'github-authentication-token-expiration') return '2026-12-31 23:59:59 UTC';
          if (h === 'x-oauth-scopes') return 'repo, read:org';
          return null;
        },
      },
      json: async () => ({ login: 'octocat' }),
    };
  };

  const res = await PROVIDERS.github.validate('ghp_testtoken12345', fetchImpl);
  assert.equal(res.account, 'octocat');
  assert.equal(res.expiresAt, '2026-12-31T23:59:59.000Z');
  assert.equal(res.scopes, 'repo, read:org');
});

test('github.validate handles classic token without expiration header', async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => ({ login: 'octocat' }),
  });

  const res = await PROVIDERS.github.validate('ghp_noexpiration', fetchImpl);
  assert.equal(res.account, 'octocat');
  assert.equal(res.expiresAt, null);
  assert.equal(res.scopes, null);
});

test('github.validate throws descriptive error on 401 Bad credentials', async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 401,
    headers: { get: () => null },
    json: async () => ({ message: 'Bad credentials' }),
  });

  await assert.rejects(
    PROVIDERS.github.validate('ghp_expiredtoken', fetchImpl),
    /Invalid, expired, or revoked Personal Access Token/
  );
});

test('connections.connect stores expires_at and scopes in DB and returns them', async () => {
  const fetchImpl = async () => {
    return {
      ok: true,
      status: 200,
      headers: {
        get: (h) => (h === 'github-authentication-token-expiration' ? '2030-01-01 00:00:00 UTC' : 'repo'),
      },
      json: async () => ({ login: 'octocat' }),
    };
  };

  const { db, platform } = setup({ fetchImpl });
  const o = await signup(platform);

  const conn = await platform.connections.connect(o.ctx, {
    provider: 'github',
    token: 'ghp_validpat123456',
    label: 'My GitHub PAT',
  });

  assert.equal(conn.account, 'octocat');
  assert.equal(conn.expiresAt, '2030-01-01T00:00:00.000Z');
  assert.equal(conn.scopes, 'repo');

  // Verify stored row in database
  const row = db.prepare('SELECT expires_at, scopes FROM provider_connections WHERE id = ?').get(conn.id);
  assert.equal(row.expires_at, '2030-01-01T00:00:00.000Z');
  assert.equal(row.scopes, 'repo');

  // Verify list returns expiration status
  const list = platform.connections.list(o.ctx);
  assert.equal(list[0].isExpired, false);
  assert.ok(list[0].daysLeft > 100);
});

test('connections.list correctly identifies expired tokens', async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    headers: {
      get: (h) => (h === 'github-authentication-token-expiration' ? '2020-01-01 00:00:00 UTC' : null),
    },
    json: async () => ({ login: 'octocat' }),
  });

  const { platform } = setup({ fetchImpl });
  const o = await signup(platform);

  await platform.connections.connect(o.ctx, {
    provider: 'github',
    token: 'ghp_pastpat123456',
  });

  const list = platform.connections.list(o.ctx);
  assert.equal(list[0].isExpired, true);
  assert.equal(list[0].daysLeft, null);
});

test('connections.check performs live token verification and updates DB', async () => {
  let expiry = '2028-05-01 00:00:00 UTC';
  let shouldFail = false;

  const fetchImpl = async () => {
    if (shouldFail) {
      return { ok: false, status: 401, headers: { get: () => null }, json: async () => ({ message: 'Bad credentials' }) };
    }
    return {
      ok: true,
      status: 200,
      headers: { get: (h) => (h === 'github-authentication-token-expiration' ? expiry : 'repo') },
      json: async () => ({ login: 'octocat' }),
    };
  };

  const { db, platform } = setup({ fetchImpl });
  const o = await signup(platform);

  const conn = await platform.connections.connect(o.ctx, { provider: 'github', token: 'ghp_validpat123456' });

  // Update expiry on GitHub and test live re-check
  expiry = '2029-12-31 23:59:59 UTC';
  const checkResult = await platform.connections.check(o.ctx, conn.id);

  assert.equal(checkResult.valid, true);
  assert.equal(checkResult.expiresAt, '2029-12-31T23:59:59.000Z');

  // Check updated DB
  const row = db.prepare('SELECT expires_at FROM provider_connections WHERE id = ?').get(conn.id);
  assert.equal(row.expires_at, '2029-12-31T23:59:59.000Z');

  // Now simulate token revoked on GitHub
  shouldFail = true;
  const failResult = await platform.connections.check(o.ctx, conn.id);
  assert.equal(failResult.valid, false);
  assert.ok(failResult.error.includes('rejected'));
});

test('github.listRepos paginates to fetch accessible repositories', async () => {
  const fetchImpl = async (url) => {
    const pageMatch = url.match(/[?&]page=(\d+)/);
    const page = pageMatch ? parseInt(pageMatch[1], 10) : 1;
    if (page === 1) {
      // Return 100 repositories for page 1
      const repos = Array.from({ length: 100 }, (_, i) => ({
        full_name: `octocat/repo-${i + 1}`,
        default_branch: 'main',
        private: i % 2 === 0,
      }));
      return { ok: true, status: 200, json: async () => repos };
    }
    if (page === 2) {
      // Return 25 repositories for page 2 (terminates pagination)
      const repos = Array.from({ length: 25 }, (_, i) => ({
        full_name: `octocat/repo-${100 + i + 1}`,
        default_branch: 'main',
        private: false,
      }));
      return { ok: true, status: 200, json: async () => repos };
    }
    return { ok: true, status: 200, json: async () => [] };
  };

  const repos = await PROVIDERS.github.listRepos('ghp_tok', fetchImpl);
  assert.equal(repos.length, 125);
  assert.equal(repos[0].fullName, 'octocat/repo-1');
  assert.equal(repos[124].fullName, 'octocat/repo-125');
});
