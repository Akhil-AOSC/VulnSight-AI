'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');

function memoryGitPatStore() {
  const docs = new Map();
  const key = (orgId, id) => `${orgId}:${id}`;
  return {
    docs,
    async save(doc) { docs.set(key(doc.orgId, doc.id), { ...doc }); },
    async get(orgId, id) { return docs.get(key(orgId, id)) || null; },
    async remove(orgId, id) { docs.delete(key(orgId, id)); },
    async list(orgId) { return [...docs.values()].filter((d) => d.orgId === orgId); },
  };
}

function memoryUserStore() {
  const docs = new Map();
  return {
    docs,
    async save(doc) { docs.set(doc.email, { ...doc, orgs: (doc.orgs || []).map((o) => ({ ...o })) }); },
    async getByEmail(email) { return docs.get(String(email || '').trim().toLowerCase()) || null; },
  };
}

function setup({ gitPatStore, userStore } = {}) {
  const db = openDatabase(':memory:');
  const secretBox = createSecretBox(generateMasterKey());
  const platform = createPlatform({
    db,
    queue: createQueue(db),
    secretBox,
    gitPatStore,
    userStore,
    fetchImpl: async (url) => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => (String(url).includes('/user/repos')
        ? [{ full_name: 'acme/app', default_branch: 'main', private: true }]
        : { login: 'octocat' }),
    }),
  });
  return { db, platform, secretBox };
}

test('each Git PAT is stored encrypted in the Git connection store and read back for API use', async () => {
  const store = memoryGitPatStore();
  const { platform } = setup({ gitPatStore: store });
  const r = await platform.auth.signup({ email: 'pat@example.com', name: 'Dev', password: 'Correct-Horse-9', orgName: 'Acme' });
  const ctx = { userId: r.user.id, orgId: r.orgId };

  const first = await platform.connections.connect(ctx, { provider: 'github', token: 'ghp_firstaccounttoken1', label: 'work' });
  const second = await platform.connections.connect(ctx, { provider: 'github', token: 'ghp_secondaccounttoken2', label: 'personal' });

  assert.equal(store.docs.size, 2);
  const work = await store.get(ctx.orgId, first.id);
  const personal = await store.get(ctx.orgId, second.id);
  assert.equal(work.provider, 'github');
  assert.equal(work.account, 'octocat');
  assert.ok(!JSON.stringify(work).includes('ghp_'));
  assert.ok(work.tokenEnc);
  assert.ok(personal.tokenEnc);

  const repos = await platform.connections.listRemoteRepos(ctx, first.id);
  assert.equal(repos[0].fullName, 'acme/app');

  await platform.connections.remove(ctx, first.id);
  assert.equal(await store.get(ctx.orgId, first.id), null);
  assert.ok(await store.get(ctx.orgId, second.id));
});

test('git connections follow the same login onto a new machine', async () => {
  const gitPatStore = memoryGitPatStore();
  const userStore = memoryUserStore();
  const first = setup({ gitPatStore, userStore });
  const created = await first.platform.auth.signup({
    email: 'shared@example.com', name: 'Dev', password: 'Correct-Horse-9', orgName: 'Acme',
  });
  const ctx = { userId: created.user.id, orgId: created.orgId };
  await first.platform.connections.connect(ctx, { provider: 'github', token: 'ghp_worktokenvalue1', label: 'work' });
  await first.platform.connections.connect(ctx, { provider: 'github', token: 'ghp_hometokenvalue2', label: 'personal' });

  const second = setup({ gitPatStore, userStore });
  assert.equal(second.db.prepare('SELECT COUNT(*) AS n FROM provider_connections').get().n, 0);

  const logged = await second.platform.auth.login({ email: 'shared@example.com', password: 'Correct-Horse-9' });
  const otherCtx = { userId: logged.user.id, orgId: created.orgId };
  const list = await second.platform.connections.list(otherCtx);
  assert.equal(list.length, 2);
  assert.deepEqual(list.map((c) => c.account).sort(), ['octocat', 'octocat']);
  assert.ok(!JSON.stringify(list).includes('ghp_'));

  const repos = await second.platform.connections.listRemoteRepos(otherCtx, list[0].id);
  assert.equal(repos[0].fullName, 'acme/app');
});
