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
  };
}

function setup(store) {
  const db = openDatabase(':memory:');
  const secretBox = createSecretBox(generateMasterKey());
  const platform = createPlatform({
    db,
    queue: createQueue(db),
    secretBox,
    gitPatStore: store,
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
  const { platform, secretBox } = setup(store);
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
  assert.equal(secretBox.decrypt(work.tokenEnc), 'ghp_firstaccounttoken1');
  assert.equal(secretBox.decrypt(personal.tokenEnc), 'ghp_secondaccounttoken2');

  const repos = await platform.connections.listRemoteRepos(ctx, first.id);
  assert.equal(repos[0].fullName, 'acme/app');

  await platform.connections.remove(ctx, first.id);
  assert.equal(await store.get(ctx.orgId, first.id), null);
  assert.ok(await store.get(ctx.orgId, second.id));
});
