'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');

const PASSWORD = 'Correct-Horse-9';

function memoryUserStore() {
  const docs = new Map();
  return {
    docs,
    async save(doc) { docs.set(doc.email, { ...doc, orgs: (doc.orgs || []).map((o) => ({ ...o })) }); },
    async getByEmail(email) { return docs.get(String(email || '').trim().toLowerCase()) || null; },
  };
}

function setup(store) {
  const db = openDatabase(':memory:');
  const platform = createPlatform({
    db,
    queue: createQueue(db),
    secretBox: createSecretBox(generateMasterKey()),
    userStore: store,
  });
  return { db, platform };
}

test('signup stores the user in the remote store without the raw password', async () => {
  const store = memoryUserStore();
  const { platform } = setup(store);
  const r = await platform.auth.signup({
    email: 'Ada@Example.com', name: 'Ada', password: PASSWORD, orgName: 'Acme',
  });
  const doc = await store.getByEmail('ada@example.com');
  assert.ok(doc);
  assert.equal(doc.id, r.user.id);
  assert.equal(doc.email, 'ada@example.com');
  assert.equal(doc.name, 'Ada');
  assert.ok(doc.passwordHash.startsWith('scrypt$'));
  assert.ok(!JSON.stringify(doc).includes(PASSWORD));
  assert.equal(doc.orgs[0].role, 'owner');
  assert.equal(doc.orgs[0].name, 'Acme');
});

test('login restores a user from the remote store and opens a session', async () => {
  const store = memoryUserStore();
  const first = setup(store);
  const created = await first.platform.auth.signup({
    email: 'dev@example.com', name: 'Dev', password: PASSWORD, orgName: 'Acme',
  });

  const second = setup(store);
  assert.equal(second.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 0);

  const logged = await second.platform.auth.login({ email: 'dev@example.com', password: PASSWORD });
  assert.equal(logged.user.id, created.user.id);
  assert.equal(logged.user.email, 'dev@example.com');
  assert.ok(logged.token);

  const me = second.platform.auth.me(logged.user.id);
  assert.equal(me.orgs[0].name, 'Acme');
  assert.equal(me.orgs[0].role, 'owner');

  await assert.rejects(
    second.platform.auth.login({ email: 'dev@example.com', password: 'Wrong-Password-9' }),
    /Incorrect email or password/
  );
});
