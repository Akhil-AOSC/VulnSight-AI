'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');
const ops = require('../src/platform/ops');

const PASSWORD = 'Correct-Horse-9';

// A populated database on disk: a user, an org, a connected provider (encrypted token), a repo and a completed scan.
async function populated(dir, key) {
  const file = path.join(dir, 'vulnsight.db');
  const db = openDatabase(file);
  const box = createSecretBox(key);
  const providerFetch = async (url) => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => (String(url).endsWith('/user') ? { login: 'octocat' } : []) });
  const platform = createPlatform({
    db, queue: createQueue(db), secretBox: box, fetchImpl: providerFetch,
    validateUrl: async (u) => ({ url: `${u}.git`, host: 'github.com', fullName: String(u).replace('https://github.com/', ''), address: '140.82.112.3' }),
  });
  const o = await platform.auth.signup({ email: 'owner@example.com', password: PASSWORD, orgName: 'Acme' });
  const ctx = { userId: o.user.id, orgId: o.orgId };
  const conn = await platform.connections.connect(ctx, { provider: 'github', token: 'ghp_BackupTestToken123456' });
  const repo = await platform.repos.add(ctx, { url: 'https://github.com/acme/app', connectionId: conn.id });
  db.prepare("INSERT INTO scans (id, org_id, repo_id, branch, trigger, status, created_at) VALUES ('scan1', ?, ?, 'main', 'manual', 'completed', ?)").run(ctx.orgId, repo.id, new Date().toISOString());
  db.prepare("INSERT INTO findings (id, scan_id, org_id, repo_id, fingerprint, severity, category, data) VALUES ('f1', 'scan1', ?, ?, 'fp1', 'high', 'sca', '{}')").run(ctx.orgId, repo.id);
  db.close();
  return { file, ctx, token: o.token, repoId: repo.id };
}

const tmp = (t) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-ops-')); t.after(() => fs.rmSync(d, { recursive: true, force: true })); return d; };

test('RECOVERY DRILL: back up, destroy the database, restore, and prove the platform works again', async (t) => {
  const dir = tmp(t);
  const key = generateMasterKey();
  const { file, ctx } = await populated(dir, key);

  const backupFile = path.join(dir, 'backups', 'daily.db');
  const info = ops.backup(file, backupFile);
  assert.deepEqual([info.users, info.orgs, info.repositories, info.scans, info.findings], [1, 1, 1, 1, 1]);
  assert.throws(() => ops.backup(file, backupFile), /Refusing to overwrite/);

  // Disaster: the database is lost.
  for (const f of fs.readdirSync(dir)) if (f.startsWith('vulnsight.db')) fs.rmSync(path.join(dir, f));
  assert.equal(fs.existsSync(file), false);

  const r = ops.restore(backupFile, file);
  assert.equal(r.keptAside, null);
  assert.equal(r.restored.users, 1);

  // The restored platform works: login, data present, and the stored provider token still decrypts with the SAME key.
  const db = openDatabase(file);
  const platform = createPlatform({ db, queue: createQueue(db), secretBox: createSecretBox(key) });
  assert.ok((await platform.auth.login({ email: 'owner@example.com', password: PASSWORD })).token);
  assert.equal((await platform.repos.list(ctx)).length, 1);
  assert.equal((await platform.dashboard.overview(ctx)).repositories.length, 1);
  const enc = db.prepare('SELECT token_enc FROM provider_connections').get().token_enc;
  assert.equal(createSecretBox(key).decrypt(enc), 'ghp_BackupTestToken123456');
  // ...and WITHOUT the master key the backup alone cannot reveal provider tokens.
  assert.throws(() => createSecretBox(generateMasterKey()).decrypt(enc));
  db.close();
});

test('restore keeps the existing database aside and refuses corrupt or foreign files', async (t) => {
  const dir = tmp(t);
  const { file } = await populated(dir, generateMasterKey());
  const good = path.join(dir, 'good.db');
  ops.backup(file, good);

  const garbage = path.join(dir, 'garbage.db');
  fs.writeFileSync(garbage, 'this is not a database');
  assert.throws(() => ops.restore(garbage, file));
  const foreign = path.join(dir, 'foreign.db');
  const { DatabaseSync } = require('node:sqlite');
  const other = new DatabaseSync(foreign); other.exec('CREATE TABLE x (a)'); other.close();
  assert.throws(() => ops.verify(foreign));
  assert.ok(fs.existsSync(file), 'a failed restore leaves the live database untouched');

  const r = ops.restore(good, file);
  assert.ok(r.keptAside && fs.existsSync(r.keptAside), 'the previous database is kept, never deleted');
});

test('INCIDENT DRILL: master key rotation moves every secret, atomically, and the old key stops working', async (t) => {
  const dir = tmp(t);
  const oldKey = generateMasterKey();
  const newKey = generateMasterKey();
  const { file, ctx, repoId } = await populated(dir, oldKey);

  const db0 = openDatabase(file);
  const grantRepo = db0.prepare("INSERT INTO scan_grants (scan_id, org_id, secret_hash, payload_enc, expires_at) VALUES ('scan1', ?, 'h', ?, ?)");
  grantRepo.run(ctx.orgId, createSecretBox(oldKey).encrypt('{"token":"x"}'), new Date(Date.now() + 1000).toISOString());
  const before = db0.prepare('SELECT token_enc FROM provider_connections').get().token_enc;
  db0.close();

  const { rotated } = ops.rotateMasterKey(file, oldKey, newKey);
  assert.equal(rotated, 3, 'provider token + webhook secret + pending grant');

  const db = openDatabase(file);
  const after = db.prepare('SELECT token_enc FROM provider_connections').get().token_enc;
  assert.notEqual(after, before);
  assert.equal(createSecretBox(newKey).decrypt(after), 'ghp_BackupTestToken123456');
  assert.throws(() => createSecretBox(oldKey).decrypt(after), 'the old key no longer opens anything');
  const platform = createPlatform({ db, queue: createQueue(db), secretBox: createSecretBox(newKey) });
  assert.equal(platform.repos.webhookSecret(ctx, repoId).length > 10, true, 'webhook secrets still decrypt under the new key');
  db.close();

  // Wrong old key: nothing changes (atomic).
  assert.throws(() => ops.rotateMasterKey(file, generateMasterKey(), generateMasterKey()));
  const db2 = openDatabase(file);
  assert.equal(createSecretBox(newKey).decrypt(db2.prepare('SELECT token_enc FROM provider_connections').get().token_enc), 'ghp_BackupTestToken123456');
  db2.close();
});

test('INCIDENT DRILL: disabling an account and revoking sessions takes effect immediately', async (t) => {
  const dir = tmp(t);
  const key = generateMasterKey();
  const { file, token } = await populated(dir, key);

  let db = openDatabase(file);
  let platform = createPlatform({ db, queue: createQueue(db), secretBox: createSecretBox(key) });
  assert.ok(platform.auth.authenticate(token), 'session works before the incident');
  db.close();

  assert.throws(() => ops.disableUser(file, 'nobody@example.com'), /No such user/);
  ops.disableUser(file, 'OWNER@example.com');

  db = openDatabase(file);
  platform = createPlatform({ db, queue: createQueue(db), secretBox: createSecretBox(key) });
  assert.throws(() => platform.auth.authenticate(token), /expired|required/i, 'the existing session is dead');
  await assert.rejects(() => platform.auth.login({ email: 'owner@example.com', password: PASSWORD }), /Incorrect email or password/, 'and they cannot log in again');
  db.close();

  const other = openDatabase(file);
  other.prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) SELECT 'abc', id, 'x', '2999-01-01' FROM users LIMIT 1").run();
  other.close();
  assert.ok(ops.revokeAllSessions(file).revoked >= 1);
});
