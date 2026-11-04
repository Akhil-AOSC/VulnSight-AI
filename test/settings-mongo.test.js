'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');

function memoryUserStore() {
  const docs = new Map();
  return {
    async save(doc) { docs.set(doc.email, JSON.parse(JSON.stringify(doc))); },
    async getByEmail(email) { return docs.get(String(email || '').trim().toLowerCase()) || null; },
  };
}

function memoryOrgSync() {
  const orgs = new Map();
  const teams = new Map();
  const notes = new Map();
  const audits = new Map();
  const key = (orgId, id) => `${orgId}:${id}`;
  return {
    async saveOrg(doc) { orgs.set(doc.id, JSON.parse(JSON.stringify(doc))); },
    async getOrg(id) { return orgs.get(id) || null; },
    async removeOrg(id) { orgs.delete(id); },
    async saveTeam(doc) { teams.set(key(doc.orgId, doc.id), JSON.parse(JSON.stringify(doc))); },
    async listTeams(orgId) { return [...teams.values()].filter((t) => t.orgId === orgId); },
    async removeTeam(orgId, id) { teams.delete(key(orgId, id)); },
    async saveNotification(doc) { notes.set(key(doc.orgId, doc.id), JSON.parse(JSON.stringify(doc))); },
    async listNotifications(orgId) { return [...notes.values()].filter((n) => n.orgId === orgId); },
    async saveAudit(doc) { audits.set(key(doc.orgId, doc.id), JSON.parse(JSON.stringify(doc))); },
    async listAudits(orgId) { return [...audits.values()].filter((a) => a.orgId === orgId); },
  };
}

function setup(stores) {
  const db = openDatabase(':memory:');
  const platform = createPlatform({
    db,
    queue: createQueue(db),
    secretBox: createSecretBox(generateMasterKey()),
    ...stores,
  });
  return { db, platform };
}

test('org settings, teams, theme, notifications and audit follow the same login', async () => {
  const userStore = memoryUserStore();
  const orgSyncStore = memoryOrgSync();
  const first = setup({ userStore, orgSyncStore });
  const created = await first.platform.auth.signup({
    email: 'sync@example.com', name: 'Dev', password: 'Correct-Horse-9', orgName: 'Acme',
  });
  const ctx = { userId: created.user.id, orgId: created.orgId };

  await first.platform.orgs.updateSettings(ctx, { aiEnabled: true, retentionDays: 45 });
  await first.platform.orgs.rename(ctx, 'Acme West');
  await first.platform.auth.setTheme(created.user.id, 'dark');
  const team = await first.platform.teams.create(ctx, { name: 'Platform' });
  await first.platform.teams.addMember(ctx, team.id, created.user.id);
  first.db.prepare('INSERT INTO notifications (id, org_id, user_id, kind, title, body, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run('n1', created.orgId, created.user.id, 'findings.new', 'New finding', 'demo', new Date().toISOString());
  await first.platform.notifications.markRead(ctx, null);

  const second = setup({ userStore, orgSyncStore });
  const logged = await second.platform.auth.login({ email: 'sync@example.com', password: 'Correct-Horse-9' });
  const other = { userId: logged.user.id, orgId: created.orgId };

  const settings = await second.platform.orgs.getSettings(other);
  assert.equal(settings.aiEnabled, true);
  assert.equal(settings.retentionDays, 45);
  assert.equal((await second.platform.auth.me(logged.user.id)).theme, 'dark');
  const teams = await second.platform.teams.list(other);
  assert.equal(teams.length, 1);
  assert.equal(teams[0].name, 'Platform');
  const notes = await second.platform.notifications.list(other);
  assert.ok(notes.some((n) => n.kind === 'findings.new' && n.read));
  const audit = await second.platform.audit.list(other);
  assert.ok(audit.some((e) => e.action === 'org.settings'));
  assert.ok(audit.some((e) => e.action === 'org.rename'));

  await first.platform.teams.delete(ctx, team.id);
  assert.equal((await second.platform.teams.list(other)).length, 0);
});
