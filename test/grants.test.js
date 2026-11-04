'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue, createWorker } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');
const { createServer } = require('../src/platform/api');
const { createAcaExecutor } = require('../src/platform/aca');
const { runJob } = require('../src/platform/scan-job');
const { createFinding } = require('../src/findings');

const PASSWORD = 'Correct-Horse-9';
const TOKEN = 'ghp_SuperSecretRepoToken0123456789';
const VALIDATED = { url: 'https://github.com/acme/private.git', host: 'github.com', fullName: 'acme/private', address: '140.82.112.3' };

async function build({ clock, executor } = {}) {
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const providerFetch = async (url) => ({
    ok: true, status: 200, headers: { get: () => null },
    json: async () => (String(url).endsWith('/user') ? { login: 'octocat' } : []),
  });
  const platform = createPlatform({ db, queue, secretBox: createSecretBox(generateMasterKey()), fetchImpl: providerFetch, validateUrl: async (url) => { const name = String(url).replace('https://github.com/', ''); return { ...VALIDATED, url: `https://github.com/${name}.git`, fullName: name }; }, clock, executor });
  const o = await platform.auth.signup({ email: 'o@example.com', password: PASSWORD });
  return { db, queue, platform, ctx: { userId: o.user.id, orgId: o.orgId } };
}

// Creates a private repo (with a connection holding TOKEN) and a scan in the given status.
async function scanWith(b, status = 'running', name = 'private') {
  const conn = b.conn || (b.conn = await b.platform.connections.connect(b.ctx, { provider: 'github', token: TOKEN }));
  const repo = await b.platform.repos.add(b.ctx, { url: `https://github.com/acme/${name}`, connectionId: conn.id });
  const scan = b.platform.scans.start(b.ctx, repo.id);
  b.db.prepare('UPDATE scans SET status = ? WHERE id = ?').run(status, scan.id);
  return { scan, repo };
}

const AUTH = { username: 'x-access-token', token: TOKEN };

test('a grant yields the credential exactly once; a replay is refused and audited', async () => {
  const b = await build();
  const { scan } = await scanWith(b);
  const secret = b.platform.grants.issue(scan.id, b.ctx.orgId, AUTH);
  assert.ok(secret.length >= 40);
  assert.deepEqual(b.platform.grants.redeem(scan.id, secret, '10.0.0.9'), AUTH);
  assert.throws(() => b.platform.grants.redeem(scan.id, secret, '203.0.113.7'), /Invalid or expired grant/);
  const events = (await b.platform.audit.list(b.ctx)).map((e) => e.action);
  assert.ok(events.includes('scan.grant_used'));
  const denied = b.db.prepare("SELECT detail, ip FROM audit_logs WHERE action = 'scan.grant_denied'").all();
  assert.equal(denied.length, 1);
  assert.match(denied[0].detail, /already used/);
  assert.equal(denied[0].ip, '203.0.113.7', 'the replaying address is recorded');
});

test('every failure looks identical to the caller', async () => {
  const b = await build();
  const { scan } = await scanWith(b);
  const secret = b.platform.grants.issue(scan.id, b.ctx.orgId, AUTH);
  const attempts = [
    () => b.platform.grants.redeem(scan.id, 'x'.repeat(43)),
    () => b.platform.grants.redeem('no-such-scan', secret),
    () => b.platform.grants.redeem(scan.id, 'short'),
    () => b.platform.grants.redeem(scan.id, undefined),
    () => b.platform.grants.redeem(undefined, secret),
    () => b.platform.grants.redeem({ $ne: 1 }, { $ne: 1 }),
  ];
  for (const attempt of attempts) assert.throws(attempt, (e) => e.message === 'Invalid or expired grant' && e.status === 403);
  assert.deepEqual(b.platform.grants.redeem(scan.id, secret), AUTH, 'bad attempts do not burn the real grant');
});

test('a grant expires, and only works while its scan is running', async () => {
  let t = Date.now();
  const b = await build({ clock: () => t });
  const { scan } = await scanWith(b);
  const secret = b.platform.grants.issue(scan.id, b.ctx.orgId, AUTH);
  t += 11 * 60 * 1000;
  assert.throws(() => b.platform.grants.redeem(scan.id, secret), /Invalid or expired/);

  const fresh = await build();
  const { scan: queued } = await scanWith(fresh, 'queued');
  const s2 = fresh.platform.grants.issue(queued.id, fresh.ctx.orgId, AUTH);
  assert.throws(() => fresh.platform.grants.redeem(queued.id, s2), /Invalid or expired/, 'not running yet');
  fresh.db.prepare("UPDATE scans SET status = 'completed' WHERE id = ?").run(queued.id);
  assert.throws(() => fresh.platform.grants.redeem(queued.id, s2), /Invalid or expired/, 'already finished');
});

test('the credential is encrypted at rest and a grant secret works only for its own scan', async () => {
  const b = await build();
  const { scan } = await scanWith(b, 'running', 'repo-a');
  const { scan: other } = await scanWith(b, 'running', 'repo-b');
  const secret = b.platform.grants.issue(scan.id, b.ctx.orgId, AUTH);
  b.platform.grants.issue(other.id, b.ctx.orgId, { username: 'u', token: 'other-token' });

  const row = b.db.prepare('SELECT * FROM scan_grants WHERE scan_id = ?').get(scan.id);
  assert.ok(!JSON.stringify(row).includes(TOKEN), 'token is not stored in clear');
  assert.ok(!JSON.stringify(row).includes(secret), 'the secret itself is not stored, only its hash');
  assert.throws(() => b.platform.grants.redeem(other.id, secret), /Invalid or expired/, 'the secret for scan A cannot redeem scan B');
  assert.deepEqual(b.platform.grants.redeem(scan.id, secret), AUTH);
});

test('HTTP endpoint: public, rate limited, returns the credential once, no-store', async (t) => {
  const b = await build();
  const { scan } = await scanWith(b);
  const server = createServer({ platform: b.platform });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (body) => fetch(`${base}/api/v1/internal/scan-grant`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

  const secret = b.platform.grants.issue(scan.id, b.ctx.orgId, AUTH);
  const ok = await post({ scanId: scan.id, secret });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await ok.json(), AUTH);
  assert.equal((await post({ scanId: scan.id, secret })).status, 403, 'replay');
  assert.equal((await post({ scanId: scan.id, secret: 'y'.repeat(43) })).status, 403);
  assert.equal((await post({})).status, 403);

  let limited = 0;
  for (let i = 0; i < 70; i++) if ((await post({ scanId: scan.id, secret: 'z'.repeat(43) })).status === 429) limited++;
  assert.ok(limited > 0, 'brute-force attempts are rate limited');
});

test('private repo round trip through the Azure executor: the start request never contains the token', async (t) => {
  const startRequests = [];
  const blobs = new Map();
  let cloneAuth;
  let base;
  let executorRef;
  const b = await build({ executor: (args) => executorRef(args) });
  const server = createServer({ platform: b.platform });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  base = `http://127.0.0.1:${server.address().port}`;

  // A fake Azure; the job it "starts" is the real job code, talking to the real API over HTTP for its grant.
  const fetchImpl = async (url, init = {}) => {
    url = String(url);
    const json = (status, body) => ({ ok: status < 300, status, json: async () => body });
    if (url.startsWith('https://vulnsight.example.test')) return fetch(url.replace('https://vulnsight.example.test', base), init);
    if (url.includes('/start')) {
      startRequests.push(init.body);
      const env = Object.fromEntries(JSON.parse(init.body).template.containers[0].env.map((e) => [e.name, e.value]));
      await runJob({
        env, fetchImpl, identity: async () => 'tok', validate: async () => VALIDATED, log: () => {},
        clone: async (v, o) => { cloneAuth = o.auth; return { dir: '/tmp/x', commit: 'abc', cleanup() {} }; },
        pipeline: async () => ({
          scanners: [{ scanner: 'osv', status: 'ok', findingCount: 1 }], raw: {}, target: {},
          findings: [createFinding({ category: 'sca', scanner: { name: 'osv' }, title: 'P', severity: 'high', identifiers: { primary: 'GHSA-9' }, location: { file: 'package-lock.json', package: 'lodash', version: '1.0.0', ecosystem: 'npm' } })],
        }),
      });
      return json(200, { name: 'exec-1' });
    }
    if (url.includes('/executions/')) return json(200, { properties: { status: 'Succeeded' } });
    if (url.includes('.blob.core.windows.net')) {
      if (init.method === 'PUT') { blobs.set(url, init.body); return { ok: true, status: 201 }; }
      if (init.method === 'DELETE') { blobs.delete(url); return { ok: true, status: 202 }; }
      return json(200, JSON.parse(blobs.get(url)));
    }
    throw new Error(`unexpected ${url}`);
  };
  executorRef = createAcaExecutor({
    subscriptionId: 'sub', resourceGroup: 'rg', jobName: 'job', image: 'img', storageAccount: 'acct',
    getToken: async () => 't', fetchImpl, sleep: async () => {}, grantUrl: 'https://vulnsight.example.test',
  });

  const { scan } = await scanWith(b, 'queued', 'private-app');
  const worker = createWorker({ queue: b.queue, handlers: b.platform.handlers });
  while (await worker.runOnce());

  assert.equal(b.platform.scans.get(b.ctx, scan.id).status, 'completed');
  assert.deepEqual(cloneAuth, AUTH, 'the job got the credential through the grant exchange');
  assert.equal(startRequests.length, 1);
  assert.ok(!startRequests[0].includes(TOKEN), 'the job-start request does not contain the token');
  assert.ok(!startRequests[0].includes('ghp_'), 'nor any token-shaped value');
  assert.match(startRequests[0], /VS_GRANT_SECRET/);
  const grantSecret = JSON.parse(startRequests[0]).template.containers[0].env.find((e) => e.name === 'VS_GRANT_SECRET').value;
  assert.equal(b.db.prepare('SELECT COUNT(*) AS n FROM scan_grants').get().n, 0, 'the grant is deleted when the scan ends');
  assert.throws(() => b.platform.grants.redeem(scan.id, grantSecret), /Invalid or expired/, 'the secret from the (still readable) request is now useless');
});
