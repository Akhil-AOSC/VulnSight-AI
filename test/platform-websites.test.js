'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startPlatform } = require('../src/platform/app');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue, createWorker } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');

const PASSWORD = 'Correct-Horse-9';

function setupPlatform() {
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const platform = createPlatform({
    db,
    queue,
    secretBox: createSecretBox(generateMasterKey()),
  });
  const worker = createWorker({ queue, handlers: platform.handlers });
  const drain = async () => { while (await worker.runOnce()); };
  return { db, queue, platform, worker, drain };
}

async function createOrg(platform, email = 'owner@example.com') {
  const res = await platform.auth.signup({
    email,
    name: 'Owner',
    password: PASSWORD,
    orgName: 'Security Corp',
  });
  return { ...res, ctx: { userId: res.user.id, orgId: res.orgId } };
}

test('websites platform service: create, list, verify, scan, report, and delete', async (t) => {
  // Spin up a dummy HTTP server to act as a public test target
  const server = http.createServer((req, res) => {
    if (req.url === '/.well-known/vulnsight-verify.txt') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('vs-verify-token-12345');
      return;
    }
    // Return sample response with missing security headers
    res.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': 'sessionid=abc123xyz; Path=/',
    });
    res.end('<html><head><title>Test App</title></head><body><form action="/login"><input name="user"/><input name="pass"/></form></body></html>');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  t.after(() => {
    server.close();
  });

  const { platform, drain } = setupPlatform();
  const { ctx } = await createOrg(platform);

  // 1. Rejects SSRF on private IP literal
  await assert.rejects(
    () => platform.websites.create(ctx, { url: `http://127.0.0.1:${port}` }),
    (err) => err.message.includes('private/internal IP address')
  );

  // 2. Creates a valid public website entry (example.com)
  const site = await platform.websites.create(ctx, {
    url: 'https://example.com',
    name: 'Example Production',
  });
  assert.equal(site.hostname, 'example.com');
  assert.equal(site.isVerified, false);
  assert.ok(site.verificationToken.startsWith('vs-verify-'));

  // 3. Rejects duplicate URL registration in the same org
  await assert.rejects(
    () => platform.websites.create(ctx, { url: 'https://example.com/' }),
    (err) => err.message.includes('already registered')
  );

  // 4. Lists websites
  const list = await platform.websites.list(ctx);
  assert.equal(list.length, 1);
  assert.equal(list[0].id, site.id);

  // 5. Active scan on unverified domain is blocked
  assert.throws(
    () => platform.websites.startScan(ctx, site.id, { profile: 'standard' }),
    (err) => err.message.includes('requires domain ownership verification')
  );

  // 6. Passive scan is allowed immediately
  const scan = platform.websites.startScan(ctx, site.id, { profile: 'passive' });
  assert.equal(scan.status, 'queued');
  assert.equal(scan.profile, 'passive');

  // Drain background queue
  await drain();

  // 7. Verify completed scan record
  const finishedScan = platform.websites.getScan(ctx, site.id, scan.id);
  assert.equal(finishedScan.status, 'completed');
  assert.ok(finishedScan.postureScore != null);
  assert.ok(finishedScan.summary.total >= 0);
  assert.ok(Array.isArray(finishedScan.passiveResults.findings));

  // 8. Export report in JSON, Markdown, and CSV
  const jsonReport = platform.websites.report(ctx, site.id, scan.id, 'json');
  assert.equal(jsonReport.ext, 'json');
  const parsedJson = JSON.parse(jsonReport.body);
  assert.equal(parsedJson.website.id, site.id);

  const mdReport = platform.websites.report(ctx, site.id, scan.id, 'markdown');
  assert.equal(mdReport.ext, 'md');
  assert.ok(mdReport.body.includes('Website Security Assessment'));

  const csvReport = platform.websites.report(ctx, site.id, scan.id, 'csv');
  assert.equal(csvReport.ext, 'csv');
  assert.ok(csvReport.body.startsWith('id,category,severity'));

  // 9. Remove website
  const removeRes = await platform.websites.remove(ctx, site.id);
  assert.equal(removeRes.ok, true);
  const emptyList = await platform.websites.list(ctx);
  assert.equal(emptyList.length, 0);
});

test('websites HTTP API endpoints: auth, CRUD, scan trigger, report download', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vssite-'));
  const app = await startPlatform({ port: 0, dataDir: dir, log: () => {}, runWorker: false });
  t.after(async () => {
    await app.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${app.port}`;
  const call = async (method, p, body, token) => {
    const res = await fetch(base + p, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  };

  // Sign up
  const signup = await call('POST', '/api/v1/auth/signup', {
    email: 'siteowner@example.com',
    password: PASSWORD,
    orgName: 'Site Org',
  });
  assert.equal(signup.status, 201);
  const token = signup.json.token;
  const orgId = signup.json.orgId;

  // 1. Add website via API
  const addRes = await call('POST', `/api/v1/orgs/${orgId}/websites`, {
    url: 'https://example.com',
    name: 'Example Production',
  }, token);
  assert.equal(addRes.status, 201);
  const siteId = addRes.json.id;
  assert.equal(addRes.json.hostname, 'example.com');

  // 2. List websites via API
  const listRes = await call('GET', `/api/v1/orgs/${orgId}/websites`, undefined, token);
  assert.equal(listRes.status, 200);
  assert.equal(listRes.json.length, 1);
  assert.equal(listRes.json[0].id, siteId);

  // 3. Get website details
  const getRes = await call('GET', `/api/v1/orgs/${orgId}/websites/${siteId}`, undefined, token);
  assert.equal(getRes.status, 200);
  assert.equal(getRes.json.name, 'Example Production');

  // 4. Trigger passive scan
  const scanRes = await call('POST', `/api/v1/orgs/${orgId}/websites/${siteId}/scans`, {
    profile: 'passive',
  }, token);
  assert.equal(scanRes.status, 202);
  const scanId = scanRes.json.id;

  // 5. List scans for website
  const scansList = await call('GET', `/api/v1/orgs/${orgId}/websites/${siteId}/scans`, undefined, token);
  assert.equal(scansList.status, 200);
  assert.equal(scansList.json.length, 1);

  // 6. Delete website
  const delRes = await call('DELETE', `/api/v1/orgs/${orgId}/websites/${siteId}`, undefined, token);
  assert.equal(delRes.status, 200);
  assert.equal(delRes.json.ok, true);

  // 7. Verify it's gone
  const afterList = await call('GET', `/api/v1/orgs/${orgId}/websites`, undefined, token);
  assert.equal(afterList.json.length, 0);
});
