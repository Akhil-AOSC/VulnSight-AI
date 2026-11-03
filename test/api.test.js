'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { startPlatform, loadMasterKey } = require('../src/platform/app');
const { createApi, createRateLimiter } = require('../src/platform/api');

const PASSWORD = 'Correct-Horse-9';

async function boot(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vsapi-'));
  const app = await startPlatform({ port: 0, dataDir: dir, log: () => {}, runWorker: false });
  t.after(async () => { await app.stop(); fs.rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${app.port}`;
  const call = async (method, p, body, token, headers = {}) => {
    const res = await fetch(base + p, {
      method, headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, json, text, headers: res.headers };
  };
  return { app, call, base };
}

test('signup/login over HTTP, security headers and error shapes', async (t) => {
  const { call } = await boot(t);
  const s = await call('POST', '/api/v1/auth/signup', { email: 'a@example.com', password: PASSWORD, orgName: 'Acme' });
  assert.equal(s.status, 201);
  assert.equal(s.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(s.headers.get('x-frame-options'), 'DENY');
  assert.match(s.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(s.headers.get('cache-control'), 'no-store');
  assert.equal(s.headers.get('access-control-allow-origin'), null, 'no CORS');

  assert.equal((await call('POST', '/api/v1/auth/login', { email: 'a@example.com', password: 'wrong' })).status, 401);
  const login = await call('POST', '/api/v1/auth/login', { email: 'a@example.com', password: PASSWORD });
  assert.equal(login.status, 200);
  assert.equal((await call('GET', '/api/v1/me', undefined, login.json.token)).json.orgs[0].role, 'owner');
  assert.equal((await call('POST', '/api/v1/auth/logout', {}, login.json.token)).status, 200);
  assert.equal((await call('GET', '/api/v1/me', undefined, login.json.token)).status, 401);

  assert.equal((await call('POST', '/api/v1/auth/signup', { email: 'x', password: PASSWORD })).status, 400);
  assert.equal((await call('POST', '/api/v1/auth/login', '{}', undefined, { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await call('POST', '/api/v1/auth/login', '{bad json', undefined, { 'content-type': 'application/json' })).status, 400);
  assert.equal((await call('POST', '/api/v1/auth/login', '[1]', undefined, { 'content-type': 'application/json' })).status, 400);
  const nf = await call('GET', '/api/v1/nope');
  assert.equal(nf.status, 404);
});

test('every non-public API route rejects unauthenticated requests', async (t) => {
  const { app, call } = await boot(t);
  const routes = createApi({ platform: app.platform }).routes.filter((r) => !r.public);
  assert.ok(routes.length > 40);
  for (const r of routes) {
    const url = '/' + r.re.source.replace(/^\^\\\//, '').replace(/\(\[\\w\.-\]\+\)/g, 'x').replace(/\\\//g, '/').replace(/\$$/, '');
    const res = await call(r.method, url, r.method === 'GET' ? undefined : {});
    assert.equal(res.status, 401, `${r.method} ${url} -> ${res.status}`);
  }
});

test('login and signup are rate limited', async (t) => {
  const { call } = await boot(t);
  const statuses = [];
  for (let i = 0; i < 12; i++) statuses.push((await call('POST', '/api/v1/auth/login', { email: 'victim@example.com', password: 'x' })).status);
  assert.equal(statuses[0], 401);
  assert.equal(statuses.at(-1), 429);
});

test('rate limiter window slides', () => {
  let t = 0;
  const l = createRateLimiter({ clock: () => t });
  assert.ok(l.allow('k', 2, 1000));
  assert.ok(l.allow('k', 2, 1000));
  assert.equal(l.allow('k', 2, 1000), false);
  t = 1001;
  assert.ok(l.allow('k', 2, 1000));
});

test('request bodies are size limited', async (t) => {
  const { call } = await boot(t);
  const big = JSON.stringify({ email: 'a@example.com', password: 'x'.repeat(2 * 1024 * 1024) });
  const res = await call('POST', '/api/v1/auth/login', big, undefined, { 'content-type': 'application/json' }).catch((e) => ({ status: 'closed', e }));
  assert.ok(res.status === 413 || res.status === 'closed');
});

test('HTTP tenant isolation and role enforcement', async (t) => {
  const { call } = await boot(t);
  const a = (await call('POST', '/api/v1/auth/signup', { email: 'a@example.com', password: PASSWORD, orgName: 'A' })).json;
  const b = (await call('POST', '/api/v1/auth/signup', { email: 'b@example.com', password: PASSWORD, orgName: 'B' })).json;

  // B probing A's organisation by id.
  for (const p of ['overview', 'repos', 'scans', 'members', 'audit', 'settings', 'connections']) {
    const res = await call('GET', `/api/v1/orgs/${a.orgId}/${p}`, undefined, b.token);
    assert.equal(res.status, 404, p);
  }
  assert.equal((await call('POST', `/api/v1/orgs/${a.orgId}/members`, { email: 'b@example.com', role: 'owner' }, b.token)).status, 404);
  assert.equal((await call('DELETE', `/api/v1/orgs/${a.orgId}`, undefined, b.token)).status, 404);
  assert.equal((await call('GET', `/api/v1/orgs/${a.orgId}/overview`, undefined, a.token)).status, 200);

  // Role limits over HTTP.
  assert.equal((await call('POST', `/api/v1/orgs/${a.orgId}/members`, { email: 'b@example.com', role: 'viewer' }, a.token)).status, 201);
  assert.equal((await call('GET', `/api/v1/orgs/${a.orgId}/overview`, undefined, b.token)).status, 200);
  assert.equal((await call('GET', `/api/v1/orgs/${a.orgId}/audit`, undefined, b.token)).status, 403);
  assert.equal((await call('PATCH', `/api/v1/orgs/${a.orgId}/settings`, { aiEnabled: true }, b.token)).status, 403);
  assert.equal((await call('POST', `/api/v1/orgs/${a.orgId}/repos`, { url: 'https://github.com/acme/app' }, b.token)).status, 403);
});

test('SSRF attempts through the API are rejected', async (t) => {
  const { call } = await boot(t);
  const a = (await call('POST', '/api/v1/auth/signup', { email: 'a@example.com', password: PASSWORD })).json;
  for (const url of ['http://169.254.169.254/latest', 'https://127.0.0.1/a/b', 'file:///etc/passwd', 'https://localhost/a/b', 'https://user:pw@github.com/a/b', 'https://evil.example.com/a/b']) {
    const res = await call('POST', `/api/v1/orgs/${a.orgId}/repos`, { url }, a.token);
    assert.equal(res.status, 400, url);
  }
});

test('webhook endpoint is public but requires a valid signature', async (t) => {
  const { app, call, base } = await boot(t);
  const a = (await call('POST', '/api/v1/auth/signup', { email: 'a@example.com', password: PASSWORD })).json;
  const ctx = { userId: a.user.id, orgId: a.orgId };
  // Insert a repository directly (the API's URL validation needs real DNS).
  const id = crypto.randomUUID();
  const secret = 'whsec_test_secret';
  app.db.prepare('INSERT INTO repositories (id, org_id, provider, full_name, clone_url, default_branch, webhook_secret, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, ctx.orgId, 'github', 'acme/app', 'https://github.com/acme/app.git', 'main', app.secretBox.encrypt(secret), new Date().toISOString());

  const body = JSON.stringify({ ref: 'refs/heads/main' });
  const post = (headers) => fetch(`${base}/api/v1/webhooks/${id}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });
  assert.equal((await post({})).status, 403, 'unsigned');
  assert.equal((await post({ 'x-hub-signature-256': 'sha256=deadbeef' })).status, 403, 'bad signature');
  const sig = `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;
  const ok = await post({ 'x-hub-signature-256': sig });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).scanned, true);
  assert.equal(app.db.prepare("SELECT trigger FROM scans WHERE repo_id = ?").get(id).trigger, 'webhook');
  assert.equal((await call('POST', '/api/v1/webhooks/00000000-0000-0000-0000-000000000000', { ref: 'x' })).status, 404);
});

test('static files: app shell served, traversal blocked, SPA fallback', async (t) => {
  const { call } = await boot(t);
  const root = await call('GET', '/');
  assert.equal(root.status, 200);
  assert.match(root.headers.get('content-type'), /text\/html/);
  assert.equal((await call('GET', '/%2e%2e/package.json')).status, 200, 'falls back to the app shell, never the file');
  const trav = await call('GET', '/..%2f..%2fpackage.json');
  assert.ok(!/"name": "vulnsight-ai"/.test(trav.text));
  assert.ok(!(await call('GET', '/src/cli.js')).text.includes('require('));
  assert.equal((await call('GET', '/some/client/route')).status, 200);
});

test('master key: required in production, generated once for dev', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vskey-'));
  try {
    assert.throws(() => loadMasterKey({ env: { NODE_ENV: 'production' }, dataDir: dir }), /required in production/);
    const k1 = loadMasterKey({ env: {}, dataDir: dir });
    assert.equal(loadMasterKey({ env: {}, dataDir: dir }), k1);
    assert.equal(loadMasterKey({ env: { VULNSIGHT_MASTER_KEY: 'abc' }, dataDir: dir }), 'abc');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
