#!/usr/bin/env node
'use strict';

// Automated security SELF-ASSESSMENT against a real, freshly started platform (real rate limits).
// It is a regression probe for common web-application weaknesses, NOT a penetration test: it
// cannot replace independent human testers, and a clean run proves only that these checks pass.
//   node scripts/security-probe.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startPlatform } = require('../src/platform/app');

const PASSWORD = 'Correct-Horse-9';
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-probe-'));
  // Functional checks run with the limiter off so a 429 can never mask the behaviour under test.
  // Throttling itself is tested on a separate instance with the real limits (check 8).
  const app = await startPlatform({ port: 0, dataDir: dir, log: () => {}, runWorker: false, limiter: { allow: () => true } });
  const base = `http://127.0.0.1:${app.port}`;
  const raw = (method, p, { token, body, headers = {}, rawBody } = {}) => fetch(base + p, {
    method, redirect: 'manual',
    headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: rawBody !== undefined ? rawBody : body === undefined ? undefined : JSON.stringify(body),
  });
  const call = async (...a) => { const r = await raw(...a); const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* not json */ } return { status: r.status, text, json, headers: r.headers }; };

  const a = (await call('POST', '/api/v1/auth/signup', { body: { email: 'a@example.com', password: PASSWORD, orgName: 'A' } })).json;
  const b = (await call('POST', '/api/v1/auth/signup', { body: { email: 'b@example.com', password: PASSWORD, orgName: 'B' } })).json;

  // seed org A with a repo, scan and findings directly
  const crypto = require('crypto');z
  const repoId = crypto.randomUUID(); const scanId = crypto.randomUUID(); const findingRow = crypto.randomUUID();
  const now = new Date().toISOString();
  app.db.prepare("INSERT INTO repositories (id, org_id, provider, full_name, clone_url, default_branch, webhook_secret, created_at) VALUES (?, ?, 'github', 'acme/app', 'https://github.com/acme/app.git', 'main', ?, ?)").run(repoId, a.orgId, app.secretBox.encrypt('s'), now);
  app.db.prepare("INSERT INTO scans (id, org_id, repo_id, branch, trigger, status, scanners, summary, created_at, finished_at) VALUES (?, ?, ?, 'main', 'manual', 'completed', '[]', '{\"total\":1,\"bySeverity\":{\"critical\":0,\"high\":1,\"medium\":0,\"low\":0},\"byCategory\":{},\"posture\":{\"score\":90,\"grade\":\"A\"},\"new\":0,\"fixed\":0}', ?, ?)").run(scanId, a.orgId, repoId, now, now);
  app.db.prepare("INSERT INTO findings (id, scan_id, org_id, repo_id, fingerprint, severity, category, data) VALUES (?, ?, ?, ?, 'fp1', 'high', 'sca', ?)").run(findingRow, scanId, a.orgId, repoId, JSON.stringify({ id: 'fp1', category: 'sca', severity: 'high', title: 'Secret finding title', identifiers: { primary: 'X', aliases: [], cwe: [] }, location: { package: 'p', version: '1' }, remediation: {}, scanner: { name: 'osv' } }));

  // 1. SQL injection in every user-controlled string reaching a query
  const sqli = ["' OR '1'='1", "1; DROP TABLE users;--", "\" OR 1=1 --", "' UNION SELECT token_hash FROM sessions --", "%27%20OR%201%3D1"];
  let sqliBad = [];
  for (const p of sqli) {
    const enc = encodeURIComponent(p);
    for (const url of [
      `/api/v1/orgs/${a.orgId}/scans/${scanId}/findings?q=${enc}`, `/api/v1/orgs/${a.orgId}/scans/${scanId}/findings?severity=${enc}`,
      `/api/v1/orgs/${a.orgId}/scans/${scanId}/findings?status=${enc}&category=${enc}&page=${enc}&pageSize=${enc}`,
      `/api/v1/orgs/${a.orgId}/audit?action=${enc}`, `/api/v1/orgs/${a.orgId}/scans?limit=${enc}&repoId=${enc}`,
    ]) {
      const r = await call('GET', url, { token: a.token });
      if (r.status >= 500 || /sqlite|syntax error|SELECT |token_hash/i.test(r.text)) sqliBad.push(`${r.status} ${url.slice(0, 60)}`);
    }
    const login = await call('POST', '/api/v1/auth/login', { body: { email: p, password: p } });
    if (login.status >= 500 || login.status === 200) sqliBad.push(`login ${login.status}`);
  }
  check('SQL injection payloads in filters, ids and login never error or leak', sqliBad.length === 0, sqliBad.join('; '));
  check('the users table survived the DROP TABLE payload', app.db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 2);

  // 2. cross-tenant access with valid ids (IDOR)
  const idor = [
    ['GET', `/api/v1/orgs/${b.orgId}/scans/${scanId}`], ['GET', `/api/v1/orgs/${b.orgId}/scans/${scanId}/findings`],
    ['GET', `/api/v1/orgs/${b.orgId}/scans/${scanId}/report?format=csv`], ['GET', `/api/v1/orgs/${b.orgId}/repos/${repoId}`],
    ['POST', `/api/v1/orgs/${b.orgId}/repos/${repoId}/scans`], ['PATCH', `/api/v1/orgs/${b.orgId}/repos/${repoId}/findings/fp1`, { status: 'suppressed', note: 'x' }],
    ['POST', `/api/v1/orgs/${b.orgId}/findings/${findingRow}/explain`], ['DELETE', `/api/v1/orgs/${b.orgId}/repos/${repoId}`],
    ['GET', `/api/v1/orgs/${a.orgId}/overview`], ['GET', `/api/v1/orgs/${a.orgId}/audit`],
  ];
  const leaks = [];
  for (const [m, u, body] of idor) { const r = await call(m, u, { token: b.token, body: body || (m === 'GET' ? undefined : {}) }); if (r.status === 200 || r.status === 202) leaks.push(`${m} ${u.slice(0, 70)} -> ${r.status}`); }
  check('user B cannot read or modify org A data using valid object ids', leaks.length === 0, leaks.join('; '));
  check('A\'s repository still exists after B\'s delete attempt', !!app.db.prepare('SELECT 1 FROM repositories WHERE id = ?').get(repoId));

  // 3. mass assignment / prototype pollution
  const evilSignup = await call('POST', '/api/v1/auth/signup', { body: { email: 'c@example.com', password: PASSWORD, role: 'owner', orgId: a.orgId, disabled: 0, id: 'attacker', __proto__: { admin: true } } });
  const cMembership = app.db.prepare('SELECT org_id FROM memberships WHERE user_id = ?').all(evilSignup.json.user.id);
  check('signup ignores role/orgId/id supplied by the client', cMembership.length === 1 && cMembership[0].org_id !== a.orgId && evilSignup.json.user.id !== 'attacker');
  const pollute = await call('PATCH', `/api/v1/orgs/${a.orgId}/settings`, { token: a.token, rawBody: '{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"aiEnabled":true}', headers: { 'content-type': 'application/json' } });
  check('prototype pollution payload has no effect', ({}).polluted === undefined && pollute.status < 500);

  // 4. malformed and hostile input must never produce a 500 or a stack trace
  const hostile = [
    ['POST', '/api/v1/auth/login', { rawBody: '{"email":' + '"a'.repeat(1) + '', headers: { 'content-type': 'application/json' } }],
    ['POST', '/api/v1/auth/login', { body: { email: 'x'.repeat(100000), password: 'y' } }],
    ['POST', '/api/v1/auth/login', { body: { email: ['a@example.com'], password: { $gt: '' } } }],
    ['POST', '/api/v1/auth/login', { body: { email: 'a@example.com\u0000', password: PASSWORD } }],
    ['POST', '/api/v1/auth/signup', { body: { email: 'z@example.com', password: PASSWORD, name: 'n'.repeat(100000) } }],
    ['POST', `/api/v1/orgs/${a.orgId}/repos`, { token: a.token, body: { url: { toString: 'x' } } }],
    ['POST', `/api/v1/orgs/${a.orgId}/repos`, { token: a.token, body: { url: 'https://github.com/a/b', branch: ['x'], config: 'nope' } }],
    ['GET', `/api/v1/orgs/%00/overview`, { token: a.token }], ['GET', `/api/v1/orgs/..%2f..%2fetc/overview`, { token: a.token }],
    ['POST', '/api/v1/auth/login', { rawBody: '[' .repeat(50000), headers: { 'content-type': 'application/json' } }],
  ];
  const bad500 = [];
  for (const [m, u, o] of hostile) { const r = await call(m, u, o); if (r.status >= 500 || /at .*\.js:\d+|node:internal/.test(r.text)) bad500.push(`${r.status} ${m} ${u.slice(0, 40)}`); }
  check('malformed, oversized, typed-wrong and null-byte input is rejected cleanly (no 5xx, no stack traces)', bad500.length === 0, bad500.join('; '));
  const nf = await call('GET', '/api/v1/does-not-exist');
  check('error responses are generic JSON', nf.status === 404 && nf.json && Object.keys(nf.json).join() === 'error');

  // 5. HTTP-level behaviour
  const trace = await raw('TRACE', '/api/v1/health').catch(() => ({ status: 0 }));
  check('TRACE is not accepted', trace.status === 404 || trace.status === 405 || trace.status === 0, String(trace.status));
  const override = await call('GET', `/api/v1/orgs/${a.orgId}/repos/${repoId}`, { token: a.token, headers: { 'x-http-method-override': 'DELETE' } });
  check('X-HTTP-Method-Override is ignored', override.status === 200 && !!app.db.prepare('SELECT 1 FROM repositories WHERE id = ?').get(repoId));
  const pre = await raw('OPTIONS', `/api/v1/orgs/${a.orgId}/overview`, { headers: { origin: 'https://evil.example', 'access-control-request-method': 'GET' } });
  check('CORS preflight is never approved', !pre.headers.get('access-control-allow-origin'));
  const cross = await call('GET', `/api/v1/orgs/${a.orgId}/overview`, { token: a.token, headers: { origin: 'https://evil.example' } });
  check('no CORS headers on normal responses', !cross.headers.get('access-control-allow-origin'));
  const cookie = await call('POST', '/api/v1/auth/login', { body: { email: 'a@example.com', password: PASSWORD } });
  check('no cookies are set (bearer tokens only, so no CSRF surface)', !cookie.headers.get('set-cookie'));
  const form = await call('POST', '/api/v1/auth/login', { rawBody: 'email=a@example.com&password=x', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  check('form-encoded (CSRF-style) posts are rejected', form.status === 415);
  const noct = await call('POST', `/api/v1/orgs/${a.orgId}/repos`, { token: a.token, rawBody: '{"url":"https://github.com/a/b"}', headers: { 'content-type': 'text/plain' } });
  check('text/plain posts with a valid token are rejected', noct.status === 415);

  // 6. static file exposure
  const leaked = [];
  for (const p of ['/package.json', '/src/cli.js', '/.env', '/.git/config', '/..%2fpackage.json', '/%2e%2e/package.json', '/.vulnsight-data/dev-master.key', '/web/../package.json', '/app.js%00.html', '/dev-master.key', '/vulnsight.db']) {
    const r = await call('GET', p);
    if (/"name": "vulnsight-ai"|require\('|BEGIN|SQLite format/.test(r.text) || r.headers.get('content-type')?.includes('octet')) leaked.push(p);
  }
  check('no source, config, key or database file is reachable over HTTP', leaked.length === 0, leaked.join(', '));

  // 7. authentication behaviour
  const t = async (email) => { const s = process.hrtime.bigint(); await call('POST', '/api/v1/auth/login', { body: { email, password: 'Wrong-Password-1' } }); return Number(process.hrtime.bigint() - s) / 1e6; };
  const known = []; const unknown = [];
  for (let i = 0; i < 4; i++) { known.push(await t('a@example.com')); unknown.push(await t(`nobody${i}@example.com`)); }
  const avg = (x) => x.reduce((p, c) => p + c, 0) / x.length;
  check('login time does not reveal whether an email exists (known/unknown ratio < 1.6)', Math.max(avg(known), avg(unknown)) / Math.min(avg(known), avg(unknown)) < 1.6, `known ${avg(known).toFixed(0)} ms, unknown ${avg(unknown).toFixed(0)} ms`);
  const wrong = await call('POST', '/api/v1/auth/login', { body: { email: 'a@example.com', password: 'nope' } });
  const none = await call('POST', '/api/v1/auth/login', { body: { email: 'nobody@example.com', password: 'nope' } });
  check('wrong password and unknown email give identical responses', wrong.status === none.status && wrong.text === none.text);
  const forged = await call('GET', '/api/v1/me', { token: 'A'.repeat(43) });
  const jwtLike = await call('GET', '/api/v1/me', { token: 'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.' });
  check('forged and JWT-alg-none style tokens are rejected', forged.status === 401 && jwtLike.status === 401);
  const weak = await call('POST', '/api/v1/auth/signup', { body: { email: 'w@example.com', password: 'password' } });
  check('weak passwords are rejected', weak.status === 400);

  // 8. brute force is throttled (fresh instance, real limits)
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-probe2-'));
  const app2 = await startPlatform({ port: 0, dataDir: dir2, log: () => {}, runWorker: false });
  await fetch(`http://127.0.0.1:${app2.port}/api/v1/auth/signup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'v@example.com', password: PASSWORD }) });
  const codes = [];
  for (let i = 0; i < 14; i++) {
    const r = await fetch(`http://127.0.0.1:${app2.port}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'v@example.com', password: `guess-${i}-Aa1` }) });
    codes.push(r.status); await r.arrayBuffer();
  }
  check('repeated wrong passwords: 401s first, then throttled with 429 (and the real password is blocked too)', codes[0] === 401 && codes.includes(429) && codes.indexOf(429) <= 11, codes.join(','));
  const blocked = await fetch(`http://127.0.0.1:${app2.port}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'v@example.com', password: PASSWORD }) });
  check('the correct password is also refused while throttled (an attacker cannot just keep guessing)', blocked.status === 429);
  await app2.stop();
  fs.rmSync(dir2, { recursive: true, force: true });

  // 9. headers
  const h = (await call('GET', '/')).headers;
  check('security headers present (CSP, nosniff, frame deny, referrer)', /script-src 'self'/.test(h.get('content-security-policy') || '') && h.get('x-content-type-options') === 'nosniff' && h.get('x-frame-options') === 'DENY' && h.get('referrer-policy') === 'no-referrer');
  check('CSP forbids inline script and inline style', !/unsafe-inline|unsafe-eval/.test(h.get('content-security-policy') || ''));
  check('server does not advertise its technology', !h.get('x-powered-by') && !/express|nginx|apache/i.test(h.get('server') || ''));

  // 10. secrets at rest
  app.db.prepare('SELECT 1').get();
  const dump = fs.readFileSync(path.join(dir, 'vulnsight.db')).toString('latin1') + (fs.existsSync(path.join(dir, 'vulnsight.db-wal')) ? fs.readFileSync(path.join(dir, 'vulnsight.db-wal')).toString('latin1') : '');
  check('no plaintext password or session token is stored in the database file', !dump.includes(PASSWORD) && !dump.includes(a.token));

  await app.stop();
  fs.rmSync(dir, { recursive: true, force: true });

  const failed = results.filter((r) => !r.ok);
  for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail && !r.ok ? `\n        -> ${r.detail}` : r.detail ? `   (${r.detail})` : ''}`);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed. This is a self-assessment, not a penetration test.`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
