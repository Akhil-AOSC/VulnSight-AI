#!/usr/bin/env node
'use strict';

// Stored-XSS probe in a REAL browser (headless Edge/Chrome over the DevTools protocol).
// Hostile payloads are stored in every user-controlled field, every screen is loaded, and the page
// is inspected for executed script or injected elements. A self-assessment, not a penetration test.
//   node scripts/xss-probe.js [path-to-edge-or-chrome]
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { startPlatform } = require('../src/platform/app');

const BROWSER = process.argv[2] || ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].find((p) => fs.existsSync(p));
if (!BROWSER) { console.error('No Chrome/Edge found. Pass its path as an argument.'); process.exit(2); }

const PAYLOADS = [
  '<img src=x onerror="window.__xss=(window.__xss||0)+1">',
  '<script>window.__xss=(window.__xss||0)+1</script>',
  '"><svg onload="window.__xss=(window.__xss||0)+1">',
  "'; window.__xss=(window.__xss||0)+1; //",
  '<a href="javascript:window.__xss=1">x</a>',
];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-xss-'));
  const app = await startPlatform({ port: 0, dataDir: dir, log: () => {}, runWorker: false, limiter: { allow: () => true } });
  const base = `http://127.0.0.1:${app.port}`;
  const api = async (method, p, token, body) => (await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined })).json();

  const [P0, P1, P2, P3, P4] = PAYLOADS;
  const user = await api('POST', '/api/v1/auth/signup', null, { email: 'xss@example.com', password: 'Correct-Horse-9', name: P0, orgName: P1 });
  const org = user.orgId;
  await api('POST', `/api/v1/orgs/${org}/teams`, user.token, { name: P2 });
  const now = new Date().toISOString();
  const repoId = crypto.randomUUID(); const scanId = crypto.randomUUID();
  app.db.prepare("INSERT INTO repositories (id, org_id, provider, full_name, clone_url, default_branch, webhook_secret, created_at) VALUES (?, ?, 'github', ?, 'https://github.com/a/b.git', ?, ?, ?)").run(repoId, org, `evil/${P0}`, P3, app.secretBox.encrypt('s'), now);
  app.db.prepare("INSERT INTO scans (id, org_id, repo_id, branch, trigger, status, scanners, summary, error, created_at, finished_at, commit_sha) VALUES (?, ?, ?, ?, 'manual', 'completed', ?, ?, ?, ?, ?, ?)")
    .run(scanId, org, repoId, P1, JSON.stringify([{ scanner: P2, status: 'error', version: P3, error: P4, findingCount: 1, durationMs: 1 }]),
      JSON.stringify({ total: 1, bySeverity: { critical: 0, high: 1, medium: 0, low: 0 }, byCategory: {}, posture: { score: 90, grade: 'A' }, new: 1, fixed: 0 }), P0, now, now, P2);
  const finding = { id: 'fp1', category: 'sast', severity: 'high', title: P0, description: P1, evidence: P2, url: 'javascript:window.__xss=9', identifiers: { primary: P3, aliases: [P4], cwe: [P0] },
    location: { file: P1, line: 3, package: P2, version: P3, ecosystem: P4, direct: true, paths: [[P0, P1]] }, remediation: { fixedIn: P2, advice: P3 }, scanner: { name: P4, version: P0 }, sources: [{ name: P2, version: P3 }] };
  app.db.prepare("INSERT INTO findings (id, scan_id, org_id, repo_id, fingerprint, severity, category, data) VALUES (?, ?, ?, ?, 'fp1', 'high', 'sast', ?)").run(crypto.randomUUID(), scanId, org, repoId, JSON.stringify(finding));
  app.db.prepare("INSERT INTO notifications (id, org_id, user_id, kind, title, body, created_at) VALUES (?, ?, ?, 'x', ?, ?, ?)").run(crypto.randomUUID(), org, user.user.id, P0, P1, now);
  app.db.prepare("INSERT INTO audit_logs (id, org_id, user_id, action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(crypto.randomUUID(), org, user.user.id, P0, P1, JSON.stringify({ x: P2 }), P3, now);
  await api('PATCH', `/api/v1/orgs/${org}/repos/${repoId}/findings/fp1`, user.token, { status: 'acknowledged', note: P0 });

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'xss-browser-'));
  const port = 9444;
  const browser = spawn(BROWSER, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', '--disable-gpu', 'about:blank'], { stdio: 'ignore' });
  let targets;
  for (let i = 0; i < 40; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.length) break; } catch { /* starting */ } await sleep(300); }
  const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener('open', r));
  let id = 0; const pending = new Map(); const dialogs = [];
  ws.addEventListener('message', (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
    if (d.method === 'Page.javascriptDialogOpening') { dialogs.push(d.params.message); }
  });
  const send = (method, params = {}) => new Promise((resolve) => { const i = ++id; pending.set(i, resolve); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async (expression) => (await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })).result.result.value;
  await send('Page.enable'); await send('Runtime.enable');

  await send('Page.navigate', { url: base + '/' });
  await sleep(1200);
  await ev(`sessionStorage.setItem('vs.token', ${JSON.stringify(user.token)}); localStorage.setItem('vs.org', ${JSON.stringify(org)}); location.reload();`);
  await sleep(1500);

  const routes = ['#/overview', '#/repos', `#/repos/${repoId}`, `#/scans/${scanId}`, '#/assistant', '#/reports', '#/settings/profile', '#/settings/organisation', '#/settings/members', '#/settings/teams', '#/settings/providers', '#/settings/notifications', '#/settings/audit'];
  let failures = 0;
  for (const hash of routes) {
    await ev(`location.hash=${JSON.stringify(hash)}`);
    await sleep(1200);
    if (hash.startsWith('#/scans/')) {
      await ev(`(() => { const b = document.querySelector('tbody button.link'); if (b) b.click(); })()`);
      await sleep(400);
    }
    const r = await ev(`({
      executed: window.__xss === undefined ? 0 : window.__xss,
      injectedImg: document.querySelectorAll('img[src="x"], svg[onload], script:not([src])').length,
      onAttrs: [...document.querySelectorAll('*')].filter((e) => [...e.attributes].some((a) => /^on/i.test(a.name))).length,
      jsLinks: [...document.querySelectorAll('a[href]')].filter((a) => /^javascript:/i.test(a.getAttribute('href'))).length,
      shownAsText: document.body.innerText.includes('<img src=x') || document.body.innerText.includes('<script>') || document.body.innerText.includes('onerror'),
    })`);
    const bad = r.executed || r.injectedImg || r.onAttrs || r.jsLinks || dialogs.length;
    if (bad) failures++;
    console.log(`${bad ? 'FAIL' : 'PASS'}  ${hash.padEnd(46)} executed=${r.executed} injectedElements=${r.injectedImg} onAttrs=${r.onAttrs} javascriptLinks=${r.jsLinks} payloadRenderedAsText=${r.shownAsText}`);
  }
  console.log(`\n${routes.length - failures}/${routes.length} screens clean (${PAYLOADS.length} payloads stored in user, org, team, repo, branch, finding, scanner, notification and audit fields).`);
  ws.close(); browser.kill(); await app.stop();
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
