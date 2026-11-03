#!/usr/bin/env node
'use strict';

// Load test against a real, freshly started platform (SQLite, in-process worker disabled).
//   node scripts/loadtest.js [virtualUsers=25] [seconds=20] [findingsPerScan=200]
//
// Each virtual user signs up, then loops through a read-heavy mix (overview, repositories, scans,
// paged findings, report export). One scan with N findings is seeded straight into the database so
// the findings endpoints have realistic data. Prints latency percentiles per endpoint.
//
// The numbers describe THIS machine running one Node process and SQLite. They are not a capacity
// plan for any other environment.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { startPlatform } = require('../src/platform/app');
const { createFinding } = require('../src/findings');

const USERS = Number(process.argv[2] || 25);
const SECONDS = Number(process.argv[3] || 20);
const FINDINGS = Number(process.argv[4] || 200);
const PASSWORD = 'Correct-Horse-9';

const pct = (sorted, p) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] : 0);

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-load-'));
  // Rate limiting is disabled here only so the test can sign in many users from one address.
  const app = await startPlatform({ port: 0, dataDir: dir, log: () => {}, runWorker: false, limiter: { allow: () => true } });
  const base = `http://127.0.0.1:${app.port}`;
  const stats = new Map();
  let errors = 0;
  let requests = 0;

  const call = async (label, method, p, token, body) => {
    const started = process.hrtime.bigint();
    let status = 0;
    try {
      const res = await fetch(base + p, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
      status = res.status;
      await res.arrayBuffer();
    } catch { status = 0; }
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    requests++;
    if (!stats.has(label)) stats.set(label, []);
    stats.get(label).push(ms);
    if (status === 0 || status >= 500) errors++;
    return status;
  };
  const json = async (method, p, token, body) => {
    const res = await fetch(base + p, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
    return res.json();
  };

  // seed one org with a scan full of findings
  const owner = await json('POST', '/api/v1/auth/signup', null, { email: 'seed@example.com', password: PASSWORD, orgName: 'Seed' });
  const org = owner.orgId;
  const repoId = crypto.randomUUID();
  const scanId = crypto.randomUUID();
  const now = new Date().toISOString();
  app.db.prepare("INSERT INTO repositories (id, org_id, provider, full_name, clone_url, default_branch, webhook_secret, created_at) VALUES (?, ?, 'github', 'acme/app', 'https://github.com/acme/app.git', 'main', ?, ?)").run(repoId, org, app.secretBox.encrypt('s'), now);
  const sev = ['critical', 'high', 'medium', 'low'];
  app.db.prepare("INSERT INTO scans (id, org_id, repo_id, branch, trigger, status, scanners, summary, created_at, finished_at) VALUES (?, ?, ?, 'main', 'manual', 'completed', '[]', ?, ?, ?)")
    .run(scanId, org, repoId, JSON.stringify({ total: FINDINGS, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, byCategory: {}, posture: { score: 50, grade: 'D' }, new: 0, fixed: 0 }), now, now);
  const ins = app.db.prepare('INSERT INTO findings (id, scan_id, org_id, repo_id, fingerprint, severity, category, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  app.db.exec('BEGIN');
  for (let i = 0; i < FINDINGS; i++) {
    const f = createFinding({ category: 'sca', scanner: { name: 'osv' }, title: `Vulnerability ${i} in package-${i}`, severity: sev[i % 4], identifiers: { primary: `GHSA-${i}`, aliases: [`CVE-2024-${i}`] }, location: { file: 'package-lock.json', package: `package-${i}`, version: '1.0.0', ecosystem: 'npm', direct: i % 2 === 0, paths: [['app@1', `package-${i}@1.0.0`]] }, remediation: { fixedIn: '2.0.0' } });
    ins.run(crypto.randomUUID(), scanId, org, repoId, f.id, f.severity, f.category, JSON.stringify(f));
  }
  app.db.exec('COMMIT');

  console.log(`Platform up. ${USERS} virtual users for ${SECONDS}s, ${FINDINGS} findings in the seeded scan.`);

  // each virtual user is a member of the seed org (so every request hits real data)
  const tokens = [];
  const t0 = Date.now();
  await Promise.all(Array.from({ length: USERS }, async (_, i) => {
    const email = `user${i}@example.com`;
    await call('signup', 'POST', '/api/v1/auth/signup', null, { email, password: PASSWORD, orgName: `Org ${i}` });
    const login = await json('POST', '/api/v1/auth/login', null, { email, password: PASSWORD });
    await call('login', 'POST', '/api/v1/auth/login', null, { email, password: PASSWORD });
    app.db.prepare("INSERT OR IGNORE INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, 'developer', ?)").run(org, login.user.id, now);
    tokens.push(login.token);
  }));
  console.log(`Setup (signup + login x${USERS}, scrypt-bound): ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  const end = Date.now() + SECONDS * 1000;
  const started = Date.now();
  await Promise.all(tokens.map(async (token) => {
    while (Date.now() < end) {
      await call('overview', 'GET', `/api/v1/orgs/${org}/overview`, token);
      await call('repos', 'GET', `/api/v1/orgs/${org}/repos`, token);
      await call('scans', 'GET', `/api/v1/orgs/${org}/scans`, token);
      await call('findings p1', 'GET', `/api/v1/orgs/${org}/scans/${scanId}/findings?page=1&pageSize=50`, token);
      await call('findings filter', 'GET', `/api/v1/orgs/${org}/scans/${scanId}/findings?severity=critical&q=package`, token);
      if (Math.random() < 0.2) await call('report csv', 'GET', `/api/v1/orgs/${org}/scans/${scanId}/report?format=csv`, token);
    }
  }));
  const elapsed = (Date.now() - started) / 1000;

  console.log(`\n${requests} requests, ${errors} errors (5xx or network), ${(requests / (elapsed + 0.0001)).toFixed(0)} req/s overall\n`);
  console.log('endpoint            count    p50     p95     p99     max   (ms)');
  for (const [label, arr] of [...stats].sort()) {
    const s = [...arr].sort((a, b) => a - b);
    console.log(`${label.padEnd(18)} ${String(s.length).padStart(6)} ${pct(s, 50).toFixed(1).padStart(7)} ${pct(s, 95).toFixed(1).padStart(7)} ${pct(s, 99).toFixed(1).padStart(7)} ${s[s.length - 1].toFixed(1).padStart(7)}`);
  }
  console.log(`\nMachine: ${os.cpus().length} CPUs (${os.cpus()[0].model.trim()}), ${(os.totalmem() / 2 ** 30).toFixed(0)} GB RAM, Node ${process.version}, ${os.platform()}`);
  await app.stop();
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(errors ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
