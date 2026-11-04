'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey, hashPassword, verifyPassword, checkPasswordPolicy } = require('../src/platform/crypto');
const { createQueue, createWorker } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');
const { validateRepoUrl, validateBranch, isPrivateIp, sanitizeWorkspace, gitEnv } = require('../src/platform/git');
const { dockerArgs, scrubbedEnv } = require('../src/platform/sandbox');
const { createFinding } = require('../src/findings');
const { createMockProvider } = require('../src/ai/providers');

const PASSWORD = 'Correct-Horse-9';

function finding(over = {}) {
  return createFinding({
    category: 'sca', scanner: { name: 'osv', ruleId: 'GHSA-1' }, title: 'Proto pollution', severity: 'high',
    identifiers: { primary: 'GHSA-1', aliases: [] },
    location: { file: 'package-lock.json', package: 'lodash', version: '4.17.15', ecosystem: 'npm', direct: true },
    remediation: { fixedIn: '4.17.19' }, ...over,
  });
}

// A platform wired with fakes: no network, no git, no scanners.
function setup(opts = {}) {
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const state = { findings: [finding()], cleaned: 0, clones: [], provider: null };
  const platform = createPlatform({
    db, queue, secretBox: createSecretBox(generateMasterKey()),
    validateUrl: opts.validateUrl || (async (url) => {
      const m = String(url).match(/^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/([\w.-]+\/[\w.-]+?)(?:\.git)?$/);
      if (!m) throw Object.assign(new Error('Invalid repository URL'), { status: 400 });
      return { url: `https://${m[1]}/${m[2]}.git`, host: m[1], fullName: m[2], address: '140.82.112.3' };
    }),
    clone: async (validated, o) => {
      state.clones.push({ validated, ...o });
      return { dir: path.join(os.tmpdir(), 'vulnsight-fake'), commit: 'abc123', cleanup: () => { state.cleaned++; } };
    },
    runScan: async () => ({
      scanners: [{ scanner: 'osv', status: 'ok', findingCount: state.findings.length, durationMs: 5 }],
      findings: state.findings, raw: { osv: { projects: [] } },
    }),
    fetchImpl: opts.fetchImpl,
    aiProviderFactory: () => state.provider,
  });
  const worker = createWorker({ queue, handlers: platform.handlers });
  const drain = async () => { while (await worker.runOnce()); };
  return { db, queue, platform, worker, drain, state };
}

async function signup(platform, email, org = 'Acme') {
  const r = await platform.auth.signup({ email, name: email.split('@')[0], password: PASSWORD, orgName: org });
  return { ...r, ctx: { userId: r.user.id, orgId: r.orgId } };
}

test('passwords hash with scrypt, verify, and policy is enforced', () => {
  const h = hashPassword(PASSWORD);
  assert.ok(h.startsWith('scrypt$'));
  assert.equal(verifyPassword(PASSWORD, h), true);
  assert.equal(verifyPassword('wrong', h), false);
  assert.equal(verifyPassword('x', 'garbage'), false);
  assert.ok(checkPasswordPolicy(''));
  assert.equal(checkPasswordPolicy('short'), null);
  assert.equal(checkPasswordPolicy(PASSWORD), null);
});

test('secrets are encrypted at rest and tamper-evident', () => {
  const box = createSecretBox(generateMasterKey());
  const enc = box.encrypt('ghp_supersecret');
  assert.ok(!enc.includes('ghp_'));
  assert.equal(box.decrypt(enc), 'ghp_supersecret');
  assert.throws(() => box.decrypt(enc.slice(0, -4) + 'AAAA'));
  assert.throws(() => createSecretBox('short'), /32 bytes/);
  assert.throws(() => createSecretBox(generateMasterKey()).decrypt(enc));
});

test('signup, login, sessions and logout', async () => {
  const { platform } = setup();
  const s = await signup(platform, 'Ann@Example.com');
  assert.equal(platform.auth.authenticate(s.token).userId, s.user.id);
  assert.equal(platform.auth.me(s.user.id).orgs[0].role, 'owner');

  await assert.rejects(() => platform.auth.signup({ email: 'ann@example.com', password: PASSWORD }), /Unable to create/);
  await assert.rejects(() => platform.auth.signup({ email: 'bad', password: PASSWORD }), /valid email/);
  await assert.rejects(() => platform.auth.signup({ email: 'b@example.com', password: '' }), /Password is required/);

  await assert.rejects(() => platform.auth.login({ email: 'ann@example.com', password: 'nope' }), /Incorrect email or password/);
  await assert.rejects(() => platform.auth.login({ email: 'ghost@example.com', password: PASSWORD }), /Incorrect email or password/);
  const login = await platform.auth.login({ email: 'ann@example.com', password: PASSWORD });
  platform.auth.logout(login.token);
  assert.throws(() => platform.auth.authenticate(login.token), /expired|required/i);
  assert.throws(() => platform.auth.authenticate(null), /required/i);
});

test('sessions expire', async () => {
  let t = Date.now();
  const db = openDatabase(':memory:');
  const platform = createPlatform({ db, queue: createQueue(db), secretBox: createSecretBox(generateMasterKey()), clock: () => t });
  const r = await platform.auth.signup({ email: 'a@example.com', password: PASSWORD });
  assert.ok(platform.auth.authenticate(r.token));
  t += 13 * 3600e3;
  assert.throws(() => platform.auth.authenticate(r.token), /expired/);
});

test('RBAC: viewers read, developers scan, only admins manage', async () => {
  const { platform } = setup();
  const owner = await signup(platform, 'owner@example.com');
  const dev = await signup(platform, 'dev@example.com', 'Other');
  const viewer = await signup(platform, 'view@example.com', 'Other2');
  platform.orgs.addMember(owner.ctx, { email: 'dev@example.com', role: 'developer' });
  platform.orgs.addMember(owner.ctx, { email: 'view@example.com', role: 'viewer' });
  const asDev = { userId: dev.user.id, orgId: owner.ctx.orgId };
  const asViewer = { userId: viewer.user.id, orgId: owner.ctx.orgId };

  const repo = await platform.repos.add(owner.ctx, { url: 'https://github.com/acme/app' });
  assert.equal(platform.repos.list(asViewer).length, 1);
  assert.throws(() => platform.scans.start(asViewer, repo.id), /permission/);
  assert.throws(() => platform.repos.remove(asDev, repo.id), /permission/);
  await assert.rejects(platform.repos.add(asDev, { url: 'https://github.com/acme/other' }), /permission/);
  assert.throws(() => platform.orgs.addMember(asDev, { email: 'x@example.com' }), /permission/);
  assert.throws(() => platform.audit.list(asDev), /permission/);
  assert.ok(platform.scans.start(asDev, repo.id).id);
  assert.ok(platform.audit.list(owner.ctx).length > 0);
});

test('tenant isolation: another org cannot see or touch anything', async () => {
  const { platform, drain } = setup();
  const a = await signup(platform, 'a@example.com', 'A');
  const b = await signup(platform, 'b@example.com', 'B');
  const repo = await platform.repos.add(a.ctx, { url: 'https://github.com/acme/app' });
  const scan = platform.scans.start(a.ctx, repo.id);
  await drain();
  const [row] = platform.scans.findings(a.ctx, scan.id).items;

  // B authenticated, but targeting A's org id: indistinguishable from a missing org.
  const intruder = { userId: b.user.id, orgId: a.ctx.orgId };
  assert.throws(() => platform.repos.list(intruder), /not found/i);
  // B using its own org with A's object ids: not found.
  const own = b.ctx;
  assert.throws(() => platform.repos.get(own, repo.id), /not found/i);
  assert.throws(() => platform.scans.get(own, scan.id), /not found/i);
  assert.throws(() => platform.scans.findings(own, scan.id), /not found/i);
  assert.throws(() => platform.scans.report(own, scan.id, 'csv'), /not found/i);
  assert.throws(() => platform.scans.start(own, repo.id), /not found/i);
  assert.throws(() => platform.findings.update(own, repo.id, row.id, { status: 'fixed' }), /not found/i);
  assert.throws(() => platform.repos.remove(own, repo.id), /not found/i);
  await assert.rejects(platform.ai.explain(own, row.rowId), /AI analysis is turned off|not found/i);
  assert.equal(platform.repos.list(own).length, 0);
  assert.equal(platform.dashboard.overview(own).totals.total, 0);
  assert.equal(platform.audit.list(own).every((e) => e.target !== repo.id), true);
});

test('member management protects the last owner and owner-only changes', async () => {
  const { platform } = setup();
  const owner = await signup(platform, 'o@example.com');
  const admin = await signup(platform, 'ad@example.com', 'X');
  platform.orgs.addMember(owner.ctx, { email: 'ad@example.com', role: 'admin' });
  const asAdmin = { userId: admin.user.id, orgId: owner.ctx.orgId };

  assert.throws(() => platform.orgs.setMemberRole(owner.ctx, owner.user.id, 'viewer'), /at least one owner/);
  assert.throws(() => platform.orgs.removeMember(owner.ctx, owner.user.id), /at least one owner/);
  assert.throws(() => platform.orgs.setMemberRole(asAdmin, admin.user.id, 'owner'), /Only owners/);
  assert.throws(() => platform.orgs.addMember(asAdmin, { email: 'o@example.com', role: 'owner' }), /Only owners|Already/);
  assert.throws(() => platform.orgs.removeMember(asAdmin, owner.user.id), /Only owners/);
  platform.orgs.setMemberRole(owner.ctx, admin.user.id, 'owner');
  platform.orgs.setMemberRole(owner.ctx, owner.user.id, 'admin');
  assert.equal(platform.orgs.listMembers(owner.ctx).find((m) => m.email === 'ad@example.com').role, 'owner');
});

test('SSRF protection rejects dangerous repository URLs', async () => {
  const publicLookup = async () => [{ address: '140.82.112.3' }];
  const ok = await validateRepoUrl('https://github.com/acme/app', { lookup: publicLookup });
  assert.deepEqual([ok.url, ok.fullName, ok.address], ['https://github.com/acme/app.git', 'acme/app', '140.82.112.3']);

  const bad = [
    'http://github.com/acme/app', 'git://github.com/acme/app', 'file:///etc/passwd', 'ssh://git@github.com/acme/app',
    'https://user:pw@github.com/acme/app', 'https://github.com:8443/acme/app', 'https://github.com/acme/app?x=1',
    'https://127.0.0.1/acme/app', 'https://169.254.169.254/latest/meta-data', 'https://[::1]/a/b', 'https://localhost/a/b',
    'https://internal/a/b', 'https://db.internal/a/b', 'https://github.com/a', 'https://github.com/a/../../etc',
    'https://github.com/a/b c', 'not a url', `https://github.com/${'a'.repeat(400)}/b`,
  ];
  for (const url of bad) await assert.rejects(validateRepoUrl(url, { lookup: publicLookup }), undefined, url);

  for (const address of ['10.0.0.5', '192.168.1.1', '172.16.0.9', '127.0.0.1', '169.254.169.254', '100.64.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:10.0.0.1', '0.0.0.0']) {
    await assert.rejects(validateRepoUrl('https://github.com/acme/app', { lookup: async () => [{ address }] }), /non-public/, address);
  }
  // Every DNS answer must be public, not just the first.
  await assert.rejects(validateRepoUrl('https://github.com/acme/app', { lookup: async () => [{ address: '140.82.112.3' }, { address: '10.0.0.1' }] }), /non-public/);
  await assert.rejects(validateRepoUrl('https://github.com/acme/app', { lookup: async () => { throw new Error('nx'); } }), /resolve/);
  await assert.rejects(validateRepoUrl('https://evil.example.com/acme/app', { lookup: publicLookup, allowHosts: ['github.com'] }), /Host not allowed/);
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(isPrivateIp('2606:4700:4700::1111'), false);
  assert.equal(isPrivateIp('garbage'), true);
});

test('branch names are validated', () => {
  assert.equal(validateBranch('feature/x-1.2'), 'feature/x-1.2');
  for (const b of ['--upload-pack=evil', '-x', 'a..b', 'a.lock', '', 'a b', 'a//b', 'x'.repeat(300), null, '$(id)', 'a;b']) {
    assert.throws(() => validateBranch(b), /Invalid branch/, String(b));
  }
});

test('git credentials go through the environment, never the command line', () => {
  const env = gitEnv('/tmp/w', { username: 'x-access-token', token: 'ghp_SECRET' });
  assert.match(Buffer.from(env.GIT_CONFIG_VALUE_0.replace('Authorization: Basic ', ''), 'base64').toString(), /ghp_SECRET/);
  assert.equal(env.GIT_TERMINAL_PROMPT, '0');
  assert.equal(env.ANTHROPIC_API_KEY, undefined);
  assert.equal(gitEnv('/tmp/w', null).GIT_CONFIG_COUNT, undefined);
});

test('sanitizeWorkspace removes symlinks and enforces limits', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-san-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, 'a.txt'), 'hello');
  fs.mkdirSync(path.join(dir, 'sub'));
  fs.writeFileSync(path.join(dir, 'sub', 'b.txt'), 'world');
  let linked = true;
  try { fs.symlinkSync(os.tmpdir(), path.join(dir, 'escape'), 'dir'); } catch { linked = false; }
  const stats = sanitizeWorkspace(dir);
  assert.equal(stats.files, 2);
  assert.equal(stats.bytes, 10);
  if (linked) {
    assert.equal(stats.removedLinks, 1);
    assert.equal(fs.existsSync(path.join(dir, 'escape')), false);
  }
  assert.throws(() => sanitizeWorkspace(dir, { maxBytes: 5, maxFiles: 10 }), /too large/);
  assert.throws(() => sanitizeWorkspace(dir, { maxBytes: 1e9, maxFiles: 1 }), /too many/);
});

test('docker worker arguments are locked down', () => {
  const args = dockerArgs({ workspace: '/data/ws', request: { scanners: ['sca'] } });
  const has = (...seq) => args.join(' ').includes(seq.join(' '));
  assert.ok(has('--user', '10001:10001'));
  assert.ok(args.includes('--read-only'));
  assert.ok(has('--cap-drop', 'ALL'));
  assert.ok(has('--security-opt', 'no-new-privileges'));
  assert.ok(args.includes('--pids-limit'));
  assert.ok(has('--memory', '1g'));
  assert.ok(args.some((a) => a.startsWith('type=bind,source=/data/ws') && a.endsWith('readonly')));
  assert.ok(!args.includes('--privileged'));
  assert.ok(!args.some((a) => /docker\.sock/.test(a)));
  assert.ok(!args.includes('--network=host') && !has('--network', 'host'));
  const env = scrubbedEnv();
  for (const k of Object.keys(env)) assert.ok(!/KEY|SECRET|TOKEN|PASSWORD/i.test(k), k);
});

test('queue retries with backoff, fails permanently, and recovers stranded jobs', () => {
  const db = openDatabase(':memory:');
  let t = 1_000_000;
  const q = createQueue(db, { clock: () => t });
  const id = q.enqueue('x', { a: 1 });
  let job = q.claim();
  assert.equal(job.id, id);
  assert.equal(q.claim(), null, 'running jobs are not handed out twice');
  assert.equal(q.fail(job, new Error('boom')), 'retry');
  assert.equal(q.claim(), null, 'backoff delays the retry');
  t += 31_000;
  job = q.claim();
  assert.equal(job.attempts, 2);
  q.fail(job, new Error('boom'));
  t += 3 * 60_000;
  job = q.claim();
  assert.equal(q.fail(job, new Error('boom')), 'failed');
  assert.equal(q.counts().failed, 1);

  q.enqueue('y', {});
  q.claim();
  t += 16 * 60_000;
  assert.ok(q.claim(), 'a crashed worker does not strand its job');
  const z = q.enqueue('z', {});
  t += 1;
  const j = q.claim();
  assert.equal(q.fail(j, new Error('denied'), { retryable: false }), 'failed');
  assert.ok(z);
});

test('full scan flow: queue, clone, scan, store, lifecycle, notifications', async () => {
  const { platform, drain, state, db } = setup();
  const o = await signup(platform, 'o@example.com');
  const repo = await platform.repos.add(o.ctx, { url: 'https://github.com/acme/app.git', branch: 'main', config: { scanners: ['sca'] } });

  const first = platform.scans.start(o.ctx, repo.id);
  assert.equal(first.status, 'queued');
  assert.throws(() => platform.scans.start(o.ctx, repo.id), /already in progress/);
  await drain();

  const done = platform.scans.get(o.ctx, first.id);
  assert.equal(done.status, 'completed');
  assert.equal(done.commit, 'abc123');
  assert.equal(done.summary.total, 1);
  assert.equal(done.summary.new, 1);
  assert.equal(state.cleaned, 1, 'workspace cleaned up');
  assert.equal(state.clones[0].branch, 'main');
  assert.ok(platform.notifications.list(o.ctx).some((n) => n.kind === 'findings.new'));

  // Triage: assign, acknowledge; suppression needs a reason.
  const fp = state.findings[0].id;
  platform.findings.update(o.ctx, repo.id, fp, { status: 'acknowledged', assigneeId: o.user.id });
  assert.throws(() => platform.findings.update(o.ctx, repo.id, fp, { status: 'suppressed' }), /note/);
  platform.findings.update(o.ctx, repo.id, fp, { status: 'suppressed', note: 'False positive: dev only' });
  assert.equal(platform.scans.findings(o.ctx, first.id).items[0].status, 'suppressed');
  assert.equal(platform.scans.findings(o.ctx, first.id, { status: 'open' }).total, 0);
  assert.equal(platform.scans.get(o.ctx, first.id).summary.total, 1, 'summary is a snapshot');
  const hist = platform.findings.history(o.ctx, repo.id, fp);
  assert.equal(hist.length, 2);
  assert.match(hist[1].detail, /suppressed/);
  platform.findings.update(o.ctx, repo.id, fp, { status: 'open' });

  // Second scan: the finding is gone -> auto fixed.
  state.findings = [];
  const second = platform.scans.start(o.ctx, repo.id);
  await drain();
  assert.equal(platform.scans.get(o.ctx, second.id).summary.fixed, 1);
  const states = db.prepare('SELECT status FROM finding_states WHERE fingerprint = ?').get(fp);
  assert.equal(states.status, 'fixed');

  // Third scan: it comes back -> reopened.
  state.findings = [finding()];
  const third = platform.scans.start(o.ctx, repo.id);
  await drain();
  assert.equal(platform.scans.findings(o.ctx, third.id).items[0].status, 'open');
  assert.ok(platform.findings.history(o.ctx, repo.id, fp).some((h) => h.action === 'reopened'));

  const ov = platform.dashboard.overview(o.ctx);
  assert.equal(ov.repositories.length, 1);
  assert.equal(ov.totals.high, 1);
  assert.equal(ov.trend.length, 3);
  assert.ok(ov.recentScans.length === 3);
});

test('scan failures are classified: access errors fail fast, others retry then fail', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app' });

  let calls = 0;
  const db = f.db;
  const failing = createPlatform({
    db, queue: f.queue, secretBox: createSecretBox(generateMasterKey()),
    validateUrl: async () => ({ url: 'https://github.com/acme/app.git', host: 'github.com', fullName: 'acme/app', address: '1.1.1.1' }),
    clone: async () => { calls++; throw new Error('Repository access denied. Check the provider connection and its permissions'); },
  });
  const scan = f.platform.scans.start(o.ctx, repo.id);
  const worker = createWorker({ queue: f.queue, handlers: failing.handlers });
  while (await worker.runOnce());
  const s = f.platform.scans.get(o.ctx, scan.id);
  assert.equal(s.status, 'failed');
  assert.match(s.error, /access denied/);
  assert.equal(calls, 1, 'no retries for access errors');
  assert.ok(f.platform.notifications.list(o.ctx).some((n) => n.kind === 'scan.failed'));
  assert.equal(f.platform.dashboard.overview(o.ctx).failedScans.length, 1);
});

test('transient failures are retried and the scan returns to queued', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app' });
  let attempt = 0;
  const flaky = createPlatform({
    db: f.db, queue: f.queue, secretBox: createSecretBox(generateMasterKey()),
    validateUrl: async () => ({ url: 'https://github.com/acme/app.git', host: 'github.com', fullName: 'acme/app', address: '1.1.1.1' }),
    clone: async () => ({ dir: os.tmpdir(), commit: 'c1', cleanup() {} }),
    runScan: async () => { attempt++; if (attempt === 1) throw new Error('network blip'); return { scanners: [{ scanner: 'osv', status: 'ok', findingCount: 0 }], findings: [], raw: {} }; },
  });
  const scan = f.platform.scans.start(o.ctx, repo.id);
  const worker = createWorker({ queue: f.queue, handlers: flaky.handlers });
  assert.equal(await worker.runOnce(), true);
  assert.equal(f.platform.scans.get(o.ctx, scan.id).status, 'queued');
  assert.equal(await worker.runOnce(), false, 'waiting for backoff');
  f.db.prepare("UPDATE jobs SET run_at = '2000-01-01T00:00:00.000Z' WHERE status = 'queued'").run();
  await worker.runOnce();
  assert.equal(f.platform.scans.get(o.ctx, scan.id).status, 'completed');
});

test('scanner results where every scanner failed mark the scan failed', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app' });
  const p = createPlatform({
    db: f.db, queue: f.queue, secretBox: createSecretBox(generateMasterKey()),
    validateUrl: async () => ({ url: 'https://github.com/acme/app.git', host: 'github.com', fullName: 'acme/app', address: '1.1.1.1' }),
    clone: async () => ({ dir: '/work/dir', commit: 'c', cleanup() {} }),
    runScan: async () => ({ scanners: [{ scanner: 'semgrep', status: 'error', error: 'semgrep failed in /work/dir/x', findingCount: 0 }], findings: [], raw: {} }),
  });
  const scan = f.platform.scans.start(o.ctx, repo.id);
  const worker = createWorker({ queue: f.queue, handlers: p.handlers });
  while (await worker.runOnce());
  const s = f.platform.scans.get(o.ctx, scan.id);
  assert.equal(s.status, 'queued', 'transient: retried first');
  f.db.prepare("UPDATE jobs SET run_at = '2000-01-01T00:00:00.000Z', attempts = 2 WHERE status = 'queued'").run();
  while (await worker.runOnce());
  assert.equal(f.platform.scans.get(o.ctx, scan.id).status, 'failed');
  assert.ok(!f.platform.scans.get(o.ctx, scan.id).error.includes('/work/dir'), 'workspace paths are scrubbed from errors');
});

test('provider tokens are validated, stored encrypted, never returned, and used for cloning', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, auth: init.headers.authorization });
    const json = url.endsWith('/user') ? { login: 'octocat' }
      : url.includes('/user/repos') ? [{ full_name: 'acme/private-app', default_branch: 'dev', private: true }]
        : url.includes('/branches') ? [{ name: 'dev' }, { name: 'main' }] : {};
    return { ok: true, status: 200, headers: { get: () => null }, json: async () => json };
  };
  const f = setup({ fetchImpl });
  const o = await signup(f.platform, 'o@example.com');
  const conn = await f.platform.connections.connect(o.ctx, { provider: 'github', token: 'ghp_abcdefghijkl' });
  assert.equal(conn.account, 'octocat');
  assert.equal(calls[0].url, 'https://api.github.com/user');

  const stored = f.db.prepare('SELECT token_enc FROM provider_connections').get().token_enc;
  assert.ok(!stored.includes('ghp_'));
  assert.ok(!JSON.stringify(await f.platform.connections.list(o.ctx)).includes('ghp_'));

  const remote = await f.platform.connections.listRemoteRepos(o.ctx, conn.id);
  assert.equal(remote[0].fullName, 'acme/private-app');
  assert.deepEqual(await f.platform.connections.listBranches(o.ctx, conn.id, 'acme/private-app'), ['dev', 'main']);
  await assert.rejects(f.platform.connections.listBranches(o.ctx, conn.id, '../../etc'), /Invalid repository name/);

  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/private-app', connectionId: conn.id });
  await assert.rejects(f.platform.repos.add(o.ctx, { url: 'https://gitlab.com/acme/x', connectionId: conn.id }), /different Git provider/);
  f.platform.scans.start(o.ctx, repo.id);
  await f.drain();
  assert.deepEqual(f.state.clones[0].auth, { username: 'x-access-token', token: 'ghp_abcdefghijkl' });

  const other = await signup(f.platform, 'x@example.com', 'X');
  await assert.rejects(f.platform.repos.add(other.ctx, { url: 'https://github.com/acme/y', connectionId: conn.id }), /not found/i);
  await assert.rejects(f.platform.connections.connect(o.ctx, { provider: 'svn', token: 'abcdefghij' }), /Unsupported/);
});

test('webhooks need a valid signature and only scan monitored branches', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app', branch: 'main' });
  const secret = f.platform.repos.webhookSecret(o.ctx, repo.id);
  const sign = (body) => `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;
  const push = (ref) => JSON.stringify({ ref });

  assert.throws(() => f.platform.automation.handleWebhook(repo.id, {}, push('refs/heads/main')), /signature/);
  assert.throws(() => f.platform.automation.handleWebhook(repo.id, { 'X-Hub-Signature-256': 'sha256=00' }, push('refs/heads/main')), /signature/);
  assert.throws(() => f.platform.automation.handleWebhook('nope', {}, '{}'), /Not found/);

  const body = push('refs/heads/main');
  const r1 = f.platform.automation.handleWebhook(repo.id, { 'X-Hub-Signature-256': sign(body) }, body);
  assert.equal(r1.scanned, true);
  assert.equal(f.platform.scans.get(o.ctx, r1.scanId).trigger, 'webhook');

  const other = push('refs/heads/feature');
  assert.equal(f.platform.automation.handleWebhook(repo.id, { 'x-hub-signature-256': sign(other) }, other).scanned, false);

  const gl = f.platform.automation.handleWebhook(repo.id, { 'X-Gitlab-Token': secret }, push('refs/heads/main'));
  assert.equal(gl.scanned, false, 'duplicate while one is already queued');
  assert.throws(() => f.platform.automation.handleWebhook(repo.id, { 'X-Gitlab-Token': 'wrong' }, body), /signature/);
});

test('schedules enqueue scans when due and reschedule', async () => {
  let t = Date.now();
  const f = setup();
  const platform = createPlatform({
    db: f.db, queue: f.queue, secretBox: createSecretBox(generateMasterKey()), clock: () => t,
    validateUrl: async () => ({ url: 'https://github.com/acme/app.git', host: 'github.com', fullName: 'acme/app', address: '1.1.1.1' }),
  });
  const o = await platform.auth.signup({ email: 'o@example.com', password: PASSWORD });
  const ctx = { userId: o.user.id, orgId: o.orgId };
  const repo = await platform.repos.add(ctx, { url: 'https://github.com/acme/app' });
  assert.throws(() => platform.repos.setSchedule(ctx, repo.id, 'monthly'), /Schedule/);
  platform.repos.setSchedule(ctx, repo.id, 'daily');
  assert.deepEqual(platform.automation.tickSchedules(), []);
  t += 25 * 3600e3;
  const started = platform.automation.tickSchedules();
  assert.equal(started.length, 1);
  assert.equal(platform.scans.get(ctx, started[0]).trigger, 'schedule');
  assert.deepEqual(platform.automation.tickSchedules(), [], 'rescheduled for tomorrow');
  platform.repos.setSchedule(ctx, repo.id, null);
});

test('retention purge removes old scans and their findings', async () => {
  let t = Date.now();
  const f = setup();
  const platform = createPlatform({
    db: f.db, queue: f.queue, secretBox: createSecretBox(generateMasterKey()), clock: () => t,
    validateUrl: async () => ({ url: 'https://github.com/acme/app.git', host: 'github.com', fullName: 'acme/app', address: '1.1.1.1' }),
    clone: async () => ({ dir: os.tmpdir(), commit: 'c', cleanup() {} }),
    runScan: async () => ({ scanners: [{ scanner: 'osv', status: 'ok', findingCount: 1 }], findings: [finding()], raw: {} }),
  });
  const o = await platform.auth.signup({ email: 'o@example.com', password: PASSWORD });
  const ctx = { userId: o.user.id, orgId: o.orgId };
  const repo = await platform.repos.add(ctx, { url: 'https://github.com/acme/app' });
  platform.scans.start(ctx, repo.id);
  const worker = createWorker({ queue: f.queue, handlers: platform.handlers });
  while (await worker.runOnce());
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM findings').get().n, 1);

  assert.throws(() => platform.orgs.updateSettings(ctx, { retentionDays: 0 }), /between/);
  platform.orgs.updateSettings(ctx, { retentionDays: 30 });
  t += 29 * 86400e3;
  assert.equal(platform.automation.purge().scansDeleted, 0);
  t += 2 * 86400e3;
  assert.equal(platform.automation.purge().scansDeleted, 1);
  for (const table of ['findings', 'scan_raw']) assert.equal(f.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, 0);
});

test('AI is off by default, consent is per org, and output is saved separately', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app' });
  f.platform.scans.start(o.ctx, repo.id);
  await f.drain();
  const row = f.platform.scans.findings(o.ctx, f.platform.scans.list(o.ctx)[0].id).items[0];

  await assert.rejects(f.platform.ai.explain(o.ctx, row.rowId), /turned off/);
  f.platform.orgs.updateSettings(o.ctx, { aiEnabled: true });
  await assert.rejects(f.platform.ai.explain(o.ctx, row.rowId), /No AI provider/);

  f.state.provider = createMockProvider('Because of X. ' + row.id);
  const out = await f.platform.ai.explain(o.ctx, row.rowId);
  assert.equal(out.meta.aiGenerated, true);
  assert.equal((await f.platform.ai.ask(o.ctx, repo.id, 'What first?')).citedFindingIds[0], row.id);
  assert.ok((await f.platform.ai.summary(o.ctx, repo.id)).text);
  assert.equal(f.platform.ai.history(o.ctx, repo.id).length, 3);
  assert.equal(f.db.prepare('SELECT severity FROM findings').get().severity, 'high', 'AI never alters findings');

  assert.equal(f.platform.orgs.updateSettings(o.ctx, { aiSendCode: true }).aiSendCode, true);
  assert.equal(f.platform.orgs.updateSettings(o.ctx, { aiEnabled: false }).aiSendCode, false, 'turning AI off revokes code sharing');

  const viewer = await signup(f.platform, 'v@example.com', 'V');
  f.platform.orgs.addMember(o.ctx, { email: 'v@example.com', role: 'viewer' });
  f.platform.orgs.updateSettings(o.ctx, { aiEnabled: true });
  await assert.rejects(f.platform.ai.explain({ userId: viewer.user.id, orgId: o.ctx.orgId }, row.rowId), /permission/);
});

test('reports export per scan in every format', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app' });
  const scan = f.platform.scans.start(o.ctx, repo.id);
  await f.drain();
  assert.match(f.platform.scans.report(o.ctx, scan.id, 'csv').body, /lodash/);
  assert.match(f.platform.scans.report(o.ctx, scan.id, 'markdown').body, /Security report: acme\/app/);
  assert.equal(JSON.parse(f.platform.scans.report(o.ctx, scan.id, 'cyclonedx').body).bomFormat, 'CycloneDX');
  assert.equal(JSON.parse(f.platform.scans.report(o.ctx, scan.id, 'json').body).summary.total, 1);
  assert.throws(() => f.platform.scans.report(o.ctx, scan.id, 'pdf'), /Format/);
  assert.ok(f.platform.audit.list(o.ctx, { action: 'report.export' }).length >= 4);
});

test('teams, repo config validation and cancelling queued scans', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const team = f.platform.teams.create(o.ctx, { name: 'Platform' });
  assert.throws(() => f.platform.teams.create(o.ctx, { name: 'Platform' }), /already exists/);
  f.platform.teams.addMember(o.ctx, team.id, o.user.id);
  assert.deepEqual(f.platform.teams.list(o.ctx)[0].members, [o.user.id]);

  await assert.rejects(f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/a', config: { scanners: ['rm -rf'] } }), /Invalid scanner/);
  await assert.rejects(f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/a', config: { branches: ['--evil'] } }), /Invalid branch/);
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/a', teamId: team.id, config: { scanners: ['sca', 'gitleaks'], threshold: 'medium' } });
  await assert.rejects(f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/a' }), /already connected/);
  assert.equal(repo.teamId, team.id);

  const scan = f.platform.scans.start(o.ctx, repo.id);
  assert.equal(f.platform.scans.cancel(o.ctx, scan.id).status, 'cancelled');
  await f.drain();
  assert.equal(f.platform.scans.get(o.ctx, scan.id).status, 'cancelled');
  assert.throws(() => f.platform.scans.start(o.ctx, repo.id, { branch: '--bad' }), /Invalid branch/);
});

test('deleting an org or repo removes its data', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const repo = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app' });
  f.platform.scans.start(o.ctx, repo.id);
  await f.drain();
  f.platform.repos.remove(o.ctx, repo.id);
  for (const t of ['repositories', 'scans', 'findings', 'finding_states']) assert.equal(f.db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n, 0, t);

  const repo2 = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/app2' });
  f.platform.scans.start(o.ctx, repo2.id);
  await f.drain();
  f.platform.orgs.delete(o.ctx);
  for (const t of ['orgs', 'memberships', 'repositories', 'scans', 'findings', 'scan_raw', 'jobs']) assert.equal(f.db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n, 0, t);
});

test('organisation trend sums the latest result of every repository', async () => {
  const f = setup();
  const o = await signup(f.platform, 'o@example.com');
  const a = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/a' });
  const b = await f.platform.repos.add(o.ctx, { url: 'https://github.com/acme/b' });
  const other = (pkg) => finding({ location: { file: 'package-lock.json', package: pkg, version: '1.0.0', ecosystem: 'npm', direct: true } });

  f.state.findings = [finding()];
  f.platform.scans.start(o.ctx, a.id);
  await f.drain();
  f.state.findings = [other('qs'), other('minimist')];
  f.platform.scans.start(o.ctx, b.id);
  await f.drain();

  const trend = f.platform.dashboard.overview(o.ctx).trend;
  assert.deepEqual(trend.map((p) => p.total), [1, 3], 'second point adds repo b to repo a');
  assert.equal(trend.at(-1).high, 3);
});
