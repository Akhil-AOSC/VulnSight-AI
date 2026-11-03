'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/platform/db');
const { createSecretBox, generateMasterKey } = require('../src/platform/crypto');
const { createQueue, createWorker } = require('../src/platform/queue');
const { createPlatform } = require('../src/platform/service');
const { createAcaExecutor, createAzureIdentity } = require('../src/platform/aca');
const { runJob, SENSITIVE } = require('../src/platform/scan-job');
const { acaExecutorFromEnv } = require('../src/platform/app');
const { createFinding } = require('../src/findings');

const SUB = '00000000-0000-0000-0000-000000000001';
const VALIDATED = { url: 'https://github.com/acme/app.git', host: 'github.com', fullName: 'acme/app', address: '140.82.112.3' };
const REPORT = {
  target: { path: '/work' }, startedAt: 'x', raw: {},
  scanners: [{ scanner: 'osv', status: 'ok', findingCount: 1, durationMs: 3 }],
  findings: [createFinding({ category: 'sca', scanner: { name: 'osv' }, title: 'Proto', severity: 'high', identifiers: { primary: 'GHSA-1' }, location: { file: 'package-lock.json', package: 'lodash', version: '4.17.15', ecosystem: 'npm', direct: true } })],
};

// A fake of the three Azure services we talk to. Starting the job runs the real job entry point
// with the environment from the request, so executor and job are tested together.
function fakeAzure({ statuses = ['Running', 'Succeeded'], job = {}, startStatus = 200 } = {}) {
  const log = { starts: [], stops: [], blobs: new Map(), calls: [], tokens: [] };
  let polls = 0;
  const jobDeps = {
    identity: async (resource) => { log.tokens.push(resource); return `tok:${resource}`; },
    validate: async () => VALIDATED,
    clone: async (v, o) => { log.clone = o; return { dir: '/tmp/vulnsight-abc', commit: 'deadbeef', cleanup() { log.cleaned = true; } }; },
    pipeline: async (target, o) => { log.pipelineOpts = o; return JSON.parse(JSON.stringify(REPORT)); },
    log: () => {},
    ...job,
  };
  const fetchImpl = async (url, init = {}) => {
    url = String(url);
    log.calls.push(`${init.method || 'GET'} ${url.replace(/\?.*/, '')}`);
    const json = (status, body) => ({ ok: status < 300, status, json: async () => body, text: async () => JSON.stringify(body) });
    if (url.includes('/jobs/') && url.includes('/start')) {
      const body = JSON.parse(init.body);
      log.starts.push(body);
      const env = Object.fromEntries(body.template.containers[0].env.map((e) => [e.name, e.value]));
      log.jobEnvAtStart = { ...env };
      await runJob({ env, fetchImpl, ...jobDeps });
      return json(startStatus, { name: 'exec-1' });
    }
    if (url.includes('/stop')) { log.stops.push(url); return json(200, {}); }
    if (url.includes('/executions/')) return json(200, { properties: { status: statuses[Math.min(polls++, statuses.length - 1)] } });
    if (url.includes('.blob.core.windows.net')) {
      const key = new URL(url).pathname;
      if (init.method === 'PUT') { log.blobs.set(key, init.body); log.blobAuth = init.headers.authorization; return { ok: true, status: 201 }; }
      if (init.method === 'DELETE') { log.blobs.delete(key); return { ok: true, status: 202 }; }
      return log.blobs.has(key) ? json(200, JSON.parse(log.blobs.get(key))) : json(404, {});
    }
    throw new Error(`unexpected request ${url}`);
  };
  const getToken = async (resource) => `tok:${resource}`;
  return { fetchImpl, getToken, log };
}

const executorFor = (az, extra = {}) => createAcaExecutor({
  subscriptionId: SUB, resourceGroup: 'rg-vulnsight', jobName: 'vulnsight-scan', image: 'acr.azurecr.io/worker:1',
  storageAccount: 'vulnsightst123', fetchImpl: az.fetchImpl, getToken: az.getToken, pollMs: 1, sleep: async () => {}, ...extra,
});

test('executor starts the job, polls it, reads and deletes the result blob', async () => {
  const az = fakeAzure();
  const out = await executorFor(az)({ validated: VALIDATED, branch: 'main', auth: null, config: { scanners: ['sca'], threshold: 'medium' }, scanId: 'scan-1' });
  assert.equal(out.commit, 'deadbeef');
  assert.equal(out.report.findings.length, 1);
  assert.equal(out.report.target.path, '<repo>', 'job removes the workspace path');
  assert.deepEqual(az.log.calls.filter((c) => c.startsWith('POST')).map((c) => c.split('/').slice(-1)[0]), ['start']);
  assert.ok(az.log.calls[0].includes(`/subscriptions/${SUB}/resourceGroups/rg-vulnsight/providers/Microsoft.App/jobs/vulnsight-scan/start`));
  assert.equal(az.log.blobs.size, 0, 'result blob is deleted after reading');
  assert.equal(az.log.jobEnvAtStart.VS_BRANCH, 'main');
  assert.equal(az.log.jobEnvAtStart.VS_SCANNERS, 'sca');
  assert.equal(az.log.jobEnvAtStart.VS_RESULT_URL, 'https://vulnsightst123.blob.core.windows.net/scan-results/scan-1.json');
  assert.deepEqual(az.log.pipelineOpts.scanners, ['sca']);
  assert.equal(az.log.pipelineOpts.threshold, 'medium');
  assert.equal(az.log.blobAuth, 'Bearer tok:https://storage.azure.com/');
  assert.ok(az.log.cleaned, 'job removes its workspace');
});

test('the executor refuses to inline a Git credential in the job start request', async () => {
  const az = fakeAzure();
  const auth = { username: 'x-access-token', token: 'ghp_SECRETTOKEN' };
  // No grant mechanism configured: fail closed rather than fall back to putting the token in the request.
  await assert.rejects(executorFor(az)({ validated: VALIDATED, branch: 'main', auth, scanId: 'scan-2' }), /securely/);
  assert.equal(az.log.starts.length, 0, 'the job was never started');
  await assert.rejects(executorFor(az, { grantUrl: 'https://api.example.test' })({ validated: VALIDATED, branch: 'main', auth, scanId: 'scan-2' }), /securely/, 'no issueGrant function');
});

test('the job scrubs its grant secret and identity from the environment before scanners run', async () => {
  let envDuringScan;
  const env = {
    VS_SCAN_ID: 's1', VS_REPO_URL: 'https://github.com/a/b.git', VS_BRANCH: 'main',
    VS_RESULT_URL: 'https://acct.blob.core.windows.net/scan-results/s1.json',
    VS_GRANT_URL: 'https://api.example.test', VS_GRANT_SECRET: 'one-time-secret-value-123456',
    IDENTITY_HEADER: 'h', IDENTITY_ENDPOINT: 'http://localhost/msi',
  };
  let redeemed;
  const fetchImpl = async (url, init) => {
    if (String(url).endsWith('/api/v1/internal/scan-grant')) { redeemed = JSON.parse(init.body); return { ok: true, status: 200, json: async () => ({ username: 'u', token: 't' }) }; }
    return { ok: true, status: 201 };
  };
  await runJob({
    env, fetchImpl, identity: async () => 'tok', validate: async () => VALIDATED, log: () => {},
    clone: async (v, o) => ({ dir: '/tmp/x', commit: 'c', cleanup() {}, auth: o.auth }),
    pipeline: async () => { envDuringScan = { ...env }; return JSON.parse(JSON.stringify(REPORT)); },
  });
  assert.deepEqual(redeemed, { scanId: 's1', secret: 'one-time-secret-value-123456' });
  for (const k of SENSITIVE) assert.equal(envDuringScan[k], undefined, `${k} must not be visible to scanners`);
});

test('a scan that fails inside the job surfaces its safe error message', async () => {
  const az = fakeAzure({ job: { pipeline: async () => { throw new Error('boom in /tmp/vulnsight-abc/src/file.js'); } } });
  await assert.rejects(executorFor(az)({ validated: VALIDATED, branch: 'main', scanId: 'scan-3' }), (e) => /boom in <workspace>/.test(e.message) && !/vulnsight-abc/.test(e.message));
  assert.equal(az.log.blobs.size, 0);
});

test('the job re-validates the URL and refuses a bad result URL', async () => {
  const az = fakeAzure({ job: { validate: async () => { throw new Error('That host resolves to a non-public address'); } } });
  await assert.rejects(executorFor(az)({ validated: VALIDATED, branch: 'main', scanId: 'scan-4' }), /non-public/);
  await assert.rejects(runJob({ env: { VS_REPO_URL: 'https://github.com/a/b', VS_BRANCH: 'main', VS_RESULT_URL: 'http://169.254.169.254/x.json' }, identity: async () => 't', fetchImpl: async () => ({ ok: true }) }), /Invalid result URL/);
  await assert.rejects(runJob({ env: { VS_REPO_URL: 'https://github.com/a/b', VS_BRANCH: 'main', VS_RESULT_URL: 'https://evil.example.com/x.json' }, identity: async () => 't', fetchImpl: async () => ({ ok: true }) }), /Invalid result URL/);
  await assert.rejects(runJob({ env: {}, identity: async () => 't' }), /missing required parameters/);
});

test('executor times out, stops the execution and reports a failed job', async () => {
  let t = 0;
  const stuck = fakeAzure({ statuses: ['Running'] });
  await assert.rejects(executorFor(stuck, { clock: () => (t += 400000), timeoutMs: 600000 })({ validated: VALIDATED, branch: 'main', scanId: 'scan-5' }), /timed out/);
  assert.equal(stuck.log.stops.length, 1);

  const failed = fakeAzure({ statuses: ['Failed'], job: { validate: async () => { throw new Error('x'); } } });
  failed.log.blobs.clear();
  const origFetch = failed.fetchImpl;
  failed.fetchImpl = async (url, init = {}) => (String(url).includes('blob.core') && init.method === 'GET' ? { ok: false, status: 404, json: async () => ({}) } : origFetch(url, init));
  await assert.rejects(executorFor(failed)({ validated: VALIDATED, branch: 'main', scanId: 'scan-6' }), /scan job failed/);
});

test('executor passes the job identity client id (the start request replaces the job env)', async () => {
  const az = fakeAzure();
  await executorFor(az, { jobClientId: 'client-123' })({ validated: VALIDATED, branch: 'main', scanId: 'scan-8' });
  assert.equal(az.log.jobEnvAtStart.AZURE_CLIENT_ID, 'client-123');
});

test('executor rejects bad configuration and unsafe ids', async () => {
  const az = fakeAzure();
  assert.throws(() => createAcaExecutor({ subscriptionId: SUB, resourceGroup: '../x', jobName: 'j', image: 'i', storageAccount: 's', getToken: az.getToken }), /resourceGroup/);
  assert.throws(() => createAcaExecutor({ subscriptionId: SUB, resourceGroup: 'rg', jobName: 'j', storageAccount: 's', getToken: az.getToken }), /image/);
  await assert.rejects(executorFor(az)({ validated: VALIDATED, branch: 'main', scanId: '../../etc/passwd' }), /Invalid scan id/);
  const noStart = fakeAzure({ startStatus: 500 });
  await assert.rejects(executorFor(noStart)({ validated: VALIDATED, branch: 'main', scanId: 'scan-7' }), /HTTP 500/);
  assert.throws(() => acaExecutorFromEnv({}), /VULNSIGHT_ACA_SUBSCRIPTION/);
});

test('managed identity tokens come from the platform endpoint and are cached', async () => {
  let calls = 0;
  const seen = [];
  const getToken = createAzureIdentity({
    endpoint: 'http://127.0.0.1:42356/msi/token', header: 'hdr', clientId: 'cid',
    fetchImpl: async (url, init) => { calls++; seen.push({ url: String(url), header: init.headers['X-IDENTITY-HEADER'] }); return { ok: true, json: async () => ({ access_token: 'abc', expires_on: String(Math.floor(Date.now() / 1000) + 3600) }) }; },
  });
  assert.equal(await getToken('https://storage.azure.com/'), 'abc');
  assert.equal(await getToken('https://storage.azure.com/'), 'abc');
  assert.equal(calls, 1);
  assert.match(seen[0].url, /resource=https%3A%2F%2Fstorage.azure.com%2F/);
  assert.match(seen[0].url, /client_id=cid/);
  assert.equal(seen[0].header, 'hdr');
  await assert.rejects(createAzureIdentity({})('https://x/'), /not available/);
});

test('platform scans through the Azure executor without cloning locally', async () => {
  const db = openDatabase(':memory:');
  const queue = createQueue(db);
  const az = fakeAzure();
  let localClones = 0;
  const platform = createPlatform({
    db, queue, secretBox: createSecretBox(generateMasterKey()),
    validateUrl: async () => VALIDATED,
    clone: async () => { localClones++; throw new Error('must not clone locally'); },
    executor: executorFor(az),
  });
  const o = await platform.auth.signup({ email: 'o@example.com', password: 'Correct-Horse-9' });
  const ctx = { userId: o.user.id, orgId: o.orgId };
  const repo = await platform.repos.add(ctx, { url: 'https://github.com/acme/app', config: { scanners: ['sca'] } });
  const scan = platform.scans.start(ctx, repo.id);
  const worker = createWorker({ queue, handlers: platform.handlers });
  while (await worker.runOnce());

  const done = platform.scans.get(ctx, scan.id);
  assert.equal(done.status, 'completed');
  assert.equal(done.commit, 'deadbeef');
  assert.equal(done.summary.total, 1);
  assert.equal(localClones, 0);
  assert.equal(platform.scans.findings(ctx, scan.id).items[0].location.package, 'lodash');
});
