'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { runSandboxed, dockerArgs, scrubbedEnv } = require('../src/platform/sandbox');
const { createAcaExecutor } = require('../src/platform/aca');
const { gitEnv } = require('../src/platform/git');

function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) { saved[k] = process.env[k]; if (vars[k] === undefined) delete process.env[k]; else process.env[k] = vars[k]; }
  const restore = () => { for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } };
  return Promise.resolve().then(fn).finally(restore);
}

test('docker mode fails closed when no egress proxy is configured', async () => {
  await withEnv({ VULNSIGHT_EGRESS_PROXY: undefined, VULNSIGHT_ALLOW_NO_PROXY: undefined }, async () => {
    let ran = false;
    await assert.rejects(runSandboxed('/w', { mode: 'docker', exec: async () => { ran = true; return { stdout: '{}' }; } }), /VULNSIGHT_EGRESS_PROXY/);
    assert.equal(ran, false, 'no container is started without the proxy');
  });
});

test('docker workers use the internal network and are told to use the proxy', async () => {
  await withEnv({ VULNSIGHT_EGRESS_PROXY: 'http://vulnsight-proxy:3128' }, async () => {
    let args;
    await runSandboxed('/w', { mode: 'docker', exec: async (cmd, a) => { args = a; return { stdout: '{}' }; } });
    assert.equal(args[args.indexOf('--network') + 1], 'vulnsight-scan');
    assert.ok(args.includes('HTTPS_PROXY=http://vulnsight-proxy:3128'));
    assert.ok(args.includes('NODE_USE_ENV_PROXY=1'), 'node clients only honour the proxy with this flag, set at startup');
    assert.ok(!args.some((a) => /^--network=?host$/.test(a)) && !args.includes('host'));
  });
  assert.ok(!dockerArgs({ workspace: '/w', request: {}, proxy: undefined }).some((a) => /HTTPS_PROXY/.test(a)));
});

test('process-mode scanners and git inherit the proxy settings', async () => {
  await withEnv({ HTTPS_PROXY: 'http://p:3128', NODE_USE_ENV_PROXY: '1' }, () => {
    const env = scrubbedEnv();
    assert.equal(env.HTTPS_PROXY, 'http://p:3128');
    assert.equal(env.NODE_USE_ENV_PROXY, '1');
    assert.equal(gitEnv('/nonexistent-dir-xyz', null).HTTPS_PROXY, 'http://p:3128');
  });
});

test('the Azure executor tells the job which proxy to use', async () => {
  const seen = [];
  const fetchImpl = async (url, init = {}) => {
    seen.push({ url: String(url), body: init.body && JSON.parse(init.body) });
    if (String(url).includes('/start')) return { ok: true, status: 200, json: async () => ({ name: 'e1' }) };
    if (String(url).includes('/executions/')) return { ok: true, status: 200, json: async () => ({ properties: { status: 'Succeeded' } }) };
    if (init.method === 'GET') return { ok: true, status: 200, json: async () => ({ ok: true, report: { findings: [], scanners: [] }, commit: 'c' }) };
    return { ok: true, status: 202 };
  };
  const execute = createAcaExecutor({
    subscriptionId: 's', resourceGroup: 'rg', jobName: 'job', image: 'img', storageAccount: 'acct',
    getToken: async () => 't', fetchImpl, sleep: async () => {}, proxyUrl: 'http://10.40.2.4:3128',
  });
  await execute({ validated: { url: 'https://github.com/a/b.git' }, branch: 'main', scanId: 'x1' });
  const env = Object.fromEntries(seen.find((c) => c.url.includes('/start')).body.template.containers[0].env.map((e) => [e.name, e.value]));
  assert.equal(env.HTTPS_PROXY, 'http://10.40.2.4:3128');
  assert.equal(env.NODE_USE_ENV_PROXY, '1');
  assert.match(env.NO_PROXY, /127\.0\.0\.1/, 'the local managed-identity endpoint is never proxied');
});
