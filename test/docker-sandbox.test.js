'use strict';

// Verifies, inside a REAL container, that the flags in dockerArgs() actually isolate a scan.
// Skipped unless Docker is available and VULNSIGHT_DOCKER_TEST=1:
//   VULNSIGHT_DOCKER_TEST=1 npm test
// Uses a plain node:22-alpine image (pulled once); it does not need the full worker image.
//
// NOT covered here: the egress allowlist network ("vulnsight-egress") is operator-created, so its
// rules cannot be tested without that network. Only the "no network at all" case is tested.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { dockerArgs, runSandboxed } = require('../src/platform/sandbox');

const IMAGE = 'node:22-alpine';
const hasDocker = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' }).status === 0;
const SKIP = process.env.VULNSIGHT_DOCKER_TEST !== '1' ? 'set VULNSIGHT_DOCKER_TEST=1 to run' : hasDocker ? false : 'docker is not available';

let workspace;
test.before(() => {
  if (SKIP) return;
  spawnSync('docker', ['pull', IMAGE], { stdio: 'ignore' });
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-dock-'));
  fs.writeFileSync(path.join(workspace, 'file.txt'), 'hello');
});
test.after(() => { if (workspace) fs.rmSync(workspace, { recursive: true, force: true }); });

// Runs a shell snippet inside the sandbox flags. Network 'none' unless a test says otherwise.
function probe(script, over = {}) {
  const args = dockerArgs({ workspace, request: {}, image: IMAGE, network: 'none', command: ['sh', '-c', script], ...over });
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: 60000, env: { ...process.env, ANTHROPIC_API_KEY: 'parent-secret', VULNSIGHT_MASTER_KEY: 'parent-master-key' } });
  return { code: r.status, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
}

test('runs as an unprivileged user with no capabilities', { skip: SKIP }, () => {
  assert.equal(probe('id -u').out, '10001');
  assert.match(probe('grep CapEff /proc/self/status').out, /0000000000000000$/);
  assert.notEqual(probe('apk add --no-cache curl').code, 0, 'cannot install software');
});

test('root filesystem and the mounted workspace are read-only', { skip: SKIP }, () => {
  assert.notEqual(probe('touch /owned').code, 0, 'root fs is read-only');
  assert.notEqual(probe('touch /work/injected').code, 0, 'workspace is read-only');
  assert.equal(probe('cat /work/file.txt').out, 'hello', 'workspace is readable');
  assert.equal(probe('touch /tmp/ok && echo yes').out, 'yes', 'tmpfs is writable');
  assert.notEqual(probe('cp /bin/sh /tmp/sh && /tmp/sh -c true').code, 0, 'tmpfs is noexec');
});

test('application secrets are not present in the container', { skip: SKIP }, () => {
  const env = probe('env').out;
  assert.ok(!/parent-secret|parent-master-key|ANTHROPIC|MASTER_KEY/.test(env));
});

test('no network when the network is none', { skip: SKIP }, () => {
  assert.notEqual(probe('wget -q -T 3 -O- http://1.1.1.1 || exit 1').code, 0);
});

test('memory and process limits are enforced', { skip: SKIP }, () => {
  const mem = probe('node -e "const a=[];for(;;)a.push(Buffer.alloc(50*1024*1024,1))"', { memory: '128m' });
  assert.ok(mem.code === 137 || mem.code === 134 || mem.code !== 0, 'memory hog is killed');
  const pids = probe('i=0; while [ $i -lt 200 ]; do sleep 5 & i=$((i+1)); done; echo done', { pids: 20 });
  assert.ok(/fork|retry|Resource|Cannot/i.test(pids.err + pids.out) || pids.code !== 0, 'process bomb is limited');
});

test('runSandboxed in docker mode kills a scan that exceeds its timeout', { skip: SKIP }, async () => {
  const exec = (command, args, opts) => new Promise((resolve, reject) => {
    const child = require('child_process').spawn(command, ['run', '--rm', '--pull=never', IMAGE, 'sleep', '30'], { signal: opts.signal });
    child.on('error', reject);
    child.on('close', () => resolve({ stdout: '{}' }));
  });
  const started = Date.now();
  await assert.rejects(runSandboxed(workspace, { mode: 'docker', timeoutMs: 1500, exec }), /timed out/);
  assert.ok(Date.now() - started < 10000);
});
