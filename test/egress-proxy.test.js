'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('net');
const http = require('http');
const { createEgressProxy, allowFromEnv, hostAllowed, DEFAULT_ALLOW } = require('../src/platform/egress-proxy');

// A plain TCP echo server stands in for "the internet". The proxy's DNS and dialing are injected,
// so every allowed host "resolves" to a public address but is dialled to this local server.
async function setup(t, opts = {}) {
  const echo = net.createServer((s) => { s.on('data', (d) => s.write(`echo:${d}`)); s.on('error', () => {}); });
  await new Promise((r) => echo.listen(0, '127.0.0.1', r));
  const log = [];
  const dialed = [];
  const proxy = createEgressProxy({
    allow: ['github.com', '*.example.org'],
    lookup: opts.lookup || (async () => [{ address: '140.82.112.3' }]),
    dial: (address, port) => { dialed.push({ address, port }); return net.connect({ host: '127.0.0.1', port: echo.address().port }); },
    log: (e) => log.push(e),
    ...opts.proxy,
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  t.after(() => { proxy.close(); echo.close(); });
  return { port: proxy.address().port, log, dialed, proxy };
}

// Sends a raw CONNECT and returns the status line (and, for a 200, the echoed reply).
function connect(port, target, { send = 'ping' } = {}) {
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = '';
    let sent = false;
    s.on('data', (d) => {
      buf += d;
      if (buf.includes('\r\n\r\n') && /200/.test(buf.split('\r\n')[0]) && !sent) { sent = true; s.write(send); }
      if (sent && buf.includes('echo:')) s.end();
    });
    const done = () => resolve({ status: buf.split('\r\n')[0], body: buf });
    s.on('close', done);
    s.on('error', done);
    setTimeout(() => { s.destroy(); }, 3000);
  });
}

test('an allowlisted host on 443 is tunnelled to the address the proxy checked', async (t) => {
  const { port, dialed, log } = await setup(t);
  const r = await connect(port, 'github.com:443');
  assert.match(r.status, /200/);
  assert.ok(r.body.includes('echo:ping'), 'bytes flow end to end');
  assert.deepEqual(dialed, [{ address: '140.82.112.3', port: 443 }], 'dials the validated address, not a name');
  assert.equal(log.length, 0);
  assert.match((await connect(port, 'deep.sub.example.org:443')).status, /200/, 'wildcard matches subdomains');
});

test('hosts outside the allowlist are refused and logged', async (t) => {
  const { port, log, dialed } = await setup(t);
  for (const target of ['evil.com:443', 'github.com.evil.com:443', 'example.org:443', 'notgithub.com:443', 'evilgithub.com:443']) {
    assert.match((await connect(port, target)).status, /403/, target);
  }
  assert.equal(dialed.length, 0, 'nothing was dialled');
  assert.ok(log.every((e) => e.event === 'egress.denied' && /allowlist/.test(e.reason)));
  assert.equal(log.length, 5);
});

test('only port 443 is allowed', async (t) => {
  const { port, log } = await setup(t);
  for (const target of ['github.com:80', 'github.com:22', 'github.com:8443', 'github.com:0']) {
    assert.match((await connect(port, target)).status, /403/, target);
  }
  assert.ok(log.every((e) => /port/.test(e.reason)));
});

test('IP literals, metadata and internal addresses cannot be reached', async (t) => {
  const { port, log, dialed } = await setup(t);
  for (const target of ['169.254.169.254:443', '127.0.0.1:443', '10.0.0.5:443', '[::1]:443', '0x7f000001:443', '2130706433:443']) {
    assert.match((await connect(port, target)).status, /403/, target);
  }
  assert.equal(dialed.length, 0);
  assert.ok(log.length >= 6);
});

test('an allowed name that resolves to a private address is refused (DNS rebinding / poisoned answer)', async (t) => {
  for (const address of ['10.1.2.3', '127.0.0.1', '169.254.169.254', '192.168.0.9', '100.64.0.1', '::1', 'fd00::5']) {
    const { port, log, dialed } = await setup(t, { lookup: async () => [{ address }] });
    assert.match((await connect(port, 'github.com:443')).status, /403/, address);
    assert.equal(dialed.length, 0, address);
    assert.match(log[0].reason, /non-public/);
  }
  // one bad answer among good ones is enough
  const mixed = await setup(t, { lookup: async () => [{ address: '140.82.112.3' }, { address: '10.0.0.1' }] });
  assert.match((await connect(mixed.port, 'github.com:443')).status, /403/);
});

test('unresolvable hosts, plain HTTP and malformed requests are refused', async (t) => {
  const { port, log } = await setup(t, { lookup: async () => { throw new Error('ENOTFOUND'); } });
  assert.match((await connect(port, 'github.com:443')).status, /502/);

  const plain = await new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port, path: 'http://github.com/', headers: { host: 'github.com' } }, (res) => resolve(res.statusCode));
  });
  assert.equal(plain, 403);
  for (const target of ['github.com', 'github.com:abc', ':443', 'a b:443', 'github.com:443/path']) {
    assert.match((await connect(port, target)).status, /400|403|^$/, target); // 400 = rejected by the HTTP parser itself
  }
  assert.ok(log.some((e) => /plain HTTP/.test(e.reason)));
});

test('the number of open tunnels is capped', async (t) => {
  const { port } = await setup(t, { proxy: { maxTunnels: 1 } });
  const first = net.connect(port, '127.0.0.1');
  first.on('error', () => {});
  await new Promise((r) => { first.write('CONNECT github.com:443 HTTP/1.1\r\nHost: x\r\n\r\n'); first.once('data', r); });
  assert.match((await connect(port, 'github.com:443')).status, /503/);
  first.destroy();
});

test('upload volume is capped', async (t) => {
  const { port, log } = await setup(t, { proxy: { maxUploadBytes: 1000 } });
  const result = await new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write('CONNECT github.com:443 HTTP/1.1\r\nHost: x\r\n\r\n'));
    let ready = false;
    s.on('data', (d) => { if (!ready && String(d).includes('200')) { ready = true; s.write(Buffer.alloc(5000, 1)); } });
    s.on('close', () => resolve('closed'));
    s.on('error', () => resolve('closed'));
    setTimeout(() => resolve('open'), 2000);
  });
  assert.equal(result, 'closed');
  assert.ok(log.some((e) => /upload limit/.test(e.reason)));
});

test('allowlist matching and environment configuration', () => {
  assert.ok(hostAllowed('github.com', ['github.com']));
  assert.ok(!hostAllowed('github.com', ['*.github.com']), 'a wildcard does not match the bare domain');
  assert.ok(hostAllowed('api.github.com', ['*.github.com']));
  assert.ok(!hostAllowed('evilgithub.com', ['*.github.com']));
  assert.ok(!hostAllowed('github.com.evil.com', ['github.com']));
  assert.deepEqual(allowFromEnv({ VULNSIGHT_EGRESS_ALLOW: 'Extra.example.com, *.cdn.example.net', VULNSIGHT_EGRESS_REPLACE: '1' }), ['extra.example.com', '*.cdn.example.net']);
  assert.ok(allowFromEnv({}).includes('api.osv.dev'));
  assert.ok(DEFAULT_ALLOW.every((h) => !/^\d+\.\d+\.\d+\.\d+$/.test(h)), 'defaults contain no IP literals');
  assert.ok(!DEFAULT_ALLOW.some((h) => h === '*' || h === '*.com'), 'no catch-all entries');
});

test('per-scan extra allowlist hosts are permitted only while listed', async (t) => {
  const extra = [];
  const { port } = await setup(t, { proxy: { extraAllow: () => extra } });
  assert.match((await connect(port, 'customer.example.com:443')).status, /403/);
  extra.push('customer.example.com');
  assert.match((await connect(port, 'customer.example.com:443')).status, /200/);
});
