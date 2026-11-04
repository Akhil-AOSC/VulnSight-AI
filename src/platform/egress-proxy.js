'use strict';

const http = require('http');
const net = require('net');
const dns = require('dns').promises;
const { isPrivateIp } = require('./git');

// Egress allowlist proxy for scan workers.
//
// Workers have no direct route to the internet. Their only way out is this proxy (HTTPS_PROXY),
// which:
//   - accepts only CONNECT tunnels (no plain HTTP, so nothing can be fetched or posted in clear),
//   - allows only listed hostnames, only on port 443,
//   - resolves DNS itself and refuses any hostname with a private, loopback, link-local or
//     metadata address in its answers, then connects to the address it checked (so a worker
//     cannot use DNS rebinding or an IP literal to reach internal services),
//   - caps concurrent tunnels and bytes sent out of the worker (exfiltration and abuse limit),
//   - logs every denial, which is the signal to alert on.
//
// It does not inspect traffic: TLS stays end-to-end between the scanner and the destination.

// Hosts the scanners legitimately need. Confirm against real denials (the log) before relying on
// this list in a new environment: tools change their endpoints.
const DEFAULT_ALLOW = [
  'github.com', 'api.github.com', 'gitlab.com', 'bitbucket.org',
  'api.osv.dev', 'osv.dev',
  'semgrep.dev', '*.semgrep.dev',
  'ghcr.io', '*.pkg.github.com', 'pkg-containers.githubusercontent.com', 'objects.githubusercontent.com',
  'mirror.gcr.io', 'public.ecr.aws',
];

const HOST = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

function hostAllowed(host, allow) {
  return allow.some((rule) => (rule.startsWith('*.') ? host.endsWith(rule.slice(1)) && host.length > rule.length - 1 : host === rule));
}

const scanAllowHosts = new Set();

function setScanEgressHosts(hosts = []) {
  scanAllowHosts.clear();
  for (const host of hosts) {
    const clean = String(host || '').toLowerCase().replace(/\.$/, '');
    if (clean) scanAllowHosts.add(clean);
  }
}

function clearScanEgressHosts() {
  scanAllowHosts.clear();
}

function createEgressProxy({
  allow = DEFAULT_ALLOW, ports = [443], lookup = (h) => dns.lookup(h, { all: true }),
  dial = (address, port) => net.connect({ host: address, port }), log = () => {},
  maxTunnels = 200, idleTimeoutMs = 60000, maxUploadBytes = 100 * 1024 * 1024,
  extraAllow = () => [...scanAllowHosts],
} = {}) {
  const rules = allow.map((r) => r.toLowerCase());
  let open = 0;

  const deny = (socket, host, reason, code = 403) => {
    log({ event: 'egress.denied', host, reason });
    socket.end(`HTTP/1.1 ${code} Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by egress policy: ${reason}\n`);
  };

  const server = http.createServer((req, res) => {
    // Plain (non-CONNECT) proxy requests are never allowed.
    log({ event: 'egress.denied', host: String(req.headers.host || ''), reason: 'plain HTTP is not allowed' });
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('Blocked by egress policy: only HTTPS tunnels are allowed\n');
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 10000;

  server.on('connect', async (req, client, head) => {
    client.on('error', () => {});
    const m = String(req.url).match(/^([^:\s]+):(\d{1,5})$/);
    if (!m) return deny(client, String(req.url).slice(0, 100), 'malformed target');
    const host = m[1].toLowerCase().replace(/\.$/, '');
    const port = Number(m[2]);

    if (net.isIP(host)) return deny(client, host, 'IP addresses are not allowed');
    if (!HOST.test(host) || host.length > 253) return deny(client, host, 'invalid hostname');
    if (!ports.includes(port)) return deny(client, host, `port ${port} is not allowed`);
    const effective = [...rules, ...extraAllow().map((h) => String(h).toLowerCase())];
    if (!hostAllowed(host, effective)) return deny(client, host, 'host is not on the allowlist');
    if (open >= maxTunnels) return deny(client, host, 'too many open tunnels', 503);

    let address;
    try {
      const answers = (await lookup(host)).map((a) => (typeof a === 'string' ? a : a.address));
      if (!answers.length) return deny(client, host, 'host did not resolve', 502);
      // Every answer must be public: a single internal address is enough to refuse.
      if (answers.some(isPrivateIp)) return deny(client, host, 'host resolves to a non-public address');
      [address] = answers;
    } catch {
      return deny(client, host, 'host did not resolve', 502);
    }

    open++;
    let sent = 0;
    const upstream = dial(address, port);
    let closed = false;
    let established = false;
    const close = () => {
      if (closed) return;
      closed = true;
      open--;
      client.destroy();
      upstream.destroy();
    };
    upstream.setTimeout(idleTimeoutMs, close);
    client.setTimeout(idleTimeoutMs, close);
    upstream.on('error', () => {
      if (!established && !client.destroyed) deny(client, host, 'connection failed', 502);
      close();
    });
    client.on('close', close);
    upstream.on('close', close);

    upstream.once('connect', () => {
      established = true;
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      client.on('data', (chunk) => {
        sent += chunk.length;
        if (sent > maxUploadBytes) {
          log({ event: 'egress.denied', host, reason: 'upload limit exceeded' });
          close();
        }
      });
      upstream.pipe(client);
      client.pipe(upstream);
    });
  });

  server.stats = () => ({ open });
  return server;
}

// Allowlist from the environment: VULNSIGHT_EGRESS_ALLOW=host1,*.host2 adds to (or with
// VULNSIGHT_EGRESS_REPLACE=1 replaces) the defaults.
function allowFromEnv(env = process.env) {
  const extra = (env.VULNSIGHT_EGRESS_ALLOW || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return env.VULNSIGHT_EGRESS_REPLACE === '1' ? extra : [...DEFAULT_ALLOW, ...extra];
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3128);
  const proxy = createEgressProxy({ allow: allowFromEnv(), log: (e) => console.log(JSON.stringify({ time: new Date().toISOString(), ...e })) });
  proxy.listen(port, process.env.HOST || '0.0.0.0', () => console.log(JSON.stringify({ msg: 'egress proxy listening', port })));
}

module.exports = {
  createEgressProxy, allowFromEnv, hostAllowed, DEFAULT_ALLOW,
  setScanEgressHosts, clearScanEgressHosts,
};
