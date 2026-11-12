'use strict';

// Network guard shared by every DAST engine.
//
// A website scanner opens connections to user-supplied hosts, so it must never be usable to reach
// the scanner's own network (loopback, private ranges, cloud metadata at 169.254.169.254).
// Checking DNS once before the request is not enough: the HTTP client resolves the name again when
// it connects, and a hostile DNS server can answer with a public address the first time and an
// internal one the second (DNS rebinding). guardedLookup() is passed as the `lookup` option to
// http/https/tls, so the address that is actually dialled is the one that was checked.

const dns = require('node:dns');
const net = require('node:net');

// ---- Address classification ---------------------------------------------------------------

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

const V4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => ({ base: ipv4ToInt(base), mask: bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0 }));

function isPublicIPv4(ip) {
  const n = ipv4ToInt(ip);
  return !V4_BLOCKED.some(({ base, mask }) => ((n & mask) >>> 0) === ((base & mask) >>> 0));
}

// Expands an IPv6 literal to 16 bytes. Handles "::" and a trailing dotted IPv4 part.
function ipv6ToBytes(ip) {
  let s = ip.toLowerCase();
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);
  // Rewrite a trailing dotted IPv4 (e.g. ::ffff:127.0.0.1) as two hex groups.
  const lastColon = s.lastIndexOf(':');
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    if (!net.isIPv4(maybeV4)) return null;
    const n = ipv4ToInt(maybeV4);
    s = `${s.slice(0, lastColon + 1)}${((n >>> 16) & 0xffff).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (part) => (part ? part.split(':').map((h) => (/^[0-9a-f]{1,4}$/.test(h) ? parseInt(h, 16) : NaN)) : []);
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  let groups = head;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 0) return null;
    groups = [...head, ...new Array(fill).fill(0), ...rest];
  }
  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) return null;
  const bytes = [];
  for (const g of groups) bytes.push((g >> 8) & 0xff, g & 0xff);
  return bytes;
}

const bytesToV4 = (b, i) => `${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`;
const prefixIs = (b, prefix) => prefix.every((v, i) => b[i] === v);

function isPublicIPv6(ip) {
  const b = ipv6ToBytes(ip);
  if (!b) return false;
  const zero10 = b.slice(0, 10).every((x) => x === 0);
  // ::ffff:a.b.c.d (IPv4-mapped) and ::a.b.c.d (IPv4-compatible): judge the embedded IPv4.
  if (zero10 && b[10] === 0xff && b[11] === 0xff) return isPublicIPv4(bytesToV4(b, 12));
  if (zero10 && b[10] === 0 && b[11] === 0) {
    if (b.slice(12).every((x) => x === 0)) return false; // ::
    if (b.slice(12, 15).every((x) => x === 0) && b[15] === 1) return false; // ::1
    return isPublicIPv4(bytesToV4(b, 12));
  }
  // NAT64 64:ff9b::/96 embeds IPv4 in the last 32 bits.
  if (prefixIs(b, [0x00, 0x64, 0xff, 0x9b]) && b.slice(4, 12).every((x) => x === 0)) return isPublicIPv4(bytesToV4(b, 12));
  if (prefixIs(b, [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01])) return false; // 64:ff9b:1::/48 local NAT64
  // 6to4 2002::/16 embeds IPv4 in bytes 2..5.
  if (b[0] === 0x20 && b[1] === 0x02) return isPublicIPv4(bytesToV4(b, 2));
  // Teredo 2001:0000::/32: client IPv4 is the last 32 bits XOR 0xffffffff. Refuse outright.
  if (prefixIs(b, [0x20, 0x01, 0x00, 0x00])) return false;
  if (prefixIs(b, [0x20, 0x01, 0x0d, 0xb8])) return false; // documentation
  if (prefixIs(b, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])) return false; // 100::/64 discard
  if ((b[0] & 0xfe) === 0xfc) return false; // fc00::/7 unique local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return false; // fe80::/10 link-local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return false; // fec0::/10 site-local (deprecated)
  if (b[0] === 0xff) return false; // multicast
  return true;
}

/** True only for an IP literal that is routable on the public internet. Non-IPs return false. */
function isPublicAddress(ip) {
  const s = String(ip || '').replace(/^\[|\]$/g, '');
  const v = net.isIP(s);
  if (v === 4) return isPublicIPv4(s);
  if (v === 6) return isPublicIPv6(s);
  return false;
}

// ---- Connect-time DNS pinning --------------------------------------------------------------

function blockedError(hostname, address) {
  const err = new Error(`Blocked connection to ${hostname}: it resolves to a non-public address (${address})`);
  err.code = 'ESSRFBLOCKED';
  return err;
}

/**
 * dns.lookup-compatible function. Refuses the whole name if ANY answer is non-public, so a
 * round-robin record that mixes a public and an internal address can't be used either.
 */
function guardedLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  const opts = typeof options === 'number' ? { family: options } : { ...(options || {}) };
  const wantAll = Boolean(opts.all);
  const literal = String(hostname).replace(/^\[|\]$/g, '');
  if (net.isIP(literal)) {
    if (!isPublicAddress(literal)) return process.nextTick(callback, blockedError(hostname, literal));
    const entry = { address: literal, family: net.isIP(literal) };
    return process.nextTick(() => (wantAll ? callback(null, [entry]) : callback(null, entry.address, entry.family)));
  }
  dns.lookup(hostname, { ...opts, all: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!addresses || !addresses.length) {
      const e = new Error(`Could not resolve ${hostname}`);
      e.code = 'ENOTFOUND';
      return callback(e);
    }
    const bad = addresses.find((a) => !isPublicAddress(a.address));
    if (bad) return callback(blockedError(hostname, bad.address));
    if (wantAll) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}

// ---- Bounded body reading ------------------------------------------------------------------

/**
 * Reads a response body as text, stopping at maxBytes or an absolute deadline (a socket idle
 * timeout alone lets a server trickle one byte every few seconds forever).
 * Resolves { body, truncated }.
 */
function readBounded(res, { maxBytes = 250000, deadlineMs = 15000 } = {}) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (truncated) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (truncated) res.destroy();
      resolve({ body: Buffer.concat(chunks).toString('utf8'), truncated });
    };
    const timer = setTimeout(() => finish(true), deadlineMs);
    res.on('data', (chunk) => {
      const room = maxBytes - size;
      if (room <= 0) return finish(true);
      const piece = chunk.length > room ? chunk.subarray(0, room) : chunk;
      chunks.push(piece);
      size += piece.length;
      if (size >= maxBytes) finish(true);
    });
    res.on('end', () => finish(false));
    res.on('error', () => finish(true));
    res.on('aborted', () => finish(true));
  });
}

// ---- WAF / edge block detection --------------------------------------------------------------

const BLOCK_SIGNATURES = [
  { by: 'Cloudflare', test: (h, b) => h['cf-mitigated'] === 'challenge' || /__cf_chl_|\/cdn-cgi\/challenge-platform|<title>Just a moment\.\.\.<\/title>|Attention Required! \| Cloudflare/i.test(b) },
  { by: 'Akamai', test: (h, b) => /akamaighost/i.test(String(h.server || '')) && /Access Denied|Reference #\d/i.test(b) },
  { by: 'Imperva / Incapsula', test: (h, b) => /Incapsula incident ID|_Incapsula_Resource/i.test(b) },
  { by: 'Sucuri', test: (h, b) => /Sucuri WebSite Firewall - Access Denied/i.test(b) || (Boolean(h['x-sucuri-block'])) },
  { by: 'AWS WAF', test: (h, b, s) => s === 403 && /awswaf|aws-waf-token/i.test(b) },
  { by: 'DataDome', test: (h) => Boolean(h['x-datadome']) && /captcha-delivery/i.test(String(h['x-datadome-cid'] || h['set-cookie'] || '')) },
];

function parseRetryAfter(value) {
  if (!value) return null;
  const s = Number(value);
  if (Number.isFinite(s)) return Math.max(0, Math.min(3600, s));
  const t = Date.parse(value);
  return Number.isFinite(t) ? Math.max(0, Math.min(3600, Math.round((t - Date.now()) / 1000))) : null;
}

/**
 * Decides whether a response is the scanner being blocked or challenged by an edge WAF/rate
 * limiter rather than the site's real content. Findings must never be derived from such pages.
 * Returns { blocked, by, reason, retryAfterSec }.
 */
function detectBlock(statusCode, headers = {}, body = '') {
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
  const text = String(body || '').slice(0, 20000);
  const retryAfterSec = parseRetryAfter(h['retry-after']);
  for (const sig of BLOCK_SIGNATURES) {
    if (sig.test(h, text, statusCode)) {
      return { blocked: true, by: sig.by, reason: statusCode === 429 ? 'rate_limited' : 'challenge', retryAfterSec };
    }
  }
  if (statusCode === 429) return { blocked: true, by: 'origin', reason: 'rate_limited', retryAfterSec };
  if (statusCode === 503 && retryAfterSec != null) return { blocked: true, by: 'origin', reason: 'rate_limited', retryAfterSec };
  return { blocked: false, by: null, reason: null, retryAfterSec };
}

// ---- Guarded single HTTP request -----------------------------------------------------------

/**
 * One HTTP(S) request with connect-time DNS pinning, a body cap and an absolute deadline.
 * Never follows redirects (callers that do must re-check scope on every hop).
 * Resolves { statusCode, headers, body, truncated }; rejects on network errors / blocks.
 */
function pinLookup(address, family) {
  return (hostname, options, callback) => {
    if (typeof options === 'function') callback = options;
    const wantAll = options && typeof options === 'object' && options.all;
    const entry = { address, family };
    process.nextTick(() => (wantAll ? callback(null, [entry]) : callback(null, address, family)));
  };
}

function requestOnce(urlObj, {
  method = 'GET', headers = {}, timeoutMs = 10000, maxBytes = 250000, lookup = guardedLookup,
  rejectUnauthorized = false, // nosemgrep
  userAgent = 'VulnSight-Security-Scanner/1.0',
} = {}) {
  const http = require('node:http');
  const https = require('node:https');
  const transport = urlObj.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err) => { if (!settled) { settled = true; clearTimeout(deadline); reject(err); } };
    const req = transport.request(urlObj, {
      method,
      lookup,
      timeout: timeoutMs,
      rejectUnauthorized, // certificate problems are reported by inspectTls, not by refusing to read the page
      headers: { 'User-Agent': userAgent, Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8', ...headers },
    }, async (res) => {
      const { body, truncated } = await readBounded(res, { maxBytes, deadlineMs: timeoutMs });
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve({ statusCode: res.statusCode, headers: res.headers, body, truncated });
    });
    const deadline = setTimeout(() => { req.destroy(); fail(new Error(`Request to ${urlObj.href} timed out after ${timeoutMs}ms`)); }, timeoutMs + 1000);
    req.on('error', fail);
    req.on('timeout', () => { req.destroy(); fail(new Error(`Request to ${urlObj.href} timed out after ${timeoutMs}ms`)); });
    req.end();
  });
}

async function guardedRequest(urlObj, opts = {}) {
  const lookup = opts.lookup || guardedLookup;
  const hostname = String(urlObj.hostname || '').replace(/^\[|\]$/g, '');
  if (net.isIP(hostname) || lookup !== guardedLookup) {
    return requestOnce(urlObj, { ...opts, lookup });
  }
  const addresses = await new Promise((resolve, reject) => {
    guardedLookup(hostname, { all: true }, (err, list) => (err ? reject(err) : resolve(list)));
  });
  let lastErr;
  for (const row of addresses) {
    try {
      return await requestOnce(urlObj, { ...opts, lookup: pinLookup(row.address, row.family) });
    } catch (err) {
      lastErr = err;
      if (!/ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH|timed out/i.test(`${err.code || ''} ${err.message || ''}`)) throw err;
    }
  }
  throw lastErr;
}

// ---- Evidence redaction --------------------------------------------------------------------

const SECRET_PATTERNS = [
  /\b(authorization|proxy-authorization)\s*[:=]\s*(bearer|basic|token)?\s*[^\s,;&]+/gi,
  /\b(cookie|set-cookie)\s*[:=]\s*[^\r\n]+/gi,
  /\b([a-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|session)[a-z0-9_.-]*)\s*([:=])\s*["']?[^\s"'&,;]+/gi,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g, // JWT
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b/g,
  /\bxox[abpr]-[A-Za-z0-9-]{10,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
];

/** Masks credentials/secrets in evidence text and caps its length. Evidence is shown to users and stored. */
function redactEvidence(text, max = 200) {
  let out = String(text == null ? '' : text);
  out = out.replace(SECRET_PATTERNS[0], (_, name) => `${name}: [redacted]`);
  out = out.replace(SECRET_PATTERNS[1], (_, name) => `${name}: [redacted]`);
  out = out.replace(SECRET_PATTERNS[2], (_, name, sep) => `${name}${sep}[redacted]`);
  for (const re of SECRET_PATTERNS.slice(3)) out = out.replace(re, '[redacted]');
  return out.slice(0, max);
}

// ---- Connection-level blocking ----------------------------------------------------------------

// Shared-hosting firewalls (Imunify360, CSF/LFD, fail2ban) ban an IP that looks like a scanner by
// silently DROPPING its packets. The client then sees connect timeouts or resets, never an HTTP
// response, so detectBlock() can't see it. These patterns cover Node, Playwright/Chromium and ZAP.
const DROPPED_RE = /ETIMEDOUT|ECONNRESET|EPIPE|ECONNABORTED|socket hang up|ERR_CONNECTION_(TIMED_OUT|RESET|CLOSED|ABORTED)|ERR_TIMED_OUT|ERR_EMPTY_RESPONSE|timed out|Timeout \d+ms exceeded|no responses/i;
const REFUSED_RE = /ECONNREFUSED|ERR_CONNECTION_REFUSED/i;
const UNREACHABLE_RE = /EHOSTUNREACH|ENETUNREACH|ERR_ADDRESS_UNREACHABLE|ERR_NAME_NOT_RESOLVED|ENOTFOUND|EAI_AGAIN|Could not resolve/i;

/** Classifies a network failure: dropped | refused | unreachable | ssrf | other. */
function classifyNetworkError(err) {
  const text = `${(err && err.code) || ''} ${(err && err.message) || err || ''}`;
  if (/ESSRFBLOCKED/.test(text)) return 'ssrf';
  if (REFUSED_RE.test(text)) return 'refused';
  if (UNREACHABLE_RE.test(text)) return 'unreachable';
  if (DROPPED_RE.test(text)) return 'dropped';
  return 'other';
}

const HOST_FIREWALL = 'host firewall';

function droppedMessage(host, detail) {
  return `The host${host ? ` ${host}` : ''} stopped answering this machine (${String(detail || 'connection timed out').slice(0, 120)}). `
    + 'Its firewall has most likely banned the scanner IP. Allowlist the IP in the hosting firewall '
    + '(on cPanel hosting: Imunify360 or CSF) or wait for the ban to expire, then scan again.';
}

/**
 * One small GET to check that the host still answers. Used between scan stages so a scan stops
 * as soon as the host starts dropping connections instead of hammering a firewall that has banned
 * us (which only extends the ban). Resolves { ok, statusCode?, kind?, message? }.
 */
async function probeReachable(targetUrl, { lookup = guardedLookup, timeoutMs = 10000 } = {}) {
  let url;
  try {
    url = new URL(targetUrl);
  } catch {
    return { ok: false, kind: 'other', message: 'Invalid URL' };
  }
  try {
    const res = await guardedRequest(url, { timeoutMs, lookup, maxBytes: 4096, userAgent: 'VulnSight-Reachability/1.0' });
    return { ok: true, statusCode: res.statusCode };
  } catch (err) {
    const kind = classifyNetworkError(err);
    return {
      ok: false,
      kind,
      message: kind === 'dropped' ? droppedMessage(url.hostname, err.code || err.message) : String(err.message || err).slice(0, 200),
    };
  }
}

module.exports = {
  classifyNetworkError,
  droppedMessage,
  probeReachable,
  HOST_FIREWALL,
  guardedRequest,
  redactEvidence,
  isPublicAddress,
  isPublicIPv4,
  isPublicIPv6,
  guardedLookup,
  readBounded,
  detectBlock,
  parseRetryAfter,
};
