'use strict';

// Edge / CDN intelligence for a website: who sits in front of the origin, and the evidence for it.
//
// Everything here is observation only: DNS answers, IP ownership against the CDN's published
// ranges, and the headers, cookie NAMES and TLS certificate the edge returned to the scanner.
// When the edge served a bot challenge, those headers describe the edge (and are reported as
// such), never the site. Nothing here tries to get past a challenge.

const dns = require('node:dns').promises;

function ipOwner(_ip) {
  return null;
}

// Providers that sit in front of a site and proxy its traffic (as opposed to plain DNS hosts).
const EDGE_PROVIDERS = new Set(['Cloudflare', 'Akamai', 'Fastly', 'Sucuri', 'Imperva', 'DataDome']);

// Who hosts the DNS zone. This says who manages the records, which is not always the CDN.
const NS_HOSTS = [
  { re: /\.ns\.cloudflare\.com$/i, name: 'Cloudflare' },
  { re: /awsdns/i, name: 'Amazon Route 53' },
  { re: /\.akam\.net$|akamaiedge|akamaitech/i, name: 'Akamai' },
  { re: /azure-dns/i, name: 'Azure DNS' },
  { re: /googledomains|\.google\.com$|ns-cloud/i, name: 'Google Cloud DNS' },
  { re: /domaincontrol\.com$/i, name: 'GoDaddy' },
  { re: /nsone\.net$/i, name: 'NS1' },
  { re: /fastly/i, name: 'Fastly' },
  { re: /sucuri/i, name: 'Sucuri' },
];

function nsHost(nameservers) {
  for (const ns of nameservers || []) {
    const hit = NS_HOSTS.find((h) => h.re.test(ns));
    if (hit) return hit.name;
  }
  return null;
}

function parseRay(value) {
  const m = String(value || '').match(/^([0-9a-f]+)-([A-Z]{3})$/i);
  if (!m) return value ? { id: String(value).slice(0, 40), code: null, city: null } : null;
  return { id: m[1], code: m[2].toUpperCase(), city: null };
}

function cookieNames(setCookie) {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  return [...new Set(list.map((c) => String(c).split(';')[0].split('=')[0].trim()).filter(Boolean))];
}

const EDGE_COOKIES = {
  __cf_bm: { provider: 'Cloudflare', label: 'Cloudflare Bot Management' },
  cf_clearance: { provider: 'Cloudflare', label: 'Cloudflare challenge clearance' },
  __cflb: { provider: 'Cloudflare', label: 'Cloudflare load balancer' },
  _cfuvid: { provider: 'Cloudflare', label: 'Cloudflare rate limiting' },
  incap_ses: { provider: 'Imperva', label: 'Imperva Incapsula session' },
  visid_incap: { provider: 'Imperva', label: 'Imperva Incapsula visitor' },
  ak_bmsc: { provider: 'Akamai', label: 'Akamai Bot Manager' },
  bm_sv: { provider: 'Akamai', label: 'Akamai Bot Manager' },
  datadome: { provider: 'DataDome', label: 'DataDome bot protection' },
};

function edgeCookie(name) {
  if (EDGE_COOKIES[name]) return EDGE_COOKIES[name];
  if (/^incap_ses_/.test(name)) return EDGE_COOKIES.incap_ses;
  if (/^visid_incap_/.test(name)) return EDGE_COOKIES.visid_incap;
  return null;
}

function pageTitle(body) {
  const m = String(body || '').match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim() : null;
}

function challengeKind(statusCode, headers, block) {
  if (!block || !block.blocked) return null;
  if (block.reason === 'rate_limited') return 'Rate limited';
  if (String(headers['cf-mitigated'] || '').toLowerCase() === 'challenge') return 'Managed challenge';
  if (statusCode === 403) return 'Blocked (403)';
  return 'Bot challenge';
}

async function resolveAll(hostname, resolver) {
  const [ns, a, aaaa] = await Promise.all([
    resolver.resolveNs(hostname).catch(() => []),
    resolver.resolve4(hostname).catch(() => []),
    resolver.resolve6(hostname).catch(() => []),
  ]);
  // NS records live on the zone apex; for www.example.com look one level up.
  let nameservers = ns;
  if (!nameservers.length && hostname.split('.').length > 2) {
    nameservers = await resolver.resolveNs(hostname.split('.').slice(1).join('.')).catch(() => []);
  }
  return { nameservers, ipv4: a, ipv6: aaaa };
}

/**
 * Builds the edge picture for one scanned site. Never throws.
 *   hostname, statusCode, headers, body  the response the scanner received for the page
 *   block                                detectBlock() result for that response
 *   tls                                  inspectTls() result
 *   resolver                             dns.promises-like object (tests inject one)
 */
async function collectEdgeIntel({
  hostname, statusCode = null, headers = {}, body = '', block = null, tls = null, resolver = dns,
} = {}) {
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[k.toLowerCase()] = v;

  let records = { nameservers: [], ipv4: [], ipv6: [] };
  try {
    records = await resolveAll(hostname, resolver);
  } catch { /* DNS is best effort */ }

  const ipv4 = records.ipv4.map((ip) => ({ ip, owner: ipOwner(ip) }));
  const ipv6 = records.ipv6.map((ip) => ({ ip, owner: ipOwner(ip) }));
  const allIps = [...ipv4, ...ipv6];
  const dnsHost = nsHost(records.nameservers);
  const ray = parseRay(h['cf-ray']);
  const names = cookieNames(h['set-cookie']);

  const signals = [];
  if (dnsHost) signals.push({ source: 'DNS nameservers', provider: dnsHost, detail: records.nameservers.join(', ') });
  if (/cloudflare/i.test(String(h.server || ''))) signals.push({ source: 'Response header', provider: 'Cloudflare', detail: `server: ${h.server}` });
  if (ray) signals.push({ source: 'Response header', provider: 'Cloudflare', detail: `cf-ray: ${h['cf-ray']}` });
  for (const name of names) {
    const c = edgeCookie(name);
    if (c) signals.push({ source: 'Cookie', provider: c.provider, detail: `${name} (${c.label})` });
  }
  const issuer = tls && !tls.error ? (typeof tls.issuer === 'object' ? (tls.issuer.O || tls.issuer.CN) : tls.issuer) : null;
  const sans = tls && tls.sans ? String(tls.sans).split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean) : [];
  if (sans.some((s) => /cloudflaressl\.com$/i.test(s))) signals.push({ source: 'TLS certificate', provider: 'Cloudflare', detail: 'Certificate names a Cloudflare SSL host' });

  // The edge provider is the CDN/WAF most signals agree on. A plain DNS host (Route 53, GoDaddy)
  // is not a CDN in front of the site, and DNS hosting counts half as much as IP or header proof,
  // because a zone can sit on Cloudflare DNS with proxying turned off.
  const tally = new Map();
  for (const s of signals) {
    if (!EDGE_PROVIDERS.has(s.provider)) continue;
    tally.set(s.provider, (tally.get(s.provider) || 0) + (s.source === 'DNS nameservers' ? 0.5 : 1));
  }
  let provider = null;
  let best = 0;
  for (const [name, score] of tally) if (score > best) { provider = name; best = score; }
  if (best < 1) provider = null; // DNS hosting alone is not proof the traffic goes through the edge
  const independentSources = new Set(signals.filter((s) => s.provider === provider).map((s) => s.source)).size;

  return {
    provider,
    confidence: !provider ? null : independentSources >= 2 ? 'confirmed' : 'likely',
    dnsHost,
    originHidden: Boolean(provider),
    signals,
    dns: { nameservers: records.nameservers, ipv4, ipv6 },
    edgeHeaders: {
      server: h.server || null,
      ray,
      cacheStatus: h['cf-cache-status'] || h['x-cache'] || null,
      mitigated: h['cf-mitigated'] || null,
      via: h.via || null,
    },
    cookieNames: names,
    botProtection: block && block.blocked ? {
      challenged: true,
      by: block.by || provider || null,
      kind: challengeKind(statusCode, h, block),
      statusCode,
      retryAfterSec: block.retryAfterSec ?? null,
      pageTitle: pageTitle(body),
    } : { challenged: false, statusCode },
    tls: tls && !tls.error ? { issuer: issuer || null, subject: tls.subject || null, sans: sans.slice(0, 8), protocol: tls.protocol || null } : null,
  };
}

module.exports = { collectEdgeIntel, ipOwner, parseRay, nsHost, cookieNames };
