'use strict';

// Edge / CDN intelligence for a website: who sits in front of the origin, and the evidence for it.
//
// Everything here is observation only: DNS answers, the headers, cookie NAMES and TLS
// certificate the response returned to the scanner.
// When the edge served a bot challenge, those headers describe the edge (and are reported as
// such), never the site. Nothing here tries to get past a challenge.

const dns = require('node:dns').promises;

function ipOwner(_ip) {
  return null;
}

function nsHost(nameservers) {
  const first = (nameservers || []).find(Boolean);
  return first ? String(first).toLowerCase().replace(/\.$/, '') : null;
}

function looksLikeReverseProxyHeader(name) {
  const key = String(name || '').toLowerCase();
  if (!key) return false;
  return key === 'via'
    || key === 'forwarded'
    || key === 'cdn-loop'
    || key === 'x-served-by'
    || key === 'x-cache'
    || key === 'x-cdn'
    || key === 'cdn'
    || /(^|-)(cdn|cache|proxy|waf|pop|ray)(-|$)/.test(key)
    || /^x-forwarded-/.test(key);
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

function pageTitle(body) {
  const m = String(body || '').match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim() : null;
}

function challengeKind(statusCode, headers, block) {
  if (!block || !block.blocked) return null;
  if (block.reason === 'rate_limited') return 'Rate limited';
  const mitigated = Object.entries(headers || {}).some(([k, v]) => (
    /mitigat/i.test(k) && /challenge/i.test(String(v || ''))
  ));
  if (mitigated) return 'Managed challenge';
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
  const dnsHost = nsHost(records.nameservers);
  const rayKey = Object.keys(h).find((k) => k.endsWith('-ray'));
  const ray = rayKey ? parseRay(h[rayKey]) : null;
  const names = cookieNames(h['set-cookie']);
  const proxyHeaders = Object.entries(h).filter(([k, v]) => v != null && v !== '' && looksLikeReverseProxyHeader(k));

  const signals = [];
  if (records.nameservers.length) {
    signals.push({ source: 'DNS nameservers', provider: null, detail: records.nameservers.join(', ') });
  }
  if (h.server) signals.push({ source: 'Response header', provider: null, detail: `server: ${h.server}` });
  for (const [k, v] of proxyHeaders) {
    const shown = Array.isArray(v) ? v[0] : v;
    signals.push({ source: 'Response header', provider: null, detail: `${k}: ${String(shown).slice(0, 80)}` });
  }
  for (const name of names) {
    signals.push({ source: 'Cookie', provider: null, detail: name });
  }
  const issuer = tls && !tls.error ? (typeof tls.issuer === 'object' ? (tls.issuer.O || tls.issuer.CN) : tls.issuer) : null;
  const sans = tls && tls.sans ? String(tls.sans).split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean) : [];
  if (issuer) signals.push({ source: 'TLS certificate', provider: null, detail: `issuer: ${issuer}` });

  const headerProof = proxyHeaders.length > 0;
  const provider = headerProof ? 'CDN / reverse proxy' : null;

  return {
    provider,
    confidence: headerProof ? 'likely' : null,
    dnsHost,
    originHidden: headerProof,
    signals,
    dns: { nameservers: records.nameservers, ipv4, ipv6 },
    edgeHeaders: {
      server: h.server || null,
      ray,
      cacheStatus: h['cf-cache-status'] || h['x-cache'] || null,
      mitigated: Object.entries(h).find(([k]) => /mitigat/i.test(k))?.[1] || null,
      via: h.via || null,
    },
    cookieNames: names,
    botProtection: block && block.blocked ? {
      challenged: true,
      by: block.by || provider || 'WAF',
      kind: challengeKind(statusCode, h, block),
      statusCode,
      retryAfterSec: block.retryAfterSec ?? null,
      pageTitle: pageTitle(body),
    } : { challenged: false, statusCode },
    tls: tls && !tls.error ? { issuer: issuer || null, subject: tls.subject || null, sans: sans.slice(0, 8), protocol: tls.protocol || null } : null,
  };
}

module.exports = { collectEdgeIntel, ipOwner, parseRay, nsHost, cookieNames };
