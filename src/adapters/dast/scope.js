'use strict';

const crypto = require('node:crypto');

const DEFAULT_LIMITS = {
  maxDepth: 3,
  maxPages: 40,
  maxDurationSec: 180,
  maxRps: 2,
};

const STATE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function normalizeLimits(input = {}) {
  const maxDepth = clampInt(input.maxDepth, 1, 8, DEFAULT_LIMITS.maxDepth);
  const maxPages = clampInt(input.maxPages, 1, 200, DEFAULT_LIMITS.maxPages);
  const maxDurationSec = clampInt(input.maxDurationSec, 15, 900, DEFAULT_LIMITS.maxDurationSec);
  const maxRps = clampInt(input.maxRps, 1, 5, DEFAULT_LIMITS.maxRps);
  return { maxDepth, maxPages, maxDurationSec, maxRps };
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function normalizeScope(hostname, input = {}) {
  const hosts = uniqueLower([
    hostname,
    ...asList(input.allowHosts),
  ]).filter(Boolean);
  return {
    allowHosts: hosts,
    allowPaths: asList(input.allowPaths).length ? asList(input.allowPaths) : ['/'],
    denyPaths: asList(input.denyPaths),
    extraHosts: uniqueLower(asList(input.extraHosts)),
  };
}

function asList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((s) => String(s).trim()).filter(Boolean);
  return String(value).split(',').map((s) => s.trim()).filter(Boolean);
}

function uniqueLower(items) {
  return [...new Set(items.map((s) => String(s).toLowerCase()))];
}

function normalizeUrl(raw, baseOrigin) {
  const parsed = new URL(raw, baseOrigin);
  parsed.hash = '';
  if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) {
    parsed.port = '';
  }
  const params = [...parsed.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
  parsed.search = '';
  for (const [k, v] of params) parsed.searchParams.append(k, v);
  return parsed;
}

function urlHash(href) {
  return crypto.createHash('sha256').update(href).digest('hex').slice(0, 32);
}

function hostInScope(hostname, scope) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  const allowed = new Set([...(scope.allowHosts || []), ...(scope.extraHosts || [])].map((h) => h.toLowerCase()));
  return allowed.has(host);
}

function pathAllowed(pathname, scope) {
  const path = pathname || '/';
  for (const deny of scope.denyPaths || []) {
    if (path.startsWith(deny)) return false;
  }
  const allows = scope.allowPaths && scope.allowPaths.length ? scope.allowPaths : ['/'];
  return allows.some((prefix) => path.startsWith(prefix));
}

function urlInScope(parsed, scope) {
  if (!['http:', 'https:'].includes(parsed.protocol)) return false;
  if (parsed.username || parsed.password) return false;
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  if (port !== '80' && port !== '443') return false;
  return hostInScope(parsed.hostname, scope) && pathAllowed(parsed.pathname, scope);
}

function isStateChangingMethod(method) {
  return STATE_METHODS.has(String(method || '').toUpperCase());
}

function crawlProfiles() {
  return {
    passive: { crawl: false, clientSpider: false, ascan: false },
    crawl: { crawl: true, clientSpider: false, ascan: false },
    crawl_js: { crawl: true, clientSpider: true, ascan: false },
    standard: { crawl: true, clientSpider: false, ascan: false },
    deep: { crawl: true, clientSpider: true, ascan: false },
    ascan: { crawl: true, clientSpider: false, ascan: true },
    exploit: { crawl: true, clientSpider: false, ascan: true },
  };
}

function normalizeProfile(profile, { allowAscan = false } = {}) {
  const key = String(profile || 'passive');
  if (['ascan', 'active', 'attack', 'zap-ascan', 'exploit'].includes(key)) {
    if (!allowAscan) {
      throw new Error('Active vulnerability testing requires an explicit authorizeActiveTesting confirmation on a verified site you are allowed to test');
    }
    return 'ascan';
  }
  const map = crawlProfiles();
  if (!map[key]) throw new Error('Profile must be one of: passive, crawl, crawl_js, ascan');
  return key === 'standard' ? 'crawl' : key === 'deep' ? 'crawl_js' : key;
}

module.exports = {
  DEFAULT_LIMITS,
  normalizeLimits,
  normalizeScope,
  normalizeUrl,
  urlHash,
  hostInScope,
  pathAllowed,
  urlInScope,
  isStateChangingMethod,
  normalizeProfile,
  crawlProfiles,
};
