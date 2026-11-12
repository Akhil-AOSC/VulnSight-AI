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

function isVerifiedScopeHost(siteHostname, candidate) {
  const site = String(siteHostname || '').toLowerCase().replace(/\.$/, '');
  const host = String(candidate || '').toLowerCase().replace(/\.$/, '');
  if (!site || !host) return false;
  return host === site || host.endsWith(`.${site}`);
}

function normalizeScope(hostname, input = {}) {
  const hosts = uniqueLower([
    hostname,
    ...asList(input.allowHosts),
  ]).filter((h) => isVerifiedScopeHost(hostname, h));
  const extras = uniqueLower(asList(input.extraHosts)).filter((h) => isVerifiedScopeHost(hostname, h));
  return {
    allowHosts: hosts.length ? hosts : [String(hostname || '').toLowerCase()].filter(Boolean),
    allowPaths: asList(input.allowPaths).length ? asList(input.allowPaths) : ['/'],
    denyPaths: asList(input.denyPaths),
    extraHosts: extras,
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
  const port = Number(parsed.port || (parsed.protocol === 'https:' ? '443' : '80'));
  const allowedPorts = (scope.ports && scope.ports.length)
    ? scope.ports.map(Number)
    : [80, 443];
  if (!allowedPorts.includes(port)) return false;
  return hostInScope(parsed.hostname, scope) && pathAllowed(parsed.pathname, scope);
}

function isStateChangingMethod(method) {
  return STATE_METHODS.has(String(method || '').toUpperCase());
}

const PUBLIC_DISCOVERY_LIMITS = {
  maxDepth: 2,
  maxPages: 12,
  maxDurationSec: 90,
  maxRps: 1,
};

const PRODUCT_PROFILES = {
  public: {
    crawl: false, publicDiscovery: true, browser: true, nuclei: null, ascan: false,
    label: 'Public Website Assessment',
  },
  passive: { crawl: false, publicDiscovery: false, browser: false, nuclei: null, ascan: false, label: 'Passive Assessment' },
  discovery: { crawl: true, publicDiscovery: false, browser: true, nuclei: null, ascan: false, label: 'Discovery Assessment' },
  standard: { crawl: true, publicDiscovery: false, browser: true, nuclei: 'safe', ascan: false, label: 'Standard Vulnerability Assessment' },
  deep: { crawl: true, publicDiscovery: false, browser: true, nuclei: 'full', ascan: true, label: 'Deep Security Assessment' },
};

function crawlProfiles() {
  return {
    public: { crawl: false, clientSpider: false, ascan: false },
    public_assessment: { crawl: false, clientSpider: false, ascan: false },
    passive: { crawl: false, clientSpider: false, ascan: false },
    discovery: { crawl: true, clientSpider: false, ascan: false },
    crawl: { crawl: true, clientSpider: false, ascan: false },
    standard: { crawl: true, clientSpider: true, ascan: false },
    crawl_js: { crawl: true, clientSpider: true, ascan: false },
    deep: { crawl: true, clientSpider: true, ascan: true },
    ascan: { crawl: true, clientSpider: true, ascan: true },
    exploit: { crawl: true, clientSpider: true, ascan: true },
  };
}

function profileNeeds(profile) {
  const key = String(profile || 'passive');
  return PRODUCT_PROFILES[key] || PRODUCT_PROFILES.passive;
}

function normalizeProfile(profile, { allowAscan = false } = {}) {
  const key = String(profile || 'passive');
  if (['ascan', 'active', 'attack', 'zap-ascan', 'exploit', 'deep'].includes(key)) {
    if (!allowAscan) {
      throw new Error('Active vulnerability testing requires an explicit authorizeActiveTesting confirmation on a site you are allowed to test');
    }
    return 'deep';
  }
  if (key === 'crawl') return 'discovery';
  if (key === 'crawl_js') return 'standard';
  if (key === 'public_assessment' || key === 'PUBLIC_ASSESSMENT') return 'public';
  if (!PRODUCT_PROFILES[key] && !crawlProfiles()[key]) {
    throw new Error('Profile must be one of: public, passive, discovery, standard, deep');
  }
  if (PRODUCT_PROFILES[key]) return key;
  throw new Error('Profile must be one of: public, passive, discovery, standard, deep');
}

module.exports = {
  DEFAULT_LIMITS,
  PUBLIC_DISCOVERY_LIMITS,
  PRODUCT_PROFILES,
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
  profileNeeds,
  isVerifiedScopeHost,
};
