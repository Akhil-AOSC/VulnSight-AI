'use strict';

const { isVerifiedScopeHost, normalizeUrl, urlInScope } = require('./scope');

const ZAP_NOISE_PLUGIN_IDS = new Set([
  '10104', // User Agent Fuzzer
  '10109', // Modern Web Application
]);

function parseHeaderLine(raw) {
  const text = String(raw || '').trim();
  if (!text) return null;
  const cut = text.indexOf(':');
  if (cut <= 0) {
    if (/^bearer\s+/i.test(text)) return { name: 'Authorization', value: text };
    return { name: 'Authorization', value: text };
  }
  const name = text.slice(0, cut).trim();
  const value = text.slice(cut + 1).trim();
  if (!/^[A-Za-z0-9-]+$/.test(name) || !value) return null;
  if (/^(host|content-length|transfer-encoding)$/i.test(name)) return null;
  return { name, value: value.slice(0, 4096) };
}

function parseCookieHeader(raw) {
  const value = String(raw || '').trim().slice(0, 4096);
  if (!value) return null;
  if (/[\r\n]/.test(value)) return null;
  return value;
}

function listedHosts(allowedHosts) {
  return (allowedHosts || []).map((h) => String(h || '').toLowerCase().replace(/\.$/, '')).filter(Boolean);
}

function hostAllowedForDeep(host, siteHostname, allowedHosts) {
  if (siteHostname && isVerifiedScopeHost(siteHostname, host)) return true;
  return listedHosts(allowedHosts).includes(String(host || '').toLowerCase());
}

function parseUrlList(raw, { siteHostname, allowedHosts, max = 40 } = {}) {
  const items = Array.isArray(raw)
    ? raw
    : String(raw || '').split(/[\s,]+/);
  const out = [];
  const seen = new Set();
  for (const item of items) {
    if (out.length >= max) break;
    const text = String(item || '').trim();
    if (!text) continue;
    let parsed;
    try {
      parsed = new URL(text);
    } catch {
      continue;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
    if (parsed.username || parsed.password) continue;
    const host = parsed.hostname.toLowerCase();
    if (siteHostname && !hostAllowedForDeep(host, siteHostname, allowedHosts)) continue;
    if (seen.has(parsed.href)) continue;
    seen.add(parsed.href);
    out.push(parsed.href);
  }
  return out;
}

function parseOriginUrl(raw, siteHostname, allowedHosts) {
  const text = String(raw || '').trim();
  if (!text) return null;
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new Error('Origin URL is not a valid http(s) URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Origin URL must be http or https');
  }
  if (parsed.username || parsed.password) throw new Error('Origin URL must not contain credentials');
  const host = parsed.hostname.toLowerCase();
  if (!hostAllowedForDeep(host, siteHostname, allowedHosts)) {
    throw new Error('Origin URL must be the registered host, a subdomain, or a hostname listed on the site grant');
  }
  return parsed.href;
}

function parseDeepScanOptions(body = {}, { siteHostname, authorizedDeep, allowedHosts } = {}) {
  const sessionCookie = parseCookieHeader(body.sessionCookie);
  const sessionHeader = parseHeaderLine(body.sessionHeader);
  const seedUrls = parseUrlList(body.seedUrls, { siteHostname, allowedHosts, max: 40 });
  const originUrl = body.originUrl ? parseOriginUrl(body.originUrl, siteHostname, allowedHosts) : null;
  const hasAuth = Boolean(sessionCookie || sessionHeader);
  const hasSeeds = seedUrls.length > 0;
  const hasOrigin = Boolean(originUrl);
  if (!hasAuth && !hasSeeds && !hasOrigin) return {};
  if (!authorizedDeep) {
    throw new Error('Session cookie, API seeds, and origin URL are only accepted on authorized Deep assessment');
  }
  return {
    ...(sessionCookie ? { sessionCookie } : {}),
    ...(sessionHeader ? { sessionHeader } : {}),
    ...(hasSeeds ? { seedUrls } : {}),
    ...(originUrl ? { originUrl } : {}),
  };
}

function redactDeepLimits(limits) {
  if (!limits || typeof limits !== 'object') return limits || null;
  const copy = { ...limits };
  copy.hasSessionCookie = Boolean(copy.sessionCookie || copy.sessionCookieEnc);
  copy.hasSessionHeader = Boolean(copy.sessionHeader || copy.sessionHeaderEnc);
  delete copy.sessionCookie;
  delete copy.sessionHeader;
  delete copy.sessionCookieEnc;
  delete copy.sessionHeaderEnc;
  return copy;
}

function sealDeepLimits(limits, box) {
  if (!limits || !box) return limits || {};
  const copy = { ...limits };
  if (copy.sessionCookie) {
    copy.sessionCookieEnc = box.encrypt(copy.sessionCookie);
    delete copy.sessionCookie;
  }
  if (copy.sessionHeader) {
    copy.sessionHeaderEnc = box.encrypt(JSON.stringify(copy.sessionHeader));
    delete copy.sessionHeader;
  }
  return copy;
}

function openDeepLimits(limits, box) {
  const copy = { ...(limits || {}) };
  if (copy.sessionCookieEnc && box) {
    copy.sessionCookie = box.decrypt(copy.sessionCookieEnc);
    delete copy.sessionCookieEnc;
  }
  if (copy.sessionHeaderEnc && box) {
    copy.sessionHeader = JSON.parse(box.decrypt(copy.sessionHeaderEnc));
    delete copy.sessionHeaderEnc;
  }
  return copy;
}

function playwrightHeaders(limits = {}) {
  const headers = {};
  if (limits.sessionCookie) headers.Cookie = limits.sessionCookie;
  if (limits.sessionHeader && limits.sessionHeader.name) {
    headers[limits.sessionHeader.name] = limits.sessionHeader.value;
  }
  return headers;
}

function mergeSeedUrls(inventoryUrls, extra, scope, maxPages) {
  const out = [];
  const seen = new Set();
  const add = (raw) => {
    if (!raw || out.length >= (maxPages || 80)) return;
    try {
      const parsed = normalizeUrl(raw);
      if (scope && !urlInScope(parsed, scope)) return;
      if (seen.has(parsed.href)) return;
      seen.add(parsed.href);
      out.push(parsed.href);
    } catch { /* skip */ }
  };
  for (const u of extra || []) add(u);
  for (const u of inventoryUrls || []) add(u);
  return out;
}

function isZapNoiseAlert(alert) {
  const id = String((alert && (alert.pluginId || alert.alertRef)) || '');
  return ZAP_NOISE_PLUGIN_IDS.has(id);
}

module.exports = {
  ZAP_NOISE_PLUGIN_IDS,
  parseDeepScanOptions,
  redactDeepLimits,
  sealDeepLimits,
  openDeepLimits,
  playwrightHeaders,
  mergeSeedUrls,
  isZapNoiseAlert,
  parseCookieHeader,
  parseHeaderLine,
};
