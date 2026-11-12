'use strict';

const { guardedRequest, redactEvidence } = require('./net-guard');
const { validateTargetUrl } = require('./passive');
const { normalizeUrl, urlInScope } = require('./scope');

const MAX_REDIRECTS = 5;
const BLOCKED_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

async function safeGet(rawUrl, { scope, timeoutMs = 8000, method = 'GET' } = {}) {
  if (BLOCKED_METHODS.has(String(method).toUpperCase())) {
    throw new Error(`State-changing method ${method} is not allowed during passive crawling`);
  }
  let current = String(rawUrl);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const validated = await validateTargetUrl(current);
    const parsed = normalizeUrl(validated.parsed.href);
    if (scope && !urlInScope(parsed, scope)) {
      return { blocked: true, reason: 'out_of_scope', url: parsed.href, hops: hop };
    }
    const res = await requestOnce(parsed, timeoutMs);
    if (!res) return { blocked: true, reason: 'fetch_failed', url: parsed.href, hops: hop };
    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
      current = new URL(res.headers.location, parsed.href).href;
      continue;
    }
    return {
      blocked: false,
      url: parsed.href,
      parsed,
      statusCode: res.statusCode,
      headers: res.headers,
      contentType: res.headers['content-type'] || '',
      body: res.body,
      hops: hop,
    };
  }
  return { blocked: true, reason: 'too_many_redirects', url: current, hops: MAX_REDIRECTS };
}

async function requestOnce(urlObj, timeoutMs) {
  try {
    const res = await guardedRequest(urlObj, { timeoutMs, maxBytes: 150000, rejectUnauthorized: true, userAgent: 'VulnSight-SafeCrawler/1.0' });
    return { statusCode: res.statusCode, headers: sanitizeHeaders(res.headers), body: res.body };
  } catch {
    return null;
  }
}

function sanitizeHeaders(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) {
    const name = key.toLowerCase();
    if (['set-cookie', 'authorization', 'proxy-authorization', 'cookie'].includes(name)) {
      out[name] = '[redacted]';
      continue;
    }
    out[name] = value;
  }
  return out;
}

module.exports = { safeGet, sanitizeHeaders, redactEvidence, MAX_REDIRECTS };
