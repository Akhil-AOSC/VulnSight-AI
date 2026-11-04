'use strict';

const http = require('node:http');
const https = require('node:https');
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

function requestOnce(urlObj, timeoutMs) {
  const transport = urlObj.protocol === 'https:' ? https : http;
  return new Promise((resolve) => {
    const req = transport.request(
      urlObj,
      {
        method: 'GET',
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'VulnSight-SafeCrawler/1.0',
          Accept: 'text/html,application/json,text/plain,*/*;q=0.8',
        },
        rejectUnauthorized: true,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (body.length < 150000) body += chunk;
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: sanitizeHeaders(res.headers),
            body,
          });
        });
      }
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.end();
  });
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

function redactEvidence(text, max = 200) {
  return String(text || '')
    .replace(/(authorization|cookie|set-cookie|api[_-]?key|token|password)\s*[:=]\s*[^\s&]+/gi, '$1=[redacted]')
    .slice(0, max);
}

module.exports = { safeGet, sanitizeHeaders, redactEvidence, MAX_REDIRECTS };
