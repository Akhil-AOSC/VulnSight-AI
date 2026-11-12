'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns/promises');
const { validateTargetUrl } = require('../adapters/dast/passive');
const { guardedRequest } = require('../adapters/dast/net-guard');

/**
 * Generate a unique verification token for domain ownership verification.
 */
function generateVerificationToken() {
  return `vs-verify-${crypto.randomBytes(16).toString('hex')}`;
}

/**
 * Verify domain ownership via DNS TXT record.
 * Checks _vulnsight-challenge.<domain> and <domain>.
 */
async function verifyViaDnsTxt(hostname, token) {
  const candidates = [
    `_vulnsight-challenge.${hostname}`,
    hostname,
  ];

  for (const candidate of candidates) {
    try {
      const records = await dns.resolveTxt(candidate);
      for (const chunk of records) {
        const text = Array.isArray(chunk) ? chunk.join('') : String(chunk);
        if (text.trim() === String(token).trim()) {
          return { verified: true, method: 'dns_txt', verifiedAt: new Date().toISOString() };
        }
      }
    } catch {
      // Ignore resolution errors for this candidate and continue
    }
  }

  return { verified: false, method: 'dns_txt', error: 'No matching DNS TXT record found.' };
}

/**
 * Verify domain ownership via HTTP well-known file.
 * GET /.well-known/vulnsight-verify.txt on the site's own origin. No redirects are followed (a
 * redirect could hand verification to another host), DNS is pinned at connect time, an HTTPS site
 * must present a trusted certificate (so an on-path attacker can't answer for it), and the token
 * must be the file's exact content or one of its lines.
 */
async function verifyViaHttpToken(targetUrl, token, { lookup } = {}) {
  let base;
  try {
    const validated = await validateTargetUrl(targetUrl);
    base = validated.parsed;
  } catch (err) {
    return { verified: false, method: 'http_token', error: err.message };
  }
  const verifyUrl = new URL('/.well-known/vulnsight-verify.txt', base.origin);
  let res;
  try {
    res = await guardedRequest(verifyUrl, {
      timeoutMs: 6000,
      maxBytes: 4096,
      rejectUnauthorized: verifyUrl.protocol === 'https:',
      headers: { Accept: 'text/plain' },
      userAgent: 'VulnSight-Ownership-Verifier/1.0',
      ...(lookup ? { lookup } : {}),
    });
  } catch (err) {
    return { verified: false, method: 'http_token', error: `HTTP request failed: ${err.message}` };
  }
  if (res.statusCode !== 200) {
    return { verified: false, method: 'http_token', error: `Verification file returned HTTP status ${res.statusCode} (expected 200).` };
  }
  const expected = String(token).trim();
  const lines = String(res.body).split(/\r?\n/).map((l) => l.trim());
  if (expected && lines.includes(expected)) {
    return { verified: true, method: 'http_token', verifiedAt: new Date().toISOString() };
  }
  return { verified: false, method: 'http_token', error: 'Verification file content does not match the expected token.' };
}

/**
 * Perform verification using either DNS or HTTP or both.
 * Supports (hostname, token) or (hostname, targetUrl, token).
 */
async function checkOwnership(hostname, targetUrlOrToken, maybeToken) {
  let targetUrl;
  let token;
  if (maybeToken !== undefined) {
    targetUrl = targetUrlOrToken;
    token = maybeToken;
  } else {
    token = targetUrlOrToken;
    targetUrl = `https://${hostname}`;
  }

  // 1. Try DNS TXT first
  const dnsRes = await verifyViaDnsTxt(hostname, token);
  if (dnsRes && dnsRes.verified) return dnsRes;

  // 2. Try HTTP file
  const httpRes = await verifyViaHttpToken(targetUrl, token);
  if (httpRes && httpRes.verified) return httpRes;

  let httpVerifyUrl = '';
  try {
    httpVerifyUrl = new URL('/.well-known/vulnsight-verify.txt', targetUrl).href;
  } catch {
    httpVerifyUrl = `https://${hostname}/.well-known/vulnsight-verify.txt`;
  }

  return {
    verified: false,
    dns: dnsRes,
    http: httpRes,
    error: `Domain ownership verification failed. Checked DNS TXT record for "_vulnsight-challenge.${hostname}" and HTTP token at "${httpVerifyUrl}".`,
  };
}

// Only these methods prove control of the domain. Rows marked verified another way (the removed
// "manual_authorization" self-attestation, or no recorded method) are treated as unverified, so
// they can't run crawls or active scans until the owner adds the DNS record or token file.
const PROVEN_METHODS = new Set(['dns_txt', 'http_token']);

function isOwnershipProven(site) {
  if (!site) return false;
  const flag = Boolean(site.is_verified ?? site.isVerified);
  const method = site.verification_method ?? site.verificationMethod;
  return flag && PROVEN_METHODS.has(method);
}

module.exports = {
  isOwnershipProven,
  PROVEN_METHODS,
  generateVerificationToken,
  verifyViaDnsTxt,
  verifyViaHttpToken,
  checkOwnership,
};
