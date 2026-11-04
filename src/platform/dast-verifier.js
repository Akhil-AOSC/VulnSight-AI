'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns/promises');
const https = require('node:https');
const http = require('node:http');
const { validateTargetUrl } = require('../adapters/dast/passive');

/**
 * Generate a unique verification token for domain ownership verification.
 */
function generateVerificationToken(websiteId, orgId) {
  const seed = `${websiteId}:${orgId}:${Date.now()}:${crypto.randomBytes(16).toString('hex')}`;
  const hash = crypto.createHash('sha256').update(seed).digest('hex').slice(0, 32);
  return `vs-verify-${hash}`;
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
        if (text.trim() === token.trim()) {
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
 * Requests /.well-known/vulnsight-verify.txt with strict SSRF protection.
 */
async function verifyViaHttpToken(targetUrl, token) {
  let base;
  try {
    const validated = await validateTargetUrl(targetUrl);
    base = validated.parsed;
  } catch (err) {
    return { verified: false, method: 'http_token', error: err.message };
  }

  const verifyUrl = new URL('/.well-known/vulnsight-verify.txt', base.origin);

  const transport = verifyUrl.protocol === 'https:' ? https : http;

  return new Promise((resolve) => {
    const req = transport.request(
      verifyUrl,
      {
        method: 'GET',
        timeout: 6000,
        headers: {
          'User-Agent': 'VulnSight-Ownership-Verifier/1.0',
          'Accept': 'text/plain',
        },
        rejectUnauthorized: false,
      },
      (res) => {
        if (res.statusCode !== 200) {
          return resolve({
            verified: false,
            method: 'http_token',
            error: `Verification file returned HTTP status ${res.statusCode} (expected 200).`,
          });
        }

        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (body.length < 1000) body += chunk;
        });
        res.on('end', () => {
          if (body.trim().includes(token.trim())) {
            resolve({ verified: true, method: 'http_token', verifiedAt: new Date().toISOString() });
          } else {
            resolve({
              verified: false,
              method: 'http_token',
              error: 'Verification file content does not match the expected token.',
            });
          }
        });
      }
    );

    req.on('error', (err) => {
      resolve({ verified: false, method: 'http_token', error: `HTTP request failed: ${err.message}` });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ verified: false, method: 'http_token', error: 'Connection timed out while fetching verification file.' });
    });
    req.end();
  });
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

module.exports = {
  generateVerificationToken,
  verifyViaDnsTxt,
  verifyViaHttpToken,
  checkOwnership,
};
