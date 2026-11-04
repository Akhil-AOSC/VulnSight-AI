'use strict';

const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');
const { validateTargetUrl } = require('./passive');
const { createFinding } = require('../../findings');

const SENSITIVE_PATHS = [
  {
    path: '/.env',
    title: 'Exposed Environment File (.env)',
    severity: 'critical',
    cwe: 'CWE-552',
    check: (body) => /^(DB_|DATABASE_|SECRET_|AWS_|API_KEY|PASSWORD|TOKEN=)/m.test(body),
    advice: 'Remove .env from public document root immediately and restrict web server access to dotfiles.',
  },
  {
    path: '/.git/HEAD',
    title: 'Exposed Git Repository Metadata (/.git/HEAD)',
    severity: 'high',
    cwe: 'CWE-538',
    check: (body) => /^ref: refs\//.test(body.trim()),
    advice: 'Block public web access to the .git directory in web server configuration.',
  },
  {
    path: '/robots.txt',
    title: 'Robots.txt Information Disclosure',
    severity: 'low',
    cwe: 'CWE-200',
    check: (body) => /Disallow:/i.test(body),
    advice: 'Ensure disallow paths in robots.txt do not expose sensitive unauthenticated admin or internal URL paths.',
  },
  {
    path: '/.well-known/security.txt',
    title: 'Security.txt Policy File',
    severity: 'low',
    cwe: 'CWE-200',
    check: (body) => /Contact:/i.test(body),
    advice: 'Informational: security.txt is present, advertising security vulnerability reporting policy.',
  },
];

function fetchEndpoint(urlObj, options = {}) {
  const { timeoutMs = 6000 } = options;
  const transport = urlObj.protocol === 'https:' ? https : http;

  return new Promise((resolve) => {
    const req = transport.request(
      urlObj,
      {
        method: 'GET',
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'VulnSight-Security-Crawler/1.0',
          'Accept': 'text/html,application/json,*/*;q=0.8',
        },
        rejectUnauthorized: false,
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
            contentType: res.headers['content-type'] || '',
            headers: res.headers,
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

function extractLinksAndForms(body, baseOrigin) {
  const links = new Set();
  const forms = [];

  // Extract <a href="...">
  const aRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["']/gi;
  let match;
  while ((match = aRegex.exec(body)) !== null) {
    const raw = match[1].trim();
    if (raw && !raw.startsWith('#') && !raw.startsWith('javascript:') && !raw.startsWith('mailto:')) {
      try {
        const u = new URL(raw, baseOrigin);
        if (u.origin === baseOrigin) {
          links.add(u.pathname + u.search);
        }
      } catch {
        /* ignore invalid url */
      }
    }
  }

  // Extract <form action="..." method="...">
  const formRegex = /<form\s+([^>]*?)>([\s\S]*?)<\/form>/gi;
  let fMatch;
  while ((fMatch = formRegex.exec(body)) !== null) {
    const formAttrs = fMatch[1];
    const formInner = fMatch[2];

    const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i);
    const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i);

    const action = (actionMatch && actionMatch[1].trim()) || '';
    const method = ((methodMatch && methodMatch[1].trim()) || 'GET').toUpperCase();

    // Extract inputs
    const params = [];
    const inputRegex = /<input\s+([^>]*?)>/gi;
    let iMatch;
    while ((iMatch = inputRegex.exec(formInner)) !== null) {
      const nameMatch = iMatch[1].match(/name=["']([^"']+)["']/i);
      if (nameMatch) params.push(nameMatch[1]);
    }

    try {
      const u = new URL(action || '/', baseOrigin);
      if (u.origin === baseOrigin) {
        forms.push({
          url: u.href,
          path: u.pathname,
          method,
          parameters: params,
        });
      }
    } catch {
      /* ignore */
    }
  }

  return { links: Array.from(links), forms };
}

/**
 * Crawl website and probe sensitive paths.
 */
async function crawlWebsite(targetUrl, options = {}) {
  const { maxEndpoints = 30, timeoutMs = 8000 } = options;
  const { parsed: base } = await validateTargetUrl(targetUrl);
  const baseOrigin = base.origin;

  const endpoints = [];
  const findings = [];
  const visited = new Set();
  const queue = [base.pathname || '/'];

  while (queue.length > 0 && endpoints.length < maxEndpoints) {
    const relPath = queue.shift();
    if (visited.has(relPath)) continue;
    visited.add(relPath);

    let targetObj;
    try {
      targetObj = new URL(relPath, baseOrigin);
    } catch {
      continue;
    }

    const res = await fetchEndpoint(targetObj, { timeoutMs });
    if (!res) continue;

    // Extract parameters from URL
    const params = [];
    targetObj.searchParams.forEach((_, key) => params.push(key));

    endpoints.push({
      url: targetObj.href,
      path: targetObj.pathname,
      method: 'GET',
      statusCode: res.statusCode,
      contentType: res.contentType,
      parameters: params,
      hasForm: false,
    });

    if (res.contentType.includes('text/html') && res.body) {
      const { links, forms } = extractLinksAndForms(res.body, baseOrigin);
      for (const form of forms) {
        endpoints.push({
          url: form.url,
          path: form.path,
          method: form.method,
          statusCode: 200,
          contentType: 'application/x-www-form-urlencoded',
          parameters: form.parameters,
          hasForm: true,
        });
      }
      for (const l of links) {
        if (!visited.has(l) && queue.length < maxEndpoints * 2) {
          queue.push(l);
        }
      }
    }
  }

  // Probe sensitive paths (.env, .git/HEAD, robots.txt, etc.)
  for (const s of SENSITIVE_PATHS) {
    const sUrl = new URL(s.path, baseOrigin);
    const sRes = await fetchEndpoint(sUrl, { timeoutMs: 5000 });
    if (sRes && sRes.statusCode === 200 && s.check(sRes.body)) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: s.severity,
          title: s.title,
          description: `The file "${s.path}" is publicly accessible and returns sensitive application data.`,
          identifiers: { cwe: [s.cwe], primary: s.cwe },
          location: { url: sUrl.href, path: s.path },
          scanner: { name: 'vulnsight-crawler', ruleId: `exposed-file-${s.path.replace(/[^a-z0-9]/gi, '_')}`, version: '1.0' },
          remediation: { advice: s.advice },
          evidence: sRes.body.slice(0, 200),
        })
      );
    }
  }

  return {
    endpoints,
    findings,
  };
}

module.exports = {
  crawlWebsite,
  extractLinksAndForms,
};
