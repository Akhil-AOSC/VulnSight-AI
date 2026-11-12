'use strict';

// Passive website inspection: TLS, response headers, cookies, CORS, technologies, and known-vulnerable
// front-end libraries. It only reads what any visitor's browser receives. It does NOT probe for
// sensitive files (that needs verified ownership and runs in the DAST pipeline), does not crawl,
// and never sends attack payloads.

const tls = require('node:tls');
const dns = require('node:dns/promises');
const net = require('node:net');
const { URL } = require('node:url');
const { createFinding } = require('../../findings');
const {
  isPublicAddress, guardedLookup, guardedRequest, detectBlock, redactEvidence,
} = require('./net-guard');

const ALLOWED_PORTS = new Set(['80', '443']);
const MAX_REDIRECTS = 5;

// Standard security header definitions & benchmarks. check(value, allHeaders) returns an issue or null.
const REQUIRED_HEADERS = [
  {
    name: 'strict-transport-security',
    title: 'Missing Strict-Transport-Security (HSTS) Header',
    severity: 'medium',
    cwe: 'CWE-319',
    advice: 'Enforce HTTPS by adding: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    check: (val) => {
      if (!val) return 'HSTS header is absent. Communication is vulnerable to SSL stripping.';
      const maxAgeMatch = val.match(/max-age=(\d+)/i);
      if (!maxAgeMatch || Number(maxAgeMatch[1]) < 10368000) {
        return 'HSTS max-age is below recommended 120 days (10,368,000 seconds).';
      }
      return null;
    },
  },
  {
    name: 'content-security-policy',
    title: 'Missing Content-Security-Policy (CSP) Header',
    severity: 'medium',
    cwe: 'CWE-1021',
    advice: "Deploy a Content-Security-Policy header restricting script-src, object-src and default-src (e.g. default-src 'self').",
    check: (val) => {
      if (!val) return 'CSP header is absent. Application is more susceptible to Cross-Site Scripting (XSS) and code injection.';
      const directive = val.match(/(?:^|;)\s*script-src\s+([^;]+)/i) || val.match(/(?:^|;)\s*default-src\s+([^;]+)/i);
      if (!directive) return 'CSP is present but has no script-src or default-src, so it does not restrict which scripts can run.';
      const scriptSrc = directive[1];
      if (/'unsafe-inline'/.test(scriptSrc) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(scriptSrc)) {
        return "CSP allows 'unsafe-inline' scripts without nonces or hashes, so it does not stop injected inline scripts.";
      }
      if (/(^|\s)(\*|https?:|data:)(\s|$)/.test(scriptSrc)) {
        return 'CSP script sources include a wildcard, a whole scheme, or data:, so scripts can be loaded from anywhere.';
      }
      return null;
    },
  },
  {
    name: 'x-frame-options',
    title: 'Missing X-Frame-Options Header (Clickjacking Risk)',
    severity: 'low',
    cwe: 'CWE-1021',
    advice: "Prevent framing by setting X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'none'.",
    check: (val, headers) => {
      // CSP frame-ancestors supersedes X-Frame-Options in every current browser.
      if (/frame-ancestors/i.test(String(headers['content-security-policy'] || ''))) return null;
      if (!val) return 'X-Frame-Options header is absent and CSP has no frame-ancestors, allowing potential clickjacking via iframe overlay.';
      const upper = val.trim().toUpperCase();
      if (upper !== 'DENY' && upper !== 'SAMEORIGIN') return `X-Frame-Options has non-standard value: ${val}`;
      return null;
    },
  },
  {
    name: 'x-content-type-options',
    title: 'Missing X-Content-Type-Options Header',
    severity: 'low',
    cwe: 'CWE-693',
    advice: 'Add: X-Content-Type-Options: nosniff to prevent browsers from MIME-sniffing the response.',
    check: (val) => (!val || val.trim().toLowerCase() !== 'nosniff' ? 'Missing or incorrect X-Content-Type-Options: nosniff.' : null),
  },
  {
    name: 'referrer-policy',
    title: 'Missing or Insecure Referrer-Policy Header',
    severity: 'low',
    cwe: 'CWE-200',
    advice: 'Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer) to prevent URL path leakage.',
    check: (val) => {
      if (!val) return 'Referrer-Policy header is absent.';
      const policies = val.toLowerCase().split(',').map((s) => s.trim());
      const effective = policies[policies.length - 1];
      if (['unsafe-url', 'no-referrer-when-downgrade'].includes(effective)) return `Referrer-Policy is set to an unsafe policy: ${val}`;
      return null;
    },
  },
  {
    name: 'permissions-policy',
    title: 'Missing Permissions-Policy Header',
    severity: 'low',
    cwe: 'CWE-693',
    advice: 'Restrict browser features by adding: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    check: (val) => (!val ? 'Permissions-Policy header is absent.' : null),
  },
];

const INFO_DISCLOSURE_HEADERS = [
  { header: 'server', title: 'Web Server Version Disclosed in Server Header', versionOnly: true },
  { header: 'x-powered-by', title: 'Server Technology Disclosed via X-Powered-By' },
  { header: 'x-aspnet-version', title: 'ASP.NET Version Disclosed in Header' },
  { header: 'x-aspnetmvc-version', title: 'ASP.NET MVC Version Disclosed in Header' },
];

// ---- Target validation ---------------------------------------------------------------------

/**
 * Validates a user-supplied URL and makes sure the hostname does not resolve to a private,
 * loopback or metadata address. The same check is repeated at connect time by guardedLookup.
 */
async function validateTargetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid website URL: ${rawUrl}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported protocol: ${parsed.protocol}. Only http and https are allowed.`);
  }
  if (parsed.username || parsed.password) throw new Error('Website URLs must not contain credentials.');

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const bare = hostname.replace(/^\[|\]$/g, '');
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new Error(`Target ${hostname} is a private/internal IP address. Scanning blocked for security.`);
  }
  if (net.isIP(bare)) {
    if (!isPublicAddress(bare)) {
      throw new Error(`Target ${hostname} is a private/internal IP address. Scanning blocked for security.`);
    }
  }
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  if (!ALLOWED_PORTS.has(port)) throw new Error(`Only ports 80 and 443 can be scanned (got ${port}).`);
  if (net.isIP(bare)) return { parsed, primaryIp: bare };

  const addresses = await dns.resolve4(hostname).catch(() => []);
  const addresses6 = await dns.resolve6(hostname).catch(() => []);
  const allIps = [...addresses, ...addresses6];
  if (!allIps.length) throw new Error(`Could not resolve hostname: ${hostname}`);
  for (const ip of allIps) {
    if (!isPublicAddress(ip)) {
      throw new Error(`Target ${hostname} resolves to private/internal IP address (${ip}). Scanning blocked for security.`);
    }
  }
  return { parsed, primaryIp: allIps[0] };
}

// ---- TLS ---------------------------------------------------------------------------------------

function inspectTls(hostname, port = 443, timeoutMs = 8000, { lookup = guardedLookup } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve(value); } };
    // Audit-only handshake: we must still read the peer cert when it is expired, self-signed,
    // or otherwise untrusted so the finding can report issuer, dates, and authorizationError.
    // Page fetches use guardedRequest with rejectUnauthorized true (see safe-fetch.js).
    const inspectUntrustedPeer = false;
    // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
    const socket = tls.connect({
      host: hostname,
      port,
      servername: net.isIP(hostname) ? undefined : hostname,
      rejectUnauthorized: inspectUntrustedPeer,
      timeout: timeoutMs,
      lookup,
    }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        const authError = socket.authorizationError ? String(socket.authorizationError) : null;
        socket.end();
        if (!cert || !cert.valid_to) return finish({ error: 'No peer certificate presented' });
        const validTo = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const daysLeft = Math.floor((validTo - Date.now()) / 86400000);
        finish({
          valid: authorized,
          authorized,
          authError,
          authorizationError: authError,
          issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN : 'Unknown',
          subject: cert.subject ? cert.subject.CN : hostname,
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysLeft,
          daysRemaining: daysLeft,
          protocol,
          cipher: cipher ? cipher.name : null,
          bits: cipher ? cipher.bits : null,
          sans: cert.subjectaltname || null,
        });
      } catch (err) {
        socket.destroy();
        finish({ error: err.message });
      }
    });
    socket.on('error', (err) => finish({ error: err.message }));
    socket.on('timeout', () => { socket.destroy(); finish({ error: 'TLS connection timed out' }); });
  });
}

/**
 * The default handshake negotiates the newest protocol, so it can't tell whether a server ALSO
 * accepts TLS 1.0/1.1. This makes one handshake capped at TLS 1.1 to find out.
 * Resolves the accepted legacy protocol name, or null.
 */
function probeLegacyTls(hostname, port = 443, timeoutMs = 6000, { lookup = guardedLookup } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve(value); } };
    let socket;
    try {
      // Probe whether the server still accepts TLS 1.0/1.1. Handshake is discarded; no HTTP is sent.
      const inspectUntrustedPeer = false;
      // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
      socket = tls.connect({
        host: hostname,
        port,
        servername: net.isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: inspectUntrustedPeer,
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.1',
        ciphers: 'DEFAULT@SECLEVEL=0',
        timeout: timeoutMs,
        lookup,
      }, () => {
        const protocol = socket.getProtocol();
        socket.end();
        finish(['TLSv1', 'TLSv1.1'].includes(protocol) ? protocol : null);
      });
    } catch {
      return finish(null);
    }
    socket.on('error', () => finish(null));
    socket.on('timeout', () => { socket.destroy(); finish(null); });
  });
}

function tlsFindings(tlsResult, legacyProtocol, urlObj) {
  const findings = [];
  const loc = { url: urlObj.href };
  if (tlsResult.error) {
    findings.push(createFinding({
      category: 'dast', severity: 'high', title: 'TLS/SSL Handshake Error',
      description: `Failed to establish a TLS connection: ${tlsResult.error}`,
      identifiers: { cwe: ['CWE-319'], primary: 'CWE-319' }, location: loc,
      scanner: { name: 'vulnsight-passive', ruleId: 'tls-error', version: '1.1' },
      remediation: { advice: 'Ensure a valid TLS certificate is installed and bound to the server.' },
      evidence: redactEvidence(tlsResult.error),
    }));
    return findings;
  }
  if (tlsResult.daysLeft <= 0) {
    findings.push(createFinding({
      category: 'dast', severity: 'critical', title: 'SSL/TLS Certificate Has Expired',
      description: `The certificate expired ${Math.abs(tlsResult.daysLeft)} days ago on ${tlsResult.validTo}. Browsers block access with security warnings.`,
      identifiers: { cwe: ['CWE-298'], primary: 'CWE-298' }, location: loc,
      scanner: { name: 'vulnsight-passive', ruleId: 'tls-cert-expired', version: '1.1' },
      remediation: { advice: 'Renew the TLS certificate immediately and automate renewal (for example with ACME/Let\'s Encrypt).' },
      evidence: `Issuer: ${tlsResult.issuer}, expired at: ${tlsResult.validTo}`,
    }));
  } else if (tlsResult.daysLeft <= 14) {
    findings.push(createFinding({
      category: 'dast', severity: 'medium', title: `SSL/TLS Certificate Expiring Soon (${tlsResult.daysLeft} days remaining)`,
      description: `The certificate for ${urlObj.hostname} expires on ${tlsResult.validTo}.`,
      identifiers: { cwe: ['CWE-298'], primary: 'CWE-298' }, location: loc,
      scanner: { name: 'vulnsight-passive', ruleId: 'tls-cert-expiring-soon', version: '1.1' },
      remediation: { advice: 'Renew the certificate before it expires and automate renewal.' },
      evidence: `Days remaining: ${tlsResult.daysLeft}`,
    }));
  }
  // Expiry is reported above; any other trust failure (self-signed, wrong host, missing chain) here.
  if (!tlsResult.authorized && tlsResult.authError && !/CERT_HAS_EXPIRED/i.test(tlsResult.authError)) {
    findings.push(createFinding({
      category: 'dast', severity: 'high', title: 'TLS Certificate Is Not Trusted',
      description: `Browsers will reject this certificate (${tlsResult.authError}). Visitors see a security warning, and users who click through can be intercepted.`,
      identifiers: { cwe: ['CWE-295'], primary: 'CWE-295' }, location: loc,
      scanner: { name: 'vulnsight-passive', ruleId: 'tls-cert-untrusted', version: '1.1' },
      remediation: { advice: 'Install a certificate from a public CA that covers this hostname, and serve the full intermediate chain.' },
      evidence: `Verification error: ${tlsResult.authError}; subject: ${tlsResult.subject}; issuer: ${tlsResult.issuer}`,
    }));
  }
  if (legacyProtocol) {
    findings.push(createFinding({
      category: 'dast', severity: 'medium', title: `Deprecated TLS Protocol Accepted (${legacyProtocol})`,
      description: `The server still completes a handshake with ${legacyProtocol}. TLS 1.0 and 1.1 are deprecated (RFC 8996) and weaken protection for old clients.`,
      identifiers: { cwe: ['CWE-326'], primary: 'CWE-326' }, location: loc,
      scanner: { name: 'vulnsight-passive', ruleId: 'tls-deprecated-version', version: '1.1' },
      remediation: { advice: 'Disable TLS 1.0 and TLS 1.1 in the server or CDN configuration; allow TLS 1.2 and 1.3 only.' },
      evidence: `Handshake capped at TLS 1.1 succeeded with ${legacyProtocol}`,
    }));
  }
  return findings;
}

// ---- Fetching ------------------------------------------------------------------------------

function fetchWebResponse(urlObj, options = {}) {
  const { timeoutMs = 10000, extraHeaders = {}, method = 'GET', lookup = guardedLookup } = options;
  return guardedRequest(urlObj, {
    method, headers: extraHeaders, timeoutMs, lookup, maxBytes: 250000,
    userAgent: 'VulnSight-Security-Scanner/1.0 (Automated Passive Security Auditor)',
  });
}

const sameSite = (a, b) => a === b || a.replace(/^www\./, '') === b.replace(/^www\./, '');

/**
 * Follows redirects within the same site (http->https and www/apex) so headers are judged on the
 * page users actually land on, not on a bare 301. Every hop is re-validated.
 */
async function fetchFinal(urlObj, { timeoutMs, lookup, validate }) {
  const chain = [];
  let current = urlObj;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const res = await fetchWebResponse(current, { timeoutMs, lookup });
    chain.push({ url: current.href, statusCode: res.statusCode });
    const loc = res.headers.location;
    if (res.statusCode >= 300 && res.statusCode < 400 && loc) {
      let next;
      try {
        next = new URL(loc, current.href);
      } catch {
        return { response: res, finalUrl: current, chain };
      }
      if (!sameSite(next.hostname, urlObj.hostname) || !['http:', 'https:'].includes(next.protocol)) {
        return { response: res, finalUrl: current, chain, offsiteRedirect: next.href };
      }
      await validate(next.href);
      current = next;
      continue;
    }
    return { response: res, finalUrl: current, chain };
  }
  throw new Error('Too many redirects');
}

// ---- Technologies --------------------------------------------------------------------------

function detectTechnologies(headers, body = '') {
  const techs = [];
  const server = headers.server;
  if (server) {
    if (/litespeed/i.test(server)) {
      techs.push({ name: 'LiteSpeed Web Server', category: 'Web Server', version: null });
    } else if (/nginx/i.test(server)) {
      const match = server.match(/nginx\/([\d.]+)/i);
      techs.push({ name: 'Nginx', category: 'Web Server', version: match ? match[1] : null });
    } else if (/apache/i.test(server)) {
      const match = server.match(/apache\/([\d.]+)/i);
      techs.push({ name: 'Apache HTTP Server', category: 'Web Server', version: match ? match[1] : null });
    } else if (/caddy/i.test(server)) {
      techs.push({ name: 'Caddy', category: 'Web Server', version: null });
    } else if (/microsoft-iis/i.test(server)) {
      const match = server.match(/microsoft-iis\/([\d.]+)/i);
      techs.push({ name: 'Microsoft IIS', category: 'Web Server', version: match ? match[1] : null });
    }
  }

  const poweredBy = headers['x-powered-by'];
  if (poweredBy) {
    if (/express/i.test(poweredBy)) techs.push({ name: 'Express', category: 'Web Framework', version: null });
    if (/php/i.test(poweredBy)) {
      const match = poweredBy.match(/php\/([\d.]+)/i);
      techs.push({ name: 'PHP', category: 'Programming Language', version: match ? match[1] : null });
    }
    if (/asp\.net/i.test(poweredBy)) techs.push({ name: 'ASP.NET', category: 'Web Framework', version: null });
  }

  if (body) {
    if (/wp-content\/|wp-includes\//i.test(body)) techs.push({ name: 'WordPress', category: 'CMS', version: null });
    if (/woocommerce/i.test(body)) techs.push({ name: 'WooCommerce', category: 'E-Commerce Platform', version: null });
    if (/elementor/i.test(body)) techs.push({ name: 'Elementor', category: 'Page Builder', version: null });
    if (/id="__next"|__NEXT_DATA__|\/_next\/static\//.test(body)) techs.push({ name: 'Next.js', category: 'Frontend Framework', version: null });
    if (/data-reactroot|react(?:-dom)?(?:\.production)?(?:\.min)?\.js/i.test(body)) techs.push({ name: 'React', category: 'Frontend Framework', version: null });
    if (/data-v-[a-f0-9]{6,8}|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js|id="__nuxt"/i.test(body)) techs.push({ name: 'Vue.js', category: 'Frontend Framework', version: null });
    const ng = body.match(/ng-version="([\d.]+)"/);
    if (ng) techs.push({ name: 'Angular', category: 'Frontend Framework', version: ng[1] });
    else if (/\sng-app[\s=>]/.test(body)) techs.push({ name: 'AngularJS', category: 'Frontend Framework', version: null });

    const bsMatch = body.match(/bootstrap[./@-](\d+\.\d+(?:\.\d+)?)(?:\/dist)?[^"']*?\.(?:js|css)/i) || body.match(/bootstrap\/(\d+\.\d+(?:\.\d+)?)\//i);
    if (bsMatch) techs.push({ name: 'Bootstrap', category: 'UI Framework', version: bsMatch[1] });
    else if (/bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)/i.test(body)) techs.push({ name: 'Bootstrap', category: 'UI Framework', version: null });

    if (/tailwind/i.test(body)) techs.push({ name: 'Tailwind CSS', category: 'UI Framework', version: null });
    if (/font-awesome|fontawesome/i.test(body)) techs.push({ name: 'Font Awesome', category: 'Font & Icon Toolkit', version: null });
    if (/owl\.carousel/i.test(body)) techs.push({ name: 'Owl Carousel', category: 'JavaScript UI Library', version: null });
    if (/googletagmanager\.com|google-analytics\.com/i.test(body)) techs.push({ name: 'Google Analytics', category: 'Analytics', version: null });

    const jqMatch = body.match(/jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.min)?\.js/i)
      || body.match(/jquery\/(\d+\.\d+(?:\.\d+)?)\/jquery/i)
      || body.match(/jquery@(\d+\.\d+(?:\.\d+)?)/i)
      || body.match(/jquery\.(?:min\.)?js\?ver=(\d+\.\d+(?:\.\d+)?)/i);
    if (jqMatch) techs.push({ name: 'jQuery', category: 'JavaScript Library', version: jqMatch[1] });
    else if (/jquery(?:\.min)?\.js/i.test(body)) techs.push({ name: 'jQuery', category: 'JavaScript Library', version: null });

    const loMatch = body.match(/lodash(?:\.min)?\.js\?ver=(\d+\.\d+\.\d+)|lodash[@/.-](\d+\.\d+\.\d+)/i);
    if (loMatch) techs.push({ name: 'Lodash', category: 'JavaScript Library', version: loMatch[1] || loMatch[2] });
    const momentMatch = body.match(/moment[@/.-](\d+\.\d+\.\d+)(?:\/min)?[^"']*\.js/i);
    if (momentMatch) techs.push({ name: 'Moment.js', category: 'JavaScript Library', version: momentMatch[1] });
  }

  if (detectEdgeProtection(headers).present && !techs.some((t) => t.category === 'CDN / Reverse Proxy')) {
    techs.push({ name: 'CDN or reverse proxy', category: 'CDN / Reverse Proxy', version: null });
  }

  const seen = new Set();
  return techs.filter((t) => {
    const key = `${t.name}-${t.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ---- Edge / WAF fingerprint (headers actually returned; no vendor catalog, no bypass) ---------

const RATE_LIMIT_HEADERS = ['ratelimit-limit', 'x-ratelimit-limit', 'ratelimit-policy', 'retry-after'];

function looksLikeReverseProxyHeader(name) {
  const key = String(name || '').toLowerCase();
  if (!key) return false;
  if (RATE_LIMIT_HEADERS.includes(key)) return false;
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

function detectEdgeProtection(headers = {}) {
  const signals = [];
  for (const [name, value] of Object.entries(headers || {})) {
    if (value == null || value === '') continue;
    const key = String(name).toLowerCase();
    if (!looksLikeReverseProxyHeader(key)) continue;
    const shown = Array.isArray(value) ? value[0] : value;
    signals.push(`${key}: ${String(shown).slice(0, 80)}`);
  }
  const rateLimitName = RATE_LIMIT_HEADERS.find((name) => headers[name]);
  const rateLimitValue = rateLimitName ? headers[rateLimitName] : null;
  return {
    present: signals.length > 0,
    providers: [],
    signals,
    hasRateLimitHeader: Boolean(rateLimitValue),
    rateLimitEvidence: rateLimitValue ? String(rateLimitValue).slice(0, 80) : null,
  };
}

function analyzeEdgeProtection(headers, urlObj) {
  const edge = detectEdgeProtection(headers);
  const findings = [];
  if (!edge.present) {
    findings.push(createFinding({
      category: 'dast',
      severity: 'low',
      title: 'No CDN or WAF fingerprint on HTTP responses',
      description: 'Responses do not show reverse-proxy or cache headers (for example Via or X-Cache). The origin may be reachable directly, so volumetric denial-of-service and unfiltered proxy traffic are not absorbed at the edge. This is a header observation only; VulnSight does not flood the site or test bypasses.',
      identifiers: { cwe: ['CWE-400'], primary: 'CWE-400' },
      location: { url: urlObj.href },
      scanner: { name: 'vulnsight-passive', ruleId: 'missing-edge-waf', version: '1.0' },
      remediation: {
        advice: 'Put the origin behind a CDN or WAF. Allow only that edge to reach origin. Enable DDoS/WAF and bot controls at the edge. Confirm with the provider dashboard, not with load tests against production.',
      },
      evidence: edge.hasRateLimitHeader
        ? `No reverse-proxy or cache headers. Rate-limit header present: ${edge.rateLimitEvidence}`
        : 'No Via, X-Cache, CDN-Loop, or similar reverse-proxy headers, and no RateLimit-Limit / Retry-After header.',
    }));
  }
  if (!edge.present && !edge.hasRateLimitHeader) {
    findings.push(createFinding({
      category: 'dast',
      severity: 'low',
      title: 'No HTTP rate-limit headers observed',
      description: 'The response does not advertise RateLimit-Limit, X-RateLimit-Limit, or Retry-After. Missing headers do not prove the application has no throttling, but there is no visible edge or API rate-limit signal. VulnSight does not send a request flood to confirm denial of service.',
      identifiers: { cwe: ['CWE-770'], primary: 'CWE-770' },
      location: { url: urlObj.href },
      scanner: { name: 'vulnsight-passive', ruleId: 'missing-ratelimit-headers', version: '1.0' },
      remediation: {
        advice: 'Enforce rate limiting at the CDN/WAF and on the origin. Optionally emit IETF RateLimit headers so clients and monitors can see the policy.',
      },
      evidence: 'RateLimit-Limit, X-RateLimit-Limit, and Retry-After are absent.',
    }));
  }
  return { edge, findings };
}

// ---- Cookies -------------------------------------------------------------------------------

// Names that usually hold session or authentication state. Matched on word boundaries so analytics
// ids such as _gid or consent_id are not treated as session cookies.
const SENSITIVE_COOKIE = /(^|[_.-])(sess|session|sessid|sid|auth|token|jwt|login|remember|csrf|xsrf)([_.-]|$)|^(phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|ci_session|wordpress_logged_in.*)$/i;

function redactCookie(cStr) {
  const parts = String(cStr).split(';');
  const first = parts.shift() || '';
  const eq = first.indexOf('=');
  const name = eq > 0 ? first.slice(0, eq).trim() : first.trim();
  return [`${name}=[redacted]`, ...parts.map((p) => p.trim())].join('; ').slice(0, 300);
}

function analyzeCookies(headers, urlObj) {
  const rawCookies = headers['set-cookie'];
  if (!rawCookies) return { cookies: [], findings: [] };
  const list = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
  const cookies = [];
  const findings = [];
  const isHttps = urlObj.protocol === 'https:';

  for (const cStr of list) {
    const parts = cStr.split(';').map((p) => p.trim());
    const [nameVal] = parts;
    const eqIdx = nameVal.indexOf('=');
    const name = eqIdx > 0 ? nameVal.slice(0, eqIdx) : nameVal;
    const lowerParts = parts.slice(1).map((p) => p.toLowerCase());
    const isSecure = lowerParts.includes('secure');
    const isHttpOnly = lowerParts.includes('httponly');
    const sameSitePart = lowerParts.find((p) => p.startsWith('samesite='));
    const sameSiteVal = sameSitePart ? sameSitePart.split('=')[1] : null;
    const sensitive = SENSITIVE_COOKIE.test(name);
    const evidence = redactCookie(cStr);

    cookies.push({ name, secure: isSecure, httpOnly: isHttpOnly, sameSite: sameSiteVal, sensitive });

    if (isHttps && !isSecure) {
      findings.push(createFinding({
        category: 'dast', severity: sensitive ? 'medium' : 'low',
        title: `Cookie "${name}" Set Without Secure Flag`,
        description: `The cookie "${name}" is set over HTTPS without the "Secure" flag, so the browser will also send it over plain HTTP if a request is ever made that way.`,
        identifiers: { cwe: ['CWE-614'], primary: 'CWE-614' },
        location: { url: urlObj.href, parameter: name },
        scanner: { name: 'vulnsight-passive', ruleId: 'cookie-no-secure', version: '1.1' },
        remediation: { advice: `Add the "Secure" directive to the Set-Cookie header for "${name}".` },
        evidence,
      }));
    }
    if (!isHttpOnly && sensitive) {
      findings.push(createFinding({
        category: 'dast', severity: 'medium',
        title: `Sensitive Cookie "${name}" Set Without HttpOnly Flag`,
        description: `The cookie "${name}" appears to store session or authentication state but lacks the "HttpOnly" attribute, so any injected script can read it via document.cookie.`,
        identifiers: { cwe: ['CWE-1004'], primary: 'CWE-1004' },
        location: { url: urlObj.href, parameter: name },
        scanner: { name: 'vulnsight-passive', ruleId: 'cookie-no-httponly', version: '1.1' },
        remediation: { advice: `Set the "HttpOnly" flag on the Set-Cookie header for "${name}".` },
        evidence,
      }));
    }
    if (!sameSiteVal || (sameSiteVal === 'none' && !isSecure)) {
      findings.push(createFinding({
        category: 'dast', severity: 'low',
        title: `Cookie "${name}" Missing SameSite Attribute`,
        description: sameSiteVal === 'none'
          ? `The cookie "${name}" uses SameSite=None without Secure, which browsers reject or treat as cross-site.`
          : `The cookie "${name}" does not specify a SameSite attribute, which can expose the application to Cross-Site Request Forgery (CSRF) in older browsers.`,
        identifiers: { cwe: ['CWE-1275'], primary: 'CWE-1275' },
        location: { url: urlObj.href, parameter: name },
        scanner: { name: 'vulnsight-passive', ruleId: 'cookie-no-samesite', version: '1.1' },
        remediation: { advice: `Add SameSite=Lax or SameSite=Strict to the Set-Cookie header for "${name}".` },
        evidence,
      }));
    }
  }
  return { cookies, findings };
}

// ---- CORS ----------------------------------------------------------------------------------

async function checkCors(urlObj, { lookup = guardedLookup, timeoutMs = 10000 } = {}) {
  const testOrigin = 'https://vulnsight-security-audit.invalid';
  const loc = { url: urlObj.href };
  const findings = [];
  try {
    const res = await fetchWebResponse(urlObj, { extraHeaders: { Origin: testOrigin }, lookup, timeoutMs });
    const acao = res.headers['access-control-allow-origin'];
    const acac = String(res.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    let nullAcao = null;
    let nullAcac = false;
    try {
      const resNull = await fetchWebResponse(urlObj, { extraHeaders: { Origin: 'null' }, lookup, timeoutMs });
      nullAcao = resNull.headers['access-control-allow-origin'] || null;
      nullAcac = String(resNull.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    } catch { /* optional second probe */ }

    if (acao === testOrigin && acac) {
      findings.push(createFinding({
        category: 'dast', severity: 'high', title: 'Arbitrary Origin Reflection with Credentials in CORS',
        description: 'The server reflects any Origin header in Access-Control-Allow-Origin while allowing credentials. Any website can make authenticated cross-origin requests and read the responses on behalf of a logged-in user.',
        identifiers: { cwe: ['CWE-942'], primary: 'CWE-942' }, location: loc,
        scanner: { name: 'vulnsight-passive', ruleId: 'cors-arbitrary-credentials', version: '1.1' },
        remediation: { advice: 'Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins and never reflect the request Origin.' },
        evidence: `Origin: ${testOrigin} -> Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: true`,
      }));
    } else if (nullAcao === 'null' && nullAcac) {
      findings.push(createFinding({
        category: 'dast', severity: 'high', title: 'CORS Trusts the "null" Origin with Credentials',
        description: 'The server allows Origin: null with credentials. Sandboxed iframes and local files send "null", so any attacker page can read authenticated responses.',
        identifiers: { cwe: ['CWE-942'], primary: 'CWE-942' }, location: loc,
        scanner: { name: 'vulnsight-passive', ruleId: 'cors-null-credentials', version: '1.1' },
        remediation: { advice: 'Remove "null" from the allowed origins.' },
        evidence: 'Origin: null -> Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: true',
      }));
    } else if (acao === testOrigin) {
      findings.push(createFinding({
        category: 'dast', severity: 'low', title: 'CORS Reflects Arbitrary Origins',
        description: 'The server echoes any Origin header in Access-Control-Allow-Origin. Without credentials this exposes only public data, but it usually means the allowlist is not enforced.',
        identifiers: { cwe: ['CWE-942'], primary: 'CWE-942' }, location: loc,
        scanner: { name: 'vulnsight-passive', ruleId: 'cors-reflects-origin', version: '1.1' },
        remediation: { advice: 'Return Access-Control-Allow-Origin only for origins on an explicit allowlist.' },
        evidence: `Origin: ${testOrigin} -> Access-Control-Allow-Origin: ${acao}`,
      }));
    } else if (acao === '*') {
      findings.push(createFinding({
        category: 'dast', severity: 'low', title: 'Wildcard CORS Header Configured (*)',
        description: 'The server responds with Access-Control-Allow-Origin: *, allowing any web page to read this response.',
        identifiers: { cwe: ['CWE-942'], primary: 'CWE-942' }, location: loc,
        scanner: { name: 'vulnsight-passive', ruleId: 'cors-wildcard', version: '1.1' },
        remediation: { advice: 'Confirm that public cross-origin read access is intended for this endpoint.' },
        evidence: 'Access-Control-Allow-Origin: *',
      }));
    }
    return { cors: { allowOrigin: acao || null, allowCredentials: acac }, findings };
  } catch {
    return { cors: null, findings: [] };
  }
}

// ---- Subresource Integrity -----------------------------------------------------------------

function analyzeSri(body, pageUrl) {
  const hosts = [];
  const scriptRe = /<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = scriptRe.exec(body)) !== null) {
    const tag = m[0];
    let src;
    try {
      src = new URL(m[1], pageUrl.href);
    } catch {
      continue;
    }
    if (!['http:', 'https:'].includes(src.protocol)) continue;
    if (sameSite(src.hostname, pageUrl.hostname)) continue;
    if (/\bintegrity\s*=/i.test(tag)) continue;
    if (!hosts.includes(src.hostname)) hosts.push(src.hostname);
  }
  if (!hosts.length) return [];
  return [createFinding({
    category: 'dast', severity: 'low',
    title: 'Third-Party Scripts Loaded Without Subresource Integrity (SRI)',
    description: `Scripts are loaded from third-party hosts (${hosts.slice(0, 3).join(', ')}${hosts.length > 3 ? ', …' : ''}) without an integrity hash. If one of those hosts is compromised, the attacker's code runs on this site. Scripts that change on every release (analytics, tag managers) cannot use SRI and should be reviewed instead.`,
    identifiers: { cwe: ['CWE-353'], primary: 'CWE-353' },
    location: { url: pageUrl.href },
    scanner: { name: 'vulnsight-passive', ruleId: 'missing-sri', version: '1.1' },
    remediation: { advice: 'Add integrity="sha384-..." and crossorigin="anonymous" to versioned third-party <script> tags, or self-host them.' },
    evidence: `External hosts loaded without SRI: ${hosts.join(', ')}`,
  })];
}

// ---- Main entry point ----------------------------------------------------------------------

/**
 * options:
 *   timeoutMs   per-request timeout
 *   lookup      connect-time DNS function (defaults to guardedLookup; tests may inject one)
 *   validate    URL validation function (defaults to validateTargetUrl)
 *   osvClient   OSV client for library advisories (null disables the lookup)
 *   checkLegacyTls  default true
 */
async function runPassiveScan(targetUrl, options = {}) {
  const {
    timeoutMs = 12000,
    lookup = guardedLookup,
    validate = validateTargetUrl,
    osvClient,
    checkLegacyTls = true,
    edgeResolver, // dns.promises-like object for the edge/CDN and email-DNS lookups; tests inject one
    skillChecks = true, // SPF/DMARC/CAA and verbose-error checks (skill-checks.js)
  } = options;
  const { parsed: seedUrl } = await validate(targetUrl);

  const findings = [];

  // 1. Fetch the page users actually land on (same-site redirects followed).
  const { response, finalUrl, chain, offsiteRedirect } = await fetchFinal(seedUrl, { timeoutMs, lookup, validate });
  const urlObj = finalUrl;
  const headers = response.headers;
  const isHttps = urlObj.protocol === 'https:';

  // 2. Edge block / challenge: findings from a challenge page would describe the WAF, not the site.
  const block = detectBlock(response.statusCode, headers, response.body);

  // 3. TLS
  let tlsResult = null;
  if (isHttps) {
    const port = urlObj.port ? Number(urlObj.port) : 443;
    tlsResult = await inspectTls(urlObj.hostname, port, timeoutMs, { lookup });
    const legacy = checkLegacyTls && !tlsResult.error ? await probeLegacyTls(urlObj.hostname, port, Math.min(timeoutMs, 6000), { lookup }) : null;
    findings.push(...tlsFindings(tlsResult, legacy, urlObj));
  } else {
    findings.push(createFinding({
      category: 'dast', severity: 'high', title: 'Plain HTTP Connection in Use (No Encryption)',
      description: 'The site is served over unencrypted HTTP and does not redirect to HTTPS. Traffic, cookies and form data can be read or changed by anyone on the network path.',
      identifiers: { cwe: ['CWE-319'], primary: 'CWE-319' },
      location: { url: urlObj.href },
      scanner: { name: 'vulnsight-passive', ruleId: 'plain-http', version: '1.1' },
      remediation: { advice: 'Serve the site over HTTPS and redirect every HTTP request to HTTPS with a 301.' },
      evidence: chain.map((c) => `${c.statusCode} ${c.url}`).join(' -> '),
    }));
  }

  // 3a. Who sits in front of the origin (CDN / WAF) and the evidence. Reads DNS, IP ownership and
  // what the edge returned, including on a challenge page, where it describes the edge, not the site.
  let edgeIntel = null;
  try {
    const { collectEdgeIntel } = require('./edge-intel');
    edgeIntel = await collectEdgeIntel({
      hostname: urlObj.hostname,
      statusCode: response.statusCode,
      headers,
      body: response.body,
      block,
      tls: tlsResult,
      ...(edgeResolver ? { resolver: edgeResolver } : {}),
    });
  } catch { /* edge details are informational; never fail the scan over them */ }

  // 3c. Checks adapted from public security-skill methodology (see skill-checks.js): SPF / DMARC /
  // CAA from DNS (no traffic to the site), and one request for a missing page to see whether the
  // error page leaks a stack trace. The error check is skipped when the edge is challenging us.
  let emailDns = null;
  if (skillChecks) {
    try {
      const checks = require('./skill-checks');
      const mail = await checks.checkEmailAndCaa(urlObj.hostname, { siteUrl: urlObj.href, ...(edgeResolver ? { resolver: edgeResolver } : {}) });
      emailDns = mail.facts;
      findings.push(...mail.findings);
      if (!block.blocked) {
        const errs = await checks.checkVerboseErrors(urlObj.origin, { lookup, timeoutMs: Math.min(timeoutMs, 10000) });
        findings.push(...errs.findings);
      }
    } catch { /* these checks add findings; they never fail the scan */ }
  }

  // 3b. HTTPS site that still serves content over plain HTTP.
  if (isHttps && seedUrl.protocol === 'https:') {
    try {
      const httpUrl = new URL(urlObj.href);
      httpUrl.protocol = 'http:';
      httpUrl.port = '';
      const plain = await fetchWebResponse(httpUrl, { timeoutMs: Math.min(timeoutMs, 6000), lookup });
      const loc = plain.headers.location || '';
      if (plain.statusCode >= 200 && plain.statusCode < 300 && !detectBlock(plain.statusCode, plain.headers, plain.body).blocked) {
        findings.push(createFinding({
          category: 'dast', severity: 'medium', title: 'HTTP Version of the Site Does Not Redirect to HTTPS',
          description: `http://${urlObj.host}/ returns content (HTTP ${plain.statusCode}) instead of redirecting to HTTPS, so users who type the address or follow old links are not protected.`,
          identifiers: { cwe: ['CWE-319'], primary: 'CWE-319' },
          location: { url: httpUrl.href },
          scanner: { name: 'vulnsight-passive', ruleId: 'http-no-https-redirect', version: '1.1' },
          remediation: { advice: 'Redirect all HTTP requests to HTTPS with a 301 and enable HSTS.' },
          evidence: `GET ${httpUrl.href} -> ${plain.statusCode}${loc ? ` Location: ${loc}` : ''}`,
        }));
      }
    } catch { /* port 80 closed is fine */ }
  }

  let cookieAnalysis = { cookies: [], findings: [] };
  let corsAnalysis = { cors: null, findings: [] };
  let technologies = [];
  let edgeAnalysis = { edge: detectEdgeProtection(headers), findings: [] };

  if (!block.blocked) {
    // 4. Security headers
    for (const rule of REQUIRED_HEADERS) {
      if (rule.name === 'strict-transport-security' && !isHttps) continue;
      const val = headers[rule.name];
      const issue = rule.check(val, headers);
      if (!issue) continue;
      findings.push(createFinding({
        category: 'dast', severity: rule.severity, title: rule.title, description: issue,
        identifiers: { cwe: [rule.cwe], primary: rule.cwe },
        location: { url: urlObj.href },
        scanner: { name: 'vulnsight-passive', ruleId: `header-${rule.name}`, version: '1.1' },
        remediation: { advice: rule.advice },
        evidence: val ? redactEvidence(`${rule.name}: ${val}`, 300) : `Header "${rule.name}" is missing from the response.`,
      }));
    }

    // 5. Version disclosure (a bare "nginx" or "cloudflare" Server header is not a finding)
    for (const info of INFO_DISCLOSURE_HEADERS) {
      const val = headers[info.header];
      if (!val) continue;
      if (info.versionOnly && !/\d/.test(String(val))) continue;
      findings.push(createFinding({
        category: 'dast', severity: 'low', title: info.title,
        description: `The response reveals server software details (${info.header}: ${val}), which helps attackers pick exploits for that exact version.`,
        identifiers: { cwe: ['CWE-200'], primary: 'CWE-200' },
        location: { url: urlObj.href },
        scanner: { name: 'vulnsight-passive', ruleId: `disclosure-${info.header}`, version: '1.1' },
        remediation: { advice: `Configure the web server or framework to remove or genericise the ${info.header} header.` },
        evidence: redactEvidence(`${info.header}: ${val}`),
      }));
    }

    // 6. Cookies, CORS, technologies, edge
    cookieAnalysis = analyzeCookies(headers, urlObj);
    findings.push(...cookieAnalysis.findings);
    corsAnalysis = await checkCors(urlObj, { lookup, timeoutMs });
    findings.push(...corsAnalysis.findings);
    technologies = detectTechnologies(headers, response.body);
    edgeAnalysis = analyzeEdgeProtection(headers, urlObj);
    findings.push(...edgeAnalysis.findings);

    // 7. Known-vulnerable front-end libraries (OSV advisories for the detected version)
    if (osvClient !== null) {
      const { auditLibraries } = require('./library-cves');
      const libs = technologies.filter((t) => t.version).map((t) => ({ name: t.name, version: t.version, source: 'html' }));
      findings.push(...await auditLibraries(libs, { ...(osvClient ? { osvClient } : {}), pageUrl: urlObj.href, scannerName: 'vulnsight-passive' }));
    }

    // 8. Subresource Integrity
    if (response.body) findings.push(...analyzeSri(response.body, urlObj));
  }

  // 9. Inventory of the landing page and the links on it. Linked pages are NOT fetched here,
  // so their status is unknown (0) rather than an assumed 200.
  let extracted = { links: [], forms: [] };
  if (response.body && !block.blocked) {
    const { extractLinksAndForms } = require('./crawler');
    extracted = extractLinksAndForms(response.body, urlObj.origin);
  }
  const { urlHash } = require('./scope');
  const seedHash = urlHash(urlObj.href);
  const pages = [{
    url: urlObj.href, urlHash: seedHash, statusCode: response.statusCode || 0,
    contentType: headers['content-type'] || '', depth: 0, title: extractTitle(response.body) || urlObj.hostname,
  }];
  const endpoints = [{
    url: urlObj.href, method: 'GET', statusCode: response.statusCode || 0,
    contentType: headers['content-type'] || '', paramNames: [...urlObj.searchParams.keys()],
  }];
  const links = [];
  for (const rel of (extracted.links || []).slice(0, 30)) {
    let u;
    try {
      u = new URL(rel, urlObj.origin);
    } catch {
      continue;
    }
    if (u.origin !== urlObj.origin || pages.some((p) => p.url === u.href)) continue;
    const h = urlHash(u.href);
    pages.push({ url: u.href, urlHash: h, statusCode: 0, contentType: '', depth: 1, title: u.pathname.replace(/^\//, '') || '/' });
    links.push({ fromHash: seedHash, toHash: h, kind: 'a' });
  }
  const forms = (extracted.forms || []).map((f) => ({ action: f.url, method: f.method || 'GET', fieldNames: f.parameters || [], submitted: false }));

  return {
    targetUrl: urlObj.href,
    requestedUrl: seedUrl.href,
    redirectChain: chain,
    offsiteRedirect: offsiteRedirect || null,
    hostname: urlObj.hostname,
    statusCode: response.statusCode,
    responseStatus: response.statusCode,
    reachable: true,
    blocked: block.blocked ? { by: block.by, reason: block.reason, retryAfterSec: block.retryAfterSec } : null,
    // Provider name as a plain string, the shape every engine uses for the pipeline.
    blockedBy: block.blocked ? (block.by || 'WAF') : null,
    tls: tlsResult,
    headers: {
      server: headers.server || null,
      contentType: headers['content-type'] || null,
      hsts: headers['strict-transport-security'] || null,
      csp: headers['content-security-policy'] || null,
      xFrameOptions: headers['x-frame-options'] || null,
      xContentTypeOptions: headers['x-content-type-options'] || null,
      referrerPolicy: headers['referrer-policy'] || null,
      permissionsPolicy: headers['permissions-policy'] || null,
    },
    cookies: cookieAnalysis.cookies,
    cors: corsAnalysis.cors,
    technologies,
    edge: edgeAnalysis.edge,
    edgeIntel,
    emailDns,
    findings,
    inventory: { engine: 'vulnsight-recon', pages, endpoints, forms, links },
  };
}

function extractTitle(body = '') {
  const m = String(body).match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 120) : '';
}

module.exports = {
  validateTargetUrl,
  inspectTls,
  probeLegacyTls,
  fetchWebResponse,
  fetchFinal,
  detectTechnologies,
  detectEdgeProtection,
  analyzeEdgeProtection,
  analyzeCookies,
  analyzeSri,
  checkCors,
  runPassiveScan,
};
