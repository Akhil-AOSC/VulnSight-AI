'use strict';

const https = require('node:https');
const http = require('node:http');
const tls = require('node:tls');
const dns = require('node:dns/promises');
const net = require('node:net');
const { URL } = require('node:url');
const { isPrivateIp } = require('../../platform/git');
const { createFinding } = require('../../findings');

// Standard security header definitions & benchmarks
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
      if (val.includes("'unsafe-inline'") && !val.includes("'nonce-") && !val.includes("'sha256-")) {
        return "CSP contains 'unsafe-inline' without nonces or hashes, weakening XSS mitigation.";
      }
      return null;
    },
  },
  {
    name: 'x-frame-options',
    title: 'Missing X-Frame-Options Header (Clickjacking Risk)',
    severity: 'low',
    cwe: 'CWE-1021',
    advice: 'Prevent framing in iframes by setting: X-Frame-Options: DENY or SAMEORIGIN.',
    check: (val) => {
      if (!val) return 'X-Frame-Options header is absent, allowing potential clickjacking via iframe overlay.';
      const upper = val.toUpperCase();
      if (upper !== 'DENY' && upper !== 'SAMEORIGIN') {
        return `X-Frame-Options has non-standard value: ${val}`;
      }
      return null;
    },
  },
  {
    name: 'x-content-type-options',
    title: 'Missing X-Content-Type-Options Header',
    severity: 'low',
    cwe: 'CWE-79',
    advice: 'Add: X-Content-Type-Options: nosniff to prevent browsers from MIME-sniffing the response.',
    check: (val) => (!val || val.toLowerCase() !== 'nosniff' ? 'Missing or incorrect X-Content-Type-Options: nosniff.' : null),
  },
  {
    name: 'referrer-policy',
    title: 'Missing or Insecure Referrer-Policy Header',
    severity: 'low',
    cwe: 'CWE-116',
    advice: 'Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer) to prevent URL path leakage.',
    check: (val) => {
      if (!val) return 'Referrer-Policy header is absent.';
      const unsafe = ['unsafe-url', 'no-referrer-when-downgrade'];
      if (unsafe.includes(val.toLowerCase())) {
        return `Referrer-Policy is set to an unsafe policy: ${val}`;
      }
      return null;
    },
  },
  {
    name: 'permissions-policy',
    title: 'Missing Permissions-Policy Header',
    severity: 'low',
    cwe: 'CWE-693',
    advice: "Restrict browser features by adding: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    check: (val) => (!val ? 'Permissions-Policy header is absent.' : null),
  },
];

// Server disclosure headers
const INFO_DISCLOSURE_HEADERS = [
  { header: 'server', title: 'Web Server Software Disclosed in Server Header' },
  { header: 'x-powered-by', title: 'Server Technology Disclosed via X-Powered-By' },
  { header: 'x-aspnet-version', title: 'ASP.NET Version Disclosed in Header' },
  { header: 'x-aspnetmvc-version', title: 'ASP.NET MVC Version Disclosed in Header' },
];

/**
 * Validate URL and ensure hostname does not resolve to private/loopback/cloud metadata IP.
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

  const hostname = parsed.hostname;
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new Error(`Target ${hostname} is a private/internal IP address. Scanning blocked for security.`);
  }
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error(`Target ${hostname} is a private/internal IP address. Scanning blocked for security.`);
    }
    return { parsed, primaryIp: hostname };
  }

  const addresses = await dns.resolve4(hostname).catch(() => []);
  const addresses6 = await dns.resolve6(hostname).catch(() => []);
  const allIps = [...addresses, ...addresses6];

  if (!allIps.length) {
    throw new Error(`Could not resolve hostname: ${hostname}`);
  }

  for (const ip of allIps) {
    if (isPrivateIp(ip)) {
      throw new Error(`Target ${hostname} resolves to private/internal IP address (${ip}). Scanning blocked for security.`);
    }
  }

  return { parsed, primaryIp: allIps[0] };
}

/**
 * Perform in-process TLS inspection on HTTPS targets.
 */
function inspectTls(hostname, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false, // We inspect cert details even if self-signed/expired
        timeout: timeoutMs,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          socket.end();

          if (!cert || !cert.valid_to) {
            return resolve({ error: 'No peer certificate presented' });
          }

          const validTo = new Date(cert.valid_to);
          const validFrom = new Date(cert.valid_from);
          const now = new Date();
          const daysLeft = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

          resolve({
            valid: authorized,
            authorized,
            authError: authError || null,
            authorizationError: authError || null,
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
          resolve({ error: err.message });
        }
      }
    );

    socket.on('error', (err) => resolve({ error: err.message }));
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ error: 'TLS connection timed out' });
    });
  });
}

/**
 * Fetch headers and response body with bounded size and timeout.
 */
function fetchWebResponse(urlObj, options = {}) {
  const { timeoutMs = 10000, extraHeaders = {}, method = 'GET' } = options;
  const isHttps = urlObj.protocol === 'https:';
  const transport = isHttps ? https : http;

  return new Promise((resolve, reject) => {
    const req = transport.request(
      urlObj,
      {
        method,
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'VulnSight-Security-Scanner/1.0 (Automated Passive Security Auditor)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          ...extraHeaders,
        },
        rejectUnauthorized: false,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (body.length < 250000) body += chunk; // Cap body inspection at 250KB
        });
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body,
            rawHeaders: res.rawHeaders,
          });
        });
      }
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request to ${urlObj.href} timed out after ${timeoutMs}ms`));
    });
    req.end();
  });
}

/**
 * Detect technologies from headers and body keywords (Wappalyzer signatures).
 */
function detectTechnologies(headers, body = '') {
  const techs = [];

  const server = headers['server'];
  if (server) {
    if (/litespeed/i.test(server)) {
      techs.push({ name: 'LiteSpeed Web Server', category: 'Web Server', version: null });
    } else if (/nginx/i.test(server)) {
      const match = server.match(/nginx\/([\d.]+)/i);
      techs.push({ name: 'Nginx', category: 'Web Server', version: match ? match[1] : null });
    } else if (/apache/i.test(server)) {
      const match = server.match(/apache\/([\d.]+)/i);
      techs.push({ name: 'Apache HTTP Server', category: 'Web Server', version: match ? match[1] : null });
    } else if (/cloudflare/i.test(server)) {
      techs.push({ name: 'Cloudflare', category: 'CDN / Reverse Proxy', version: null });
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
    if (/litespeed/i.test(body) && !techs.some((t) => t.name.includes('LiteSpeed'))) {
      techs.push({ name: 'LiteSpeed Web Server', category: 'Web Server', version: null });
    }
    if (/wp-content|wp-includes/i.test(body)) techs.push({ name: 'WordPress', category: 'CMS', version: null });
    if (/woocommerce/i.test(body)) techs.push({ name: 'WooCommerce', category: 'E-Commerce Platform', version: null });
    if (/elementor/i.test(body)) techs.push({ name: 'Elementor', category: 'Page Builder', version: null });
    if (/__next|__NEXT_DATA__/i.test(body)) techs.push({ name: 'Next.js', category: 'Frontend Framework', version: null });
    if (/react|react-dom/i.test(body) || /data-reactroot/i.test(body)) techs.push({ name: 'React', category: 'Frontend Framework', version: null });
    if (/vue|v-bind|v-model/i.test(body) || /data-v-[a-f0-9]/i.test(body)) techs.push({ name: 'Vue.js', category: 'Frontend Framework', version: null });
    if (/ng-version|ng-app/i.test(body)) techs.push({ name: 'Angular', category: 'Frontend Framework', version: null });
    
    const bsMatch = body.match(/bootstrap[.-]([\d.]+)(?:\.bundle|\.min)?\.js/i) || body.match(/bootstrap\/([\d.]+)\//i);
    if (bsMatch) {
      techs.push({ name: 'Bootstrap', category: 'UI Framework', version: bsMatch[1] });
    } else if (/bootstrap(?:\.min)?\.(?:css|js)/i.test(body)) {
      techs.push({ name: 'Bootstrap', category: 'UI Framework', version: null });
    }

    if (/tailwind/i.test(body)) techs.push({ name: 'Tailwind CSS', category: 'UI Framework', version: null });
    if (/font-awesome|fontawesome/i.test(body)) techs.push({ name: 'Font Awesome', category: 'Font & Icon Toolkit', version: null });
    if (/owl\.carousel/i.test(body)) techs.push({ name: 'Owl Carousel', category: 'JavaScript UI Library', version: null });
    if (/googletagmanager\.com|google-analytics\.com/i.test(body)) techs.push({ name: 'Google Analytics', category: 'Analytics', version: null });

    const jqMatch = body.match(/jquery[.-]([\d.]+)(?:\.min)?\.js/i) || body.match(/jquery\/([\d.]+)\/jquery/i) || body.match(/jquery-([\d.]+)/i);
    if (jqMatch) {
      techs.push({ name: 'jQuery', category: 'JavaScript Library', version: jqMatch[1] });
    } else if (/jquery(?:\.min)?\.js/i.test(body)) {
      techs.push({ name: 'jQuery', category: 'JavaScript Library', version: null });
    }
  }

  // Deduplicate
  const seen = new Set();
  return techs.filter((t) => {
    const key = `${t.name}-${t.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Analyze Cookie security attributes.
 */
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

    const lowerParts = parts.map((p) => p.toLowerCase());
    const isSecure = lowerParts.includes('secure');
    const isHttpOnly = lowerParts.includes('httponly');
    const sameSitePart = lowerParts.find((p) => p.startsWith('samesite='));
    const sameSite = sameSitePart ? sameSitePart.split('=')[1] : null;

    cookies.push({ name, secure: isSecure, httpOnly: isHttpOnly, sameSite });

    if (isHttps && !isSecure) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'medium',
          title: `Cookie "${name}" Set Without Secure Flag`,
          description: `The cookie "${name}" is transmitted over HTTPS without the "Secure" flag, allowing transmission over unencrypted connections if requested.`,
          identifiers: { cwe: ['CWE-614'], primary: 'CWE-614' },
          location: { url: urlObj.href, parameter: name },
          scanner: { name: 'vulnsight-passive', ruleId: 'cookie-no-secure', version: '1.0' },
          remediation: { advice: `Add the "Secure" directive to the Set-Cookie header for "${name}".` },
          evidence: cStr,
        })
      );
    }

    if (!isHttpOnly && /(session|auth|token|jwt|id|key|login)/i.test(name)) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'medium',
          title: `Sensitive Cookie "${name}" Set Without HttpOnly Flag`,
          description: `The cookie "${name}" appears to store session or authentication state but lacks the "HttpOnly" attribute, making it accessible to client-side scripts via document.cookie.`,
          identifiers: { cwe: ['CWE-1004'], primary: 'CWE-1004' },
          location: { url: urlObj.href, parameter: name },
          scanner: { name: 'vulnsight-passive', ruleId: 'cookie-no-httponly', version: '1.0' },
          remediation: { advice: `Set the "HttpOnly" flag on the Set-Cookie header for "${name}".` },
          evidence: cStr,
        })
      );
    }

    if (!sameSite) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'low',
          title: `Cookie "${name}" Missing SameSite Attribute`,
          description: `The cookie "${name}" does not specify a SameSite attribute, which can expose the application to Cross-Site Request Forgery (CSRF).`,
          identifiers: { cwe: ['CWE-1275'], primary: 'CWE-1275' },
          location: { url: urlObj.href, parameter: name },
          scanner: { name: 'vulnsight-passive', ruleId: 'cookie-no-samesite', version: '1.0' },
          remediation: { advice: `Add SameSite=Lax or SameSite=Strict to the Set-Cookie header for "${name}".` },
          evidence: cStr,
        })
      );
    }
  }

  return { cookies, findings };
}

/**
 * Check CORS configuration against an arbitrary origin.
 */
async function checkCors(urlObj) {
  try {
    const testOrigin = 'https://vulnsight-security-audit.com';
    const res = await fetchWebResponse(urlObj, {
      method: 'GET',
      extraHeaders: { Origin: testOrigin },
    });

    const acao = res.headers['access-control-allow-origin'];
    const acac = res.headers['access-control-allow-credentials'];
    const findings = [];

    if (acao === testOrigin && acac === 'true') {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'high',
          title: 'Arbitrary Origin Reflection with Credentials in CORS',
          description: 'The server reflects untrusted arbitrary Origin headers in Access-Control-Allow-Origin while allowing credentials (Access-Control-Allow-Credentials: true). Any website can make authenticated cross-origin requests on behalf of the user.',
          identifiers: { cwe: ['CWE-942'], primary: 'CWE-942' },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: 'cors-arbitrary-credentials', version: '1.0' },
          remediation: { advice: 'Restrict Access-Control-Allow-Origin to an explicit whitelist of trusted domains, and do not reflect the Origin request header.' },
          evidence: `Origin: ${testOrigin} -> Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: ${acac}`,
        })
      );
    } else if (acao === '*') {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'low',
          title: 'Wildcard CORS Header Configured (*)',
          description: 'The server responds with Access-Control-Allow-Origin: *, allowing any public web page to read response data.',
          identifiers: { cwe: ['CWE-942'], primary: 'CWE-942' },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: 'cors-wildcard', version: '1.0' },
          remediation: { advice: 'Evaluate whether public unrestricted cross-origin read access is intended for this endpoint.' },
          evidence: `Access-Control-Allow-Origin: *`,
        })
      );
    }

    return {
      cors: { allowOrigin: acao || null, allowCredentials: acac === 'true' },
      findings,
    };
  } catch {
    return { cors: null, findings: [] };
  }
}

/**
 * Main Entry Point: Passive Website Security Scanner
 */
async function runPassiveScan(targetUrl, options = {}) {
  const { timeoutMs = 12000 } = options;
  const { parsed: urlObj } = await validateTargetUrl(targetUrl);

  const findings = [];
  const isHttps = urlObj.protocol === 'https:';

  // 1. TLS Inspection
  let tlsResult = null;
  if (isHttps) {
    tlsResult = await inspectTls(urlObj.hostname, urlObj.port ? Number(urlObj.port) : 443, timeoutMs);
    if (tlsResult.error) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'high',
          title: 'TLS/SSL Handshake Error',
          description: `Failed to establish secure TLS connection: ${tlsResult.error}`,
          identifiers: { cwe: ['CWE-319'], primary: 'CWE-319' },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: 'tls-error', version: '1.0' },
          remediation: { advice: 'Ensure valid SSL/TLS certificate is installed and bound to the server.' },
          evidence: tlsResult.error,
        })
      );
    } else {
      if (tlsResult.daysLeft <= 0) {
        findings.push(
          createFinding({
            category: 'dast',
            severity: 'critical',
            title: 'SSL/TLS Certificate Has Expired',
            description: `The SSL/TLS certificate expired ${Math.abs(tlsResult.daysLeft)} days ago on ${tlsResult.validTo}. Browsers will block access with security warnings.`,
            identifiers: { cwe: ['CWE-298'], primary: 'CWE-298' },
            location: { url: urlObj.href },
            scanner: { name: 'vulnsight-passive', ruleId: 'tls-cert-expired', version: '1.0' },
            remediation: { advice: 'Renew the SSL/TLS certificate immediately.' },
            evidence: `Issuer: ${tlsResult.issuer}, Expired at: ${tlsResult.validTo}`,
          })
        );
      } else if (tlsResult.daysLeft <= 14) {
        findings.push(
          createFinding({
            category: 'dast',
            severity: 'medium',
            title: `SSL/TLS Certificate Expiring Soon (${tlsResult.daysLeft} days remaining)`,
            description: `The certificate for ${urlObj.hostname} expires on ${tlsResult.validTo}.`,
            identifiers: { cwe: ['CWE-298'], primary: 'CWE-298' },
            location: { url: urlObj.href },
            scanner: { name: 'vulnsight-passive', ruleId: 'tls-cert-expiring-soon', version: '1.0' },
            remediation: { advice: 'Renew the SSL/TLS certificate before expiration to prevent service disruption.' },
            evidence: `Days remaining: ${tlsResult.daysLeft}`,
          })
        );
      }

      if (tlsResult.protocol && ['TLSv1', 'TLSv1.1'].includes(tlsResult.protocol)) {
        findings.push(
          createFinding({
            category: 'dast',
            severity: 'high',
            title: `Deprecated TLS Protocol Supported (${tlsResult.protocol})`,
            description: `The server negotiated ${tlsResult.protocol}, which is deprecated and contains known cryptographic weaknesses (e.g. BEAST, POODLE).`,
            identifiers: { cwe: ['CWE-326'], primary: 'CWE-326' },
            location: { url: urlObj.href },
            scanner: { name: 'vulnsight-passive', ruleId: 'tls-deprecated-version', version: '1.0' },
            remediation: { advice: 'Disable TLS 1.0 and TLS 1.1 in web server configuration. Enforce TLS 1.2 or TLS 1.3.' },
            evidence: `Negotiated Protocol: ${tlsResult.protocol}`,
          })
        );
      }
    }
  } else {
    findings.push(
      createFinding({
        category: 'dast',
        severity: 'high',
        title: 'Plain HTTP Connection in Use (No Encryption)',
        description: 'The target website is accessible over unencrypted HTTP. All network traffic, cookies, and user data are vulnerable to eavesdropping and tampering.',
        identifiers: { cwe: ['CWE-319'], primary: 'CWE-319' },
        location: { url: urlObj.href },
        scanner: { name: 'vulnsight-passive', ruleId: 'plain-http', version: '1.0' },
        remediation: { advice: 'Enforce HTTPS and configure 301 redirects from HTTP to HTTPS.' },
      })
    );
  }

  // 2. Fetch main page response
  const response = await fetchWebResponse(urlObj, { timeoutMs });
  const headers = response.headers;

  // 3. Security Headers Analysis
  for (const rule of REQUIRED_HEADERS) {
    if (rule.name === 'strict-transport-security' && !isHttps) continue;
    const val = headers[rule.name];
    const issue = rule.check(val);
    if (issue) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: rule.severity,
          title: rule.title,
          description: issue,
          identifiers: { cwe: [rule.cwe], primary: rule.cwe },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: `header-${rule.name}`, version: '1.0' },
          remediation: { advice: rule.advice },
          evidence: val ? `${rule.name}: ${val}` : `Header "${rule.name}" is missing from response.`,
        })
      );
    }
  }

  // 4. Server Information Disclosure Headers
  for (const info of INFO_DISCLOSURE_HEADERS) {
    const val = headers[info.header];
    if (val) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'low',
          title: info.title,
          description: `The response leaks underlying server software details (${info.header}: ${val}), aiding attackers in targeting specific version vulnerabilities.`,
          identifiers: { cwe: ['CWE-200'], primary: 'CWE-200' },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: `disclosure-${info.header}`, version: '1.0' },
          remediation: { advice: `Configure the web server or application framework to strip the ${info.header} header.` },
          evidence: `${info.header}: ${val}`,
        })
      );
    }
  }

  // 5. Cookie Analysis
  const cookieAnalysis = analyzeCookies(headers, urlObj);
  findings.push(...cookieAnalysis.findings);

  // 6. CORS Analysis
  const corsAnalysis = await checkCors(urlObj);
  findings.push(...corsAnalysis.findings);

  // 7. Technology Detection
  const technologies = detectTechnologies(headers, response.body);

  // 8. Library Vulnerability Correlation
  const jqTech = technologies.find((t) => t.name === 'jQuery');
  if (jqTech && jqTech.version) {
    const v = parseFloat(jqTech.version);
    if (!isNaN(v) && v < 3.5) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'medium',
          title: `Outdated jQuery Library (v${jqTech.version}) with Known XSS Vulnerabilities`,
          description: `The website loads jQuery version ${jqTech.version}. jQuery versions prior to 3.5.0 contain known Cross-Site Scripting (XSS) vulnerabilities (CVE-2020-11022, CVE-2020-11023) within the jQuery.htmlPrefilter method when parsing untrusted HTML elements.`,
          identifiers: { cwe: ['CWE-79'], primary: 'CWE-79' },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: 'outdated-jquery', version: '1.0' },
          remediation: { advice: 'Upgrade to jQuery 3.5.0 or newer (or latest 3.x release) to mitigate XSS vulnerabilities.' },
          evidence: `Detected jQuery version: ${jqTech.version}`,
        })
      );
    }
  }

  const bsTech = technologies.find((t) => t.name === 'Bootstrap');
  if (bsTech && bsTech.version) {
    const v = parseFloat(bsTech.version);
    if (!isNaN(v) && v < 4.5) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'low',
          title: `Outdated Bootstrap Library (v${bsTech.version}) (XSS Risk in Tooltip/Popover Plugins)`,
          description: `The website loads Bootstrap version ${bsTech.version}. Versions prior to 4.5.0 contain known XSS flaws in data-template and tooltip attributes (CVE-2019-8331, CVE-2018-14041).`,
          identifiers: { cwe: ['CWE-79'], primary: 'CWE-79' },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: 'outdated-bootstrap', version: '1.0' },
          remediation: { advice: 'Upgrade to Bootstrap 4.5.0+ or Bootstrap 5.x to eliminate client-side XSS attack surfaces.' },
          evidence: `Detected Bootstrap version: ${bsTech.version}`,
        })
      );
    }
  }

  // 9. Subresource Integrity (SRI) Audit on External Scripts
  if (response.body) {
    const scriptSrcRegex = /<script\s+[^>]*?src=["'](https?:\/\/[^"']+)["'][^>]*?>/gi;
    const thirdPartyScriptsWithoutSri = [];
    let sMatch;
    while ((sMatch = scriptSrcRegex.exec(response.body)) !== null) {
      const fullTag = sMatch[0];
      const srcUrl = sMatch[1];
      if (!srcUrl.startsWith(urlObj.origin) && !fullTag.includes('integrity=')) {
        try {
          const parsedSrc = new URL(srcUrl);
          if (parsedSrc.hostname !== urlObj.hostname && !thirdPartyScriptsWithoutSri.includes(parsedSrc.hostname)) {
            thirdPartyScriptsWithoutSri.push(parsedSrc.hostname);
          }
        } catch {
          /* ignore invalid url */
        }
      }
    }
    if (thirdPartyScriptsWithoutSri.length > 0) {
      findings.push(
        createFinding({
          category: 'dast',
          severity: 'low',
          title: 'Third-Party CDN Scripts Missing Subresource Integrity (SRI)',
          description: `External JavaScript files are loaded from third-party hosts (${thirdPartyScriptsWithoutSri.slice(0, 3).join(', ')}) without cryptographic Subresource Integrity (SRI) validation hashes. If a third-party CDN or supplier is compromised, attackers can execute arbitrary malicious code in visitors browsers.`,
          identifiers: { cwe: ['CWE-353'], primary: 'CWE-353' },
          location: { url: urlObj.href },
          scanner: { name: 'vulnsight-passive', ruleId: 'missing-sri', version: '1.0' },
          remediation: { advice: 'Add integrity="sha384-..." and crossorigin="anonymous" attributes to all external <script> tags.' },
          evidence: `External hosts loaded without SRI: ${thirdPartyScriptsWithoutSri.join(', ')}`,
        })
      );
    }
  }

  // 10. Sensitive Paths & Public Reconnaissance
  const probeTargets = [
    {
      path: '/.env',
      title: 'Exposed Environment Configuration File (.env)',
      severity: 'critical',
      cwe: 'CWE-552',
      check: (res) => res.statusCode === 200 && /^(DB_|DATABASE_|SECRET_|AWS_|API_KEY|PASSWORD|TOKEN=)/m.test(res.body),
      advice: 'Remove .env from public web directory immediately and restrict web server access to dotfiles.',
    },
    {
      path: '/.git/HEAD',
      title: 'Exposed Git Repository Metadata (/.git/HEAD)',
      severity: 'high',
      cwe: 'CWE-538',
      check: (res) => res.statusCode === 200 && /^ref: refs\//.test(res.body.trim()),
      advice: 'Block public web access to the .git directory in web server configuration.',
    },
    {
      path: '/robots.txt',
      title: 'Robots.txt Discloses Internal Application Paths',
      severity: 'low',
      cwe: 'CWE-200',
      check: (res) => res.statusCode === 200 && /Disallow:\s*\/\w+/i.test(res.body),
      advice: 'Review robots.txt disallow directives to ensure sensitive administrative or staging paths are not disclosed to public crawlers.',
    },
    {
      path: '/xmlrpc.php',
      title: 'Exposed XML-RPC API Interface (Brute-Force & Pingback Risk)',
      severity: 'medium',
      cwe: 'CWE-306',
      check: (res) => (res.statusCode === 200 || res.statusCode === 405) && /XML-RPC server accepts POST requests only/i.test(res.body),
      advice: 'Disable xmlrpc.php or block external access via web server rules if XML-RPC API is not required.',
    },
    {
      path: '/wp-login.php',
      title: 'Exposed Administrative Login Portal (/wp-login.php)',
      severity: 'low',
      cwe: 'CWE-200',
      check: (res) => res.statusCode === 200 && (/<form[^>]*login/i.test(res.body) || /user_login/i.test(res.body)),
      advice: 'Protect the administrative login page with multi-factor authentication, IP allowlists, or rate limiting.',
    },
    {
      path: '/phpinfo.php',
      title: 'Exposed PHP Information Script (phpinfo.php)',
      severity: 'high',
      cwe: 'CWE-200',
      check: (res) => res.statusCode === 200 && (/PHP Version/i.test(res.body) || /<title>phpinfo\(\)/i.test(res.body)),
      advice: 'Remove phpinfo.php immediately to prevent full server environment disclosure.',
    },
  ];

  await Promise.allSettled(
    probeTargets.map(async (target) => {
      try {
        const probeUrl = new URL(target.path, urlObj.origin);
        const res = await fetchWebResponse(probeUrl, { timeoutMs: 4000 });
        if (res && target.check(res)) {
          findings.push(
            createFinding({
              category: 'dast',
              severity: target.severity,
              title: target.title,
              description: `The path "${target.path}" is publicly accessible on the web server and discloses sensitive application data or attack surfaces.`,
              identifiers: { cwe: [target.cwe], primary: target.cwe },
              location: { url: probeUrl.href, path: target.path },
              scanner: { name: 'vulnsight-passive', ruleId: `exposed-${target.path.replace(/[^a-z0-9]/gi, '_')}`, version: '1.0' },
              remediation: { advice: target.advice },
              evidence: res.body.slice(0, 200).trim(),
            })
          );
        }
      } catch {
        /* ignore network probe errors */
      }
    })
  );

  // 11. Discovered Pages, Endpoints & Forms Inventory
  let extracted = { links: [], forms: [] };
  try {
    const { extractLinksAndForms } = require('./crawler');
    if (response.body) {
      extracted = extractLinksAndForms(response.body, urlObj.origin);
    }
  } catch {
    /* fallback */
  }

  let urlHashFn = (h) => {
    try {
      const crypto = require('node:crypto');
      return crypto.createHash('sha256').update(h).digest('hex').slice(0, 16);
    } catch {
      return String(h).slice(0, 16);
    }
  };

  const seedHash = urlHashFn(urlObj.href);
  const discoveredPages = [
    {
      url: urlObj.href,
      urlHash: seedHash,
      statusCode: response.statusCode || 200,
      contentType: headers['content-type'] || 'text/html',
      depth: 0,
      title: extractTitle(response.body) || urlObj.hostname,
    },
  ];

  const discoveredEndpoints = [
    {
      url: urlObj.href,
      method: 'GET',
      statusCode: response.statusCode || 200,
      contentType: headers['content-type'] || 'text/html',
      paramNames: Array.from(urlObj.searchParams.keys()),
    },
  ];

  const discoveredLinks = [];
  for (const rel of (extracted.links || []).slice(0, 30)) {
    try {
      const u = new URL(rel, urlObj.origin);
      if (u.origin === urlObj.origin && !discoveredPages.some((p) => p.url === u.href)) {
        const pHash = urlHashFn(u.href);
        discoveredPages.push({
          url: u.href,
          urlHash: pHash,
          statusCode: 200,
          contentType: 'text/html',
          depth: 1,
          title: u.pathname.replace(/^\//, '').replace(/\.html?$/, '') || 'Internal Page',
        });
        discoveredEndpoints.push({
          url: u.href,
          method: 'GET',
          statusCode: 200,
          contentType: 'text/html',
          paramNames: Array.from(u.searchParams.keys()),
        });
        discoveredLinks.push({
          fromHash: seedHash,
          toHash: pHash,
          kind: 'a',
        });
      }
    } catch {
      /* ignore invalid url */
    }
  }

  const discoveredForms = (extracted.forms || []).map((f) => ({
    action: f.url,
    method: f.method || 'GET',
    fieldNames: f.parameters || [],
    submitted: false,
  }));

  return {
    targetUrl: urlObj.href,
    hostname: urlObj.hostname,
    statusCode: response.statusCode,
    tls: tlsResult,
    headers: {
      server: headers['server'] || null,
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
    findings,
    inventory: {
      engine: 'vulnsight-recon',
      pages: discoveredPages,
      endpoints: discoveredEndpoints,
      forms: discoveredForms,
      links: discoveredLinks,
    },
  };
}

function extractTitle(body = '') {
  const m = String(body).match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 120) : '';
}

module.exports = {
  validateTargetUrl,
  inspectTls,
  fetchWebResponse,
  detectTechnologies,
  analyzeCookies,
  checkCors,
  runPassiveScan,
};
