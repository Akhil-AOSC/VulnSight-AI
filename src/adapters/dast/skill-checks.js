'use strict';

// Website checks taken from the methodology in public security skills:
//   - mahmutka/cybersecurity-claude-skills: pentest-recon (DNS TXT review: SPF, DMARC) and
//     web-hacking (A02 sensitive data in URLs, A05 verbose errors and exposed paths)
//   - sickn33 vulnerability-scanner (OWASP Top 10:2025, A10 exceptional conditions)
//
// Only the detection ideas are used. Nothing here sends exploit payloads, brute-forces anything
// or tries to get past a firewall. DNS checks and the inventory review send no traffic to the
// site; the error-page check is one GET to a random path, the same as a visitor mistyping a URL.

const dns = require('node:dns').promises;
const { Resolver } = require('node:dns').promises;
const crypto = require('node:crypto');
const { createFinding } = require('../../findings');
const { guardedRequest, guardedLookup, detectBlock, redactEvidence } = require('./net-guard');

const SCANNER = 'vulnsight-checks';

function finding({ severity, title, description, cwe, owasp, url, parameter = null, ruleId, advice, evidence }) {
  return createFinding({
    category: 'dast',
    severity,
    title,
    description,
    identifiers: { primary: cwe, cwe: [cwe], aliases: owasp ? [owasp] : [] },
    location: { url, parameter },
    scanner: { name: SCANNER, ruleId, version: '1.0' },
    remediation: { advice },
    evidence: evidence == null ? null : redactEvidence(evidence, 300),
  });
}

// ---- Email and certificate DNS checks (no traffic to the site) ----------------------------------

// Second-level labels under which the next label is the registrable domain (com.au, co.uk, ...).
const PUBLIC_SECOND_LEVEL = new Set(['com', 'net', 'org', 'co', 'gov', 'edu', 'ac', 'id', 'asn', 'ltd', 'plc', 'me']);

/** The domain email and CAA policy are set on: www.shop.example.com.au -> example.com.au. */
function policyDomain(hostname) {
  const labels = String(hostname || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const keep = PUBLIC_SECOND_LEVEL.has(labels[labels.length - 2]) && labels[labels.length - 1].length === 2 ? 3 : 2;
  return labels.slice(-keep).join('.');
}

const flat = (records) => (records || []).map((r) => (Array.isArray(r) ? r.join('') : String(r)));

// A DNS answer of "this name has no such record" (ENODATA/ENOTFOUND) is a real result we can act on.
// A resolver failure (refused, server fail, timeout) is not: the record may well exist. Treating the
// second as "no record" produced false "No SPF record" findings on machines with a flaky resolver.
const NO_RECORD = new Set(['ENODATA', 'ENOTFOUND', 'ENOTIMP']);
const PUBLIC_DNS = ['1.1.1.1', '8.8.8.8'];

function makePublicResolvers() {
  return PUBLIC_DNS.map((ip) => {
    const r = new Resolver();
    r.setServers([ip]);
    return r;
  });
}

async function tryResolve(resolver, method, name) {
  if (!resolver || typeof resolver[method] !== 'function') return { ok: false, records: [] };
  try {
    return { ok: true, records: (await resolver[method](name)) || [] };
  } catch (err) {
    if (NO_RECORD.has(err && err.code)) return { ok: true, records: [] }; // genuinely no such record
    return { ok: false, records: [], error: (err && err.code) || String(err && err.message) };
  }
}

// Queries the primary resolver, then public resolvers if it hit an infrastructure error. ok is true
// only when some resolver actually answered (including "no such record"); false means unknown.
async function resolveWithFallback(primary, fallbacks, method, name) {
  const first = await tryResolve(primary, method, name);
  if (first.ok) return first;
  for (const r of fallbacks) {
    const res = await tryResolve(r, method, name);
    if (res.ok) return res;
  }
  return { ok: false, records: [] };
}

async function checkEmailAndCaa(hostname, { resolver = dns, siteUrl, publicResolvers } = {}) {
  const domain = policyDomain(hostname);
  const url = siteUrl || `https://${hostname}/`;
  const findings = [];
  const facts = { domain, spf: null, dmarc: null, caa: [], resolved: true };
  const fallbacks = publicResolvers || makePublicResolvers();

  const txtRes = await resolveWithFallback(resolver, fallbacks, 'resolveTxt', domain);
  const txt = flat(txtRes.records);
  const spfRecords = txt.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  facts.spf = spfRecords[0] || null;
  if (!txtRes.ok) facts.resolved = false;
  // Only judge SPF when the lookup actually answered. A resolver outage is not "no record".
  if (!txtRes.ok) {
    // skip
  } else if (!spfRecords.length) {
    findings.push(finding({
      severity: 'medium', ruleId: 'email-spf-missing', cwe: 'CWE-290', owasp: 'OWASP-A07:2025', url,
      title: `No SPF record for ${domain}`,
      description: `${domain} publishes no SPF record, so receiving mail servers cannot tell which servers may send email for it. Attackers can send phishing email that appears to come from this domain.`,
      advice: `Publish a TXT record on ${domain} listing your real mail senders and ending in -all, for example "v=spf1 include:_spf.google.com -all".`,
      evidence: `TXT ${domain}: no v=spf1 record`,
    }));
  } else if (spfRecords.length > 1) {
    findings.push(finding({
      severity: 'medium', ruleId: 'email-spf-multiple', cwe: 'CWE-290', owasp: 'OWASP-A07:2025', url,
      title: `Multiple SPF records for ${domain}`,
      description: 'More than one v=spf1 record makes SPF evaluation fail (permerror), so receivers treat the domain as having no valid SPF policy.',
      advice: 'Merge the SPF records into a single TXT record.',
      evidence: spfRecords.join(' | '),
    }));
  } else {
    // A record with no "all" term (and no redirect=) defaults to neutral, the same as ?all.
    const m = spfRecords[0].match(/\s([+?~-]?)all(\s|$)/i);
    const all = m ? m[1] : (/redirect=/i.test(spfRecords[0]) ? '-' : '?');
    if (all === '+' || all === '') {
      findings.push(finding({
        severity: 'high', ruleId: 'email-spf-pass-all', cwe: 'CWE-290', owasp: 'OWASP-A07:2025', url,
        title: `SPF for ${domain} allows any server to send mail (+all)`,
        description: 'The SPF record ends in +all, which authorises every server on the internet to send email for this domain.',
        advice: 'End the SPF record with -all (or ~all while testing) after listing the real senders.',
        evidence: `TXT ${domain}: ${spfRecords[0]}`,
      }));
    } else if (all === '?') {
      findings.push(finding({
        severity: 'medium', ruleId: 'email-spf-neutral', cwe: 'CWE-290', owasp: 'OWASP-A07:2025', url,
        title: `SPF for ${domain} ends in ?all (neutral)`,
        description: 'A neutral ?all tells receivers to make no judgement about unlisted senders, so spoofed email from other servers is not rejected or flagged by SPF.',
        advice: 'Change the ending to -all (or ~all while testing) once every legitimate sender is listed.',
        evidence: `TXT ${domain}: ${spfRecords[0]}`,
      }));
    }
  }

  const dmarcRes = await resolveWithFallback(resolver, fallbacks, 'resolveTxt', `_dmarc.${domain}`);
  const dmarcTxt = flat(dmarcRes.records).filter((t) => /^v=DMARC1/i.test(t.trim()));
  facts.dmarc = dmarcTxt[0] || null;
  if (!dmarcRes.ok) facts.resolved = false;
  if (!dmarcRes.ok) {
    // skip: a resolver outage is not a missing DMARC policy
  } else if (!dmarcTxt.length) {
    findings.push(finding({
      severity: 'medium', ruleId: 'email-dmarc-missing', cwe: 'CWE-290', owasp: 'OWASP-A07:2025', url,
      title: `No DMARC policy for ${domain}`,
      description: `Without DMARC, receivers have no instruction to reject email that fails SPF/DKIM for ${domain}, and you get no reports of spoofing attempts.`,
      advice: `Publish TXT _dmarc.${domain} "v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}", then move to p=reject.`,
      evidence: `TXT _dmarc.${domain}: none`,
    }));
  } else {
    const policy = ((dmarcTxt[0].match(/;\s*p=([a-z]+)/i) || [])[1] || '').toLowerCase();
    if (policy === 'none') {
      findings.push(finding({
        severity: 'low', ruleId: 'email-dmarc-none', cwe: 'CWE-290', owasp: 'OWASP-A07:2025', url,
        title: `DMARC for ${domain} is monitor-only (p=none)`,
        description: 'p=none only collects reports. Spoofed email that fails DMARC is still delivered.',
        advice: 'After reviewing the reports, raise the policy to p=quarantine and then p=reject.',
        evidence: `TXT _dmarc.${domain}: ${dmarcTxt[0]}`,
      }));
    }
  }

  const caaRes = await resolveWithFallback(resolver, fallbacks, 'resolveCaa', domain);
  facts.caa = (caaRes.records || []).map((r) => {
    const tag = Object.keys(r).find((k) => k !== 'critical') || '';
    return `${tag} ${r[tag] == null ? '' : r[tag]}`.trim();
  });
  if (!caaRes.ok) facts.resolved = false;
  if (!caaRes.records.length && caaRes.ok) {
    findings.push(finding({
      severity: 'low', ruleId: 'dns-caa-missing', cwe: 'CWE-295', owasp: 'OWASP-A04:2025', url,
      title: `No CAA record for ${domain}`,
      description: 'Without a CAA record, any public certificate authority may issue certificates for this domain, which widens the room for a mis-issued certificate.',
      advice: `Add CAA records naming only the CAs you use, for example ${domain} CAA 0 issue "letsencrypt.org".`,
      evidence: `CAA ${domain}: none`,
    }));
  }

  return { findings, facts };
}

// ---- Verbose error pages (OWASP A05 / A10 exceptional conditions) -------------------------------

const ERROR_SIGNATURES = [
  { name: 'Java stack trace', re: /(java|javax|org\.springframework)\.[\w.$]+(Exception|Error)\b[\s\S]{0,400}?\bat [\w.$]+\([\w$]+\.java:\d+\)/ },
  { name: 'Python traceback', re: /Traceback \(most recent call last\):/ },
  { name: 'Django debug page', re: /You(?:'|&#x27;|&#39;)re seeing this error because you have <code>DEBUG = True<\/code>/ },
  { name: 'PHP error with file path', re: /(Fatal error|Parse error|Warning|Notice|Deprecated)(<\/b>)?:\s[\s\S]{0,300}? in (<b>)?(\/|[A-Z]:\\)[^<\s]+\.php(<\/b>)? on line (<b>)?\d+/ },
  { name: 'ASP.NET error page', re: /Server Error in '\/[^']*' Application|<b>\s*Exception Details:\s*<\/b>/ },
  { name: 'Laravel / Symfony debug page', re: /Whoops, looks like something went wrong|Illuminate\\[A-Za-z\\]+Exception|Symfony\\Component\\[A-Za-z\\]+Exception/ },
  { name: 'Rails routing error page', re: /<h1>Routing Error<\/h1>[\s\S]{0,400}No route matches/ },
  { name: 'Node.js stack trace', re: /\bat [\w.<>$]+ \((?:\/|[A-Z]:\\)[^)\s]+\.(?:js|ts|mjs|cjs):\d+:\d+\)/ },
  { name: 'Database error message', re: /SQLSTATE\[[0-9A-Z]+\]|You have an error in your SQL syntax|ORA-\d{5}:|PG::[A-Z]\w+Error|SQLite3::\w+Exception|Unclosed quotation mark after the character string/ },
  { name: 'Spring Boot default error page', re: /<h1>Whitelabel Error Page<\/h1>/ },
];

function matchErrorSignature(body) {
  const text = String(body || '');
  for (const sig of ERROR_SIGNATURES) {
    const m = text.match(sig.re);
    if (m) return { name: sig.name, snippet: m[0].replace(/\s+/g, ' ').slice(0, 220) };
  }
  return null;
}

async function checkVerboseErrors(originUrl, { lookup = guardedLookup, timeoutMs = 10000, request = guardedRequest } = {}) {
  const probe = new URL(`/vulnsight-not-found-${crypto.randomBytes(5).toString('hex')}`, originUrl);
  let res;
  try {
    res = await request(probe, { timeoutMs, lookup, maxBytes: 200000, userAgent: 'VulnSight-Security-Scanner/1.0' });
  } catch {
    return { findings: [], checked: false };
  }
  if (detectBlock(res.statusCode, res.headers, res.body).blocked) return { findings: [], checked: false, blocked: true };
  const hit = matchErrorSignature(res.body);
  if (!hit) return { findings: [], checked: true, statusCode: res.statusCode };
  const minor = hit.name === 'Spring Boot default error page';
  return {
    checked: true,
    statusCode: res.statusCode,
    findings: [finding({
      severity: minor ? 'low' : 'medium',
      ruleId: 'verbose-error-page',
      cwe: minor ? 'CWE-200' : 'CWE-209',
      owasp: 'OWASP-A10:2025',
      url: probe.href,
      title: minor ? 'Default framework error page reveals the stack' : `Error page exposes internal details (${hit.name})`,
      description: minor
        ? 'The default error page identifies the framework in use.'
        : `A request for a page that does not exist returned a ${hit.name.toLowerCase()}. Stack traces and debug pages reveal file paths, framework versions and code structure that help an attacker plan an exploit.`,
      advice: 'Turn off debug mode in production and serve a generic error page; log the details server-side instead.',
      evidence: `GET ${probe.pathname} -> HTTP ${res.statusCode}: ${hit.snippet}`,
    })],
  };
}

// ---- Crawl inventory review (no traffic) ----------------------------------------------------------

const SECRET_PARAM = /^(pass(word|wd)?|pwd|secret|token|access_?token|auth(_?token)?|api_?key|apikey|session(_?id)?|sid|jwt|bearer|credit_?card|card_?number|cvv|ssn)$/i;
const PASSWORD_FIELD = /pass(word|wd)?$|^pwd$/i;
const SSRF_PARAM = /^(url|uri|webhook|proxy|dest|destination|callback|fetch|target)$/i;

function reviewInventory(inventory) {
  const findings = [];
  const seenParam = new Set();
  const urls = [
    ...((inventory && inventory.pages) || []).map((p) => p.url),
    ...((inventory && inventory.endpoints) || []).map((e) => e.url),
  ];
  for (const raw of urls) {
    let u;
    try { u = new URL(raw); } catch { continue; }
    for (const name of u.searchParams.keys()) {
      if (!SECRET_PARAM.test(name)) continue;
      const key = `${u.pathname}|${name.toLowerCase()}`;
      if (seenParam.has(key)) continue;
      seenParam.add(key);
      findings.push(finding({
        severity: 'medium', ruleId: 'sensitive-data-in-url', cwe: 'CWE-598', owasp: 'OWASP-A04:2025',
        url: `${u.origin}${u.pathname}`, parameter: name,
        title: `Sensitive value passed in the URL (${name})`,
        description: `The site links to ${u.pathname} with a "${name}" query parameter. Values in URLs are stored in browser history, server and proxy logs, and sent to other sites in the Referer header.`,
        advice: 'Send credentials and tokens in a POST body or an Authorization header, never in the query string.',
        evidence: `${u.pathname}?${name}=[redacted]`,
      }));
    }
  }
  const seenSsrf = new Set();
  for (const raw of urls) {
    let u;
    try { u = new URL(raw); } catch { continue; }
    for (const name of u.searchParams.keys()) {
      if (!SSRF_PARAM.test(name)) continue;
      const key = `${u.pathname}|${name.toLowerCase()}`;
      if (seenSsrf.has(key)) continue;
      seenSsrf.add(key);
      findings.push(finding({
        severity: 'high', ruleId: 'possible-ssrf-surface', cwe: 'CWE-918', owasp: 'OWASP-A10:2025',
        url: `${u.origin}${u.pathname}`, parameter: name,
        title: `URL-fetch parameter (${name}) — SSRF surface`,
        description: `The crawl saw ${u.pathname} with a "${name}" query parameter that often feeds a server-side HTTP client. This is an SSRF review surface, not a confirmed open fetch.`,
        advice: 'Allow only a fixed scheme and host list for server-side fetches; do not take a destination URL from the request.',
        evidence: `${u.pathname}?${name}=[redacted]`,
      }));
    }
  }
  const seenIdor = new Set();
  for (const raw of urls) {
    let u;
    try { u = new URL(raw); } catch { continue; }
    if (!/\/(?:users?|accounts?|profiles?|orders?|invoices?|documents?|files?|records?)\/\d+(?:\/|$)/i.test(u.pathname)) continue;
    const key = u.pathname.replace(/\/\d+(?=\/|$)/g, '/{id}');
    if (seenIdor.has(key)) continue;
    seenIdor.add(key);
    findings.push(finding({
      severity: 'high', ruleId: 'possible-idor-surface', cwe: 'CWE-639', owasp: 'OWASP-A01:2025',
      url: `${u.origin}${u.pathname}`,
      title: 'Object identifier in URL (IDOR surface)',
      description: `${u.pathname} includes a numeric object id. This is an access-control review surface (CWE-639), not a confirmed IDOR. Authorization is not tested by swapping ids.`,
      advice: 'Authorize every object fetch server-side by the caller, not by the id in the URL alone.',
      evidence: u.pathname,
    }));
  }
  for (const form of (inventory && inventory.forms) || []) {
    const fields = form.fieldNames || [];
    const pw = fields.filter((f) => PASSWORD_FIELD.test(f));
    let action;
    try { action = new URL(form.action); } catch { continue; }
    const method = String(form.method || 'GET').toUpperCase();
    if (/^(POST|PUT|PATCH|DELETE)$/.test(method)) {
      const hasCsrf = fields.some((f) => /csrf|xsrf|authenticity_token|__requestverificationtoken|_csrf/i.test(f));
      if (!hasCsrf) {
        findings.push(finding({
          severity: 'high', ruleId: 'form-missing-csrf', cwe: 'CWE-352', owasp: 'OWASP-A01:2025',
          url: action.href,
          title: 'State-changing form has no CSRF token field',
          description: `A ${method} form at ${action.pathname || action.href} has no csrf/xsrf/_token field in the crawled HTML. That is a CSRF control gap, not a confirmed exploit.`,
          advice: 'Add a per-session CSRF token (header or hidden field) and reject state-changing requests that omit it.',
          evidence: `<form method="${method}" action="${action.href}"> fields: ${fields.join(', ') || '(none)'}`,
        }));
      }
    }
    if (!pw.length) continue;
    if (action.protocol === 'http:') {
      findings.push(finding({
        severity: 'high', ruleId: 'password-form-over-http', cwe: 'CWE-319', owasp: 'OWASP-A04:2025',
        url: action.href,
        title: 'Password form submits over unencrypted HTTP',
        description: `A form with a password field (${pw.join(', ')}) sends to ${action.origin} over plain HTTP, so the password crosses the network in clear text.`,
        advice: 'Serve the form and its action over HTTPS only, and redirect HTTP to HTTPS.',
        evidence: `<form method="${form.method}" action="${action.href}"> fields: ${fields.join(', ')}`,
      }));
    }
    if (method === 'GET') {
      findings.push(finding({
        severity: 'medium', ruleId: 'password-form-get', cwe: 'CWE-598', owasp: 'OWASP-A04:2025',
        url: action.href,
        title: 'Password form uses GET',
        description: 'Submitting this form puts the password in the URL, where it ends up in browser history and server logs.',
        advice: 'Use method="post" for any form with a password field.',
        evidence: `<form method="GET" action="${action.href}"> fields: ${fields.join(', ')}`,
      }));
    }
  }
  return findings;
}

module.exports = {
  checkEmailAndCaa,
  checkVerboseErrors,
  reviewInventory,
  matchErrorSignature,
  policyDomain,
  ERROR_SIGNATURES,
};
