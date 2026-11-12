'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  checkEmailAndCaa, checkVerboseErrors, reviewInventory, matchErrorSignature, policyDomain,
} = require('../src/adapters/dast/skill-checks');
const { SENSITIVE_PATHS } = require('../src/adapters/dast/crawler');

const rule = (findings, id) => findings.find((f) => f.scanner.ruleId === id);

function dnsWith({ txt = {}, caa = {} } = {}) {
  return {
    resolveTxt: async (name) => (txt[name] || []).map((t) => [t]),
    resolveCaa: async (name) => caa[name] || [],
  };
}

test('policyDomain finds the registrable domain, including two-level suffixes', () => {
  assert.equal(policyDomain('zango.com.au'), 'zango.com.au');
  assert.equal(policyDomain('www.zango.com.au'), 'zango.com.au');
  assert.equal(policyDomain('shop.example.co.uk'), 'example.co.uk');
  assert.equal(policyDomain('app.example.com'), 'example.com');
});

test('SPF ending in ?all, missing DMARC and missing CAA are reported', async () => {
  const resolver = dnsWith({ txt: { 'zango.com.au': ['google-site-verification=abc', 'v=spf1 a include:sendgrid.net ?all'] } });
  const { findings, facts } = await checkEmailAndCaa('zango.com.au', { resolver });
  assert.equal(rule(findings, 'email-spf-neutral').severity, 'medium');
  assert.ok(rule(findings, 'email-dmarc-missing'));
  assert.ok(rule(findings, 'dns-caa-missing'));
  assert.equal(facts.spf, 'v=spf1 a include:sendgrid.net ?all');
  assert.equal(facts.dmarc, null);
  assert.ok(findings.every((f) => f.scanner.name === 'vulnsight-checks' && f.category === 'dast'));
});

test('a strict SPF, enforcing DMARC and a CAA record produce no findings', async () => {
  const resolver = dnsWith({
    txt: { 'example.com': ['v=spf1 include:_spf.google.com -all'], '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com'] },
    caa: { 'example.com': [{ critical: 0, issue: 'letsencrypt.org' }] },
  });
  const { findings, facts } = await checkEmailAndCaa('www.example.com', { resolver });
  assert.deepEqual(findings, []);
  assert.deepEqual(facts.caa, ['issue letsencrypt.org']);
});

test('SPF +all is high, no SPF and multiple SPF records are reported, DMARC p=none is low', async () => {
  const plusAll = await checkEmailAndCaa('a.com', { resolver: dnsWith({ txt: { 'a.com': ['v=spf1 +all'] } }) });
  assert.equal(rule(plusAll.findings, 'email-spf-pass-all').severity, 'high');
  const none = await checkEmailAndCaa('b.com', { resolver: dnsWith() });
  assert.ok(rule(none.findings, 'email-spf-missing'));
  const multi = await checkEmailAndCaa('c.com', { resolver: dnsWith({ txt: { 'c.com': ['v=spf1 -all', 'v=spf1 mx -all'] } }) });
  assert.ok(rule(multi.findings, 'email-spf-multiple'));
  const monitor = await checkEmailAndCaa('d.com', { resolver: dnsWith({ txt: { 'd.com': ['v=spf1 -all'], '_dmarc.d.com': ['v=DMARC1; p=none'] } }) });
  assert.equal(rule(monitor.findings, 'email-dmarc-none').severity, 'low');
});

function throwingResolver(code = 'ECONNREFUSED') {
  const fail = () => { const err = new Error(code); err.code = code; return Promise.reject(err); };
  return { resolveTxt: fail, resolveCaa: fail };
}

test('a flaky primary resolver falls back to public DNS and reports the real record', async () => {
  const primary = throwingResolver('ECONNREFUSED');
  const publicResolvers = [dnsWith({ txt: { 'zango.com.au': ['v=spf1 include:_spf.google.com ?all'] } })];
  const { findings, facts } = await checkEmailAndCaa('zango.com.au', { resolver: primary, publicResolvers });
  assert.equal(facts.spf, 'v=spf1 include:_spf.google.com ?all');
  assert.ok(rule(findings, 'email-spf-neutral'), 'the real ?all record is reported, not "missing"');
  assert.equal(rule(findings, 'email-spf-missing'), undefined);
});

test('when every resolver fails, no "missing record" findings are invented', async () => {
  const { findings, facts } = await checkEmailAndCaa('zango.com.au', {
    resolver: throwingResolver('ESERVFAIL'),
    publicResolvers: [throwingResolver('ECONNREFUSED'), throwingResolver('ETIMEOUT')],
  });
  assert.equal(facts.resolved, false);
  assert.deepEqual(findings, [], 'a resolver outage must not produce false findings');
});

test('ENODATA is a genuine "no record" and is still reported', async () => {
  const noData = () => { const e = new Error('ENODATA'); e.code = 'ENODATA'; return Promise.reject(e); };
  const { findings } = await checkEmailAndCaa('x.com', { resolver: { resolveTxt: noData, resolveCaa: noData }, publicResolvers: [] });
  assert.ok(rule(findings, 'email-spf-missing'));
  assert.ok(rule(findings, 'email-dmarc-missing'));
  assert.ok(rule(findings, 'dns-caa-missing'));
});

test('error-page signatures match real stack traces and not normal pages', () => {
  assert.equal(matchErrorSignature('<pre>Traceback (most recent call last):\n  File "app.py"</pre>').name, 'Python traceback');
  assert.equal(matchErrorSignature('<b>Fatal error</b>: Uncaught Error in <b>/var/www/html/index.php</b> on line <b>12</b>').name, 'PHP error with file path');
  assert.equal(matchErrorSignature('java.lang.NullPointerException\n\tat com.acme.Shop.run(Shop.java:42)').name, 'Java stack trace');
  assert.equal(matchErrorSignature("Server Error in '/' Application.").name, 'ASP.NET error page');
  assert.equal(matchErrorSignature('Error: boom\n    at handler (/srv/app/routes.js:10:5)').name, 'Node.js stack trace');
  assert.equal(matchErrorSignature('<h1>404 Not Found</h1><p>The page you requested does not exist.</p>'), null);
});

test('checkVerboseErrors reports a leaking 404 page and stays quiet on a WAF challenge', async () => {
  const leaking = async () => ({ statusCode: 500, headers: {}, body: 'Traceback (most recent call last):\n  File "/srv/app.py"' });
  const res = await checkVerboseErrors('https://shop.example/', { request: leaking });
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].scanner.ruleId, 'verbose-error-page');
  assert.match(res.findings[0].location.url, /\/vulnsight-not-found-[0-9a-f]+$/);

  const challenged = async () => ({ statusCode: 403, headers: { 'cf-mitigated': 'challenge' }, body: '<title>Just a moment...</title>' });
  const quiet = await checkVerboseErrors('https://shop.example/', { request: challenged });
  assert.deepEqual(quiet.findings, []);
  assert.equal(quiet.blocked, true);
});

test('reviewInventory flags secrets in URLs and unsafe password forms, with values redacted', () => {
  const findings = reviewInventory({
    pages: [
      { url: 'https://shop.example/reset?token=abc123SECRET&lang=en' },
      { url: 'https://shop.example/orders/42' },
      { url: 'https://shop.example/fetch?url=https://internal' },
    ],
    endpoints: [{ url: 'https://shop.example/api/items?api_key=K-999' }, { url: 'https://shop.example/search?q=shoes' }],
    forms: [
      { action: 'http://shop.example/login', method: 'GET', fieldNames: ['email', 'password'] },
      { action: 'https://shop.example/search', method: 'GET', fieldNames: ['q'] },
      { action: 'https://shop.example/profile', method: 'POST', fieldNames: ['email', 'name'] },
      { action: 'https://shop.example/safe', method: 'POST', fieldNames: ['email', '_csrf'] },
    ],
  });
  const params = findings.filter((f) => f.scanner.ruleId === 'sensitive-data-in-url').map((f) => f.location.parameter).sort();
  assert.deepEqual(params, ['api_key', 'token']);
  assert.ok(rule(findings, 'password-form-over-http'));
  assert.ok(rule(findings, 'password-form-get'));
  assert.ok(!JSON.stringify(findings).includes('abc123SECRET'), 'parameter values must not be stored');
  assert.ok(!JSON.stringify(findings).includes('K-999'));
  assert.ok(rule(findings, 'possible-idor-surface'));
  assert.ok(rule(findings, 'possible-ssrf-surface'));
  assert.ok(!JSON.stringify(findings).includes('https://internal'));
});

test('new exposed-path matchers accept the real formats and reject a generic home page', () => {
  const byPath = Object.fromEntries(SENSITIVE_PATHS.map((s) => [s.path, s]));
  const home = '<!doctype html><html><head><title>Shop</title></head><body>Welcome</body></html>';
  for (const s of SENSITIVE_PATHS) assert.equal(s.match(home), false, `${s.path} must not match a normal page`);
  assert.ok(byPath['/actuator/env'].match('{"activeProfiles":[],"propertySources":[{"name":"server.ports"}]}'));
  assert.ok(byPath['/v3/api-docs'].match('{"openapi":"3.0.1","paths":{"/api/items":{}}}'));
  assert.ok(byPath['/web.config'].match('<configuration><system.webServer></system.webServer></configuration>'));
  assert.ok(byPath['/wp-config.php.bak'].match("define( 'DB_PASSWORD', 'x' );"));
  assert.ok(byPath['/uploads/'].match('<html><head><title>Index of /uploads</title>'));
});
