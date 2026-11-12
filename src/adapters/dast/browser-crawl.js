'use strict';

const { createFinding } = require('../../findings');
const { createClient } = require('../../osv');
const { RULES, mask } = require('../builtin-secrets');
const { emptyInventory, pushPage, pushEndpoint } = require('./inventory');
const { normalizeUrl, urlInScope, hostInScope, pathAllowed, isStateChangingMethod } = require('./scope');

function scoped(parsed, scope, allowAnyPort) {
  if (!scope) return true;
  if (!allowAnyPort) return urlInScope(parsed, scope);
  if (!['http:', 'https:'].includes(parsed.protocol)) return false;
  return hostInScope(parsed.hostname, scope) && pathAllowed(parsed.pathname, scope);
}
const { redactEvidence, classifyNetworkError } = require('./net-guard');

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/;
const DANGER_CLICK = /logout|delete|remove|pay|checkout|unsubscribe/i;
const THIRD_PARTY_TYPES = new Set(['script', 'stylesheet', 'font', 'image', 'media']);

function loadPlaywright() {
  try {
    return require('playwright-core');
  } catch {
    return null;
  }
}

function inDenyPath(parsed, scope) {
  const path = parsed.pathname || '/';
  return (scope.denyPaths || []).some((deny) => path.startsWith(deny));
}

async function runBrowserCrawl(targetUrl, {
  scope,
  limits = {},
  onProgress = async () => {},
  shouldStop = async () => false,
  proxy,
  osvClient,
  allowAnyPort = false,
  publicMode = false,
  extraHTTPHeaders = {},
} = {}) {
  const pw = loadPlaywright();
  if (!pw) {
    const skip = new Error('Playwright is not installed. Run npx playwright install chromium.');
    skip.code = 'ENGINE_SKIP';
    throw skip;
  }

  const maxPages = publicMode ? Math.min(limits.maxPages || 12, 12) : (limits.maxPages || 40);
  const maxDepth = publicMode ? Math.min(limits.maxDepth || 2, 2) : (limits.maxDepth || 8);
  const maxDurationSec = publicMode ? Math.min(limits.maxDurationSec || 90, 90) : (limits.maxDurationSec || 180);
  const maxRps = publicMode ? 1 : (limits.maxRps || 2);
  const minGap = Math.round(1000 / maxRps);
  const started = Date.now();
  const inventory = emptyInventory('vulnsight-browser');
  const findings = [];
  const queue = [{ href: targetUrl, depth: 0 }];
  const seen = new Set();
  const bundleBodies = [];
  let lastNav = 0;
  // How many navigations were tried and how many got an HTTP response. A crawl where nothing
  // loaded is reported as failed, not as a clean run with zero findings.
  const reach = { attempted: 0, loaded: 0, failures: 0, lastError: null };

  const launchOpts = { headless: true };
  if (proxy) launchOpts.proxy = { server: proxy };

  let browser;
  try {
    browser = await pw.chromium.launch(launchOpts);
  } catch (err) {
    const skip = new Error(`Chromium is not installed (${String(err.message || err).slice(0, 180)}). Run npx playwright install chromium.`);
    skip.code = 'ENGINE_SKIP';
    throw skip;
  }
  try {
    const headerBag = extraHTTPHeaders && Object.keys(extraHTTPHeaders).length
      ? extraHTTPHeaders
      : undefined;
    const context = await browser.newContext({
      javaScriptEnabled: true,
      serviceWorkers: 'block',
      acceptDownloads: false,
      ignoreHTTPSErrors: true,
      ...(headerBag ? { extraHTTPHeaders: headerBag } : {}),
    });
    context.on('dialog', (dialog) => dialog.dismiss().catch(() => {}));

    await context.route('**/*', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      if (method !== 'GET' && method !== 'HEAD') return route.abort();
      let parsed;
      try {
        parsed = normalizeUrl(req.url());
      } catch {
        return route.abort();
      }
      const type = req.resourceType();
      const inScope = scoped(parsed, scope, allowAnyPort);
      if (inDenyPath(parsed, scope || {})) return route.abort();
      if ((type === 'document' || type === 'xhr' || type === 'fetch') && !inScope) return route.abort();
      if (!inScope && !THIRD_PARTY_TYPES.has(type)) return route.abort();
      return route.continue();
    });

    const page = await context.newPage();
    page.on('request', (req) => {
      const method = req.method().toUpperCase();
      if (isStateChangingMethod(method)) return;
      let parsed;
      try {
        parsed = new URL(req.url());
      } catch {
        return;
      }
      if (!scoped(parsed, scope, allowAnyPort)) return;
      if (req.resourceType() === 'xhr' || req.resourceType() === 'fetch' || req.resourceType() === 'document') {
        pushEndpoint(inventory, parsed, { method, statusCode: 0, contentType: '' });
      }
    });
    page.on('response', async (res) => {
      try {
        const url = res.url();
        const ct = String(res.headers()['content-type'] || '');
        if (!/javascript|ecmascript/i.test(ct) && !/\.js(\?|$)/i.test(url)) return;
        if (!scoped(new URL(url), scope, allowAnyPort) && !THIRD_PARTY_TYPES.has('script')) return;
        const body = await res.text();
        if (body && body.length < 400000) bundleBodies.push({ url, body });
      } catch {
        /* ignore */
      }
    });
    await page.evaluate(() => {
      window.addEventListener('securitypolicyviolation', (ev) => {
        window.__vsCsp = window.__vsCsp || [];
        window.__vsCsp.push({
          blockedURI: ev.blockedURI,
          violatedDirective: ev.violatedDirective,
          effectiveDirective: ev.effectiveDirective,
        });
      });
    }).catch(() => {});

    while (queue.length && inventory.pages.length < maxPages) {
      if (await shouldStop()) {
        inventory.stopped = true;
        break;
      }
      if ((Date.now() - started) / 1000 > maxDurationSec) {
        inventory.stopped = true;
        break;
      }
      const next = queue.shift();
      const nextHref = typeof next === 'string' ? next : next.href;
      const depth = typeof next === 'string' ? 0 : Number(next.depth || 0);
      let parsed;
      try {
        parsed = normalizeUrl(nextHref);
      } catch {
        continue;
      }
      if (seen.has(parsed.href)) continue;
      if (!scoped(parsed, scope, allowAnyPort)) continue;
      seen.add(parsed.href);

      const wait = minGap - (Date.now() - lastNav);
      if (wait > 0) await sleep(wait);
      lastNav = Date.now();

      let response;
      reach.attempted += 1;
      try {
        response = await page.goto(parsed.href, { waitUntil: 'domcontentloaded', timeout: 15000 });
      } catch (err) {
        reach.failures += 1;
        reach.lastError = String((err && err.message) || err).split('\n')[0].slice(0, 160);
        // Several consecutive dropped connections: the host has stopped answering. Stop here
        // rather than keep hitting a firewall that has banned us.
        if (classifyNetworkError(err) === 'dropped' && reach.loaded === 0 && reach.failures >= 2) break;
        continue;
      }
      if (response) reach.loaded += 1;
      const status = response ? response.status() : 0;
      const title = await page.title().catch(() => '');
      pushPage(inventory, parsed, {
        statusCode: status,
        contentType: response ? response.headers()['content-type'] : 'text/html',
        depth,
        title,
      });
      await onProgress({
        engine: 'vulnsight-browser',
        stage: 'browser',
        pages: inventory.pages.length,
        endpoints: inventory.endpoints.length,
      });

      const hrefs = await page.$$eval('a[href]', (els) => els.map((el) => el.getAttribute('href')).filter(Boolean)).catch(() => []);
      for (const href of hrefs) {
        try {
          const u = normalizeUrl(href, parsed.origin);
          if (!scoped(u, scope, allowAnyPort)) continue;
          if (depth + 1 > maxDepth) continue;
          if (!seen.has(u.href)) queue.push({ href: u.href, depth: depth + 1 });
        } catch {
          /* skip */
        }
      }

      const forms = await page.$$eval('form', (els) => els.map((el) => ({
        action: el.getAttribute('action') || '',
        method: (el.getAttribute('method') || 'GET').toUpperCase(),
        fields: [...el.querySelectorAll('input[name],select[name],textarea[name]')].map((i) => i.getAttribute('name')).filter(Boolean),
      }))).catch(() => []);
      for (const form of forms) {
        try {
          const action = normalizeUrl(form.action || parsed.href, parsed.origin);
          inventory.forms.push({
            action: action.href,
            method: form.method,
            fieldNames: form.fields,
            submitted: false,
          });
        } catch {
          /* skip */
        }
      }

      const buttons = page.locator('button, [type=submit], a');
      const count = await buttons.count().catch(() => 0);
      for (let i = 0; i < Math.min(count, 40); i += 1) {
        const el = buttons.nth(i);
        const text = `${await el.innerText().catch(() => '')} ${await el.getAttribute('href').catch(() => '')}`;
        if (DANGER_CLICK.test(text)) continue;
        // Do not click submit buttons; navigation-only anchors already queued from hrefs.
      }

      if (!publicMode) {
        const scriptUrls = await page.evaluate(() => {
          const fromDom = [...document.querySelectorAll('script[src]')].map((el) => el.src).filter(Boolean);
          const fromPerf = (performance.getEntriesByType('resource') || [])
            .filter((entry) => entry.initiatorType === 'script' || /\.js(\?|$)/i.test(entry.name))
            .map((entry) => entry.name);
          return [...new Set([...fromDom, ...fromPerf])];
        }).catch(() => []);
        inventory.scripts = inventory.scripts || [];
        for (const raw of scriptUrls) {
          try {
            const scriptUrl = new URL(raw, parsed.href);
            if (/\/cdn-cgi\//i.test(scriptUrl.pathname)) continue;
            if (!scoped(scriptUrl, scope, allowAnyPort)) continue;
            pushEndpoint(inventory, scriptUrl, {
              method: 'GET',
              statusCode: 0,
              contentType: 'application/javascript',
            });
            if (!inventory.scripts.includes(scriptUrl.href)) inventory.scripts.push(scriptUrl.href);
          } catch {
            /* skip */
          }
        }
      }

      await collectRuntimeFindings(page, parsed, findings, osvClient);
    }

    const bundleCap = publicMode ? 20 : 80;
    for (const bundle of bundleBodies.slice(0, bundleCap)) {
      scanBundleSecrets(bundle, findings);
    }
  } finally {
    await browser.close().catch(() => {});
  }

  inventory.findings = findings;
  inventory.evidenceNote = 'Response bodies are not persisted; snippets are redacted.';
  inventory.reachability = reach;
  return inventory;
}

async function collectRuntimeFindings(page, parsed, findings, osvClient) {
  const libs = await page.evaluate(() => ({
    jquery: (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) || null,
    vue: (window.Vue && window.Vue.version) || null,
    angular: (document.querySelector('[ng-version]') && document.querySelector('[ng-version]').getAttribute('ng-version')) || null,
    bootstrap: (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) || null,
    react: (window.React && window.React.version) || null,
    mixed: [...document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]')].length,
    csp: window.__vsCsp || [],
  })).catch(() => ({}));

  const packages = [
    libs.jquery && { name: 'jquery', version: libs.jquery },
    libs.vue && { name: 'vue', version: libs.vue },
    libs.angular && { name: '@angular/core', version: libs.angular },
    libs.bootstrap && { name: 'bootstrap', version: libs.bootstrap },
    libs.react && { name: 'react', version: libs.react },
  ].filter(Boolean);

  if (packages.length) {
    try {
      const client = osvClient || createClient();
      const queries = packages.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: String(p.version).replace(/^[^0-9]*/, '').split(' ')[0] }));
      const idLists = await client.queryBatch(queries);
      const allIds = idLists.flat();
      const vulns = allIds.length ? await client.getVulns(allIds) : new Map();
      packages.forEach((pkg, i) => {
        const ids = idLists[i] || [];
        if (!ids.length) return;
        const aliases = ids.filter((id) => /^CVE-/i.test(id) || /^GHSA-/i.test(id));
        findings.push(createFinding({
          category: 'dast',
          severity: 'medium',
          title: `Runtime library ${pkg.name}@${pkg.version} has known vulnerabilities`,
          description: `The live page exposes ${pkg.name} ${pkg.version}. OSV reports ${ids.length} associated advisories.`,
          identifiers: { primary: `runtime-${pkg.name}`, cwe: ['CWE-1104'], aliases },
          location: { url: parsed.href },
          scanner: { name: 'vulnsight-browser', ruleId: `runtime-lib-${pkg.name}`, version: '1.0' },
          remediation: { advice: `Upgrade ${pkg.name} to a version without known OSV advisories.` },
          evidence: redactEvidence(`${pkg.name}@${pkg.version} ${ids.slice(0, 5).join(',')}`),
        }));
        void vulns;
      });
    } catch {
      /* OSV optional */
    }
  }

  const storage = await page.evaluate(() => {
    const read = (store) => {
      const out = [];
      try {
        for (let i = 0; i < store.length; i += 1) {
          const key = store.key(i);
          out.push({ key, value: store.getItem(key) || '' });
        }
      } catch {
        /* ignore */
      }
      return out;
    };
    return { local: read(window.localStorage), session: read(window.sessionStorage) };
  }).catch(() => ({ local: [], session: [] }));

  for (const item of [...(storage.local || []), ...(storage.session || [])]) {
    if (JWT_RE.test(item.value || '')) {
      findings.push(createFinding({
        category: 'dast',
        severity: 'medium',
        title: `Token-like value stored in browser storage (${item.key})`,
        description: 'A JWT-shaped value was found in localStorage or sessionStorage. Tokens in web storage are readable by any script on the origin.',
        identifiers: { primary: 'browser-storage-token', cwe: ['CWE-922'] },
        location: { url: parsed.href, parameter: item.key },
        scanner: { name: 'vulnsight-browser', ruleId: 'browser-storage-token', version: '1.0' },
        remediation: { advice: 'Store session tokens in HttpOnly cookies, not localStorage or sessionStorage.' },
        evidence: redactEvidence(`storage key ${item.key}`),
      }));
    }
  }

  if (libs.mixed) {
    findings.push(createFinding({
      category: 'dast',
      severity: 'low',
      title: 'Mixed content resources on an HTTPS page',
      description: 'The rendered document references http:// assets, which browsers may block and which allow network tampering.',
      identifiers: { primary: 'mixed-content', cwe: ['CWE-319'] },
      location: { url: parsed.href },
      scanner: { name: 'vulnsight-browser', ruleId: 'mixed-content', version: '1.0' },
      remediation: { advice: 'Serve all scripts, styles and images over HTTPS.' },
      evidence: redactEvidence(`${libs.mixed} mixed-content nodes`),
    }));
  }
  for (const viol of libs.csp || []) {
    findings.push(createFinding({
      category: 'dast',
      severity: 'low',
      title: 'Content-Security-Policy violation in the live page',
      description: `The browser reported a CSP violation for ${viol.violatedDirective || 'an unknown directive'}.`,
      identifiers: { primary: 'csp-violation', cwe: ['CWE-1021'] },
      location: { url: parsed.href },
      scanner: { name: 'vulnsight-browser', ruleId: 'csp-violation', version: '1.0' },
      remediation: { advice: 'Tighten CSP so required assets are allowed explicitly; do not add unsafe-inline to silence violations.' },
      evidence: redactEvidence(String(viol.blockedURI || viol.effectiveDirective || '')),
    }));
  }
}

function scanBundleSecrets(bundle, findings) {
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    const match = rule.re.exec(bundle.body);
    if (!match) continue;
    findings.push(createFinding({
      category: 'dast',
      severity: 'high',
      title: `Secret material in loaded JavaScript (${rule.id})`,
      description: `A ${rule.title} pattern matched a JavaScript response loaded by the page.`,
      identifiers: { primary: rule.id, cwe: ['CWE-798'] },
      location: { url: bundle.url },
      scanner: { name: 'vulnsight-browser', ruleId: rule.id, version: '1.0' },
      remediation: { advice: 'Revoke the credential and stop shipping secrets in frontend bundles.' },
      evidence: mask(match[0], match[0]),
    }));
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = { runBrowserCrawl, loadPlaywright };
