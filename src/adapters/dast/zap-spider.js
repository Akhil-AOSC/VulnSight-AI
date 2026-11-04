'use strict';

const { extractLinksAndForms } = require('./crawler');
const { safeGet, redactEvidence } = require('./safe-fetch');
const {
  normalizeUrl, urlHash, urlInScope, normalizeLimits, isStateChangingMethod,
} = require('./scope');

/**
 * Production crawl adapter.
 * Prefers OWASP ZAP Traditional / Client Spider when ZAP_API_URL is set.
 * Otherwise uses a GET-only builtin spider that writes the same inventory shape.
 * Never calls ZAP ascan. Never submits forms.
 */
async function runWebsiteCrawl(targetUrl, options = {}) {
  const limits = normalizeLimits(options);
  const scope = options.scope;
  const onProgress = options.onProgress || (async () => {});
  const shouldStop = options.shouldStop || (async () => false);
  const clientSpider = Boolean(options.clientSpider);
  const started = Date.now();

  if (process.env.ZAP_API_URL) {
    try {
      return await runZapSpider(targetUrl, { ...options, limits, scope, onProgress, shouldStop, clientSpider, started });
    } catch (err) {
      if (options.requireZap) throw err;
    }
  }

  return runBuiltinGetCrawl(targetUrl, { limits, scope, onProgress, shouldStop, started, engine: clientSpider ? 'builtin-get' : 'builtin-get' });
}

async function runZapSpider(targetUrl, ctx) {
  const base = process.env.ZAP_API_URL.replace(/\/$/, '');
  const key = process.env.ZAP_API_KEY || '';
  const qs = (path, extra = {}) => {
    const u = new URL(path, `${base}/`);
    if (key) u.searchParams.set('apikey', key);
    for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, String(v));
    return u.href;
  };
  const getJson = async (path, extra) => {
    const res = await fetch(qs(path, extra), { method: 'GET' });
    if (!res.ok) throw new Error(`ZAP API ${path} returned ${res.status}`);
    return res.json();
  };

  await getJson('/JSON/spider/action/setOptionPostForm/', { Boolean: 'false' });
  await getJson('/JSON/spider/action/setOptionProcessForm/', { Boolean: 'false' });
  await getJson('/JSON/spider/action/setOptionMaxDepth/', { Integer: ctx.limits.maxDepth });
  await getJson('/JSON/spider/action/setOptionMaxDuration/', { Integer: Math.ceil(ctx.limits.maxDurationSec / 60) });

  const started = await getJson('/JSON/spider/action/scan/', { url: targetUrl, recurse: 'true' });
  const scanId = started.scan;
  let last = 0;
  while (true) {
    if (await ctx.shouldStop()) {
      await getJson('/JSON/spider/action/stop/', { scanId }).catch(() => {});
      break;
    }
    const status = await getJson('/JSON/spider/view/status/', { scanId });
    const pct = Number(status.status || 0);
    if (pct !== last) {
      last = pct;
      await ctx.onProgress({ engine: 'zap-traditional', stage: 'traditional', percent: pct });
    }
    if (pct >= 100) break;
    await sleep(1000);
    if ((Date.now() - ctx.started) / 1000 > ctx.limits.maxDurationSec) {
      await getJson('/JSON/spider/action/stop/', { scanId }).catch(() => {});
      break;
    }
  }

  if (ctx.clientSpider) {
    await ctx.onProgress({ engine: 'zap-client', stage: 'client', percent: 0 });
    await getJson('/JSON/ajaxSpider/action/scan/', { url: targetUrl }).catch(() => {});
  }

  const urls = await getJson('/JSON/core/view/urls/', {});
  const inventory = emptyInventory('zap-traditional');
  for (const href of urls.urls || []) {
    if (inventory.pages.length >= ctx.limits.maxPages) break;
    let parsed;
    try {
      parsed = normalizeUrl(href);
    } catch {
      continue;
    }
    if (!urlInScope(parsed, ctx.scope)) continue;
    pushPage(inventory, parsed, { statusCode: 0, contentType: '', depth: 0 });
  }
  return inventory;
}

async function runBuiltinGetCrawl(targetUrl, ctx) {
  const seed = normalizeUrl(targetUrl);
  const inventory = emptyInventory('builtin-get');
  const queue = [{ href: seed.href, depth: 0 }];
  const seen = new Set();
  let lastRequest = 0;
  const minGap = Math.ceil(1000 / ctx.limits.maxRps);

  while (queue.length && inventory.pages.length < ctx.limits.maxPages) {
    if (await ctx.shouldStop()) {
      inventory.stopped = true;
      break;
    }
    if ((Date.now() - ctx.started) / 1000 > ctx.limits.maxDurationSec) {
      inventory.stopped = true;
      inventory.stopReason = 'duration';
      break;
    }

    const item = queue.shift();
    if (seen.has(item.href) || item.depth > ctx.limits.maxDepth) continue;
    seen.add(item.href);

    const wait = lastRequest + minGap - Date.now();
    if (wait > 0) await sleep(wait);
    lastRequest = Date.now();

    const res = await safeGet(item.href, { scope: ctx.scope, timeoutMs: 8000, method: 'GET' });
    if (!res || res.blocked) continue;

    const parsed = normalizeUrl(res.url);
    const page = pushPage(inventory, parsed, {
      statusCode: res.statusCode,
      contentType: res.contentType,
      depth: item.depth,
      title: extractTitle(res.body),
    });
    pushEndpoint(inventory, parsed, {
      method: 'GET',
      statusCode: res.statusCode,
      contentType: res.contentType,
    });

    if (res.contentType.includes('text/html') && res.body) {
      const { links, forms } = extractLinksAndForms(res.body, parsed.origin);
      for (const rel of links) {
        let next;
        try {
          next = normalizeUrl(rel, parsed.origin);
        } catch {
          continue;
        }
        if (!urlInScope(next, ctx.scope)) continue;
        inventory.links.push({
          fromHash: page.urlHash,
          toHash: urlHash(next.href),
          kind: 'a',
        });
        if (!seen.has(next.href)) queue.push({ href: next.href, depth: item.depth + 1 });
      }
      for (const form of forms) {
        if (isStateChangingMethod(form.method)) {
          inventory.forms.push({
            action: form.url,
            method: form.method,
            fieldNames: form.parameters || [],
            submitted: false,
          });
          continue;
        }
        inventory.forms.push({
          action: form.url,
          method: form.method || 'GET',
          fieldNames: form.parameters || [],
          submitted: false,
        });
      }
    }

    await ctx.onProgress({
      engine: inventory.engine,
      stage: 'traditional',
      pages: inventory.pages.length,
      endpoints: inventory.endpoints.length,
      forms: inventory.forms.length,
      queue: queue.length,
    });
  }

  inventory.findings = [];
  inventory.evidenceNote = 'Response bodies are not persisted; snippets are redacted.';
  return inventory;
}

function emptyInventory(engine) {
  return {
    engine,
    pages: [],
    endpoints: [],
    forms: [],
    links: [],
    findings: [],
    stopped: false,
  };
}

function pushPage(inventory, parsed, extra) {
  const href = parsed.href;
  const hash = urlHash(href);
  let page = inventory.pages.find((p) => p.urlHash === hash);
  if (!page) {
    page = {
      url: href,
      urlHash: hash,
      path: parsed.pathname,
      statusCode: extra.statusCode || 0,
      contentType: extra.contentType || '',
      depth: extra.depth || 0,
      title: extra.title || '',
    };
    inventory.pages.push(page);
  }
  return page;
}

function pushEndpoint(inventory, parsed, extra) {
  const paramNames = [...parsed.searchParams.keys()];
  inventory.endpoints.push({
    url: parsed.href,
    path: parsed.pathname,
    method: extra.method,
    statusCode: extra.statusCode,
    contentType: extra.contentType,
    paramNames,
  });
}

function extractTitle(html) {
  const m = String(html || '').match(/<title[^>]*>([^<]{1,200})<\/title>/i);
  return m ? m[1].trim() : '';
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = {
  runWebsiteCrawl,
  runBuiltinGetCrawl,
  redactEvidence,
};
