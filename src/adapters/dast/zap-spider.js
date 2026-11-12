'use strict';

const { extractLinksAndForms } = require('./crawler');
const { safeGet, redactEvidence } = require('./safe-fetch');
const {
  normalizeUrl, urlHash, urlInScope, normalizeLimits, isStateChangingMethod,
} = require('./scope');
const { emptyInventory, pushPage, pushEndpoint } = require('./inventory');

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

  if (clientSpider && !options.skipBrowser) {
    try {
      const { runBrowserCrawl } = require('./browser-crawl');
      return await runBrowserCrawl(targetUrl, { scope, limits, onProgress, shouldStop, proxy: options.proxy });
    } catch (err) {
      if (options.requireBrowser) throw err;
    }
  }

  if (process.env.ZAP_API_URL) {
    try {
      const zapInv = await runZapSpider(targetUrl, { ...options, limits, scope, onProgress, shouldStop, clientSpider, started });
      if (zapInv && zapInv.pages && zapInv.pages.length) return zapInv;
    } catch (err) {
      if (options.requireZap) throw err;
    }
  }

  return runBuiltinGetCrawl(targetUrl, { limits, scope, onProgress, shouldStop, started, engine: 'builtin-get' });
}

async function runZapSpider(targetUrl, ctx) {
  const {
    zapGet, withZapMutex, prepareZapSession, flattenZapList, rememberZapUrls, countZapResponses,
  } = require('./zap-client');
  return withZapMutex(async () => {
  const session = ctx.zapSession || await prepareZapSession({ scope: ctx.scope, proxyUrl: ctx.proxy, maxRps: ctx.limits.maxRps });
  await zapGet('/JSON/spider/action/setOptionPostForm/', { Boolean: 'false' });
  await zapGet('/JSON/spider/action/setOptionProcessForm/', { Boolean: 'false' });
  await zapGet('/JSON/spider/action/setOptionMaxDepth/', { Integer: ctx.limits.maxDepth });
  await zapGet('/JSON/spider/action/setOptionMaxDuration/', { Integer: Math.ceil(ctx.limits.maxDurationSec / 60) });

  const started = await zapGet('/JSON/spider/action/scan/', {
    url: targetUrl,
    recurse: 'true',
    contextName: session.contextName,
  });
  const scanId = started.scan;
  let last = 0;
  while (true) {
    if (await ctx.shouldStop()) {
      await zapGet('/JSON/spider/action/stop/', { scanId }).catch(() => {});
      break;
    }
    const status = await zapGet('/JSON/spider/view/status/', { scanId });
    const pct = Number(status.status || 0);
    if (pct !== last) {
      last = pct;
      await ctx.onProgress({ engine: 'zap-traditional', stage: 'traditional', percent: pct });
    }
    if (pct >= 100) break;
    await sleep(1000);
    if ((Date.now() - ctx.started) / 1000 > ctx.limits.maxDurationSec) {
      await zapGet('/JSON/spider/action/stop/', { scanId }).catch(() => {});
      break;
    }
  }

  if (ctx.clientSpider) {
    await ctx.onProgress({ engine: 'zap-client', stage: 'client', percent: 0 });
    const ajax = await zapGet('/JSON/ajaxSpider/action/scan/', {
      url: targetUrl,
      contextName: session.contextName,
    }).catch(() => null);
    if (ajax) {
      const ajaxDeadline = Date.now() + Math.min(ctx.limits.maxDurationSec, 90) * 1000;
      while (Date.now() < ajaxDeadline) {
        if (await ctx.shouldStop()) {
          await zapGet('/JSON/ajaxSpider/action/stop/', {}).catch(() => {});
          break;
        }
        const st = await zapGet('/JSON/ajaxSpider/view/status/', {}).catch(() => ({ status: 'stopped' }));
        await ctx.onProgress({ engine: 'zap-client', stage: 'client', percent: st.status === 'running' ? 50 : 100 });
        if (String(st.status).toLowerCase() !== 'running') break;
        await sleep(1500);
      }
    }
  }

  // The spider lists URLs it TRIED. Only stored messages prove the host answered, so count them:
  // a spider that got no responses (host firewall dropping ZAP) must not look like a clean run.
  const responses = await countZapResponses(targetUrl);
  if (responses === 0) {
    const empty = emptyInventory('zap-traditional');
    empty.zapSession = session;
    empty.reachability = { attempted: 1, loaded: 0, failures: 1, lastError: 'ZAP stored no responses from the host (no responses)' };
    return empty;
  }

  const fromCore = await zapGet('/JSON/core/view/urls/', {}).catch(() => ({ urls: [] }));
  const fromSpider = await zapGet('/JSON/spider/view/results/', { scanId }).catch(() => ({ results: [] }));
  const hrefs = [...new Set([...flattenZapList(fromCore.urls), ...flattenZapList(fromSpider.results)])];
  const inventory = emptyInventory('zap-traditional');
  for (const href of hrefs) {
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
  inventory.findings = [];
  inventory.evidenceNote = 'Response bodies are not persisted; snippets are redacted.';
  rememberZapUrls(hrefs);
  session.urls = [...new Set([...(session.urls || []), ...hrefs])];
  inventory.zapSession = session;
  inventory.reachability = { attempted: responses, loaded: responses, failures: 0, lastError: null };
  return inventory;
  });
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
  emptyInventory,
  pushPage,
  pushEndpoint,
};
