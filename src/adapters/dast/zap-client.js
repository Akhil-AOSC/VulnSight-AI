'use strict';

function zapBase() {
  const zapUrl = process.env.ZAP_API_URL;
  if (!zapUrl) {
    throw new Error('Active exploit scanning needs OWASP ZAP. Start ZAP and set ZAP_API_URL (optional ZAP_API_KEY). The GET-only crawler cannot run exploits.');
  }
  return { base: zapUrl.replace(/\/$/, ''), key: process.env.ZAP_API_KEY || '' };
}

async function zapGet(path, extra = {}, { fetchImpl = fetch, timeoutMs = 15000 } = {}) {
  const { base, key } = zapBase();
  const u = new URL(path, `${base}/`);
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined || v === null) continue;
    u.searchParams.set(k, String(v));
  }
  const headers = { Accept: 'application/json' };
  if (key) headers['X-ZAP-API-Key'] = key;
  const res = await fetchImpl(u.href, { method: 'GET', headers, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    const detail = String(body).slice(0, 180).replace(/\s+/g, ' ');
    throw new Error(`ZAP API ${path} returned ${res.status}${detail ? `: ${detail}` : ''}`);
  }
  return res.json();
}

let zapChain = Promise.resolve();
let currentSession = null;

function withZapMutex(fn) {
  const run = zapChain.then(() => fn(), () => fn());
  zapChain = run.then(() => undefined, () => undefined);
  return run;
}

function getZapSession() {
  return currentSession;
}

function resetZapSession() {
  currentSession = null;
}

function rememberZapUrls(urls = []) {
  if (!currentSession) return;
  const extra = flattenZapList(urls);
  const prev = currentSession.urls || [];
  currentSession.urls = [...new Set([...prev, ...extra])];
}

function flattenZapList(value, depth = 0) {
  if (value == null || depth > 6) return [];
  if (Array.isArray(value)) return value.flatMap((v) => flattenZapList(v, depth + 1));
  if (typeof value === 'string') return /^https?:\/\//i.test(value) ? [value] : [];
  if (typeof value === 'object') {
    const preferred = value.url || value.urls || value.list || value.results || value.site || value.sites;
    if (preferred != null) return flattenZapList(preferred, depth + 1);
    return Object.values(value).flatMap((v) => flattenZapList(v, depth + 1));
  }
  return [];
}

function hostRegex(host) {
  const h = String(host).replace(/[.*+?^${}()|[\]\\]/g, '\\.');
  return `https?://(www\\.)?${h}.*`;
}

async function applyZapSessionHeaders({ sessionCookie, sessionHeader } = {}) {
  if (sessionCookie) {
    await zapGet('/JSON/replacer/action/addRule/', {
      description: 'vs-session-cookie',
      enabled: 'true',
      matchType: 'REQ_HEADER',
      matchRegex: 'false',
      matchString: 'Cookie',
      replacement: sessionCookie,
    }).catch(() => {});
  }
  if (sessionHeader && sessionHeader.name && sessionHeader.value) {
    await zapGet('/JSON/replacer/action/addRule/', {
      description: 'vs-session-header',
      enabled: 'true',
      matchType: 'REQ_HEADER',
      matchRegex: 'false',
      matchString: sessionHeader.name,
      replacement: sessionHeader.value,
    }).catch(() => {});
  }
}

async function prepareZapSession({ scope = {}, proxyUrl, maxRps = 1, sessionCookie, sessionHeader } = {}) {
  const name = `vs-${Date.now()}`;
  await zapGet('/JSON/core/action/newSession/', { name, overwrite: 'true' });
  const contextName = `vs-ctx-${Date.now()}`;
  const created = await zapGet('/JSON/context/action/newContext/', { contextName });
  const hosts = [...new Set([...(scope.allowHosts || []), ...(scope.extraHosts || [])])];
  for (const host of hosts) {
    await zapGet('/JSON/context/action/includeInContext/', { contextName, regex: hostRegex(host) });
    const bare = String(host).replace(/^www\./, '');
    if (bare !== host) {
      await zapGet('/JSON/context/action/includeInContext/', { contextName, regex: hostRegex(bare) }).catch(() => {});
    }
  }
  for (const deny of scope.denyPaths || []) {
    const re = String(deny).startsWith('/') ? `.*${String(deny).replace(/[.*+?^${}()|[\]\\]/g, '\\.')}.*` : String(deny);
    await zapGet('/JSON/context/action/excludeFromContext/', { contextName, regex: re });
  }
  if (proxyUrl) {
    const parsed = new URL(proxyUrl);
    await zapGet('/JSON/core/action/setOptionProxyChainName/', { String: parsed.hostname });
    await zapGet('/JSON/core/action/setOptionProxyChainPort/', { Integer: String(parsed.port || 80) });
    await zapGet('/JSON/core/action/setOptionUseProxyChain/', { Boolean: 'true' });
  }
  const delay = Math.max(200, Math.round(1000 / Math.max(1, maxRps)));
  await zapGet('/JSON/ascan/action/setOptionThreadPerHost/', { Integer: '1' });
  await zapGet('/JSON/ascan/action/setOptionDelayInMs/', { Integer: String(delay) });
  await zapGet('/JSON/spider/action/setOptionThreadCount/', { Integer: '1' });
  const info = await zapGet('/JSON/context/view/context/', { contextName }).catch(() => ({}));
  const ctx = info.context || info;
  const contextId = String(created.contextId || ctx.id || ctx.contextId || '1');
  currentSession = { contextName, contextId };
  return currentSession;
}

async function seedZapUrls(urls = []) {
  for (const url of urls.slice(0, 80)) {
    await zapGet('/JSON/core/action/accessUrl/', { url, followRedirects: 'true' }).catch(() => {});
  }
}

function urlInZapTree(href, target) {
  try {
    const a = new URL(href);
    const b = new URL(target);
    return a.hostname.replace(/^www\./, '') === b.hostname.replace(/^www\./, '');
  } catch {
    return String(href).includes(String(target));
  }
}

function pickTreeUrl(urls, targetUrl) {
  const list = flattenZapList(urls);
  const exact = list.find((u) => u === targetUrl);
  if (exact) return exact;
  const sameHost = list.find((u) => urlInZapTree(u, targetUrl));
  if (sameHost) return sameHost;
  try {
    const origin = new URL(targetUrl).origin + '/';
    return list.find((u) => u === origin || u === origin.slice(0, -1)) || null;
  } catch {
    return null;
  }
}

async function listZapTreeUrls() {
  const [urls, sites, spider] = await Promise.all([
    zapGet('/JSON/core/view/urls/', {}).catch(() => ({ urls: [] })),
    zapGet('/JSON/core/view/sites/', {}).catch(() => ({ sites: [] })),
    zapGet('/JSON/spider/view/allUrls/', {}).catch(() => ({ allUrls: [] })),
  ]);
  return [...new Set([
    ...flattenZapList(urls.urls),
    ...flattenZapList(sites.sites),
    ...flattenZapList(spider.allUrls || spider.urls || spider),
  ])];
}

async function ensureInScanTree(targetUrl, { timeoutMs = 12000, seedUrls = [] } = {}) {
  const seeds = [...new Set([targetUrl, ...seedUrls])].filter(Boolean).slice(0, 80);
  await seedZapUrls(seeds);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const match = pickTreeUrl(await listZapTreeUrls(), targetUrl);
    if (match) return match;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  return pickTreeUrl(await listZapTreeUrls(), targetUrl);
}

/**
 * Number of HTTP messages ZAP stored for the target (apex and www variants). Stored messages are
 * the only proof the host answered ZAP. Returns null when ZAP can't say, so an older ZAP API never
 * turns a good run into a failure.
 */
async function countZapResponses(targetUrl) {
  let origin;
  try {
    origin = new URL(targetUrl);
  } catch {
    return null;
  }
  const host = origin.hostname.replace(/^www\./, '');
  const bases = [...new Set([`${origin.protocol}//${host}`, `${origin.protocol}//www.${host}`])];
  let total = 0;
  let known = false;
  for (const baseurl of bases) {
    try {
      const res = await zapGet('/JSON/core/view/numberOfMessages/', { baseurl });
      total += Number(res.numberOfMessages || 0);
      known = true;
    } catch { /* try the next variant */ }
  }
  return known ? total : null;
}

module.exports = {
  countZapResponses,
  zapGet, zapBase, withZapMutex, prepareZapSession, seedZapUrls, hostRegex, ensureInScanTree,
  flattenZapList, listZapTreeUrls, pickTreeUrl, getZapSession, resetZapSession, rememberZapUrls,
};
