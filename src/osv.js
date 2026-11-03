'use strict';

// Client for the OSV.dev vulnerability database (https://google.github.io/osv.dev/api/).

const DEFAULT_API = process.env.VULNSIGHT_OSV_API || 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000; // OSV's querybatch limit
const TIMEOUT_MS = 30000;
const MAX_RETRIES = 2;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function request(url, init = {}, attempt = 0) {
  let res;
  try {
    res = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (err) {
    if (attempt < MAX_RETRIES) {
      await sleep(500 * 2 ** attempt);
      return request(url, init, attempt + 1);
    }
    throw new Error(`Could not reach OSV.dev (${url}): ${err.message}`);
  }
  if ((res.status === 429 || res.status >= 500) && attempt < MAX_RETRIES) {
    await sleep(500 * 2 ** attempt);
    return request(url, init, attempt + 1);
  }
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`OSV.dev returned HTTP ${res.status} for ${url}`);
  return res.json();
}

function postJson(url, body) {
  return request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function createClient({ api = DEFAULT_API, concurrency = 8 } = {}) {
  const vulnCache = new Map();

  // queries: [{ package: { name, ecosystem }, version }]
  // returns an array (same order) of vulnerability ID lists.
  async function queryBatch(queries) {
    const results = [];
    for (let i = 0; i < queries.length; i += BATCH_SIZE) {
      const chunk = queries.slice(i, i + BATCH_SIZE);
      const res = await postJson(`${api}/querybatch`, { queries: chunk });
      for (let j = 0; j < chunk.length; j++) {
        const result = (res && res.results && res.results[j]) || {};
        const ids = (result.vulns || []).map((v) => v.id);
        let token = result.next_page_token;
        while (token) {
          const page = await postJson(`${api}/query`, { ...chunk[j], page_token: token });
          ids.push(...((page && page.vulns) || []).map((v) => v.id));
          token = page && page.next_page_token;
        }
        results.push(ids);
      }
    }
    return results;
  }

  // Returns Map<id, vuln>. IDs that no longer exist are left out.
  async function getVulns(ids) {
    const missing = [...new Set(ids)].filter((id) => !vulnCache.has(id));
    await mapWithConcurrency(missing, concurrency, async (id) => {
      vulnCache.set(id, await request(`${api}/vulns/${encodeURIComponent(id)}`));
    });
    const out = new Map();
    for (const id of ids) {
      const vuln = vulnCache.get(id);
      if (vuln) out.set(id, vuln);
    }
    return out;
  }

  return { queryBatch, getVulns };
}

module.exports = { createClient };
