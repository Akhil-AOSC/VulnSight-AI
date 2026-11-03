/**
 * Client for OSV.dev (Open Source Vulnerabilities) REST API.
 * Supports batching via /v1/querybatch and detail retrieval via /v1/vulns/{id}.
 */

const DEFAULT_BASE_URL = 'https://api.osv.dev/v1';
const BATCH_SIZE = 500;
const CONCURRENCY_LIMIT = 10;

export class OSVClient {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || DEFAULT_BASE_URL;
    this.fetch = options.fetch || globalThis.fetch;
    this.cache = new Map(); // vulnId -> full vulnerability object
    this.timeoutMs = options.timeoutMs || 15000;
  }

  /**
   * Helper to perform fetch with timeout and retries
   */
  async _fetchWithRetry(url, fetchOptions = {}, retries = 2) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await this.fetch(url, {
          ...fetchOptions,
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (response.status === 429 && attempt < retries) {
          // Rate limited, exponential backoff
          const delay = Math.pow(2, attempt + 1) * 1000;
          await new Promise((resolve) => setTimeout(resolve, delay));
          continue;
        }

        if (!response.ok) {
          throw new Error(`OSV API request failed with status ${response.status} (${response.statusText})`);
        }

        return await response.json();
      } catch (err) {
        clearTimeout(timer);
        if (attempt === retries) {
          throw err;
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  }

  /**
   * Queries vulnerabilities for a list of dependencies in batches.
   *
   * @param {Array<{name: string, version: string}>} dependencies
   * @returns {Promise<Map<string, Array<object>>>} Map from `${name}@${version}` to array of full vuln objects
   */
  async queryDependencies(dependencies) {
    if (!dependencies || dependencies.length === 0) {
      return new Map();
    }

    // Step 1: Chunk into batches for /v1/querybatch
    const chunks = [];
    for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
      chunks.push(dependencies.slice(i, i + BATCH_SIZE));
    }

    // Map: `${name}@${version}` -> Set of vuln IDs
    const matchedVulnIdsByDep = new Map();
    const allUniqueVulnIds = new Set();

    for (const chunk of chunks) {
      const queries = chunk.map((dep) => ({
        package: {
          name: dep.name,
          ecosystem: 'npm',
        },
        version: dep.version,
      }));

      const batchResponse = await this._fetchWithRetry(`${this.baseUrl}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
      });

      const results = batchResponse.results || [];
      for (let i = 0; i < chunk.length; i++) {
        const dep = chunk[i];
        const key = `${dep.name}@${dep.version}`;
        const result = results[i];

        if (result && Array.isArray(result.vulns) && result.vulns.length > 0) {
          const vulnIds = result.vulns.map((v) => v.id);
          matchedVulnIdsByDep.set(key, vulnIds);
          for (const id of vulnIds) {
            allUniqueVulnIds.add(id);
          }
        }
      }
    }

    // Step 2: Fetch full details for all unique vulnerability IDs with concurrency limiting
    const vulnIdsToFetch = Array.from(allUniqueVulnIds).filter((id) => !this.cache.has(id));
    await this._fetchVulnDetailsConcurrently(vulnIdsToFetch);

    // Step 3: Assemble results map `${name}@${version}` -> full vuln objects
    const resultMap = new Map();
    for (const [depKey, vulnIds] of matchedVulnIdsByDep.entries()) {
      const fullVulns = vulnIds
        .map((id) => this.cache.get(id))
        .filter(Boolean);
      resultMap.set(depKey, fullVulns);
    }

    return resultMap;
  }

  /**
   * Fetches full vulnerability details by ID with concurrency limiting.
   */
  async _fetchVulnDetailsConcurrently(vulnIds) {
    let index = 0;
    const workers = [];

    const worker = async () => {
      while (index < vulnIds.length) {
        const currentIndex = index++;
        const vulnId = vulnIds[currentIndex];
        try {
          const vuln = await this.getVulnerabilityById(vulnId);
          if (vuln) {
            this.cache.set(vulnId, vuln);
          }
        } catch (err) {
          console.warn(`[WARN] Failed to fetch details for vulnerability ${vulnId}: ${err.message}`);
        }
      }
    };

    const workerCount = Math.min(CONCURRENCY_LIMIT, vulnIds.length);
    for (let i = 0; i < workerCount; i++) {
      workers.push(worker());
    }

    await Promise.all(workers);
  }

  /**
   * Fetches details of a single vulnerability by ID from /v1/vulns/{id}.
   */
  async getVulnerabilityById(vulnId) {
    if (this.cache.has(vulnId)) {
      return this.cache.get(vulnId);
    }

    const vuln = await this._fetchWithRetry(`${this.baseUrl}/vulns/${encodeURIComponent(vulnId)}`);
    this.cache.set(vulnId, vuln);
    return vuln;
  }
}
