'use strict';

const ARM = 'https://management.azure.com';
const API_VERSION = '2024-03-01'; // Microsoft.App/jobs
const BLOB_VERSION = '2021-08-06';
const TERMINAL = new Set(['Succeeded', 'Failed', 'Stopped', 'Degraded']);
const SAFE_NAME = /^[\w.-]{1,80}$/;

// Managed identity token source for code running inside Azure Container Apps (or Apps/Functions):
// the platform injects IDENTITY_ENDPOINT and IDENTITY_HEADER. No keys or secrets are stored.
function createAzureIdentity({ endpoint, header, clientId, fetchImpl = fetch } = {}) {
  const cache = new Map();
  return async function getToken(resource) {
    const hit = cache.get(resource);
    if (hit && hit.expires > Date.now() + 60000) return hit.token;
    if (!endpoint || !header) throw new Error('Managed identity is not available in this environment');
    const url = new URL(endpoint);
    url.searchParams.set('resource', resource);
    url.searchParams.set('api-version', '2019-08-01');
    if (clientId) url.searchParams.set('client_id', clientId);
    const res = await fetchImpl(url, { headers: { 'X-IDENTITY-HEADER': header }, signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`Could not get a managed identity token (HTTP ${res.status})`);
    const body = await res.json();
    cache.set(resource, { token: body.access_token, expires: Number(body.expires_on) * 1000 || Date.now() + 5 * 60000 });
    return body.access_token;
  };
}

// Runs each scan as an Azure Container Apps Job execution:
//   1. start the job with this scan's parameters (the job clones and scans by itself),
//   2. poll the execution until it finishes (or time out and stop it),
//   3. read the result the job wrote to Blob Storage, then delete it.
// The API never sees the repository contents, and the scan runs in a short-lived container with
// its own identity. Verified only against fakes: see docs/STATUS.md.
function createAcaExecutor({
  subscriptionId, resourceGroup, jobName, image, storageAccount, container = 'scan-results',
  getToken, fetchImpl = fetch, pollMs = 5000, timeoutMs = 15 * 60 * 1000,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)), clock = () => Date.now(),
  allowHosts = ['github.com', 'gitlab.com', 'bitbucket.org'], resources = { cpu: 1, memory: '2Gi' },
  grantUrl = null, // public base URL of this API, where the job redeems its credential grant
  proxyUrl = null, // allowlist proxy the job must use (the start request replaces the job's env)
  jobClientId = null, // client id of the job's user-assigned identity (the start request replaces the job's env)
}) {
  for (const [k, v] of Object.entries({ subscriptionId, resourceGroup, jobName, image, storageAccount })) {
    if (!v || !SAFE_NAME.test(String(v)) && k !== 'image') throw new Error(`Azure scan executor: ${k} is missing or invalid`);
  }
  const jobUrl = `${ARM}/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.App/jobs/${jobName}`;
  const blobUrl = (scanId) => `https://${storageAccount}.blob.core.windows.net/${container}/${scanId}.json`;

  async function arm(method, url, body) {
    const res = await fetchImpl(url, {
      method,
      headers: { authorization: `Bearer ${await getToken('https://management.azure.com/')}`, ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`Azure Container Apps request failed (HTTP ${res.status})`);
    return res.status === 204 ? null : res.json().catch(() => null);
  }

  async function blob(method, scanId) {
    return fetchImpl(blobUrl(scanId), {
      method,
      headers: { authorization: `Bearer ${await getToken('https://storage.azure.com/')}`, 'x-ms-version': BLOB_VERSION },
      signal: AbortSignal.timeout(60000),
    });
  }

  return async function execute({ validated, branch, auth, config = {}, scanId, issueGrant }) {
    if (!SAFE_NAME.test(String(scanId))) throw new Error('Invalid scan id');
    const env = [
      ['VS_SCAN_ID', scanId], ['VS_REPO_URL', validated.url], ['VS_BRANCH', branch],
      ['VS_SCANNERS', (config.scanners || []).join(',')], ['VS_THRESHOLD', config.threshold || 'low'],
      ['VS_RESULT_URL', blobUrl(scanId)], ['VS_ALLOW_HOSTS', allowHosts.join(',')],
    ];
    // The Git credential is never placed in this request (it is readable by anyone who can read job
    // executions). The job gets a single-use grant secret and exchanges it with the API for the credential.
    if (auth) {
      if (typeof issueGrant !== 'function' || !grantUrl) throw new Error('Cannot hand the repository credential to the scan job securely (grant URL not configured)');
      env.push(['VS_GRANT_URL', grantUrl], ['VS_GRANT_SECRET', issueGrant(auth)]);
    }
    if (jobClientId) env.push(['AZURE_CLIENT_ID', jobClientId]);
    if (proxyUrl) env.push(['HTTPS_PROXY', proxyUrl], ['NODE_USE_ENV_PROXY', '1'], ['NO_PROXY', '127.0.0.1,localhost']);

    const started = await arm('POST', `${jobUrl}/start?api-version=${API_VERSION}`, {
      template: { containers: [{ name: 'scanner', image, resources, env: env.map(([name, value]) => ({ name, value })) }] },
    });
    const execution = started && started.name;
    if (!execution || !SAFE_NAME.test(execution)) throw new Error('Azure did not start the scan job');

    const deadline = clock() + timeoutMs;
    let status = 'Running';
    while (!TERMINAL.has(status)) {
      if (clock() > deadline) {
        await arm('POST', `${jobUrl}/executions/${execution}/stop?api-version=${API_VERSION}`).catch(() => {});
        throw new Error('The scan timed out');
      }
      await sleep(pollMs);
      const info = await arm('GET', `${jobUrl}/executions/${execution}?api-version=${API_VERSION}`);
      status = (info && info.properties && info.properties.status) || 'Running';
    }

    // The job writes a result even when the scan itself fails (with a safe error message).
    const res = await blob('GET', scanId);
    let payload = null;
    if (res.ok) payload = await res.json().catch(() => null);
    await blob('DELETE', scanId).catch(() => {});

    if (payload && payload.ok) return { report: payload.report, commit: payload.commit || null, scrub: ['/work', '/tmp'] };
    if (payload && payload.error) throw new Error(payload.error);
    throw new Error(status === 'Succeeded' ? 'The scan job returned no result' : 'The scan job failed');
  };
}

module.exports = { createAcaExecutor, createAzureIdentity, API_VERSION, BLOB_VERSION };
