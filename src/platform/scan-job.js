'use strict';

// Entry point of the Azure Container Apps scan job. It clones and scans one repository inside
// its own short-lived container and writes the result to Blob Storage with its managed identity.
// The container is the sandbox, so the scanners run in this process tree.

const { validateRepoUrl, cloneRepo } = require('./git');
const { createAzureIdentity, BLOB_VERSION } = require('./aca');
const { runPipeline } = require('../pipeline');

// Scrubbed from the environment before any scanner starts: scanners are child processes and
// would otherwise inherit the Git token and the identity endpoint.
const SENSITIVE = ['VS_GRANT_SECRET', 'VS_GIT_TOKEN', 'IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'MSI_ENDPOINT', 'MSI_SECRET'];

const safeMessage = (err) => String((err && err.message) || err).replace(/\/[\w./-]*vulnsight-[\w-]+/g, '<workspace>').slice(0, 300);

async function runJob({
  env = process.env, fetchImpl = fetch, validate = validateRepoUrl, clone = cloneRepo,
  pipeline = runPipeline, identity, log = console.log,
} = {}) {
  const req = {
    scanId: env.VS_SCAN_ID, url: env.VS_REPO_URL, branch: env.VS_BRANCH,
    scanners: (env.VS_SCANNERS || '').split(',').filter(Boolean), threshold: env.VS_THRESHOLD || 'low',
    resultUrl: env.VS_RESULT_URL, allowHosts: (env.VS_ALLOW_HOSTS || 'github.com,gitlab.com,bitbucket.org').split(','),
    grantUrl: env.VS_GRANT_URL, grantSecret: env.VS_GRANT_SECRET,
  };
  const getToken = identity || createAzureIdentity({ endpoint: env.IDENTITY_ENDPOINT, header: env.IDENTITY_HEADER, clientId: env.AZURE_CLIENT_ID, fetchImpl });
  for (const k of SENSITIVE) delete env[k]; // before anything else runs: scanners must not inherit them

  if (!req.url || !req.branch || !req.resultUrl) throw new Error('Scan job is missing required parameters');
  // Only ever write to the storage account we were pointed at, over https.
  if (!/^https:\/\/[a-z0-9]+\.blob\.core\.windows\.net\/[\w-]+\/[\w.-]+\.json$/.test(req.resultUrl)) throw new Error('Invalid result URL');

  let payload;
  let workspace = null;
  try {
    // Exchange the single-use grant for the repository credential (private repositories only).
    let auth = null;
    if (req.grantSecret) {
      if (!/^https:\/\/[^/@\s]+$/.test(String(req.grantUrl || ''))) throw new Error('Invalid grant URL');
      const res = await fetchImpl(`${req.grantUrl}/api/v1/internal/scan-grant`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ scanId: req.scanId, secret: req.grantSecret }),
      });
      if (!res.ok) throw new Error('Repository access denied: the credential grant was refused or already used');
      auth = await res.json();
    }
    // The job re-validates the URL itself (defence in depth: it does not trust its caller).
    const validated = await validate(req.url, { allowHosts: req.allowHosts });
    workspace = await clone(validated, { branch: req.branch, auth });
    const report = await pipeline({ path: workspace.dir }, { scanners: req.scanners.length ? req.scanners : undefined, threshold: req.threshold });
    report.target = { path: '<repo>' };
    payload = { ok: true, report, commit: workspace.commit };
  } catch (err) {
    payload = { ok: false, error: safeMessage(err) };
    log(JSON.stringify({ level: 'warn', scan: req.scanId, message: payload.error }));
  } finally {
    if (workspace) workspace.cleanup();
  }

  const res = await fetchImpl(req.resultUrl, {
    method: 'PUT',
    headers: {
      authorization: `Bearer ${await getToken('https://storage.azure.com/')}`,
      'x-ms-version': BLOB_VERSION, 'x-ms-blob-type': 'BlockBlob', 'content-type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Could not store the scan result (HTTP ${res.status})`);
  return payload;
}

if (require.main === module) {
  runJob().then(() => process.exit(0)).catch((err) => {
    console.error(safeMessage(err));
    process.exit(1);
  });
}

module.exports = { runJob, SENSITIVE };
