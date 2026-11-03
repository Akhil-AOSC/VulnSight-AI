'use strict';

const fs = require('fs');
const path = require('path');
const { initEnv } = require('../env');
initEnv();
const { openDatabase } = require('./db');
const { createSecretBox, generateMasterKey } = require('./crypto');
const { createQueue, createWorker } = require('./queue');
const { createPlatform } = require('./service');
const { createServer } = require('./api');
const { createAcaExecutor, createAzureIdentity } = require('./aca');

// Where the master key comes from. Production must supply it (from Azure Key Vault via an
// environment reference, or a mounted secret); the generated dev key is for local use only.
function loadMasterKey({ env = process.env, dataDir }) {
  if (env.VULNSIGHT_MASTER_KEY) return env.VULNSIGHT_MASTER_KEY;
  if (env.NODE_ENV === 'production') throw new Error('VULNSIGHT_MASTER_KEY is required in production');
  const file = path.join(dataDir, 'dev-master.key');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const key = generateMasterKey();
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(file, key, { mode: 0o600 });
  return key;
}

// Azure Container Apps scan jobs: VULNSIGHT_SANDBOX=aca plus the VULNSIGHT_ACA_* settings.
function acaExecutorFromEnv(env) {
  const need = ['SUBSCRIPTION', 'RESOURCE_GROUP', 'JOB', 'IMAGE', 'STORAGE_ACCOUNT'];
  const missing = need.filter((k) => !env[`VULNSIGHT_ACA_${k}`]);
  if (missing.length) throw new Error(`VULNSIGHT_SANDBOX=aca needs: ${missing.map((k) => `VULNSIGHT_ACA_${k}`).join(', ')}`);
  return createAcaExecutor({
    subscriptionId: env.VULNSIGHT_ACA_SUBSCRIPTION, resourceGroup: env.VULNSIGHT_ACA_RESOURCE_GROUP,
    jobName: env.VULNSIGHT_ACA_JOB, image: env.VULNSIGHT_ACA_IMAGE, storageAccount: env.VULNSIGHT_ACA_STORAGE_ACCOUNT,
    container: env.VULNSIGHT_ACA_CONTAINER || 'scan-results', jobClientId: env.VULNSIGHT_ACA_JOB_CLIENT_ID || null, proxyUrl: env.VULNSIGHT_ACA_PROXY_URL || null, grantUrl: (env.VULNSIGHT_PUBLIC_URL || '').replace(/\/$/, '') || null,
    getToken: createAzureIdentity({ endpoint: env.IDENTITY_ENDPOINT, header: env.IDENTITY_HEADER, clientId: env.VULNSIGHT_ACA_API_CLIENT_ID || undefined }),
  });
}

// Starts the whole platform in one process: HTTP API, background worker, scheduler, retention.
// In the hosted deployment the API and worker run as separate containers (see deploy/).
async function startPlatform({
  port = 4400, host = '127.0.0.1', dataDir = path.join(process.cwd(), '.vulnsight-data'),
  env = process.env, runWorker = true, sandboxMode, limiter, log = (e) => console.log(JSON.stringify(e)),
  enableMongo = runWorker, enableAutoAi = runWorker,
} = {}) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = openDatabase(env.VULNSIGHT_DB || path.join(dataDir, 'vulnsight.db'));
  const secretBox = createSecretBox(loadMasterKey({ env, dataDir }));
  const queue = createQueue(db);
  const mode = sandboxMode || env.VULNSIGHT_SANDBOX || 'process';
  const executor = mode === 'aca' ? acaExecutorFromEnv(env) : undefined; // otherwise the local executor
  const platform = createPlatform({ db, queue, secretBox, sandboxMode: mode, executor, enableMongo, enableAutoAi });
  const worker = createWorker({ queue, handlers: platform.handlers, onError: (err, job, outcome) => log({ level: 'warn', job: job.type, outcome, message: err.message }) });

  if (enableMongo) {
    try {
      const orgRows = db.prepare('SELECT id FROM orgs ORDER BY created_at').all();
      for (const org of orgRows) {
        await platform.dashboard.syncMongo(org.id);
      }
    } catch (e) {
      log({ level: 'warn', message: `MongoDB sync warning: ${e.message}` });
    }
  }

  const server = createServer({ platform, trustProxy: env.VULNSIGHT_TRUST_PROXY === '1', hsts: env.VULNSIGHT_HSTS === '1', log, ...(limiter ? { limiter } : {}) });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });

  const timers = [];
  if (runWorker) {
    worker.start();
    timers.push(setInterval(() => { try { platform.automation.tickSchedules(); } catch (e) { log({ level: 'error', message: e.message }); } }, 60 * 1000));
    timers.push(setInterval(() => { try { platform.automation.purge(); } catch (e) { log({ level: 'error', message: e.message }); } }, 24 * 3600 * 1000));
  }
  timers.forEach((t) => t.unref());

  const stop = async () => {
    worker.stop();
    timers.forEach(clearInterval);
    await new Promise((r) => server.close(r));
    db.close();
  };
  return { server, platform, db, secretBox, stop, port: server.address().port };
}

module.exports = { startPlatform, loadMasterKey, acaExecutorFromEnv };
