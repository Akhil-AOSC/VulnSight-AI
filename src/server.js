'use strict';

// Local web dashboard: serves the files in ui/ and a small JSON API.
// It only listens on 127.0.0.1 and rejects requests addressed to any other
// host name, so other websites can't drive it through the browser.

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { initEnv } = require('./env');
initEnv();

const { detectProjects } = require('./detect');
const { scanProjects, applyThreshold } = require('./scanner');
const { buildJsonReport } = require('./report');
const { isGitUrl, cloneRepository } = require('./git');
const { generateAiAnalysis } = require('./ai');
const {
  isMongoConfigured,
  saveScanToMongo,
  listScansFromMongo,
  getScanFromMongo,
} = require('./db');
const pkg = require('../package.json');

const UI_DIR = path.join(__dirname, '..', 'ui');
const STATIC_FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
};
const MAX_BODY_BYTES = 64 * 1024;
const MAX_HISTORY = 50;
const THRESHOLDS = ['low', 'medium', 'high', 'critical'];

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function defaultHistoryFile() {
  return path.join(os.homedir(), '.vulnsight', 'history.json');
}

// Past scans, newest first, kept in MongoDB Atlas or local JSON file.
function createHistoryStore(file = defaultHistoryFile(), { useMongo = (file !== null && isMongoConfigured()) } = {}) {
  let scans = [];
  try {
    const loaded = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
    if (Array.isArray(loaded)) scans = loaded;
  } catch {
    scans = [];
  }

  function save() {
    if (!file) return;
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, JSON.stringify(scans));
    } catch {
      /* best effort */
    }
  }

  return {
    async list() {
      if (useMongo) {
        const fromMongo = await listScansFromMongo();
        if (fromMongo && fromMongo.length > 0) return fromMongo;
      }
      return scans.map((s) => ({
        id: s.id,
        scannedAt: s.scannedAt,
        target: s.target,
        projectCount: Array.isArray(s.projects) ? s.projects.length : (s.projectCount || 0),
        summary: s.summary,
        ai: s.ai || null,
        source: 'local',
      }));
    },
    async get(id) {
      if (useMongo) {
        const fromMongo = await getScanFromMongo(id);
        if (fromMongo) return fromMongo;
      }
      return scans.find((s) => s.id === id) || null;
    },
    async add(scan) {
      scans = [scan, ...scans].slice(0, MAX_HISTORY);
      save();
      if (useMongo) {
        await saveScanToMongo(scan);
      }
    },
  };
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new HttpError(413, 'Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        reject(new HttpError(400, 'Request body is not valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function createApp({
  scan = scanProjects,
  history = createHistoryStore(),
  defaultTarget = process.cwd(),
  enableAi = Boolean(process.env.GROQ_API_KEY) && scan === scanProjects,
} = {}) {
  async function runScan(body) {
    const rawTarget = typeof body.path === 'string' && body.path.trim() ? body.path.trim() : defaultTarget;
    const threshold = THRESHOLDS.includes(body.threshold) ? body.threshold : 'low';
    const dev = body.dev === true;

    let dir;
    let cleanup = null;
    let isRemote = false;

    if (isGitUrl(rawTarget)) {
      isRemote = true;
      try {
        const cloned = await cloneRepository(rawTarget);
        dir = cloned.dir;
        cleanup = cloned.cleanup;
      } catch (err) {
        throw new HttpError(400, err.message);
      }
    } else {
      dir = path.resolve(rawTarget);
    }

    try {
      let detected;
      try {
        detected = detectProjects(dir, { dev });
      } catch (err) {
        throw new HttpError(400, err.message);
      }
      if (!detected.projects.length) {
        const hint = detected.warnings.length ? ` ${detected.warnings.join(' ')}` : '';
        throw new HttpError(400, `No supported dependency files found in ${rawTarget}.${hint}`);
      }

      if (isRemote) {
        for (const p of detected.projects) {
          p.file = path.relative(dir, p.file) || path.basename(p.file);
        }
      }

      const results = applyThreshold(await scan(detected.projects), threshold);
      const jsonReport = buildJsonReport(results, detected.warnings);

      // Enhance findings with Groq Open-Source LLM
      let ai = null;
      try {
        ai = await generateAiAnalysis(jsonReport);
        if (ai && ai.packageExplanations) {
          for (const proj of jsonReport.projects) {
            for (const vuln of proj.vulnerabilities) {
              if (ai.packageExplanations[vuln.package]) {
                vuln.aiExplanation = ai.packageExplanations[vuln.package];
              }
            }
          }
        }
      } catch (err) {
        console.warn('[AI Warning] Could not generate AI analysis:', err.message);
      }

      const record = {
        id: crypto.randomUUID(),
        scannedAt: new Date().toISOString(),
        target: isRemote ? rawTarget : dir,
        options: { dev, threshold },
        ai,
        ...jsonReport,
      };

      await history.add(record);
      return record;
    } finally {
      if (cleanup) cleanup();
    }
  }

  return async function handle(req, res) {
    try {
      // Blocks DNS-rebinding: only accept requests addressed to this machine.
      const host = String(req.headers.host || '').replace(/:\d+$/, '');
      if (!['localhost', '127.0.0.1', '[::1]'].includes(host)) throw new HttpError(403, 'Forbidden host');

      const url = new URL(req.url, 'http://localhost');

      if (req.method === 'GET' && STATIC_FILES[url.pathname]) {
        const [file, type] = STATIC_FILES[url.pathname];
        res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
        res.end(fs.readFileSync(path.join(UI_DIR, file)));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/config') {
        sendJson(res, 200, {
          version: pkg.version,
          defaultTarget: path.resolve(defaultTarget),
          aiEnabled: Boolean(process.env.GROQ_API_KEY),
          mongoEnabled: isMongoConfigured(),
        });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/scans') {
        const list = await history.list();
        sendJson(res, 200, list);
        return;
      }
      const match = url.pathname.match(/^\/api\/scans\/([\w-]+)$/);
      if (req.method === 'GET' && match) {
        const record = await history.get(match[1]);
        if (!record) throw new HttpError(404, 'Scan not found');
        sendJson(res, 200, record);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/scans') {
        // Requiring JSON forces a CORS preflight, which this server never approves.
        if (!String(req.headers['content-type'] || '').startsWith('application/json')) {
          throw new HttpError(415, 'Expected application/json');
        }
        sendJson(res, 201, await runScan(await readJsonBody(req)));
        return;
      }
      throw new HttpError(404, 'Not found');
    } catch (err) {
      sendJson(res, err.status || 500, { error: err.message });
    }
  };
}

function startServer({ port = Number(process.env.VULNSIGHT_PORT) || 4321, ...opts } = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(createApp(opts));
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

module.exports = { createApp, createHistoryStore, startServer };
