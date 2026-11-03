'use strict';

// Local web dashboard: serves the files in ui/ and a small JSON API.
// It only listens on 127.0.0.1 and rejects requests addressed to any other
// host name, so other websites can't drive it through the browser.

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { detectProjects } = require('./detect');
const { scanProjects, applyThreshold } = require('./scanner');
const { buildJsonReport } = require('./report');
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

// Past scans, newest first, kept in a JSON file so they survive restarts.
function createHistoryStore(file = defaultHistoryFile()) {
  let scans = [];
  try {
    const loaded = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
    if (Array.isArray(loaded)) scans = loaded;
  } catch {
    scans = [];
  }

  function save() {
    if (!file) return;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(scans));
  }

  return {
    list: () => scans.map((s) => ({
      id: s.id,
      scannedAt: s.scannedAt,
      target: s.target,
      projectCount: s.projects.length,
      summary: s.summary,
    })),
    get: (id) => scans.find((s) => s.id === id) || null,
    add(scan) {
      scans = [scan, ...scans].slice(0, MAX_HISTORY);
      save();
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

function createApp({ scan = scanProjects, history = createHistoryStore(), defaultTarget = process.cwd() } = {}) {
  async function runScan(body) {
    const target = typeof body.path === 'string' && body.path.trim() ? body.path.trim() : defaultTarget;
    const threshold = THRESHOLDS.includes(body.threshold) ? body.threshold : 'low';
    const dev = body.dev === true;
    const dir = path.resolve(target);

    let detected;
    try {
      detected = detectProjects(dir, { dev });
    } catch (err) {
      throw new HttpError(400, err.message);
    }
    if (!detected.projects.length) {
      const hint = detected.warnings.length ? ` ${detected.warnings.join(' ')}` : '';
      throw new HttpError(400, `No supported dependency files found in ${dir}.${hint}`);
    }

    const results = applyThreshold(await scan(detected.projects), threshold);
    const record = {
      id: crypto.randomUUID(),
      scannedAt: new Date().toISOString(),
      target: dir,
      options: { dev, threshold },
      ...buildJsonReport(results, detected.warnings),
    };
    history.add(record);
    return record;
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
        sendJson(res, 200, { version: pkg.version, defaultTarget: path.resolve(defaultTarget) });
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/scans') {
        sendJson(res, 200, history.list());
        return;
      }
      const match = url.pathname.match(/^\/api\/scans\/([\w-]+)$/);
      if (req.method === 'GET' && match) {
        const record = history.get(match[1]);
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

function startServer({ port = 4321, ...opts } = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(createApp(opts));
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

module.exports = { createApp, createHistoryStore, startServer };
