'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { AuthError, ValidationError, NotFoundError } = require('./rbac');

const WEB_DIR = path.join(__dirname, '..', '..', 'web');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };

const MAX_BODY = 1024 * 1024;
const MAX_WEBHOOK_BODY = 5 * 1024 * 1024;

// In-memory sliding-window limiter, keyed by string. A hosted deployment with several API
// instances would back this with Redis; the interface is the same.
function createRateLimiter({ clock = () => Date.now() } = {}) {
  const hits = new Map();
  return {
    // Returns true when the call is allowed.
    allow(key, limit, windowMs) {
      const t = clock();
      const recent = (hits.get(key) || []).filter((x) => t - x < windowMs);
      if (recent.length >= limit) { hits.set(key, recent); return false; }
      recent.push(t);
      hits.set(key, recent);
      if (hits.size > 50000) for (const [k, v] of hits) if (!v.length || t - v[v.length - 1] > windowMs) hits.delete(k);
      return true;
    },
  };
}

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new ValidationError('Request body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function createApi({ platform, trustProxy = false, hsts = false, limiter = createRateLimiter(), log = () => {} }) {
  const routes = [];
  const route = (method, pattern, handler, opts = {}) => {
    const keys = [];
    const re = new RegExp(`^${pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([\\w.-]+)'; })}$`);
    routes.push({ method, re, keys, handler, ...opts });
  };

  const org = (p) => `/api/v1/orgs/:org${p}`;
  const ctxOf = (req, params) => ({ userId: req.userId, orgId: params.org, ip: req.ip });

  // ---- public ----
  route('GET', '/api/v1/health', async () => ({ ok: true }), { public: true });
  route('POST', '/api/v1/auth/signup', async (req, p, body) => platform.auth.signup(body, { ip: req.ip }), { public: true, authLimit: true, status: 201 });
  route('POST', '/api/v1/auth/login', async (req, p, body) => platform.auth.login(body, { ip: req.ip }), { public: true, authLimit: true });
  // Called by scan jobs, not people: trades a single-use grant secret for the repository credential.
  route('POST', '/api/v1/internal/scan-grant', async (req, p, body) => {
    if (!limiter.allow(`grant:${req.ip}`, 60, 60000)) throw Object.assign(new ValidationError('Too many requests'), { status: 429 });
    return platform.grants.redeem(body.scanId, body.secret, req.ip);
  }, { public: true });
  route('POST', '/api/v1/webhooks/:repo', async (req, p) => platform.automation.handleWebhook(p.repo, req.headers, req.rawBody), { public: true, raw: true });

  // ---- session ----
  route('POST', '/api/v1/auth/logout', async (req) => { platform.auth.logout(req.token); return { ok: true }; });
  route('GET', '/api/v1/me', async (req) => platform.auth.me(req.userId));
  route('PATCH', '/api/v1/me', async (req, p, b) => platform.auth.setTheme(req.userId, b.theme));
  route('POST', '/api/v1/orgs', async (req, p, body) => platform.orgs.create(req.userId, body), { status: 201 });

  // ---- organisation ----
  route('GET', org('/overview'), async (req, p) => platform.dashboard.overview(ctxOf(req, p)));
  route('GET', org('/settings'), async (req, p) => platform.orgs.getSettings(ctxOf(req, p)));
  route('PATCH', org('/settings'), async (req, p, b) => platform.orgs.updateSettings(ctxOf(req, p), b));
  route('PATCH', org(''), async (req, p, b) => platform.orgs.rename(ctxOf(req, p), b.name));
  route('DELETE', org(''), async (req, p) => { await platform.orgs.delete(ctxOf(req, p)); return { ok: true }; });
  route('GET', org('/members'), async (req, p) => platform.orgs.listMembers(ctxOf(req, p)));
  route('POST', org('/members'), async (req, p, b) => platform.orgs.addMember(ctxOf(req, p), b), { status: 201 });
  route('PATCH', org('/members/:user'), async (req, p, b) => platform.orgs.setMemberRole(ctxOf(req, p), p.user, b.role));
  route('DELETE', org('/members/:user'), async (req, p) => { platform.orgs.removeMember(ctxOf(req, p), p.user); return { ok: true }; });
  route('GET', org('/teams'), async (req, p) => platform.teams.list(ctxOf(req, p)));
  route('POST', org('/teams'), async (req, p, b) => platform.teams.create(ctxOf(req, p), b), { status: 201 });
  route('DELETE', org('/teams/:team'), async (req, p) => { await platform.teams.delete(ctxOf(req, p), p.team); return { ok: true }; });
  route('POST', org('/teams/:team/members/:user'), async (req, p) => { await platform.teams.addMember(ctxOf(req, p), p.team, p.user); return { ok: true }; });
  route('DELETE', org('/teams/:team/members/:user'), async (req, p) => { await platform.teams.removeMember(ctxOf(req, p), p.team, p.user); return { ok: true }; });
  route('GET', org('/audit'), async (req, p, b, q) => platform.audit.list(ctxOf(req, p), q));
  route('GET', org('/notifications'), async (req, p) => platform.notifications.list(ctxOf(req, p)));
  route('POST', org('/notifications/read'), async (req, p, b) => { await platform.notifications.markRead(ctxOf(req, p), b.id); return { ok: true }; });

  // ---- git providers ----
  route('GET', org('/connections'), async (req, p) => platform.connections.list(ctxOf(req, p)));
  route('POST', org('/connections'), async (req, p, b) => platform.connections.connect(ctxOf(req, p), b), { status: 201 });
  route('DELETE', org('/connections/:conn'), async (req, p) => { await platform.connections.remove(ctxOf(req, p), p.conn); return { ok: true }; });
  route('POST', org('/connections/:conn/check'), async (req, p) => platform.connections.check(ctxOf(req, p), p.conn));
  route('GET', org('/connections/:conn/repos'), async (req, p) => platform.connections.listRemoteRepos(ctxOf(req, p), p.conn));
  route('GET', org('/connections/:conn/branches'), async (req, p, b, q) => platform.connections.listBranches(ctxOf(req, p), p.conn, q.repo));

  // ---- repositories ----
  route('GET', org('/repos'), async (req, p) => platform.repos.list(ctxOf(req, p)));
  route('POST', org('/repos'), async (req, p, b) => platform.repos.add(ctxOf(req, p), b), { status: 201 });
  route('GET', org('/repos/:repo'), async (req, p) => platform.repos.get(ctxOf(req, p), p.repo));
  route('PATCH', org('/repos/:repo'), async (req, p, b) => platform.repos.update(ctxOf(req, p), p.repo, b));
  route('DELETE', org('/repos/:repo'), async (req, p) => { await platform.repos.remove(ctxOf(req, p), p.repo); return { ok: true }; });
  route('PUT', org('/repos/:repo/schedule'), async (req, p, b) => platform.repos.setSchedule(ctxOf(req, p), p.repo, b.schedule === undefined ? null : b.schedule));
  route('GET', org('/repos/:repo/branches'), async (req, p) => platform.repos.branches(ctxOf(req, p), p.repo));
  route('GET', org('/repos/:repo/webhook'), async (req, p) => ({ url: `/api/v1/webhooks/${p.repo}`, secret: platform.repos.webhookSecret(ctxOf(req, p), p.repo) }));

  // ---- websites (DAST) ----
  route('GET', org('/websites'), async (req, p) => platform.websites.list(ctxOf(req, p)));
  route('POST', org('/websites'), async (req, p, b) => platform.websites.create(ctxOf(req, p), b), { status: 201 });
  route('GET', org('/websites/:site'), async (req, p) => platform.websites.get(ctxOf(req, p), p.site));
  route('DELETE', org('/websites/:site'), async (req, p) => { await platform.websites.remove(ctxOf(req, p), p.site); return { ok: true }; });
  route('POST', org('/websites/:site/verify'), async (req, p, b) => platform.websites.verify(ctxOf(req, p), p.site, b));
  route('POST', org('/websites/:site/scans'), async (req, p, b) => platform.websites.startScan(ctxOf(req, p), p.site, b), { status: 202 });
  route('GET', org('/websites/:site/scans'), async (req, p, b, q) => platform.websites.listScans(ctxOf(req, p), p.site, q));
  route('GET', org('/websites/:site/scans/:scan'), async (req, p) => platform.websites.getScan(ctxOf(req, p), p.site, p.scan));
  route('GET', org('/websites/:site/scans/:scan/report'), async (req, p, b, q) => ({ download: platform.websites.report(ctxOf(req, p), p.site, p.scan, q.format || 'json') }));

  // ---- scans and findings ----
  route('POST', org('/repos/:repo/scans'), async (req, p, b) => platform.scans.start(ctxOf(req, p), p.repo, b), { status: 202 });
  route('POST', org('/quick-scan'), async (req, p, b) => platform.scans.quickScan(ctxOf(req, p), b), { status: 202 });
  route('POST', org('/mongo/sync'), async (req, p) => {
    const ctx = ctxOf(req, p);
    platform.authorize(ctx, 'repos:read');
    return platform.dashboard.syncMongo(ctx.orgId);
  });
  route('GET', org('/scans'), async (req, p, b, q) => platform.scans.list(ctxOf(req, p), q));
  route('GET', org('/scans/:scan'), async (req, p) => platform.scans.get(ctxOf(req, p), p.scan));
  route('POST', org('/scans/:scan/cancel'), async (req, p) => platform.scans.cancel(ctxOf(req, p), p.scan));
  route('GET', org('/scans/:scan/findings'), async (req, p, b, q) => platform.scans.findings(ctxOf(req, p), p.scan, q));
  route('GET', org('/scans/:scan/report'), async (req, p, b, q) => ({ download: platform.scans.report(ctxOf(req, p), p.scan, q.format || 'json') }));
  route('PATCH', org('/repos/:repo/findings/:fp'), async (req, p, b) => platform.findings.update(ctxOf(req, p), p.repo, p.fp, b));
  route('GET', org('/repos/:repo/findings/:fp/history'), async (req, p) => platform.findings.history(ctxOf(req, p), p.repo, p.fp));

  // ---- AI ----
  route('POST', org('/findings/:finding/explain'), async (req, p) => platform.ai.explain(ctxOf(req, p), p.finding));
  route('POST', org('/findings/:finding/fix'), async (req, p) => platform.ai.fix(ctxOf(req, p), p.finding));
  route('POST', org('/repos/:repo/ai/ask'), async (req, p, b) => platform.ai.ask(ctxOf(req, p), p.repo, b.question, Array.isArray(b.history) ? b.history : []));
  route('POST', org('/repos/:repo/ai/summary'), async (req, p) => platform.ai.summary(ctxOf(req, p), p.repo));
  route('GET', org('/repos/:repo/ai/history'), async (req, p) => platform.ai.history(ctxOf(req, p), p.repo));

  function match(method, pathname) {
    for (const r of routes) {
      if (r.method !== method) continue;
      const m = pathname.match(r.re);
      if (m) return { r, params: Object.fromEntries(r.keys.map((k, i) => [k, m[i + 1]])) };
    }
    return null;
  }

  const clientIp = (req) => {
    if (trustProxy && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
    return req.socket.remoteAddress || 'unknown';
  };

  function send(res, status, body, extra = {}) {
    const headers = { ...SECURITY_HEADERS, 'cache-control': 'no-store', ...extra };
    if (hsts) headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
    if (typeof body === 'string' || Buffer.isBuffer(body)) {
      res.writeHead(status, headers);
      res.end(body);
    } else {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
      res.end(JSON.stringify(body));
    }
  }

  function serveStatic(res, pathname) {
    const name = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
    // Only plain filenames from the web directory: no separators, so no path traversal.
    if (!/^[\w.-]+$/.test(name) || !TYPES[path.extname(name)]) return false;
    const file = path.join(WEB_DIR, name);
    if (!fs.existsSync(file)) return false;
    send(res, 200, fs.readFileSync(file), { 'content-type': TYPES[path.extname(name)], 'cache-control': 'no-cache, no-store, must-revalidate' });
    return true;
  }

  async function handle(req, res) {
    const started = Date.now();
    req.ip = clientIp(req);
    const url = new URL(req.url, 'http://localhost');
    try {
      if (!url.pathname.startsWith('/api/')) {
        if (req.method === 'GET' && serveStatic(res, url.pathname)) return;
        // Single-page app: unknown non-API paths serve the shell.
        if (req.method === 'GET' && serveStatic(res, '/')) return;
        throw new NotFoundError();
      }

      const m = match(req.method, url.pathname);
      if (!m) throw new NotFoundError();
      const { r, params } = m;

      if (!limiter.allow(`ip:${req.ip}`, 600, 60000)) throw Object.assign(new ValidationError('Too many requests'), { status: 429 });

      let raw = Buffer.alloc(0);
      let body = {};
      if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) {
        raw = await readBody(req, r.raw ? MAX_WEBHOOK_BODY : MAX_BODY);
        if (!r.raw && raw.length) {
          if (!String(req.headers['content-type'] || '').startsWith('application/json')) throw Object.assign(new ValidationError('Expected application/json'), { status: 415 });
          try { body = JSON.parse(raw.toString('utf8')); } catch { throw new ValidationError('Invalid JSON'); }
          if (body === null || typeof body !== 'object' || Array.isArray(body)) throw new ValidationError('Expected a JSON object');
        }
      }
      req.rawBody = raw;

      if (r.authLimit) {
        const email = String((body && body.email) || '').toLowerCase().slice(0, 200);
        if (!limiter.allow(`auth:${req.ip}`, 20, 15 * 60000) || !limiter.allow(`auth:${email}`, 10, 15 * 60000)) {
          throw Object.assign(new ValidationError('Too many attempts. Try again later'), { status: 429 });
        }
      }

      if (!r.public) {
        const header = String(req.headers.authorization || '');
        req.token = header.startsWith('Bearer ') ? header.slice(7) : null;
        req.userId = platform.auth.authenticate(req.token).userId;
      }

      const query = Object.fromEntries(url.searchParams);
      const result = await r.handler(req, params, body, query);
      log({ method: req.method, path: url.pathname, status: r.status || 200, ms: Date.now() - started });

      if (result && result.download) {
        const d = result.download;
        send(res, 200, d.body, { 'content-type': d.type, 'content-disposition': `attachment; filename="report.${d.ext}"` });
        return;
      }
      send(res, r.status || 200, result === undefined ? { ok: true } : result);
    } catch (err) {
      const status = err.status && Number.isInteger(err.status) ? err.status : 500;
      if (status >= 500) {
        const errorId = crypto.randomUUID();
        log({ level: 'error', errorId, path: url.pathname, message: err.message, stack: err.stack });
        send(res, 500, { error: 'Internal error', errorId });
      } else {
        send(res, status, { error: err.message });
      }
    }
  }

  return { handle, routes };
}

function createServer(opts) {
  const api = createApi(opts);
  return http.createServer(api.handle);
}

module.exports = { createApi, createServer, createRateLimiter, SECURITY_HEADERS };
