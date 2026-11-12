'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { loadPlaywright, runBrowserCrawl } = require('../src/adapters/dast/browser-crawl');
const { normalizeScope } = require('../src/adapters/dast/scope');

const pw = loadPlaywright();
let chromiumOk = false;
if (pw) {
  try {
    chromiumOk = true;
  } catch {
    chromiumOk = false;
  }
}
const SKIP = !pw ? 'playwright-core is not installed' : false;

test('browser crawl finds SPA endpoints, blocks POST, and emits runtime findings', { skip: SKIP }, async (t) => {
  let launched = false;
  try {
    const browser = await pw.chromium.launch({ headless: true });
    launched = true;
    await browser.close();
  } catch (err) {
    t.skip(`Chromium not available: ${err.message}`);
    return;
  }
  if (!launched) return;

  const posts = [];
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      posts.push(req.url);
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('posted');
      return;
    }
    if (req.url === '/api/items') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('[{"id":1}]');
      return;
    }
    if (req.url === '/app.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      res.end('console.log("ok");');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><html><head><title>SPA</title></head><body>
      <a href="/about" id="spa-link">About</a>
      <form action="/login" method="POST"><input name="user"><button type="submit">Save</button></form>
      <script src="/app.js"></script>
      <script>
        window.jQuery = { fn: { jquery: '1.12.4' } };
        history.pushState({}, '', '/about');
        localStorage.setItem('session', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abcdeghijk');
        fetch('/api/items');
      </script>
    </body></html>`);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const origin = `http://127.0.0.1:${port}/`;
  const scope = normalizeScope('127.0.0.1', {});
  const inventory = await runBrowserCrawl(origin, {
    scope,
    limits: { maxPages: 5, maxDurationSec: 30, maxRps: 5 },
    allowAnyPort: true,
    osvClient: {
      queryBatch: async (queries) => queries.map(() => ['CVE-2020-11022']),
      getVulns: async () => new Map(),
    },
  });
  assert.ok(inventory.endpoints.some((e) => String(e.url).includes('/api/items')), 'XHR endpoint recorded');
  assert.equal(posts.length, 0, 'POST form was not submitted');
  assert.ok(inventory.findings.some((f) => f.scanner.ruleId === 'browser-storage-token'));
  assert.ok(inventory.findings.some((f) => /jquery/i.test(f.title) || /jquery/i.test(f.scanner.ruleId)));
});
