'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const path = require('path');
const { createApp, createHistoryStore } = require('../src/server');

const EXAMPLE = path.join(__dirname, '..', 'examples', 'npm-app');

// Every lodash version gets one fake critical issue; nothing else is vulnerable.
async function fakeScan(projects) {
  return projects.map((p) => ({
    ...p,
    issues: p.dependencies.filter((d) => d.name === 'lodash').map((d) => ({
      id: 'GHSA-test', aliases: ['CVE-2020-1'], title: 'Test issue', severity: 'critical', cvssScore: 9.8,
      package: d.name, version: d.version, ecosystem: d.ecosystem, fixedIn: '4.17.21',
      url: 'https://osv.dev/vulnerability/GHSA-test', direct: d.direct, paths: d.paths,
    })),
  }));
}

async function withServer(fn) {
  const server = http.createServer(createApp({ scan: fakeScan, history: createHistoryStore(null), defaultTarget: EXAMPLE }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    server.close();
  }
}

const postScan = (base, body, headers = { 'content-type': 'application/json' }) =>
  fetch(`${base}/api/scans`, { method: 'POST', headers, body: JSON.stringify(body) });

test('dashboard page and assets are served', async () => {
  await withServer(async (base) => {
    for (const [file, type] of [['/', 'text/html'], ['/app.js', 'text/javascript'], ['/styles.css', 'text/css']]) {
      const res = await fetch(base + file);
      assert.equal(res.status, 200, file);
      assert.ok(res.headers.get('content-type').startsWith(type), file);
    }
  });
});

test('a scan is stored in history and can be fetched again', async () => {
  await withServer(async (base) => {
    const res = await postScan(base, { path: EXAMPLE });
    assert.equal(res.status, 201);
    const record = await res.json();
    assert.equal(record.summary.issues, 1);
    assert.equal(record.summary.critical, 1);
    assert.deepEqual(record.projects[0].upgradePlan.map((p) => p.target), ['4.17.21']);

    const list = await (await fetch(`${base}/api/scans`)).json();
    assert.deepEqual(list.map((s) => s.id), [record.id]);

    const again = await (await fetch(`${base}/api/scans/${record.id}`)).json();
    assert.equal(again.target, record.target);
  });
});

test('severity threshold is applied to stored results', async () => {
  await withServer(async (base) => {
    const record = await (await postScan(base, { path: EXAMPLE, threshold: 'critical' })).json();
    assert.equal(record.summary.issues, 1);
    const none = await (await postScan(base, { path: EXAMPLE, threshold: 'high' })).json();
    assert.equal(none.summary.issues, 1, 'critical issues still count at the high threshold');
  });
});

test('bad requests get clear errors', async () => {
  await withServer(async (base) => {
    const missing = await postScan(base, { path: path.join(__dirname, 'no-such-folder') });
    assert.equal(missing.status, 400);
    assert.match((await missing.json()).error, /Not a directory/);

    const empty = await postScan(base, { path: __dirname });
    assert.equal(empty.status, 400);
    assert.match((await empty.json()).error, /No supported dependency files/);

    const notJson = await postScan(base, { path: EXAMPLE }, { 'content-type': 'text/plain' });
    assert.equal(notJson.status, 415);

    assert.equal((await fetch(`${base}/api/scans/unknown-id`)).status, 404);
  });
});

test('requests addressed to another host name are rejected', async () => {
  await withServer(async (base) => {
    const { port } = new URL(base);
    const status = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path: '/api/scans', headers: { host: `evil.example:${port}` } }, (res) => {
        res.resume();
        resolve(res.statusCode);
      }).on('error', reject);
    });
    assert.equal(status, 403);
  });
});
