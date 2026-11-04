'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanBuiltinSast } = require('../src/adapters/builtin-sast');
const { scanBuiltinSecrets } = require('../src/adapters/builtin-secrets');
const { createSemgrepAdapter } = require('../src/adapters/semgrep');
const { runAdapter } = require('../src/adapters/runner');

const INSECURE = path.join(__dirname, '..', 'examples', 'insecure-app');

function scanDir(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-sast-'));
  for (const [name, body] of Object.entries(files)) {
    const dest = path.join(root, name);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, body);
  }
  try {
    return { root, findings: scanBuiltinSast(root) };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('builtin SAST finds XSS, command injection and eval in the fixture', () => {
  const findings = scanBuiltinSast(INSECURE);
  assert.ok(findings.some((f) => f.identifiers.primary.endsWith('direct-response-write') && f.location.line === 8));
  assert.ok(findings.some((f) => f.identifiers.primary.endsWith('detect-child-process') && f.location.line === 13));
  assert.ok(findings.some((f) => f.identifiers.primary.endsWith('detect-eval-with-expression') && f.location.line === 18));
  assert.ok(findings.every((f) => f.category === 'sast' && f.location.file === 'app.js' && f.evidence));
});

test('XSS and command injection match template literals and skip safe calls', () => {
  const { findings } = scanDir({
    'app.js': `
      res.send('hello');
      res.send(\`<h1>\${req.query.name}</h1>\`);
      execFile('ping', [req.query.host]);
      exec(\`ping \${req.query.host}\`);
      eval('2+2');
      eval(req.body.expression);
      // res.send(req.query.x)
    `,
  });
  const ids = findings.map((f) => `${f.identifiers.primary}@${f.location.line}`);
  assert.ok(ids.some((id) => id.startsWith('javascript.express.security.audit.xss.direct-response-write@')));
  assert.ok(ids.some((id) => id.startsWith('javascript.lang.security.detect-child-process@')));
  assert.ok(ids.some((id) => id.startsWith('javascript.lang.security.detect-eval-with-expression@')));
  assert.equal(findings.filter((f) => f.evidence.includes("res.send('hello')")).length, 0);
  assert.equal(findings.filter((f) => f.evidence.includes('execFile')).length, 0);
  assert.equal(findings.filter((f) => f.evidence.startsWith('//')).length, 0);
});

test('builtin secrets finds the fixture tokens and redacts them', () => {
  const findings = scanBuiltinSecrets(INSECURE);
  assert.ok(findings.some((f) => f.identifiers.primary === 'github-pat' && f.location.file === 'config.js'));
  assert.ok(findings.some((f) => f.identifiers.primary === 'slack-webhook-url'));
  assert.ok(!JSON.stringify(findings).includes('ghp_7Xq2'));
  assert.ok(findings.every((f) => f.category === 'secret' && f.evidence.includes('[REDACTED]')));
});

test('expanded builtin SAST finds XSS, eval, SQL concat and pickle', () => {
  const { findings } = scanDir({
    'web.js': `
      el.innerHTML = name;
      document.write(html);
      eval(userCode);
      db.query('SELECT * FROM users WHERE id=' + req.query.id);
      fs.readFile(req.params.file);
      res.redirect(req.query.next);
      fetch(req.body.url);
    `,
    'app.py': `
      eval(request.args['q'])
      pickle.loads(body)
      cur.execute('SELECT * FROM t WHERE id=' + user_id)
    `,
  });
  const ids = findings.map((f) => f.identifiers.primary);
  assert.ok(ids.some((id) => id.includes('innerhtml')));
  assert.ok(ids.some((id) => id.includes('detect-eval') || id.includes('dangerous-eval')));
  assert.ok(ids.some((id) => id.includes('sql-concat') || id.includes('sql-format')));
  assert.ok(ids.some((id) => id.includes('pickle')));
  assert.ok(ids.some((id) => id.includes('path-traversal')));
  assert.ok(ids.some((id) => id.includes('ssrf')));
});

test('semgrep adapter falls back to builtin rules when the CLI is missing', async () => {
  const r = await runAdapter(createSemgrepAdapter({
    resolveEngine: () => ({ kind: 'builtin', bin: null }),
  }), { path: INSECURE });
  assert.equal(r.status, 'ok', r.error);
  assert.equal(r.version, 'builtin-rules');
  assert.ok(r.findings.some((f) => f.category === 'sast' && /xss|direct-response-write|eval|child-process/.test(f.identifiers.primary)));
});
