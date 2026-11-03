'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { parseSemgrep, createSemgrepAdapter, DEFAULT_CONFIG } = require('../src/adapters/semgrep');
const { parseEslintJson } = require('../src/adapters/eslint-sast');
const { parseGitleaks, createGitleaksAdapter } = require('../src/adapters/gitleaks');
const { scanTarget } = require('../src/adapters');

const ROOT = path.join(__dirname, '..', 'examples', 'npm-app');

const SEMGREP_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: 'javascript.express.security.audit.xss.direct-response-write',
      path: 'src/app.js',
      start: { line: 12, col: 3 },
      end: { line: 12, col: 40 },
      extra: {
        message: 'User input flows into res.send(), which allows XSS.\nUse a template engine.',
        severity: 'ERROR',
        lines: 'res.send(req.query.name)',
        metadata: { cwe: ['CWE-79: Improper Neutralization of Input'], references: ['https://owasp.org/xss'] },
        fix: 'res.send(escape(req.query.name))',
      },
    },
    { check_id: 'rules.info', path: 'a.js', start: { line: 1 }, end: { line: 1 }, extra: { message: 'm', severity: 'INFO', lines: 'requires login', metadata: {} } },
  ],
  errors: [{ message: 'Syntax error in bad.js' }],
});

const SECRET = 'AKIAIOSFODNN7EXAMPLE';
const GITLEAKS_RAW = JSON.stringify([{
  RuleID: 'aws-access-token',
  Description: 'Identified an AWS Access Token',
  File: 'config/.env',
  StartLine: 3,
  EndLine: 3,
  Match: `AWS_KEY=${SECRET}`,
  Secret: SECRET,
}]);

test('parseSemgrep maps severity, CWE, location, fix and hides login placeholder', () => {
  const { findings, errors } = parseSemgrep(SEMGREP_OUTPUT, ROOT, '1.80.0');
  assert.equal(findings.length, 2);
  const [xss, info] = findings;
  assert.equal(xss.category, 'sast');
  assert.equal(xss.severity, 'high');
  assert.deepEqual(xss.identifiers.cwe, ['CWE-79']);
  assert.equal(xss.title, 'User input flows into res.send(), which allows XSS.');
  assert.deepEqual([xss.location.file, xss.location.line], ['src/app.js', 12]);
  assert.equal(xss.remediation.advice, 'res.send(escape(req.query.name))');
  assert.equal(xss.evidence, 'res.send(req.query.name)');
  assert.equal(xss.url, 'https://owasp.org/xss');
  assert.equal(info.severity, 'low');
  assert.equal(info.evidence, null);
  assert.deepEqual(errors, ['Syntax error in bad.js']);
  assert.deepEqual(parseSemgrep('{}', ROOT, '1').findings, []);
});

test('parseGitleaks never lets the raw secret into a finding', () => {
  const [f] = parseGitleaks(GITLEAKS_RAW, ROOT, '8.18.0');
  assert.equal(f.category, 'secret');
  assert.equal(f.severity, 'high');
  assert.deepEqual(f.identifiers.cwe, ['CWE-798']);
  assert.deepEqual([f.location.file, f.location.line], ['config/.env', 3]);
  assert.equal(f.evidence, 'AWS_KEY=[REDACTED]');
  assert.ok(!JSON.stringify(f).includes(SECRET));

  // Also safe when gitleaks already redacted it.
  const [g] = parseGitleaks(JSON.stringify([{ RuleID: 'r', File: 'a', Match: 'x=REDACTED', Secret: 'REDACTED' }]), ROOT, '8');
  assert.equal(g.evidence, 'x=REDACTED');

  assert.deepEqual(parseGitleaks('', ROOT, '8'), []);
  assert.deepEqual(parseGitleaks('null', ROOT, '8'), []);
  assert.deepEqual(parseGitleaks('[]', ROOT, '8'), []);
});

function fakeExec(outputs) {
  const calls = [];
  const exec = async (command, args, opts) => {
    calls.push({ command, args, cwd: opts && opts.cwd });
    if (args[0] === '--version' || args[0] === 'version') return { stdout: outputs.version, stderr: '', code: 0 };
    // Gitleaks writes its report to the path given by --report-path (not to stdout).
    const at = args.indexOf('--report-path');
    if (at !== -1) {
      fs.writeFileSync(args[at + 1], outputs.scan);
      return { stdout: '', stderr: '', code: 0 };
    }
    return { stdout: outputs.scan, stderr: '', code: 0 };
  };
  return { exec, calls };
}

test('adapters build safe command lines and run inside the target directory', async () => {
  const sem = fakeExec({ version: '1.80.0\n', scan: SEMGREP_OUTPUT });
  const gl = fakeExec({ version: 'v8.18.0\n', scan: GITLEAKS_RAW });
  const report = await scanTarget({ path: ROOT }, [
    createSemgrepAdapter({ exec: sem.exec }),
    createGitleaksAdapter({ exec: gl.exec }),
  ]);

  assert.deepEqual(report.scanners.map((s) => [s.scanner, s.status, s.version, s.findingCount]),
    [['semgrep', 'ok', '1.80.0', 2], ['gitleaks', 'ok', '8.18.0', 1]]);
  assert.deepEqual(report.findings.map((f) => f.category).sort(), ['sast', 'sast', 'secret']);

  const semArgs = sem.calls.find((c) => c.args[0] === 'scan');
  assert.ok(semArgs.args.includes('--metrics=off'));
  assert.equal(semArgs.cwd, ROOT);
  const glArgs = gl.calls.find((c) => c.args[0] === 'detect');
  assert.ok(glArgs.args.includes('--redact'));
  assert.ok(glArgs.args.includes('--no-git'));
  const reportPath = glArgs.args[glArgs.args.indexOf('--report-path') + 1];
  assert.notEqual(reportPath, '-', 'gitleaks does not support "-" for stdout');
  assert.ok(!path.resolve(reportPath).startsWith(path.resolve(ROOT)), 'report is written outside the scanned tree');
  assert.equal(fs.existsSync(reportPath), false, 'temp report is deleted');
  assert.equal(report.raw.gitleaks, null);
  assert.ok(!JSON.stringify(report).includes(SECRET));
});

test('a missing scanner binary becomes an error status, not a crash', async () => {
  const report = await scanTarget({ path: ROOT }, [createSemgrepAdapter({ command: 'definitely-not-installed-xyz' })]);
  assert.equal(report.scanners[0].status, 'error');
  assert.match(report.scanners[0].error, /not installed/);
  assert.deepEqual(report.findings, []);
});

test('a gitleaks run that produces no report fails loudly instead of looking clean', async () => {
  const exec = async (cmd, args) => (args[0] === 'version' ? { stdout: '8.21.2' } : { stdout: '' });
  const report = await scanTarget({ path: ROOT }, [createGitleaksAdapter({ exec })]);
  assert.equal(report.scanners[0].status, 'error');
  assert.match(report.scanners[0].error, /did not produce a report/);
});

test('SAST prefers Opengrep and uses the local rule pack', async () => {
  const sem = fakeExec({ version: '1.2.3\n', scan: SEMGREP_OUTPUT });
  const report = await scanTarget({ path: ROOT }, [
    createSemgrepAdapter({
      exec: sem.exec,
      fallback: true,
      ensure: async () => 'opengrep',
    }),
  ]);
  assert.equal(report.scanners[0].status, 'ok');
  assert.equal(report.scanners[0].version, 'opengrep 1.2.3');
  assert.equal(report.scanners[0].findingCount, 2);
  const scan = sem.calls.find((c) => c.args[0] === 'scan');
  assert.equal(scan.command, 'opengrep');
  assert.equal(scan.cwd, ROOT);
  assert.ok(scan.args.includes(DEFAULT_CONFIG));
  assert.ok(!scan.args.includes('--metrics=off'));
  assert.ok(fs.existsSync(DEFAULT_CONFIG));
});

test('SAST uses ESLint JSON when Opengrep and Semgrep are absent', async () => {
  const eslintOut = JSON.stringify([{
    filePath: path.join(ROOT, 'index.js'),
    messages: [{
      ruleId: 'vulnsight/xss-res-send', severity: 2, message: 'User input written into the HTTP response (XSS)',
      line: 4, endLine: 4, source: 'res.send(req.query.name)',
    }],
  }]);
  const exec = async (command, args) => {
    if (args[0] === '--version') return { stdout: 'v9.15.0\n', stderr: '', code: 0 };
    return { stdout: eslintOut, stderr: '', code: 1 };
  };
  const report = await scanTarget({ path: ROOT }, [
    createSemgrepAdapter({
      exec,
      fallback: true,
      resolveEngine: () => ({ kind: 'eslint', bin: 'eslint' }),
    }),
  ]);
  assert.equal(report.scanners[0].status, 'ok', report.scanners[0].error);
  assert.match(report.scanners[0].version, /eslint/);
  assert.ok(report.findings.some((f) => f.identifiers.primary === 'vulnsight/xss-res-send' && f.location.line === 4));
});

test('parseEslintJson maps rule, line and CWE', () => {
  const findings = parseEslintJson(JSON.stringify([{
    filePath: path.join(ROOT, 'app.js'),
    messages: [
      { ruleId: 'vulnsight/detect-eval-with-expression', severity: 2, message: 'eval', line: 18, source: 'eval(req.body.expression)' },
      { ruleId: null, severity: 2, message: 'ignored parse error', line: 1 },
    ],
  }]), ROOT, 'eslint 9');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
  assert.deepEqual(findings[0].identifiers.cwe, ['CWE-95']);
  assert.equal(findings[0].location.line, 18);
});

test('semgrep secret-detection findings never carry evidence', () => {
  const out = JSON.stringify({ results: [{
    check_id: 'generic.secrets.security.detected-github-token.detected-github-token', path: 'config.js',
    start: { line: 3 }, end: { line: 3 },
    extra: { message: 'GitHub Token detected', severity: 'ERROR', lines: "token: 'ghp_REALLOOKINGSECRETVALUE0123456789abcd'", metadata: {} },
  }, {
    check_id: 'rules.other', path: 'a.js', start: { line: 1 }, end: { line: 1 },
    extra: { message: 'm', severity: 'WARNING', lines: 'x = 1', metadata: { category: 'secrets' } },
  }] });
  const { findings } = parseSemgrep(out, ROOT, '1');
  assert.deepEqual(findings.map((f) => f.evidence), [null, null]);
  assert.ok(!JSON.stringify(findings).includes('ghp_REAL'));
});
