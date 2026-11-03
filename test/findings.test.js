'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { createFinding, dedupeFindings, fromScaIssue } = require('../src/findings');
const { runAdapter, execTool } = require('../src/adapters/runner');
const { createScaAdapter } = require('../src/adapters/sca');
const { scanTarget } = require('../src/adapters');

const base = {
  category: 'sca',
  scanner: { name: 'osv', ruleId: 'GHSA-aaaa' },
  title: 'Prototype pollution',
  severity: 'high',
  identifiers: { primary: 'GHSA-aaaa', aliases: ['CVE-2020-0001'] },
  location: { file: 'package-lock.json', package: 'lodash', version: '4.17.15', ecosystem: 'npm' },
};

test('createFinding fills defaults, fingerprints stably and validates', () => {
  const a = createFinding(base);
  const b = createFinding({ ...base, title: 'Different wording' });
  assert.equal(a.id, b.id);
  assert.equal(a.status, 'open');
  assert.equal(a.aiAnalysis, null);
  assert.notEqual(a.id, createFinding({ ...base, location: { ...base.location, version: '4.17.16' } }).id);
  assert.throws(() => createFinding({ ...base, category: 'nope' }), /category/);
  assert.throws(() => createFinding({ ...base, severity: 'urgent' }), /severity/);
  assert.throws(() => createFinding({ ...base, title: '' }), /title/);
});

test('fromScaIssue maps a scanner issue', () => {
  const f = fromScaIssue({
    id: 'GHSA-aaaa', aliases: ['CVE-2020-0001'], title: 't', severity: 'critical', cvssScore: 9.8,
    package: 'lodash', version: '4.17.15', ecosystem: 'npm', fixedIn: '4.17.19', url: 'https://osv.dev/x',
    direct: true, paths: [['app@1', 'lodash@4.17.15']],
  }, { file: 'package-lock.json' });
  assert.equal(f.category, 'sca');
  assert.equal(f.remediation.fixedIn, '4.17.19');
  assert.equal(f.location.direct, true);
  assert.equal(f.cvssScore, 9.8);
});

test('dedupeFindings merges alias overlap, keeps highest severity and all sources', () => {
  const a = createFinding(base);
  const b = createFinding({
    ...base,
    scanner: { name: 'trivy', ruleId: 'CVE-2020-0001' },
    severity: 'critical',
    cvssScore: 9.1,
    identifiers: { primary: 'CVE-2020-0001', aliases: ['GHSA-aaaa'] },
    remediation: { fixedIn: '4.17.19' },
  });
  const other = createFinding({ ...base, identifiers: { primary: 'GHSA-zzzz', aliases: [] }, location: { ...base.location, package: 'qs' } });

  const out = dedupeFindings([a, b, other]);
  assert.equal(out.length, 2);
  assert.equal(out[0].severity, 'critical');
  assert.equal(out[0].cvssScore, 9.1);
  assert.equal(out[0].remediation.fixedIn, '4.17.19');
  assert.deepEqual(out[0].sources.map((s) => s.name), ['osv', 'trivy']);
  assert.equal(a.severity, 'high', 'input is not mutated');
});

test('runAdapter reports ok, skipped, error and timeout without throwing', async () => {
  const mk = (over) => ({ name: 'x', category: 'sca', version: async () => '1', supports: async () => true, run: async () => ({ findings: [] }), ...over });
  assert.equal((await runAdapter(mk(), {})).status, 'ok');
  assert.equal((await runAdapter(mk({ supports: async () => false }), {})).status, 'skipped');
  const failed = await runAdapter(mk({ run: async () => { throw new Error('boom'); } }), {});
  assert.deepEqual([failed.status, failed.error], ['error', 'boom']);
  const slow = await runAdapter(mk({ run: () => new Promise(() => {}) }), {}, { timeoutMs: 20 });
  assert.equal(slow.status, 'timeout');
});

test('execTool runs without a shell and reports missing tools', async () => {
  const out = await execTool(process.execPath, ['-e', 'console.log("hi")']);
  assert.equal(out.stdout.trim(), 'hi');
  await assert.rejects(execTool('definitely-not-a-real-tool-xyz', []), /not installed/);
  await assert.rejects(execTool(process.execPath, ['-e', 'process.exit(3)']), /code 3/);
  await assert.rejects(execTool(process.execPath, ['-e', 'console.log("x".repeat(1000))'], { maxBytes: 100 }), /exceeded/);
});

test('scanTarget runs the SCA adapter end to end and one failing scanner does not break the rest', async () => {
  const client = {
    async queryBatch(queries) { return queries.map((q) => (q.package.name === 'lodash' ? ['GHSA-aaaa'] : [])); },
    async getVulns(ids) {
      return new Map(ids.map((id) => [id, {
        id, summary: 'Prototype pollution', database_specific: { severity: 'HIGH' },
        affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '99.0.0' }] }] }],
      }]));
    },
  };
  const broken = { name: 'broken', category: 'sast', version: async () => '0', supports: async () => true, run: async () => { throw new Error('not installed'); } };
  const target = { path: path.join(__dirname, '..', 'examples', 'npm-app') };

  const report = await scanTarget(target, [createScaAdapter({ client }), broken]);
  assert.deepEqual(report.scanners.map((s) => [s.scanner, s.status]), [['osv', 'ok'], ['broken', 'error']]);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].identifiers.primary, 'GHSA-aaaa');
  assert.equal(report.findings[0].remediation.fixedIn, '99.0.0');
});
