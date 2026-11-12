'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mapNucleiResult, nucleiArgs, runNuclei } = require('../src/adapters/dast/nuclei');
const { normalizeScope } = require('../src/adapters/dast/scope');

test('mapNucleiResult maps severity, CWE, CVE and redacts evidence', () => {
  const finding = mapNucleiResult({
    'template-id': 'exposed-env',
    'matched-at': 'https://example.com/.env',
    'extracted-results': ['AWS_SECRET=supersecretvalue'],
    info: {
      name: 'Exposed .env',
      severity: 'info',
      classification: { 'cwe-id': ['CWE-200'], 'cve-id': ['CVE-2024-0001'] },
    },
  });
  assert.equal(finding.severity, 'low');
  assert.equal(finding.scanner.ruleId, 'exposed-env');
  assert.deepEqual(finding.identifiers.cwe, ['CWE-200']);
  assert.ok(finding.identifiers.aliases.includes('CVE-2024-0001'));
  assert.equal(finding.location.url, 'https://example.com/.env');
  assert.match(finding.evidence, /\[redacted\]/);
  assert.ok(!finding.evidence.includes('supersecretvalue'));
});

test('nuclei argv includes rate-limit, dos etags and no-interactsh', () => {
  const args = nucleiArgs({ listFile: '/tmp/urls.txt', proxy: 'http://127.0.0.1:9', mode: 'safe', maxRps: 2 });
  assert.ok(args.includes('-rate-limit'));
  assert.ok(args.includes('-etags'));
  assert.ok(args.includes('dos,fuzz,intrusive,brute-force,oast,rce'));
  assert.ok(args.includes('-no-interactsh'));
  assert.ok(args.includes('-lna'));
  assert.ok(args.includes('-proxy'));
});

test('safe mode drops intrusive Nuclei matches even if tags leaked through', () => {
  const { isIntrusiveMatch } = require('../src/adapters/dast/nuclei');
  assert.equal(isIntrusiveMatch({ info: { tags: ['cve'] }, request: 'GET / HTTP/1.1' }), false);
  assert.equal(isIntrusiveMatch({ info: { tags: ['rce'] }, request: 'GET / HTTP/1.1' }), true);
  assert.equal(isIntrusiveMatch({ info: { tags: ['misc'] }, request: 'POST /login HTTP/1.1' }), true);
});

test('runNuclei refuses unverified and out-of-scope URLs', async () => {
  await assert.rejects(
    () => runNuclei(['https://example.com/'], { verified: false, scope: normalizeScope('example.com') }),
    /policy-authorized|verified/
  );
  const listed = [];
  const result = await runNuclei(
    ['https://victim.org/', 'https://example.com/app'],
    {
      verified: true,
      scope: normalizeScope('example.com'),
      exec: async (cmd, args) => {
        const fs = require('node:fs');
        const listFile = args[args.indexOf('-list') + 1];
        listed.push(fs.readFileSync(listFile, 'utf8'));
        return { stdout: '', stderr: '', code: 0 };
      },
    }
  );
  assert.equal(result.findings.length, 0);
  assert.equal(listed.length, 1);
  assert.match(listed[0], /example\.com/);
  assert.doesNotMatch(listed[0], /victim\.org/);
});
