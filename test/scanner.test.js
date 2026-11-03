'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { scanProjects, findFixedVersion } = require('../src/scanner');
const { runTest, EXIT } = require('../src/cli');

const VULNS = {
  'GHSA-aaaa': {
    id: 'GHSA-aaaa',
    aliases: ['CVE-2020-0001'],
    summary: 'Prototype pollution',
    database_specific: { severity: 'HIGH' },
    affected: [{
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }],
    }],
  },
  'GHSA-bbbb': {
    id: 'GHSA-bbbb',
    summary: 'Command injection',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [{
      package: { ecosystem: 'npm', name: 'lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    }],
  },
  // Same issue as GHSA-aaaa under another ID: must be merged, not reported twice.
  'CVE-2020-0001': { id: 'CVE-2020-0001', aliases: ['GHSA-aaaa'], affected: [] },
  'GHSA-wthd': { id: 'GHSA-wthd', withdrawn: '2021-01-01T00:00:00Z', affected: [] },
};

function fakeClient() {
  return {
    async queryBatch(queries) {
      return queries.map((q) => (q.package.name === 'lodash' ? Object.keys(VULNS) : []));
    },
    async getVulns(ids) {
      return new Map(ids.map((id) => [id, VULNS[id]]));
    },
  };
}

const project = {
  file: '/proj/package-lock.json',
  type: 'npm',
  ecosystem: 'npm',
  name: 'app@1.0.0',
  skipped: [],
  dependencies: [
    { name: 'lodash', version: '4.17.15', ecosystem: 'npm', direct: true, paths: [['app@1.0.0', 'lodash@4.17.15']] },
    { name: 'left-pad', version: '1.3.0', ecosystem: 'npm', direct: true, paths: [['app@1.0.0', 'left-pad@1.3.0']] },
  ],
};

test('scanProjects merges aliases, drops withdrawn advisories and finds fixes', async () => {
  const [result] = await scanProjects([project], { client: fakeClient() });
  const ids = result.issues.map((i) => i.id).sort();
  assert.deepEqual(ids, ['GHSA-aaaa', 'GHSA-bbbb']);

  const pollution = result.issues.find((i) => i.id === 'GHSA-aaaa');
  assert.deepEqual(pollution.aliases, ['CVE-2020-0001']);
  assert.equal(pollution.severity, 'high');
  assert.equal(pollution.fixedIn, '4.17.19');

  const injection = result.issues.find((i) => i.id === 'GHSA-bbbb');
  assert.equal(injection.severity, 'critical');
  assert.equal(injection.cvssScore, 9.8);
});

test('findFixedVersion ignores fixes at or below the installed version', () => {
  const vuln = {
    affected: [{
      package: { ecosystem: 'PyPI', name: 'Django' },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.2.28' }, { introduced: '3.0' }, { fixed: '3.2.14' }] }],
    }],
  };
  assert.equal(findFixedVersion(vuln, { ecosystem: 'PyPI', name: 'django', version: '3.2.0' }), '3.2.14');
  assert.equal(findFixedVersion(vuln, { ecosystem: 'PyPI', name: 'django', version: '4.0' }), null);
});

test('runTest applies the severity threshold and sets the exit code', async () => {
  const output = [];
  const scan = (projects) => scanProjects(projects, { client: fakeClient() });
  const target = path.join(__dirname, '..', 'examples', 'npm-app');

  const code = await runTest(
    { target, threshold: 'critical', json: true, color: false },
    { scan, stdout: (s) => output.push(s), stderr: () => {} },
  );
  assert.equal(code, EXIT.ISSUES);
  const report = JSON.parse(output[0]);
  assert.deepEqual(report.projects[0].vulnerabilities.map((v) => v.id), ['GHSA-bbbb']);
  assert.equal(report.projects[0].vulnerabilities[0].remediation, 'Upgrade lodash to 4.17.21');
});
