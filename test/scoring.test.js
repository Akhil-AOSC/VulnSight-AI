'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { cvss3Score, severityOf, levelFromScore } = require('../src/severity');
const { compareVersions } = require('../src/versions');

test('CVSS v3 base scores match the official calculator', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'), 3.1);
  assert.equal(cvss3Score('CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N'), 6.4);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('not a vector'), null);
});

test('severityOf prefers the advisory rating and falls back to CVSS', () => {
  assert.equal(severityOf({ database_specific: { severity: 'MODERATE' } }).level, 'medium');
  assert.equal(severityOf({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }).level, 'critical');
  assert.equal(severityOf({}).level, 'unknown');
  assert.equal(levelFromScore(7.5), 'high');
});

test('compareVersions orders semver and PEP 440 versions', () => {
  const sorted = ['1.10.0', '1.2.0', '1.2.0-beta.1', '1.2.0rc1', '1.2.0.post1', '1.2.0.dev1', '0.9']
    .sort(compareVersions);
  assert.deepEqual(sorted, ['0.9', '1.2.0.dev1', '1.2.0-beta.1', '1.2.0rc1', '1.2.0', '1.2.0.post1', '1.10.0']);
  assert.equal(compareVersions('1.2', '1.2.0'), 0);
  assert.equal(compareVersions('1.2.0.dev1', '1.2.0a1'), -1);
  assert.equal(compareVersions('1.2.0rc1', '1.2.0'), -1);
  assert.equal(compareVersions('1.2.0', '1.2.0.post1'), -1);
  assert.equal(compareVersions('4.17.21', '4.17.5'), 1);
  assert.equal(compareVersions('v2.0.0', '2.0.0'), 0);
});
