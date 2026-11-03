'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { findPackageUsages, attachUsages, isLocalDir } = require('../src/code-context');
const { createFinding } = require('../src/findings');
const { describeFinding } = require('../src/ai/assistant');

test('findPackageUsages locates require/import sites and skips node_modules', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-ctx-'));
  try {
    fs.mkdirSync(path.join(root, 'src'));
    fs.mkdirSync(path.join(root, 'node_modules', 'lodash'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src', 'app.js'), "const _ = require('lodash');\nconst x = 1;\n");
    fs.writeFileSync(path.join(root, 'node_modules', 'lodash', 'index.js'), "module.exports = {};\nrequire('lodash');\n");
    const hits = findPackageUsages(root, 'lodash');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].file, 'src/app.js');
    assert.equal(hits[0].line, 1);
    assert.match(hits[0].snippet, /require\('lodash'\)/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('attachUsages adds usage sites onto SCA findings without changing fingerprints', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-ctx-'));
  try {
    fs.writeFileSync(path.join(root, 'main.js'), "import minimist from 'minimist';\n");
    const finding = createFinding({
      category: 'sca',
      scanner: { name: 'osv', ruleId: 'GHSA-x' },
      title: 'Prototype pollution',
      severity: 'high',
      identifiers: { primary: 'GHSA-x' },
      location: { file: 'package-lock.json', package: 'minimist', version: '1.2.0', ecosystem: 'npm' },
    });
    const before = finding.id;
    attachUsages([finding], root);
    assert.equal(finding.id, before);
    assert.equal(finding.location.usages[0].file, 'main.js');
    assert.match(finding.evidence, /main\.js:1/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('describeFinding always lists usage files and only sends snippets with sendCode', () => {
  const finding = createFinding({
    category: 'sca',
    scanner: { name: 'osv', ruleId: 'GHSA-x' },
    title: 'Prototype pollution',
    severity: 'high',
    identifiers: { primary: 'GHSA-x' },
    location: {
      file: 'package-lock.json',
      package: 'minimist',
      version: '1.2.0',
      ecosystem: 'npm',
      usages: [{ file: 'src/app.js', line: 4, snippet: "const args = minimist(process.argv)" }],
    },
  });
  const metaOnly = describeFinding(finding, { consent: { aiEnabled: true } });
  assert.match(metaOnly, /src\/app\.js:4/);
  assert.equal(metaOnly.includes('minimist(process.argv)'), false);

  const withCode = describeFinding(finding, { consent: { aiEnabled: true, sendCode: true } });
  assert.match(withCode, /minimist\(process\.argv\)/);
});

test('isLocalDir rejects git urls', () => {
  assert.equal(isLocalDir('https://github.com/acme/app.git'), false);
  assert.equal(isLocalDir('git@github.com:acme/app.git'), false);
  assert.equal(isLocalDir(__dirname), true);
});
