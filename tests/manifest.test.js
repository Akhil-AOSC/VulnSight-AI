import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { parseManifest } from '../src/manifest/parser.js';

test('Manifest Parser: parses vulnerable fixture with lockfile v3', () => {
  const fixtureDir = path.resolve('test-fixtures/vulnerable-npm-project');
  const manifest = parseManifest(fixtureDir);

  assert.equal(manifest.projectName, 'sample-vulnerable-app');
  assert.equal(manifest.hasLockfile, true);
  assert.equal(manifest.lockfileVersion, 3);
  assert.equal(manifest.directCount, 3);
  assert.equal(manifest.transitiveCount, 1);
  assert.equal(manifest.totalDependencies, 4);

  const lodash = manifest.dependencies.find((d) => d.name === 'lodash');
  assert.ok(lodash);
  assert.equal(lodash.version, '4.17.15');
  assert.equal(lodash.isDirect, true);

  const qs = manifest.dependencies.find((d) => d.name === 'qs');
  assert.ok(qs);
  assert.equal(qs.version, '6.5.2');
  assert.equal(qs.isDirect, false);
});

test('Manifest Parser: parses clean fixture with zero transitive deps', () => {
  const fixtureDir = path.resolve('test-fixtures/clean-npm-project');
  const manifest = parseManifest(fixtureDir);

  assert.equal(manifest.projectName, 'sample-clean-app');
  assert.equal(manifest.directCount, 2);
  assert.equal(manifest.transitiveCount, 0);
  assert.equal(manifest.totalDependencies, 2);
});

test('Manifest Parser: throws error when package.json does not exist', () => {
  assert.throws(() => {
    parseManifest(path.resolve('non-existent-dir-12345'));
  }, /No package.json found/);
});
