'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseNpmLock } = require('../src/parsers/npm');
const python = require('../src/parsers/python');
const { detectProjects } = require('../src/detect');

const lockV3 = {
  name: 'app',
  version: '1.0.0',
  lockfileVersion: 3,
  packages: {
    '': { name: 'app', version: '1.0.0', dependencies: { a: '^1.0.0', b: '^2.0.0' }, devDependencies: { d: '1.0.0' } },
    'node_modules/a': { version: '1.0.0', dependencies: { c: '^1.0.0' } },
    'node_modules/a/node_modules/c': { version: '1.5.0' },
    'node_modules/b': { version: '2.0.0', dependencies: { c: '^3.0.0' } },
    'node_modules/c': { version: '3.1.0' },
    'node_modules/d': { version: '1.0.0', dev: true },
    'node_modules/linked': { link: true, resolved: 'packages/linked' },
  },
};

test('npm v3 lockfile resolves nested and hoisted packages with paths', () => {
  const { name, dependencies } = parseNpmLock(lockV3);
  assert.equal(name, 'app@1.0.0');
  const byKey = Object.fromEntries(dependencies.map((d) => [`${d.name}@${d.version}`, d]));

  assert.deepEqual(Object.keys(byKey).sort(), ['a@1.0.0', 'b@2.0.0', 'c@1.5.0', 'c@3.1.0']);
  assert.equal(byKey['a@1.0.0'].direct, true);
  assert.equal(byKey['c@1.5.0'].direct, false);
  assert.deepEqual(byKey['c@1.5.0'].paths, [['app@1.0.0', 'a@1.0.0', 'c@1.5.0']]);
  assert.deepEqual(byKey['c@3.1.0'].paths, [['app@1.0.0', 'b@2.0.0', 'c@3.1.0']]);
});

test('npm dev dependencies are only included with dev: true', () => {
  const names = (opts) => parseNpmLock(lockV3, opts).dependencies.map((d) => d.name);
  assert.ok(!names().includes('d'));
  assert.ok(names({ dev: true }).includes('d'));
});

test('npm v1 lockfile walks nested dependencies and skips non-registry versions', () => {
  const { dependencies } = parseNpmLock({
    name: 'old', version: '0.1.0', lockfileVersion: 1,
    dependencies: {
      x: { version: '1.0.0', dependencies: { y: { version: '2.0.0' } } },
      z: { version: 'github:user/z#abc' },
      t: { version: '1.0.0', dev: true },
    },
  });
  assert.deepEqual(dependencies.map((d) => `${d.name}@${d.version}`), ['x@1.0.0', 'y@2.0.0']);
  assert.deepEqual(dependencies[1].paths, [['old@0.1.0', 'x@1.0.0', 'y@2.0.0']]);
});

test('requirements.txt handles comments, extras, markers, hashes and unpinned specs', () => {
  const { requirements, includes, unpinned } = python.parseRequirementsText([
    '# comment',
    'Django==3.2.0  # inline comment',
    'requests[security]==2.19.0 ; python_version >= "3.6"',
    'urllib3==1.24.1 \\',
    '    --hash=sha256:abc',
    'flask>=2.0',
    '-r dev.txt',
    '--index-url https://example.org/simple',
    'git+https://github.com/x/y.git',
  ].join('\n'));

  assert.deepEqual(requirements, [
    { name: 'Django', version: '3.2.0' },
    { name: 'requests', version: '2.19.0' },
    { name: 'urllib3', version: '1.24.1' },
  ]);
  assert.deepEqual(includes, ['dev.txt']);
  assert.deepEqual(unpinned, ['flask', 'git+https://github.com/x/y.git']);
});

test('requirements.txt follows -r includes and normalises names', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-'));
  fs.writeFileSync(path.join(dir, 'requirements.txt'), 'Py_YAML==5.3\n-r base.txt\n');
  fs.writeFileSync(path.join(dir, 'base.txt'), 'requests==2.19.0\n-r requirements.txt\n');
  const { dependencies } = python.loadRequirements(path.join(dir, 'requirements.txt'));
  assert.deepEqual(dependencies.map((d) => `${d.name}@${d.version}`), ['py-yaml@5.3', 'requests@2.19.0']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('poetry.lock and Pipfile.lock are parsed', () => {
  const poetry = python.parsePoetryLock([
    '[[package]]', 'name = "Django"', 'version = "3.2.0"', 'category = "main"', '',
    '[package.dependencies]', 'sqlparse = ">=0.2.2"', '',
    '[[package]]', 'name = "pytest"', 'version = "6.0.0"', 'category = "dev"', '',
    '[metadata]', 'lock-version = "1.1"',
  ].join('\n'));
  assert.deepEqual(poetry.dependencies.map((d) => `${d.name}@${d.version}`), ['django@3.2.0']);

  const pipenv = python.parsePipfileLock({
    default: { requests: { version: '==2.19.0' }, mylib: { git: 'https://x' } },
    develop: { pytest: { version: '==6.0.0' } },
  }, { dev: true });
  assert.deepEqual(pipenv.dependencies.map((d) => `${d.name}@${d.version}`), ['requests@2.19.0', 'pytest@6.0.0']);
  assert.deepEqual(pipenv.skipped, ['mylib']);
});

test('detectProjects finds the example projects', () => {
  const npmApp = detectProjects(path.join(__dirname, '..', 'examples', 'npm-app'));
  assert.equal(npmApp.projects.length, 1);
  assert.equal(npmApp.projects[0].type, 'npm');

  const pyApp = detectProjects(path.join(__dirname, '..', 'examples', 'python-app'));
  assert.equal(pyApp.projects[0].type, 'pip');
  assert.deepEqual(pyApp.projects[0].skipped, ['flask']);
});
