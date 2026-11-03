'use strict';

const fs = require('fs');
const path = require('path');
const npm = require('./parsers/npm');
const python = require('./parsers/python');
const jsLock = require('./parsers/js-lock');
const go = require('./parsers/go');

const PARSERS = [
  { test: (n) => n === 'npm-shrinkwrap.json' || n === 'package-lock.json', type: 'npm', ecosystem: 'npm', load: npm.loadNpmLockfile },
  { test: (n) => n === 'yarn.lock', type: 'yarn', ecosystem: 'npm', load: jsLock.loadYarnLock },
  { test: (n) => n === 'pnpm-lock.yaml', type: 'pnpm', ecosystem: 'npm', load: jsLock.loadPnpmLock },
  { test: (n) => n === 'go.sum', type: 'go', ecosystem: 'Go', load: go.loadGoSum },
  { test: (n) => n === 'poetry.lock', type: 'poetry', ecosystem: 'PyPI', load: python.loadPoetryLock },
  { test: (n) => n === 'Pipfile.lock', type: 'pipenv', ecosystem: 'PyPI', load: python.loadPipfileLock },
  { test: (n) => /^requirements.*\.txt$/i.test(n), type: 'pip', ecosystem: 'PyPI', load: python.loadRequirements },
];

function loadProject(filePath, opts = {}) {
  const parser = PARSERS.find((p) => p.test(path.basename(filePath)));
  if (!parser) {
    throw new Error(`Unsupported file: ${path.basename(filePath)}. Supported: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, go.sum, requirements*.txt, poetry.lock, Pipfile.lock`);
  }
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
  const { name, dependencies, skipped } = parser.load(filePath, opts);
  return { file: filePath, type: parser.type, ecosystem: parser.ecosystem, name, dependencies, skipped };
}

function detectProjects(dir, opts = {}) {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    throw new Error(`Not a directory: ${dir}`);
  }
  const names = fs.readdirSync(dir);
  const has = (n) => names.includes(n);
  const files = [];
  const warnings = [];

  // npm prefers the shrinkwrap when both exist.
  if (has('npm-shrinkwrap.json')) files.push('npm-shrinkwrap.json');
  else if (has('package-lock.json')) files.push('package-lock.json');
  else if (has('yarn.lock')) files.push('yarn.lock');
  else if (has('pnpm-lock.yaml')) files.push('pnpm-lock.yaml');
  else if (has('package.json')) {
    warnings.push('Found package.json without a lockfile. Run "npm install --package-lock-only" first.');
  }

  if (has('go.sum')) files.push('go.sum');
  if (has('poetry.lock')) files.push('poetry.lock');
  if (has('Pipfile.lock')) files.push('Pipfile.lock');
  files.push(...names.filter((n) => /^requirements.*\.txt$/i.test(n)).sort());

  return { projects: files.map((f) => loadProject(path.join(dir, f), opts)), warnings };
}

module.exports = { detectProjects, loadProject };
