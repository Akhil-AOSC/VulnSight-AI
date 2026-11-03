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

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build',
  'venv', '.venv', 'env', '.env', '__pycache__', '.cache',
  '.next', '.nuxt', 'vendor', '.turbo', '.idea', '.vscode',
]);

function loadProject(filePath, opts = {}) {
  const parser = PARSERS.find((p) => p.test(path.basename(filePath)));
  if (!parser) {
    throw new Error(`Unsupported file: ${path.basename(filePath)}. Supported: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, go.sum, requirements*.txt, poetry.lock, Pipfile.lock`);
  }
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
  const { name, dependencies, skipped } = parser.load(filePath, opts);
  return { file: filePath, type: parser.type, ecosystem: parser.ecosystem, name, dependencies, skipped };
}

function findSubdirectoryProjects(baseDir, currentDir, opts, depth = 1, maxDepth = 2) {
  if (depth > maxDepth) return [];
  const found = [];
  let entries = [];
  try {
    entries = fs.readdirSync(currentDir, { withFileTypes: true });
  } catch {
    return [];
  }

  for (const entry of entries) {
    if (!entry.isDirectory() || IGNORE_DIRS.has(entry.name)) continue;
    const subDir = path.join(currentDir, entry.name);
    let subNames = [];
    try {
      subNames = fs.readdirSync(subDir);
    } catch {
      continue;
    }
    const hasSub = (n) => subNames.includes(n);
    const subFiles = [];
    if (hasSub('npm-shrinkwrap.json')) subFiles.push('npm-shrinkwrap.json');
    else if (hasSub('package-lock.json')) subFiles.push('package-lock.json');
    if (hasSub('poetry.lock')) subFiles.push('poetry.lock');
    if (hasSub('Pipfile.lock')) subFiles.push('Pipfile.lock');
    subFiles.push(...subNames.filter((n) => /^requirements.*\.txt$/i.test(n)).sort());

    if (subFiles.length > 0) {
      for (const f of subFiles) {
        try {
          found.push(loadProject(path.join(subDir, f), opts));
        } catch { /* skip unparseable files */ }
      }
    } else {
      found.push(...findSubdirectoryProjects(baseDir, subDir, opts, depth + 1, maxDepth));
    }
  }
  return found;
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
  if (has('npm-shrinkwrap.json')) files.push(path.join(dir, 'npm-shrinkwrap.json'));
  else if (has('package-lock.json')) files.push(path.join(dir, 'package-lock.json'));
  else if (has('yarn.lock')) files.push(path.join(dir, 'yarn.lock'));
  else if (has('pnpm-lock.yaml')) files.push(path.join(dir, 'pnpm-lock.yaml'));
  else if (has('package.json')) {
    warnings.push('Found package.json without a lockfile. Run "npm install --package-lock-only" first.');
  }

  if (has('go.sum')) files.push(path.join(dir, 'go.sum'));
  if (has('poetry.lock')) files.push(path.join(dir, 'poetry.lock'));
  if (has('Pipfile.lock')) files.push(path.join(dir, 'Pipfile.lock'));
  files.push(...names.filter((n) => /^requirements.*\.txt$/i.test(n)).sort().map((f) => path.join(dir, f)));

  const rootProjects = files.map((f) => loadProject(f, opts));
  const subProjects = findSubdirectoryProjects(dir, dir, opts, 1, 2);
  const allProjects = [...rootProjects, ...subProjects];

  if (allProjects.length > 0) {
    return { projects: allProjects, warnings: rootProjects.length ? warnings : [] };
  }

  return { projects: [], warnings };
}

module.exports = { detectProjects, loadProject };
