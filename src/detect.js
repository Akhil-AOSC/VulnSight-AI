'use strict';

const fs = require('fs');
const path = require('path');
const npm = require('./parsers/npm');
const python = require('./parsers/python');

const PARSERS = [
  { test: (n) => n === 'npm-shrinkwrap.json' || n === 'package-lock.json', type: 'npm', ecosystem: 'npm', load: npm.loadNpmLockfile },
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
    throw new Error(`Unsupported file: ${path.basename(filePath)}. Supported: package-lock.json, npm-shrinkwrap.json, requirements*.txt, poetry.lock, Pipfile.lock`);
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
  if (has('npm-shrinkwrap.json')) files.push('npm-shrinkwrap.json');
  else if (has('package-lock.json')) files.push('package-lock.json');
  else if (has('package.json')) {
    if (has('yarn.lock')) warnings.push('yarn.lock is not supported yet, so the npm dependencies were not scanned.');
    else if (has('pnpm-lock.yaml')) warnings.push('pnpm-lock.yaml is not supported yet, so the npm dependencies were not scanned.');
    else warnings.push('Found package.json without a lockfile. Run "npm install --package-lock-only" first.');
  }

  if (has('poetry.lock')) files.push('poetry.lock');
  if (has('Pipfile.lock')) files.push('Pipfile.lock');
  files.push(...names.filter((n) => /^requirements.*\.txt$/i.test(n)).sort());

  if (files.length > 0) {
    return { projects: files.map((f) => loadProject(path.join(dir, f), opts)), warnings };
  }

  // If no dependency files found in the root, search subdirectories (e.g. monorepos or subfolders)
  const subProjects = findSubdirectoryProjects(dir, dir, opts, 1, 2);
  if (subProjects.length > 0) {
    return { projects: subProjects, warnings: [] };
  }

  return { projects: [], warnings };
}

module.exports = { detectProjects, loadProject };
