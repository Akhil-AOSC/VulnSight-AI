'use strict';

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'vendor', 'coverage',
  '.vulnsight-data', '.next', '__pycache__', 'out', 'tmp',
]);
const SOURCE_EXTS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.go']);
const MAX_FILES = 400;
const MAX_FILE_BYTES = 200000;
const MAX_HITS = 5;
const MAX_SNIPPET = 200;

function walkSourceFiles(root, acc = [], state = { files: 0 }) {
  if (state.files >= MAX_FILES) return acc;
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const entry of entries) {
    if (state.files >= MAX_FILES) break;
    if (entry.name.startsWith('.') && entry.name !== '.') continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walkSourceFiles(full, acc, state);
    } else if (entry.isFile() && SOURCE_EXTS.has(path.extname(entry.name))) {
      state.files += 1;
      acc.push(full);
    }
  }
  return acc;
}

function usagePattern(packageName) {
  const esc = String(packageName).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    `(?:require\\(\\s*['"]${esc}(?:/[^'"]*)?['"]|from\\s+['"]${esc}(?:/[^'"]*)?['"]|import\\s+['"]${esc}(?:/[^'"]*)?['"]|\\b(?:import|from)\\s+${esc}\\b)`,
    'i',
  );
}

function findPackageUsages(root, packageName, { maxHits = MAX_HITS } = {}) {
  if (!root || !packageName) return [];
  let files;
  try {
    if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) return [];
    files = walkSourceFiles(root);
  } catch {
    return [];
  }
  const re = usagePattern(packageName);
  const hits = [];
  for (const file of files) {
    let text;
    try {
      if (fs.statSync(file).size > MAX_FILE_BYTES) continue;
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      if (!re.test(lines[i])) continue;
      hits.push({
        file: path.relative(root, file).split(path.sep).join('/'),
        line: i + 1,
        snippet: lines[i].trim().slice(0, MAX_SNIPPET),
      });
      if (hits.length >= maxHits) return hits;
    }
  }
  return hits;
}

function attachUsages(findings, root) {
  if (!root || !Array.isArray(findings)) return findings;
  const cache = new Map();
  for (const finding of findings) {
    const pkg = finding && finding.location && finding.location.package;
    if (!pkg || finding.category !== 'sca') continue;
    if (!cache.has(pkg)) cache.set(pkg, findPackageUsages(root, pkg));
    const usages = cache.get(pkg);
    if (!usages.length) continue;
    finding.location.usages = usages;
    if (!finding.evidence) {
      finding.evidence = usages.map((u) => `${u.file}:${u.line}: ${u.snippet}`).join('\n');
    }
  }
  return findings;
}

function isLocalDir(value) {
  if (!value || typeof value !== 'string') return false;
  if (/^(https?:|git@|ssh:)/i.test(value)) return false;
  try {
    const resolved = path.resolve(value);
    return fs.existsSync(resolved) && fs.statSync(resolved).isDirectory();
  } catch {
    return false;
  }
}

function usagesForFinding(finding, repoRoot) {
  const existing = finding && finding.location && finding.location.usages;
  if (Array.isArray(existing) && existing.length) return existing;
  const pkg = finding && finding.location && finding.location.package;
  if (!pkg || !isLocalDir(repoRoot)) return [];
  return findPackageUsages(path.resolve(repoRoot), pkg);
}

module.exports = { findPackageUsages, attachUsages, usagesForFinding, isLocalDir };
