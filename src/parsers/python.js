'use strict';

const fs = require('fs');
const path = require('path');

const ECOSYSTEM = 'PyPI';

// PEP 503 name normalisation, so "Django", "django" and "Py_YAML" all match OSV.
function normalizeName(name) {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

function toDependency(projectLabel, name, version) {
  const normalized = normalizeName(name);
  return {
    name: normalized,
    version,
    ecosystem: ECOSYSTEM,
    direct: true,
    paths: [[projectLabel, `${normalized}@${version}`]],
  };
}

function dedupe(deps) {
  const byKey = new Map();
  for (const d of deps) byKey.set(`${d.name}@${d.version}`, d);
  return [...byKey.values()];
}

// Returns pinned requirements, nested -r includes, and anything we can't pin
// to an exact version (ranges, URLs, VCS links).
function parseRequirementsText(text) {
  const requirements = [];
  const includes = [];
  const unpinned = [];

  const lines = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;

    const include = line.match(/^(?:-r|--requirement)(?:\s+|=)(\S+)/);
    if (include) {
      includes.push(include[1]);
      continue;
    }
    if (line.startsWith('-')) continue; // -e, -c, --index-url and other pip options
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(line) || line.includes(' @ ')) {
      unpinned.push(line);
      continue;
    }

    const spec = line.split(';')[0].replace(/\s+--\S+/g, '').trim();
    const pinned = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+!-]+)$/);
    if (pinned) {
      requirements.push({ name: pinned[1], version: pinned[2] });
    } else {
      const name = spec.match(/^[A-Za-z0-9][A-Za-z0-9._-]*/);
      unpinned.push(name ? name[0] : spec);
    }
  }

  return { requirements, includes, unpinned };
}

function loadRequirements(filePath) {
  const projectLabel = path.basename(path.dirname(path.resolve(filePath)));
  const deps = [];
  const skipped = [];
  const seen = new Set();

  (function read(file) {
    const abs = path.resolve(file);
    if (seen.has(abs)) return;
    seen.add(abs);
    const { requirements, includes, unpinned } = parseRequirementsText(fs.readFileSync(abs, 'utf8'));
    for (const r of requirements) deps.push(toDependency(projectLabel, r.name, r.version));
    skipped.push(...unpinned);
    for (const inc of includes) read(path.resolve(path.dirname(abs), inc));
  })(filePath);

  return { name: projectLabel, dependencies: dedupe(deps), skipped };
}

function parsePoetryLock(text, { dev = false, projectLabel = 'project' } = {}) {
  const deps = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m);
    const version = block.match(/^version\s*=\s*"([^"]+)"/m);
    if (!name || !version) continue;
    if (!dev && /^category\s*=\s*"dev"/m.test(block)) continue;
    deps.push(toDependency(projectLabel, name[1], version[1]));
  }
  return { name: projectLabel, dependencies: dedupe(deps), skipped: [] };
}

function parsePipfileLock(lock, { dev = false, projectLabel = 'project' } = {}) {
  const deps = [];
  const skipped = [];
  const sections = dev ? ['default', 'develop'] : ['default'];
  for (const section of sections) {
    for (const [name, entry] of Object.entries(lock[section] || {})) {
      const version = typeof entry.version === 'string' ? entry.version.replace(/^===?/, '') : null;
      if (version) deps.push(toDependency(projectLabel, name, version));
      else skipped.push(name);
    }
  }
  return { name: projectLabel, dependencies: dedupe(deps), skipped };
}

function loadPoetryLock(filePath, opts = {}) {
  const projectLabel = path.basename(path.dirname(path.resolve(filePath)));
  return parsePoetryLock(fs.readFileSync(filePath, 'utf8'), { ...opts, projectLabel });
}

function loadPipfileLock(filePath, opts = {}) {
  const projectLabel = path.basename(path.dirname(path.resolve(filePath)));
  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`Could not parse ${filePath}: ${err.message}`);
  }
  return parsePipfileLock(lock, { ...opts, projectLabel });
}

module.exports = {
  ECOSYSTEM,
  normalizeName,
  parseRequirementsText,
  loadRequirements,
  parsePoetryLock,
  loadPoetryLock,
  parsePipfileLock,
  loadPipfileLock,
};
