'use strict';

const fs = require('fs');
const path = require('path');

const ECOSYSTEM = 'npm';

const isRegistryVersion = (v) => typeof v === 'string' && /^\d+\.\d+\.\d+/.test(v);

function readRootPackage(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  } catch {
    return {};
  }
}

// Shared by yarn and pnpm: nodes = Map<key, {name, version, deps: [nodeKey...]}>,
// rootKeys = nodeKeys the project depends on directly. Breadth-first, so each
// package gets its shortest "introduced through" path.
function buildDependencies(nodes, rootKeys, rootLabel) {
  const byKey = new Map();
  const seen = new Set();
  const queue = [];
  for (const key of rootKeys) {
    if (nodes.has(key) && !seen.has(key)) {
      seen.add(key);
      queue.push({ key, chain: [] });
    }
  }

  while (queue.length) {
    const { key, chain } = queue.shift();
    const node = nodes.get(key);
    const label = `${node.name}@${node.version}`;
    if (isRegistryVersion(node.version)) {
      let dep = byKey.get(label);
      if (!dep) {
        dep = { name: node.name, version: node.version, ecosystem: ECOSYSTEM, direct: false, paths: [] };
        byKey.set(label, dep);
      }
      dep.direct = dep.direct || chain.length === 0;
      dep.paths.push([rootLabel, ...chain, label]);
    }
    for (const child of node.deps) {
      if (nodes.has(child) && !seen.has(child)) {
        seen.add(child);
        queue.push({ key: child, chain: [...chain, label] });
      }
    }
  }
  return [...byKey.values()];
}

const unquote = (s) => s.trim().replace(/^["']|["']$/g, '');

// yarn.lock v1 ("name@^1.0.0:" / `version "1.2.3"`) and Berry ("name@npm:^1.0.0": / `version: 1.2.3`).
function parseYarnLock(text, { rootPackage = {}, dev = false, projectLabel = 'project' } = {}) {
  const entries = new Map(); // descriptor -> node
  let current = null;
  let section = null;

  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();

    if (indent === 0) {
      const descriptors = line.replace(/:$/, '').split(',').map(unquote);
      const name = descriptors[0].slice(0, descriptors[0].indexOf('@', 1));
      current = { name, version: null, rawDeps: [], descriptors };
      for (const d of descriptors) entries.set(d, current);
      section = null;
    } else if (!current) {
      continue;
    } else if (indent === 2) {
      const m = line.match(/^version:?\s+(.+)$/);
      if (m) current.version = unquote(m[1]);
      section = /^(dependencies|optionalDependencies):?$/.test(line) ? 'deps' : null;
    } else if (indent === 4 && section === 'deps') {
      const m = line.match(/^("[^"]+"|\S+?):?\s+(.+)$/);
      if (m) current.rawDeps.push([unquote(m[1]), unquote(m[2])]);
    }
  }

  const find = (name, range) => entries.get(`${name}@${range}`) || entries.get(`${name}@npm:${range}`);
  const nodes = new Map();
  const keyOf = (n) => `${n.name}@${n.version}`;
  for (const n of new Set(entries.values())) {
    if (n.version) nodes.set(keyOf(n), { name: n.name, version: n.version, deps: [] });
  }
  for (const n of new Set(entries.values())) {
    if (!n.version) continue;
    nodes.get(keyOf(n)).deps = n.rawDeps.map(([dn, range]) => find(dn, range)).filter((c) => c && c.version).map(keyOf);
  }

  const wanted = { ...rootPackage.dependencies, ...rootPackage.optionalDependencies, ...(dev ? rootPackage.devDependencies : {}) };
  const rootKeys = Object.entries(wanted).map(([n, r]) => find(n, r)).filter((c) => c && c.version).map(keyOf);

  const rootLabel = rootPackage.name ? `${rootPackage.name}@${rootPackage.version || '0.0.0'}` : projectLabel;
  return { name: rootLabel, dependencies: buildDependencies(nodes, rootKeys, rootLabel), skipped: [] };
}

// Minimal indentation-based reader for the subset of YAML pnpm-lock.yaml uses: nested maps,
// quoted keys and scalar values. Not a general YAML parser.
function readYamlMap(text) {
  const root = {};
  const stack = [{ indent: -1, obj: root }];
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const m = raw.trim().match(/^(?:'([^']+)'|"([^"]+)"|([^:\s][^:]*?)):(?:\s+(.*))?$/);
    if (!m) continue;
    const key = m[1] || m[2] || m[3];
    const value = m[4] === undefined ? undefined : unquote(m[4].replace(/\s+#.*$/, ''));
    while (stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1].obj;
    if (value === undefined || value === '') {
      parent[key] = {};
      stack.push({ indent, obj: parent[key] });
    } else {
      parent[key] = value;
    }
  }
  return root;
}

// "/@scope/name@1.2.3(peer@1.0.0)" (v9: no leading "/") or v6 "/name@1.2.3" -> {name, version}
function splitPnpmKey(key) {
  const clean = key.replace(/^\//, '').replace(/\(.*$/, '');
  const at = clean.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: clean.slice(0, at), version: clean.slice(at + 1) };
}

function parsePnpmLock(text, { rootPackage = {}, dev = false, projectLabel = 'project' } = {}) {
  const lock = readYamlMap(text);
  const nodes = new Map();
  const defs = { ...(lock.snapshots || {}) };
  const pkgs = lock.packages || {};
  for (const [k, v] of Object.entries(pkgs)) if (!(k in defs)) defs[k] = v;

  for (const [key, entry] of Object.entries(defs)) {
    const nv = splitPnpmKey(key);
    if (!nv) continue;
    const id = `${nv.name}@${nv.version}`;
    const deps = Object.entries({ ...(entry.dependencies || {}), ...(entry.optionalDependencies || {}) })
      .map(([n, v]) => (typeof v === 'string' ? `${n}@${v.replace(/\(.*$/, '')}` : null))
      .filter(Boolean);
    const existing = nodes.get(id);
    nodes.set(id, { name: nv.name, version: nv.version, deps: existing ? [...existing.deps, ...deps] : deps });
  }

  const importer = (lock.importers && lock.importers['.']) || lock;
  const rootKeys = [];
  for (const section of dev ? ['dependencies', 'optionalDependencies', 'devDependencies'] : ['dependencies', 'optionalDependencies']) {
    for (const [name, spec] of Object.entries(importer[section] || {})) {
      const version = typeof spec === 'string' ? spec : spec && spec.version;
      if (version) rootKeys.push(`${name}@${String(version).replace(/\(.*$/, '')}`);
    }
  }

  const rootLabel = rootPackage.name ? `${rootPackage.name}@${rootPackage.version || '0.0.0'}` : projectLabel;
  return { name: rootLabel, dependencies: buildDependencies(nodes, rootKeys, rootLabel), skipped: [] };
}

function loadYarnLock(filePath, opts = {}) {
  const dir = path.dirname(path.resolve(filePath));
  return parseYarnLock(fs.readFileSync(filePath, 'utf8'), { ...opts, rootPackage: readRootPackage(dir), projectLabel: path.basename(dir) });
}

function loadPnpmLock(filePath, opts = {}) {
  const dir = path.dirname(path.resolve(filePath));
  return parsePnpmLock(fs.readFileSync(filePath, 'utf8'), { ...opts, rootPackage: readRootPackage(dir), projectLabel: path.basename(dir) });
}

module.exports = { parseYarnLock, parsePnpmLock, loadYarnLock, loadPnpmLock, readYamlMap };
