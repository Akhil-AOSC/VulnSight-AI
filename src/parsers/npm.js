'use strict';

const fs = require('fs');
const path = require('path');

const ECOSYSTEM = 'npm';

// Only versions that come from the registry can be matched against OSV.
// Git URLs, file: links and aliases are skipped.
function isRegistryVersion(version) {
  return typeof version === 'string' && /^\d+\.\d+\.\d+/.test(version);
}

function nameFromLocation(location) {
  const idx = location.lastIndexOf('node_modules/');
  return idx === -1 ? location : location.slice(idx + 'node_modules/'.length);
}

// Mirrors Node's module resolution: look in the nearest node_modules first,
// then walk up towards the project root.
function resolveLocation(packages, fromLocation, depName) {
  let base = fromLocation;
  for (;;) {
    const candidate = base ? `${base}/node_modules/${depName}` : `node_modules/${depName}`;
    if (packages[candidate]) return candidate;
    if (!base) return null;
    const idx = base.lastIndexOf('/node_modules/');
    base = idx === -1 ? '' : base.slice(0, idx);
  }
}

// lockfileVersion 2 and 3: a flat "packages" map keyed by install location.
// Walks the graph breadth-first from the root so every package gets its
// shortest "introduced through" path.
function walkPackages(packages, includeDev) {
  const found = [];
  const visited = new Set(['']);
  const queue = [];

  function enqueue(fromLocation, deps, chain) {
    for (const depName of Object.keys(deps || {})) {
      let location = resolveLocation(packages, fromLocation, depName);
      if (location === null) continue;
      if (packages[location].link) {
        location = packages[location].resolved;
        if (!packages[location]) continue;
      }
      if (visited.has(location)) continue;
      visited.add(location);
      queue.push({ location, chain });
    }
  }

  const root = packages[''] || {};
  enqueue('', {
    ...root.dependencies,
    ...root.optionalDependencies,
    ...(includeDev ? root.devDependencies : {}),
  }, []);

  while (queue.length) {
    const { location, chain } = queue.shift();
    const entry = packages[location];
    const name = entry.name || nameFromLocation(location);
    const label = `${name}@${entry.version}`;
    // Workspace packages live outside node_modules; traverse them but don't report them.
    const isLocal = !location.includes('node_modules/');

    if (!isLocal && isRegistryVersion(entry.version)) {
      found.push({ name, version: entry.version, chain, direct: chain.length === 0 });
    }

    enqueue(location, {
      ...entry.dependencies,
      ...entry.optionalDependencies,
      ...entry.peerDependencies,
      ...(isLocal && includeDev ? entry.devDependencies : {}),
    }, [...chain, label]);
  }

  return found;
}

// lockfileVersion 1: nested "dependencies" objects. Hoisting means we can't
// tell direct from transitive dependencies here, so "direct" stays unknown.
function walkV1(deps, includeDev, chain = [], found = []) {
  for (const [name, entry] of Object.entries(deps || {})) {
    if (entry.dev && !includeDev) continue;
    if (isRegistryVersion(entry.version)) {
      found.push({ name, version: entry.version, chain, direct: null });
    }
    if (entry.dependencies) {
      walkV1(entry.dependencies, includeDev, [...chain, `${name}@${entry.version}`], found);
    }
  }
  return found;
}

function parseNpmLock(lock, { dev = false, fallbackName = 'project' } = {}) {
  const rootEntry = (lock.packages && lock.packages['']) || {};
  const rootName = lock.name || rootEntry.name || fallbackName;
  const rootVersion = lock.version || rootEntry.version || '0.0.0';
  const rootLabel = `${rootName}@${rootVersion}`;

  const found = lock.packages
    ? walkPackages(lock.packages, dev)
    : walkV1(lock.dependencies, dev);

  const byKey = new Map();
  for (const f of found) {
    const key = `${f.name}@${f.version}`;
    let dep = byKey.get(key);
    if (!dep) {
      dep = { name: f.name, version: f.version, ecosystem: ECOSYSTEM, direct: false, paths: [] };
      byKey.set(key, dep);
    }
    dep.direct = dep.direct || f.direct === true;
    dep.paths.push([rootLabel, ...f.chain, key]);
  }

  return { name: rootLabel, dependencies: [...byKey.values()], skipped: [] };
}

function loadNpmLockfile(filePath, opts = {}) {
  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`Could not parse ${filePath}: ${err.message}`);
  }
  return parseNpmLock(lock, { ...opts, fallbackName: path.basename(path.dirname(filePath)) });
}

module.exports = { parseNpmLock, loadNpmLockfile, resolveLocation, ECOSYSTEM };
