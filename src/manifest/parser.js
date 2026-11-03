import fs from 'node:fs';
import path from 'node:path';

/**
 * Extracts normalized package name from node_modules path key (e.g. node_modules/@scope/pkg -> @scope/pkg)
 */
function extractPackageName(key) {
  const parts = key.split('node_modules/');
  return parts[parts.length - 1];
}

/**
 * Parses package.json and package-lock.json (supporting lockfile v1, v2, v3)
 * to resolve all direct and transitive dependencies.
 *
 * @param {string} projectDir - Path to the directory containing package.json
 * @param {object} options - Options { includeDev: boolean }
 * @returns {object} Normalized dependency manifest and dependency tree
 */
export function parseManifest(projectDir, options = { includeDev: true }) {
  const resolvedDir = path.resolve(projectDir);
  const pkgPath = path.join(resolvedDir, 'package.json');
  const lockPath = path.join(resolvedDir, 'package-lock.json');

  if (!fs.existsSync(pkgPath)) {
    throw new Error(`No package.json found at: ${resolvedDir}`);
  }

  const pkgJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const directDeps = new Set(Object.keys(pkgJson.dependencies || {}));
  const directDevDeps = new Set(Object.keys(pkgJson.devDependencies || {}));
  const directPeerDeps = new Set(Object.keys(pkgJson.peerDependencies || {}));
  const directOptionalDeps = new Set(Object.keys(pkgJson.optionalDependencies || {}));

  const allDirectDeps = new Set([
    ...directDeps,
    ...directDevDeps,
    ...directPeerDeps,
    ...directOptionalDeps,
  ]);

  const dependencyMap = new Map(); // key: `${name}@${version}` -> dependency object

  let lockfileVersion = null;
  let hasLockfile = false;

  if (fs.existsSync(lockPath)) {
    hasLockfile = true;
    const lockJson = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    lockfileVersion = lockJson.lockfileVersion || 1;

    if (lockJson.packages && (lockfileVersion === 2 || lockfileVersion === 3)) {
      // Modern npm lockfile format (v2/v3)
      for (const [key, pkgData] of Object.entries(lockJson.packages)) {
        if (!key || key === '') continue; // Skip root project definition

        const name = pkgData.name || extractPackageName(key);
        const version = pkgData.version;

        if (!name || !version) continue;

        const isDev = Boolean(pkgData.dev);
        if (!options.includeDev && isDev) {
          continue;
        }

        const isDirect = allDirectDeps.has(name) && !key.includes('node_modules/' + name + '/node_modules/');
        const mapKey = `${name}@${version}`;

        if (!dependencyMap.has(mapKey)) {
          // Construct dependency chain hint from path
          const pathSegments = key.split('node_modules/').filter(Boolean);
          const chain = pathSegments.length > 0 ? pathSegments : [name];

          dependencyMap.set(mapKey, {
            name,
            version,
            isDirect,
            isDev,
            dependencyChain: chain,
            resolved: pkgData.resolved || null,
            integrity: pkgData.integrity || null,
          });
        }
      }
    } else if (lockJson.dependencies) {
      // Legacy npm lockfile format (v1) or fallback v2
      function walkV1(deps, parentChain = [], parentIsDev = false) {
        for (const [name, depData] of Object.entries(deps)) {
          const version = depData.version;
          if (!version) continue;

          const isDev = parentIsDev || Boolean(depData.dev);
          if (!options.includeDev && isDev) {
            continue;
          }

          const currentChain = [...parentChain, name];
          const isDirect = parentChain.length === 0 && allDirectDeps.has(name);
          const mapKey = `${name}@${version}`;

          if (!dependencyMap.has(mapKey)) {
            dependencyMap.set(mapKey, {
              name,
              version,
              isDirect,
              isDev,
              dependencyChain: currentChain,
              resolved: depData.resolved || null,
              integrity: depData.integrity || null,
            });
          }

          if (depData.dependencies) {
            walkV1(depData.dependencies, currentChain, isDev);
          }
        }
      }

      walkV1(lockJson.dependencies);
    }
  } else {
    // No package-lock.json found; fallback to direct dependencies in package.json
    // and attempt to inspect node_modules if present
    const nodeModulesDir = path.join(resolvedDir, 'node_modules');

    function resolveInstalledVersion(name) {
      try {
        const subPkg = path.join(nodeModulesDir, name, 'package.json');
        if (fs.existsSync(subPkg)) {
          const subData = JSON.parse(fs.readFileSync(subPkg, 'utf8'));
          return subData.version;
        }
      } catch {
        // ignore
      }
      return null;
    }

    const collectDirect = (deps, isDev) => {
      for (const [name, declaredRange] of Object.entries(deps || {})) {
        if (!options.includeDev && isDev) continue;
        const installedVer = resolveInstalledVersion(name);
        const version = installedVer || declaredRange.replace(/^[\^~>=<]/, '');
        const mapKey = `${name}@${version}`;
        if (!dependencyMap.has(mapKey)) {
          dependencyMap.set(mapKey, {
            name,
            version,
            isDirect: true,
            isDev,
            declaredRange,
            dependencyChain: [name],
            resolved: null,
          });
        }
      }
    };

    collectDirect(pkgJson.dependencies, false);
    collectDirect(pkgJson.devDependencies, true);
    collectDirect(pkgJson.optionalDependencies, false);
  }

  const dependencies = Array.from(dependencyMap.values());
  const directCount = dependencies.filter((d) => d.isDirect).length;
  const transitiveCount = dependencies.filter((d) => !d.isDirect).length;

  return {
    projectDir: resolvedDir,
    projectName: pkgJson.name || path.basename(resolvedDir),
    projectVersion: pkgJson.version || '0.0.0',
    hasLockfile,
    lockfileVersion,
    totalDependencies: dependencies.length,
    directCount,
    transitiveCount,
    dependencies,
  };
}
