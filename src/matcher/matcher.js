import semver from 'semver';

/**
 * Normalizes a version string into a valid semver if possible.
 */
function cleanVersion(ver) {
  if (!ver || typeof ver !== 'string') return null;
  const cleaned = semver.clean(ver, { loose: true });
  if (cleaned) return cleaned;
  const coerced = semver.coerce(ver);
  return coerced ? coerced.version : null;
}

/**
 * Evaluates whether a given package version matches an OSV vulnerability record.
 * Also extracts the recommended fix version if available.
 *
 * @param {string} packageName - Package name
 * @param {string} packageVersion - Installed package version
 * @param {object} vuln - Full OSV vulnerability object
 * @returns {{ isVulnerable: boolean, fixedVersion: string | null, affectedRanges: string[] }}
 */
export function matchVulnerability(packageName, packageVersion, vuln) {
  const normalizedDepName = packageName.toLowerCase();
  const normalizedVer = cleanVersion(packageVersion) || packageVersion;

  if (!vuln.affected || !Array.isArray(vuln.affected)) {
    return { isVulnerable: false, fixedVersion: null, affectedRanges: [] };
  }

  // Find all affected blocks for this package in npm ecosystem
  const matchingAffected = vuln.affected.filter((aff) => {
    const affName = aff.package?.name?.toLowerCase();
    const ecosystem = aff.package?.ecosystem?.toLowerCase();
    return affName === normalizedDepName && (!ecosystem || ecosystem === 'npm');
  });

  if (matchingAffected.length === 0) {
    return { isVulnerable: false, fixedVersion: null, affectedRanges: [] };
  }

  let isVulnerable = false;
  const candidateFixes = [];
  const affectedRangeDescriptions = [];

  for (const aff of matchingAffected) {
    // Check explicit versions list if provided
    if (Array.isArray(aff.versions) && aff.versions.length > 0) {
      if (aff.versions.includes(packageVersion) || aff.versions.includes(normalizedVer)) {
        isVulnerable = true;
      }
    }

    // Check ranges (SEMVER or ECOSYSTEM)
    if (Array.isArray(aff.ranges)) {
      for (const range of aff.ranges) {
        if (!Array.isArray(range.events)) continue;

        let currentIntroduced = null;

        for (const event of range.events) {
          if (event.introduced !== undefined) {
            currentIntroduced = event.introduced === '0' ? '0.0.0' : cleanVersion(event.introduced) || event.introduced;
          }

          if (event.fixed !== undefined) {
            const fixedVer = cleanVersion(event.fixed) || event.fixed;
            candidateFixes.push(fixedVer);

            const introStr = currentIntroduced || '0.0.0';
            affectedRangeDescriptions.push(`>= ${introStr} < ${fixedVer}`);

            // Test if version is in [currentIntroduced, fixedVer)
            if (semver.valid(normalizedVer) && semver.valid(fixedVer)) {
              const introValid = semver.valid(introStr);
              const isAfterIntro = introValid ? semver.gte(normalizedVer, introStr) : true;
              const isBeforeFixed = semver.lt(normalizedVer, fixedVer);

              if (isAfterIntro && isBeforeFixed) {
                isVulnerable = true;
              }
            } else if (normalizedVer === introStr) {
              isVulnerable = true;
            }

            currentIntroduced = null;
          }

          if (event.last_affected !== undefined) {
            const lastAffVer = cleanVersion(event.last_affected) || event.last_affected;
            const introStr = currentIntroduced || '0.0.0';
            affectedRangeDescriptions.push(`>= ${introStr} <= ${lastAffVer}`);

            if (semver.valid(normalizedVer) && semver.valid(lastAffVer)) {
              const introValid = semver.valid(introStr);
              const isAfterIntro = introValid ? semver.gte(normalizedVer, introStr) : true;
              const isBeforeOrEqualLast = semver.lte(normalizedVer, lastAffVer);

              if (isAfterIntro && isBeforeOrEqualLast) {
                isVulnerable = true;
              }
            } else if (normalizedVer === lastAffVer || normalizedVer === introStr) {
              isVulnerable = true;
            }

            currentIntroduced = null;
          }
        }
      }
    }
  }

  // Determine best recommended fixed version (prefer nearest higher version)
  let bestFix = null;
  if (candidateFixes.length > 0) {
    const validFixes = candidateFixes.filter((v) => semver.valid(v));
    if (validFixes.length > 0 && semver.valid(normalizedVer)) {
      // Find fixes higher than current version, sorted ascending
      const higherFixes = validFixes
        .filter((v) => semver.gt(v, normalizedVer))
        .sort(semver.compare);

      bestFix = higherFixes.length > 0 ? higherFixes[0] : validFixes.sort(semver.rcompare)[0];
    } else {
      bestFix = candidateFixes[candidateFixes.length - 1];
    }
  }

  return {
    isVulnerable,
    fixedVersion: bestFix,
    affectedRanges: affectedRangeDescriptions,
  };
}
