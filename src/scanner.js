import { parseManifest } from './manifest/parser.js';
import { OSVClient } from './osv/client.js';
import { matchVulnerability } from './matcher/matcher.js';
import { extractSeverity, meetsThreshold, SEVERITY_LEVELS } from './scoring/severity.js';

/**
 * Executes a full vulnerability scan on the specified project directory.
 *
 * @param {string} projectDir - Target directory containing package.json
 * @param {object} options - Scan configuration options
 * @returns {Promise<object>} Complete scan result data
 */
export async function runScan(projectDir, options = {}) {
  const startTime = Date.now();
  const includeDev = options.includeDev !== false;
  const failThreshold = options.failThreshold || 'low';
  const client = options.osvClient || new OSVClient({ timeoutMs: options.timeoutMs });

  // Step 1: Parse manifest & lockfile (direct + transitive resolution)
  const manifest = parseManifest(projectDir, { includeDev });

  // Step 2: Query OSV API in batches
  const vulnMap = await client.queryDependencies(manifest.dependencies);

  // Step 3: Match vulnerabilities & compute severities
  const findings = [];
  const processedKeys = new Set(); // Prevent duplicate (package, vulnId) findings

  for (const dep of manifest.dependencies) {
    const depKey = `${dep.name}@${dep.version}`;
    const rawVulns = vulnMap.get(depKey) || [];

    for (const rawVuln of rawVulns) {
      const findingKey = `${depKey}:${rawVuln.id}`;
      if (processedKeys.has(findingKey)) continue;

      // Verify range matching
      const match = matchVulnerability(dep.name, dep.version, rawVuln);
      if (!match.isVulnerable) continue;

      processedKeys.add(findingKey);

      // Extract severity and CVSS
      const severity = extractSeverity(rawVuln);

      // Extract aliases (CVEs)
      const aliases = Array.isArray(rawVuln.aliases) ? rawVuln.aliases : [];

      // Extract references
      const references = Array.isArray(rawVuln.references)
        ? rawVuln.references.map((r) => (typeof r === 'string' ? r : r.url)).filter(Boolean)
        : [];

      findings.push({
        id: rawVuln.id,
        aliases,
        packageName: dep.name,
        packageVersion: dep.version,
        isDirect: dep.isDirect,
        isDev: dep.isDev,
        dependencyChain: dep.dependencyChain,
        severity,
        title: rawVuln.summary || rawVuln.details?.slice(0, 120) || 'No title provided',
        fixedVersion: match.fixedVersion,
        affectedRanges: match.affectedRanges,
        references,
      });
    }
  }

  // Step 4: Sort findings by severity rank descending, then by package name
  findings.sort((a, b) => {
    if (b.severity.rank !== a.severity.rank) {
      return b.severity.rank - a.severity.rank;
    }
    return a.packageName.localeCompare(b.packageName);
  });

  // Step 5: Calculate severity counts
  const summary = {
    critical: findings.filter((f) => f.severity.level === 'CRITICAL').length,
    high: findings.filter((f) => f.severity.level === 'HIGH').length,
    medium: findings.filter((f) => f.severity.level === 'MEDIUM').length,
    low: findings.filter((f) => f.severity.level === 'LOW').length,
    unknown: findings.filter((f) => f.severity.level === 'UNKNOWN').length,
  };

  // Step 6: Determine threshold breach
  const thresholdBreached = findings.some((f) => meetsThreshold(f.severity.level, failThreshold));

  const durationMs = Date.now() - startTime;

  return {
    targetDir: manifest.projectDir,
    projectName: manifest.projectName,
    projectVersion: manifest.projectVersion,
    hasLockfile: manifest.hasLockfile,
    lockfileVersion: manifest.lockfileVersion,
    totalDependencies: manifest.totalDependencies,
    directCount: manifest.directCount,
    transitiveCount: manifest.transitiveCount,
    failThreshold,
    thresholdBreached,
    summary,
    findings,
    durationMs,
  };
}
