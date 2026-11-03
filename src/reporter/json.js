/**
 * Formats scan results into structured JSON for CI/CD pipelines, SARIF, or data export.
 */
export function formatJsonReport(scanResult) {
  return JSON.stringify(
    {
      scanner: {
        name: 'vuln-scanner',
        version: '0.1.0',
        dataSource: 'OSV.dev (Open Source Vulnerabilities)',
      },
      metadata: {
        targetDir: scanResult.targetDir,
        projectName: scanResult.projectName,
        projectVersion: scanResult.projectVersion,
        scannedAt: new Date().toISOString(),
        durationMs: scanResult.durationMs,
        lockfile: {
          present: scanResult.hasLockfile,
          version: scanResult.lockfileVersion,
        },
        dependencyCounts: {
          total: scanResult.totalDependencies,
          direct: scanResult.directCount,
          transitive: scanResult.transitiveCount,
        },
      },
      summary: scanResult.summary,
      ci: {
        failThreshold: scanResult.failThreshold,
        thresholdBreached: scanResult.thresholdBreached,
        recommendedExitCode: scanResult.thresholdBreached ? 1 : 0,
      },
      findings: scanResult.findings.map((f) => ({
        id: f.id,
        aliases: f.aliases,
        packageName: f.packageName,
        installedVersion: f.packageVersion,
        isDirect: f.isDirect,
        isDev: f.isDev,
        dependencyChain: f.dependencyChain,
        severity: f.severity,
        title: f.title,
        fixedVersion: f.fixedVersion,
        affectedRanges: f.affectedRanges,
        references: f.references,
      })),
    },
    null,
    2
  );
}
