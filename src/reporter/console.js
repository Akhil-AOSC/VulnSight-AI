import pc from 'picocolors';

/**
 * Format severity badge with appropriate terminal colors
 */
function formatSeverityBadge(level) {
  switch (level) {
    case 'CRITICAL':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'HIGH':
      return pc.bgMagenta(pc.white(pc.bold('   HIGH   ')));
    case 'MEDIUM':
      return pc.bgYellow(pc.black(pc.bold('  MEDIUM  ')));
    case 'LOW':
      return pc.bgCyan(pc.black(pc.bold('   LOW    ')));
    default:
      return pc.bgGray(pc.white(' UNKNOWN  '));
  }
}

/**
 * Renders the terminal console report.
 *
 * @param {object} scanResult - Result object from scanner engine
 * @returns {string} Formatted console string
 */
export function formatConsoleReport(scanResult) {
  const {
    targetDir,
    projectName,
    projectVersion,
    totalDependencies,
    directCount,
    transitiveCount,
    hasLockfile,
    lockfileVersion,
    findings,
    summary,
    durationMs,
    thresholdBreached,
    failThreshold,
  } = scanResult;

  const lines = [];

  // Banner
  lines.push('');
  lines.push(pc.cyan(pc.bold('═══════════════════════════════════════════════════════════════════════════')));
  lines.push(pc.cyan(pc.bold('              VULN-SCANNER · Open Source Dependency Auditor                ')));
  lines.push(pc.cyan(pc.bold('═══════════════════════════════════════════════════════════════════════════')));
  lines.push('');

  // Target summary
  lines.push(pc.bold(' Target Project:      ') + pc.white(projectName) + pc.gray(` (v${projectVersion})`));
  lines.push(pc.bold(' Target Directory:    ') + pc.gray(targetDir));
  lines.push(
    pc.bold(' Lockfile:            ') +
      (hasLockfile
        ? pc.green(`package-lock.json (format v${lockfileVersion || 1})`)
        : pc.yellow('None detected (direct manifest scan only)'))
  );
  lines.push(
    pc.bold(' Dependencies:        ') +
      pc.white(`${totalDependencies} resolved `) +
      pc.gray(`(${directCount} direct, ${transitiveCount} transitive)`)
  );
  lines.push(pc.bold(' Scan Duration:       ') + pc.gray(`${(durationMs / 1000).toFixed(2)}s`));
  lines.push('');

  // Summary box
  lines.push(pc.bold(' Vulnerability Summary:'));
  lines.push(' ─────────────────────────────────────────────────────────────────────────');
  const summaryParts = [
    pc.bgRed(pc.white(pc.bold(` CRITICAL: ${summary.critical} `))),
    pc.bgMagenta(pc.white(pc.bold(` HIGH: ${summary.high} `))),
    pc.bgYellow(pc.black(pc.bold(` MEDIUM: ${summary.medium} `))),
    pc.bgCyan(pc.black(pc.bold(` LOW: ${summary.low} `))),
  ];
  lines.push(`   ${summaryParts.join('  ')}`);
  lines.push(' ─────────────────────────────────────────────────────────────────────────');
  lines.push('');

  if (findings.length === 0) {
    lines.push(pc.green(pc.bold('  ✓ No known open-source vulnerabilities found in dependency tree!')));
    lines.push('');
    return lines.join('\n');
  }

  // Findings list
  lines.push(pc.bold(` Detailed Findings (${findings.length} vulnerabilities detected):`));
  lines.push('');

  findings.forEach((finding, index) => {
    const badge = formatSeverityBadge(finding.severity.level);
    const scoreStr = finding.severity.score !== null ? ` (CVSS ${finding.severity.score})` : '';
    const depType = finding.isDirect
      ? pc.blue(pc.bold('[DIRECT]'))
      : pc.gray(`[TRANSITIVE via ${finding.dependencyChain.join(' → ')}]`);

    lines.push(` ${pc.bold(`${index + 1}.`)} ${badge}${pc.bold(scoreStr)}  ${pc.bold(pc.white(finding.packageName))}@${pc.yellow(finding.packageVersion)}  ${depType}`);

    // Identifiers (GHSA & CVEs)
    const aliases = finding.aliases && finding.aliases.length > 0 ? ` (${finding.aliases.join(', ')})` : '';
    lines.push(`    ${pc.gray('Advisory:')}   ${pc.underline(pc.cyan(finding.id))}${aliases}`);

    if (finding.title) {
      lines.push(`    ${pc.gray('Summary:')}    ${finding.title}`);
    }

    if (finding.fixedVersion) {
      lines.push(`    ${pc.gray('Fix:')}        ${pc.green(pc.bold(`Upgrade ${finding.packageName} to >= ${finding.fixedVersion}`))}`);
    } else {
      lines.push(`    ${pc.gray('Fix:')}        ${pc.yellow('No published fix version available yet')}`);
    }

    if (finding.references && finding.references.length > 0) {
      lines.push(`    ${pc.gray('Details:')}    ${pc.gray(finding.references[0])}`);
    }

    lines.push('');
  });

  // Conclusion / CI status
  lines.push(pc.cyan('───────────────────────────────────────────────────────────────────────────'));
  if (thresholdBreached) {
    lines.push(
      pc.red(
        pc.bold(
          `  ✗ FAILURE: Vulnerabilities meet or exceed fail-threshold '${failThreshold}'. Exiting with code 1.`
        )
      )
    );
  } else {
    lines.push(
      pc.yellow(
        pc.bold(
          `  ! WARNING: Vulnerabilities detected, but none exceeded fail-threshold '${failThreshold}'. Exiting with code 0.`
        )
      )
    );
  }
  lines.push(pc.cyan('───────────────────────────────────────────────────────────────────────────'));
  lines.push('');

  return lines.join('\n');
}
