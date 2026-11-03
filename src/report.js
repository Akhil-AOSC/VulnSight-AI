'use strict';

const path = require('path');
const { LEVELS, rank } = require('./severity');
const { compareVersions } = require('./versions');

const MAX_PATHS_SHOWN = 3;

function palette(enabled) {
  const wrap = (code) => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return {
    bold: wrap('1'),
    dim: wrap('2'),
    red: wrap('31'),
    green: wrap('32'),
    yellow: wrap('33'),
    blue: wrap('34'),
    magenta: wrap('35'),
    critical: wrap('1;35'),
  };
}

function severityColor(c, level) {
  return { critical: c.critical, high: c.red, medium: c.yellow, low: c.blue }[level] || c.dim;
}

const nameOfLabel = (label) => label.slice(0, label.lastIndexOf('@'));
const isDirect = (issue) => issue.direct || issue.paths.some((p) => p.length === 2);

function fixAdvice(issue, project) {
  if (!issue.fixedIn) return 'No fixed version is available yet';
  if (issue.ecosystem === 'PyPI') {
    return `Upgrade ${issue.package} to ${issue.fixedIn} in ${path.basename(project.file)}`;
  }
  if (isDirect(issue)) return `Upgrade ${issue.package} to ${issue.fixedIn}`;
  const parent = nameOfLabel(issue.paths[0][1]);
  return `Fixed in ${issue.package}@${issue.fixedIn}. Upgrade ${parent} to a version that uses it, `
    + `or force it with "overrides" in package.json`;
}

function sortIssues(issues) {
  return [...issues].sort((a, b) =>
    rank(b.severity) - rank(a.severity) || a.package.localeCompare(b.package) || a.id.localeCompare(b.id));
}

function countBySeverity(issues) {
  const counts = {};
  for (const level of LEVELS) counts[level] = 0;
  for (const issue of issues) counts[issue.severity]++;
  return counts;
}

// One upgrade per vulnerable package: the highest fixed version among its issues.
function upgradePlan(issues) {
  const byPackage = new Map();
  for (const issue of issues) {
    const key = `${issue.package}@${issue.version}`;
    if (!byPackage.has(key)) byPackage.set(key, { package: issue.package, version: issue.version, target: null, fixes: 0, unfixed: 0 });
    const entry = byPackage.get(key);
    if (!issue.fixedIn) {
      entry.unfixed++;
      continue;
    }
    entry.fixes++;
    if (!entry.target || compareVersions(issue.fixedIn, entry.target) > 0) entry.target = issue.fixedIn;
  }
  return [...byPackage.values()].sort((a, b) => a.package.localeCompare(b.package));
}

function renderIssue(issue, project, c) {
  const color = severityColor(c, issue.severity);
  const cves = issue.aliases.filter((a) => a.startsWith('CVE-'));
  const idLine = [issue.id, cves.length ? `(${cves.join(', ')})` : '', issue.cvssScore !== null ? `CVSS ${issue.cvssScore.toFixed(1)}` : '']
    .filter(Boolean).join('  ');

  const lines = [
    color(`✗ [${issue.severity.toUpperCase()}] ${issue.title}`),
    `  Package: ${c.bold(`${issue.package}@${issue.version}`)}`,
    `  ID: ${idLine}`,
  ];
  issue.paths.slice(0, MAX_PATHS_SHOWN).forEach((p, i) => {
    lines.push(`  ${i === 0 ? 'Introduced through:' : '                   '} ${p.join(' > ')}`);
  });
  if (issue.paths.length > MAX_PATHS_SHOWN) {
    lines.push(c.dim(`                      ...and ${issue.paths.length - MAX_PATHS_SHOWN} more paths`));
  }
  lines.push(`  Fix: ${issue.fixedIn ? c.green(fixAdvice(issue, project)) : c.dim(fixAdvice(issue, project))}`);
  lines.push(`  Info: ${issue.url}`);
  return lines.join('\n');
}

function renderSummary(project, c) {
  const counts = countBySeverity(project.issues);
  const parts = ['critical', 'high', 'medium', 'low', 'unknown']
    .filter((l) => counts[l])
    .map((l) => severityColor(c, l)(`${counts[l]} ${l}`));
  const paths = project.issues.reduce((n, i) => n + i.paths.length, 0);
  const n = project.dependencies.length;
  const tested = `Tested ${n} ${n === 1 ? 'dependency' : 'dependencies'} for known issues`;

  if (!project.issues.length) return c.green(`✓ ${tested}, no vulnerable paths found.`);
  const found = `${project.issues.length} ${project.issues.length === 1 ? 'issue' : 'issues'}`;
  return `${tested}, ${c.bold(`found ${found}`)} (${parts.join(', ')}), ${paths} vulnerable ${paths === 1 ? 'path' : 'paths'}.`;
}

function renderText(results, warnings = [], { color = false } = {}) {
  const c = palette(color);
  const out = [];
  for (const w of warnings) out.push(c.yellow(`Warning: ${w}`));

  for (const project of results) {
    out.push('', c.bold(`Testing ${project.file}...`), '');
    for (const issue of sortIssues(project.issues)) out.push(renderIssue(issue, project, c), '');

    out.push(`Package manager:  ${project.type}`);
    out.push(`Target file:      ${path.basename(project.file)}`);
    out.push(`Project name:     ${project.name}`);
    out.push('');
    out.push(renderSummary(project, c));

    const plan = upgradePlan(project.issues);
    if (plan.length) {
      out.push('', c.bold('Remediation:'));
      for (const p of plan) {
        const label = `${p.package}@${p.version}`;
        if (p.target) {
          const extra = p.unfixed ? c.dim(` (${p.unfixed} not fixable yet)`) : '';
          out.push(`  Upgrade ${label} to ${c.green(`${p.package}@${p.target}`)} to fix ${p.fixes} ${p.fixes === 1 ? 'issue' : 'issues'}${extra}`);
        } else {
          out.push(c.dim(`  ${label}: no fixed version available for ${p.unfixed} ${p.unfixed === 1 ? 'issue' : 'issues'}`));
        }
      }
    }

    if (project.skipped.length) {
      out.push('', c.yellow(`Not scanned (no exact version pinned): ${project.skipped.join(', ')}`));
    }
  }
  return out.join('\n');
}

function buildJsonReport(results, warnings = []) {
  const projects = results.map((p) => ({
    file: p.file,
    packageManager: p.type,
    ecosystem: p.ecosystem,
    projectName: p.name,
    dependencyCount: p.dependencies.length,
    skipped: p.skipped,
    summary: countBySeverity(p.issues),
    upgradePlan: upgradePlan(p.issues),
    vulnerabilities: sortIssues(p.issues).map((i) => ({ ...i, remediation: fixAdvice(i, p) })),
  }));
  const all = results.flatMap((p) => p.issues);
  return {
    ok: all.length === 0,
    warnings,
    summary: {
      issues: all.length,
      dependencies: projects.reduce((n, p) => n + p.dependencyCount, 0),
      ...countBySeverity(all),
    },
    projects,
  };
}

function renderJson(results, warnings = []) {
  return JSON.stringify(buildJsonReport(results, warnings), null, 2);
}

module.exports = { renderText, renderJson, buildJsonReport, upgradePlan, fixAdvice };
