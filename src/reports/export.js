'use strict';

const crypto = require('crypto');
const { summarize, findingRisk } = require('../risk');
const { rank } = require('../severity');

const sortFindings = (findings) =>
  [...findings].sort((a, b) => rank(b.severity) - rank(a.severity) || String(a.location.file).localeCompare(String(b.location.file)) || a.id.localeCompare(b.id));

// Spreadsheet apps run cells starting with = + - @ as formulas. Scanned content (package names,
// titles, file paths) is attacker-controlled, so neutralise those cells.
function csvCell(value) {
  let s = value == null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const CSV_COLUMNS = [
  ['id', (f) => f.id], ['category', (f) => f.category], ['severity', (f) => f.severity],
  ['risk', (f) => findingRisk(f).score], ['status', (f) => f.status], ['title', (f) => f.title],
  ['identifier', (f) => f.identifiers.primary], ['aliases', (f) => f.identifiers.aliases.join(' ')],
  ['cwe', (f) => f.identifiers.cwe.join(' ')], ['file', (f) => f.location.file], ['line', (f) => f.location.line],
  ['package', (f) => f.location.package], ['version', (f) => f.location.version],
  ['fixed_in', (f) => f.remediation.fixedIn], ['scanners', (f) => (f.sources || [f.scanner]).map((s) => s.name).join(' ')],
  ['url', (f) => f.url],
];

function renderCsv(findings) {
  const rows = [CSV_COLUMNS.map(([h]) => h).join(',')];
  for (const f of sortFindings(findings)) rows.push(CSV_COLUMNS.map(([, get]) => csvCell(get(f))).join(','));
  return rows.join('\r\n') + '\r\n';
}

function renderJsonReport(report) {
  return JSON.stringify({ ...report, summary: summarize(report.findings), findings: sortFindings(report.findings) }, null, 2);
}

const mdEscape = (s) => String(s == null ? '' : s).replace(/[|\\]/g, '\\$&').replace(/\r?\n/g, ' ');

function renderMarkdown(report, { title = 'VulnSight AI security report' } = {}) {
  const s = summarize(report.findings);
  const lines = [`# ${title}`, ''];
  lines.push(`Scanned: \`${report.target && report.target.path}\`  `);
  lines.push(`Generated: ${report.startedAt || new Date().toISOString()}`, '');
  lines.push(`**Posture: ${s.posture.grade} (${s.posture.score}/100)** · ${s.total} open findings · ${s.fixable} with a known fix`, '');
  lines.push('| Critical | High | Medium | Low |', '|---|---|---|---|');
  lines.push(`| ${s.bySeverity.critical} | ${s.bySeverity.high} | ${s.bySeverity.medium} | ${s.bySeverity.low} |`, '');

  lines.push('## Scanners', '', '| Scanner | Status | Version | Findings | Time |', '|---|---|---|---|---|');
  for (const sc of report.scanners || []) {
    lines.push(`| ${mdEscape(sc.scanner)} | ${sc.status}${sc.error ? ` (${mdEscape(sc.error)})` : ''} | ${mdEscape(sc.version)} | ${sc.findingCount} | ${sc.durationMs}ms |`);
  }

  lines.push('', '## Findings', '');
  if (!report.findings.length) lines.push('No findings.');
  else {
    lines.push('| Severity | Category | Title | Location | Fix |', '|---|---|---|---|---|');
    for (const f of sortFindings(report.findings)) {
      const where = f.location.package ? `${f.location.package}@${f.location.version}` : `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`;
      lines.push(`| ${f.severity} | ${f.category} | ${mdEscape(f.title)} | ${mdEscape(where)} | ${mdEscape(f.remediation.fixedIn || f.remediation.advice || '')} |`);
    }
  }
  return lines.join('\n') + '\n';
}

// --- CycloneDX 1.5 SBOM -------------------------------------------------------------------

function purl({ ecosystem, name, version }) {
  const enc = encodeURIComponent;
  if (ecosystem === 'npm') {
    const scoped = name.startsWith('@') ? `%40${name.slice(1).split('/').map(enc).join('/')}` : enc(name);
    return `pkg:npm/${scoped}@${enc(version)}`;
  }
  if (ecosystem === 'PyPI') return `pkg:pypi/${enc(name.toLowerCase().replace(/[_.]+/g, '-'))}@${enc(version)}`;
  if (ecosystem === 'Go') return `pkg:golang/${name.split('/').map(enc).join('/')}@v${enc(version)}`;
  return `pkg:generic/${enc(name)}@${enc(version)}`;
}

// Builds the SBOM from the SCA scanner's dependency inventory (report.raw.osv.projects), and
// attaches vulnerabilities for components that have findings.
function renderCycloneDx(report, { name = 'project', version = '0.1.0', now = new Date() } = {}) {
  const projects = (report.raw && report.raw.osv && report.raw.osv.projects) || [];
  const components = new Map();
  const dependsOn = new Map();

  for (const project of projects) {
    for (const dep of project.dependencies) {
      const ref = purl(dep);
      if (!components.has(ref)) {
        components.set(ref, { type: 'library', 'bom-ref': ref, name: dep.name, version: dep.version, purl: ref });
        dependsOn.set(ref, new Set());
      }
      for (const p of dep.paths || []) {
        if (p.length >= 3) {
          const parent = p[p.length - 2];
          const at = parent.lastIndexOf('@');
          const parentRef = purl({ ecosystem: dep.ecosystem, name: parent.slice(0, at), version: parent.slice(at + 1) });
          if (dependsOn.has(parentRef)) dependsOn.get(parentRef).add(ref);
        }
      }
    }
  }

  const vulnerabilities = [];
  for (const f of report.findings.filter((x) => x.category === 'sca' && x.location.package)) {
    const ref = purl({ ecosystem: f.location.ecosystem, name: f.location.package, version: f.location.version });
    if (!components.has(ref)) continue;
    vulnerabilities.push({
      id: f.identifiers.primary,
      source: { name: 'OSV', url: f.url || undefined },
      ratings: [{ severity: f.severity, ...(f.cvssScore != null ? { score: f.cvssScore, method: 'CVSSv31' } : {}) }],
      description: f.title,
      recommendation: f.remediation.fixedIn ? `Upgrade to ${f.remediation.fixedIn}` : undefined,
      affects: [{ ref }],
    });
  }

  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: 'application', name: 'vulnsight-ai', version: require('../../package.json').version }] },
      component: { type: 'application', name, version },
    },
    components: [...components.values()],
    dependencies: [...dependsOn].map(([ref, set]) => ({ ref, dependsOn: [...set] })),
    vulnerabilities,
  }, null, 2);
}

module.exports = { renderCsv, renderJsonReport, renderMarkdown, renderCycloneDx, csvCell, purl, sortFindings };
