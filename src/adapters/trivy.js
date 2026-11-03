'use strict';

const fs = require('fs');
const path = require('path');
const { execTool } = require('./runner');
const { createFinding } = require('../findings');

const SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const sev = (s) => SEVERITY[String(s).toUpperCase()] || 'unknown';

function cvssScore(v) {
  for (const src of Object.values(v.CVSS || {})) {
    if (src && typeof src.V3Score === 'number') return src.V3Score;
  }
  return null;
}

// Vulnerabilities in a filesystem or image result. `category` is sca for lockfiles/filesystems
// and container for images.
function vulnFinding(v, result, { root, category, version }) {
  const ids = [v.VulnerabilityID];
  const cwe = (v.CweIDs || []).map((c) => String(c).toUpperCase());
  return createFinding({
    category,
    scanner: { name: 'trivy', version, ruleId: v.VulnerabilityID },
    title: (v.Title || v.VulnerabilityID).slice(0, 200),
    description: v.Description || null,
    severity: sev(v.Severity),
    cvssScore: cvssScore(v),
    identifiers: { primary: ids[0], aliases: [], cwe },
    location: {
      file: category === 'container' ? result.Target : relFile(result.Target, root),
      package: v.PkgName,
      version: v.InstalledVersion,
      ecosystem: trivyEcosystem(result.Type),
    },
    remediation: { fixedIn: v.FixedVersion ? String(v.FixedVersion).split(',')[0].trim() : null },
    url: v.PrimaryURL || (v.References || [])[0] || null,
  });
}

function misconfigFinding(m, result, { root, version }) {
  const cause = m.CauseMetadata || {};
  return createFinding({
    category: 'iac',
    scanner: { name: 'trivy', version, ruleId: m.ID },
    title: (m.Title || m.ID).slice(0, 200),
    description: m.Description || m.Message || null,
    severity: sev(m.Severity),
    identifiers: { primary: m.AVDID || m.ID, aliases: [] },
    location: { file: relFile(result.Target, root), line: cause.StartLine || null, endLine: cause.EndLine || null },
    remediation: { advice: m.Resolution || null },
    evidence: m.Message || null,
    url: m.PrimaryURL || (m.References || [])[0] || null,
  });
}

function relFile(target, root) {
  if (!target) return null;
  const abs = path.resolve(root, target);
  return path.relative(root, abs).split(path.sep).join('/');
}

// Trivy's "Type" is the package manager; map to OSV ecosystem names so findings from
// Trivy and OSV can be deduplicated.
const ECOSYSTEMS = { npm: 'npm', yarn: 'npm', pnpm: 'npm', pip: 'PyPI', pipenv: 'PyPI', poetry: 'PyPI', gomod: 'Go', gobinary: 'Go' };
function trivyEcosystem(type) {
  return ECOSYSTEMS[type] || type || null;
}

function parseTrivy(stdout, opts) {
  const data = JSON.parse(stdout);
  const out = [];
  for (const result of data.Results || []) {
    for (const v of result.Vulnerabilities || []) out.push(vulnFinding(v, result, opts));
    if (opts.misconfig) for (const m of result.Misconfigurations || []) out.push(misconfigFinding(m, result, opts));
  }
  return out;
}

// Filesystem scan (lockfile vulnerabilities, optional IaC misconfiguration) or image scan.
//   mode 'fs'    -> target.path       (categories: sca, iac)
//   mode 'image' -> target.image      (category: container)
function createTrivyAdapter({ mode = 'fs', misconfig = true, command = 'trivy', exec = execTool } = {}) {
  return {
    name: mode === 'image' ? 'trivy-image' : 'trivy',
    category: mode === 'image' ? 'container' : 'sca',
    async version() {
      const { stdout } = await exec(command, ['--version']);
      const m = stdout.match(/Version:\s*(\S+)/i);
      return m ? m[1] : stdout.trim().split('\n')[0];
    },
    async supports(target) {
      if (mode === 'image') return typeof target.image === 'string' && /^[\w][\w./:@-]*$/.test(target.image);
      return !!target.path && fs.existsSync(target.path) && fs.statSync(target.path).isDirectory();
    },
    async run(target, { signal } = {}) {
      const version = await this.version();
      const common = ['--format', 'json', '--quiet', '--no-progress', '--skip-version-check'];
      let args;
      let cwd;
      if (mode === 'image') {
        args = ['image', ...common, '--scanners', 'vuln', target.image];
      } else {
        args = ['fs', ...common, '--scanners', misconfig ? 'vuln,misconfig' : 'vuln', '.'];
        cwd = target.path;
      }
      const { stdout } = await exec(command, args, { cwd, signal });
      const root = target.path || process.cwd();
      const category = mode === 'image' ? 'container' : 'sca';
      return { findings: parseTrivy(stdout, { root, category, version, misconfig: mode !== 'image' && misconfig }), raw: null };
    },
  };
}

module.exports = { createTrivyAdapter, parseTrivy };
