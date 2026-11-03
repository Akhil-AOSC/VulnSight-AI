'use strict';

const fs = require('fs');
const path = require('path');
const { detectProjects } = require('../detect');
const { scanProjects } = require('../scanner');
const { createClient } = require('../osv');
const { fromScaIssue } = require('../findings');
const { buildJsonReport } = require('../report');
const { attachUsages } = require('../code-context');

const VERSION = 'osv.dev-api-v1';

// Wraps the existing lockfile + OSV.dev scanner behind the adapter contract.
function createScaAdapter({ client = createClient(), scan = scanProjects, options = {} } = {}) {
  return {
    name: 'osv',
    category: 'sca',
    async version() { return VERSION; },
    async supports(target) {
      return !!target.path && fs.existsSync(target.path) && fs.statSync(target.path).isDirectory();
    },
    async run(target) {
      const { projects, warnings } = detectProjects(target.path, options);
      const results = await scan(projects, { client });
      const rel = (file) => path.relative(target.path, file).split(path.sep).join('/');
      const findings = results.flatMap((r) =>
        r.issues.map((issue) => fromScaIssue(issue, { file: rel(r.file), scannerVersion: VERSION })));
      attachUsages(findings, target.path);
      // Full dependency inventory + upgrade plans and vulnerabilities per project.
      const jsonReport = buildJsonReport(results.map((r) => ({ ...r, file: rel(r.file) })), warnings);
      const inventory = results.map((r, idx) => ({
        file: rel(r.file),
        type: r.type,
        packageManager: r.type,
        ecosystem: r.ecosystem,
        name: r.name,
        projectName: r.name,
        dependencyCount: r.dependencies.length,
        skipped: r.skipped || [],
        summary: jsonReport.projects[idx] ? jsonReport.projects[idx].summary : {},
        upgradePlan: jsonReport.projects[idx] ? jsonReport.projects[idx].upgradePlan : [],
        vulnerabilities: jsonReport.projects[idx] ? jsonReport.projects[idx].vulnerabilities : [],
        dependencies: r.dependencies.map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem, direct: d.direct, paths: d.paths })),
      }));
      return { findings, raw: { warnings, summary: jsonReport.summary, projects: inventory } };
    },
  };
}

module.exports = { createScaAdapter };
