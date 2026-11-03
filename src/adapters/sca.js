'use strict';

const fs = require('fs');
const path = require('path');
const { detectProjects } = require('../detect');
const { scanProjects } = require('../scanner');
const { createClient } = require('../osv');
const { fromScaIssue } = require('../findings');

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
      // Full dependency inventory: feeds SBOM generation.
      const inventory = results.map((r) => ({
        file: rel(r.file), type: r.type, name: r.name,
        dependencies: r.dependencies.map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem, direct: d.direct, paths: d.paths })),
      }));
      return { findings, raw: { warnings, projects: inventory } };
    },
  };
}

module.exports = { createScaAdapter };
