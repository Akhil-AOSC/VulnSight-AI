'use strict';

const fs = require('fs');
const path = require('path');
const { execTool } = require('./runner');
const { createFinding } = require('../findings');

const SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

// Checkov output is one object, or an array of objects (one per framework).
function parseCheckov(stdout, root, version) {
  const text = stdout.trim();
  if (!text) return [];
  const data = JSON.parse(text);
  const reports = Array.isArray(data) ? data : [data];
  const findings = [];

  for (const report of reports) {
    for (const check of (report.results && report.results.failed_checks) || []) {
      const range = check.file_line_range || [];
      const file = path.relative(root, path.resolve(root, String(check.file_path || '').replace(/^[\\/]+/, ''))).split(path.sep).join('/');
      findings.push(createFinding({
        category: 'iac',
        scanner: { name: 'checkov', version, ruleId: check.check_id },
        title: check.check_name || check.check_id,
        description: check.resource ? `Resource: ${check.resource}` : null,
        // Checkov only assigns severity when connected to a Prisma key; default to medium.
        severity: SEVERITY[String(check.severity).toUpperCase()] || 'medium',
        identifiers: { primary: check.check_id, aliases: check.bc_check_id ? [check.bc_check_id] : [] },
        location: { file, line: range[0] || null, endLine: range[1] || null },
        remediation: { advice: check.guideline ? `See ${check.guideline}` : null },
        evidence: check.resource || null,
        url: check.guideline || null,
      }));
    }
  }
  return findings;
}

// Infrastructure-as-code scanning (Terraform, Kubernetes, Dockerfile, ARM/Bicep, CloudFormation...).
function createCheckovAdapter({ command = 'checkov', commandArgs = [], exec = execTool } = {}) {
  return {
    name: 'checkov',
    category: 'iac',
    async version() {
      const { stdout } = await exec(command, [...commandArgs, '--version']);
      return stdout.trim().split('\n').pop();
    },
    async supports(target) {
      return !!target.path && fs.existsSync(target.path) && fs.statSync(target.path).isDirectory();
    },
    async run(target, { signal } = {}) {
      const version = await this.version();
      // Checkov exits 1 when checks fail, which is a normal result here.
      const { stdout } = await exec(command, [...commandArgs, '-d', '.', '--output', 'json', '--quiet', '--compact', '--skip-download'], {
        cwd: target.path, signal, okCodes: [0, 1],
      });
      return { findings: parseCheckov(stdout, target.path, version), raw: null };
    },
  };
}

module.exports = { createCheckovAdapter, parseCheckov };
