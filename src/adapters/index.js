'use strict';

const { createScaAdapter } = require('./sca');
const { createSemgrepAdapter } = require('./semgrep');
const { createGitleaksAdapter } = require('./gitleaks');
const { runAdapter, runAdapters, execTool } = require('./runner');
const { dedupeFindings } = require('../findings');

// Runs the given adapters against one target and returns a single scan report with
// per-scanner provenance and deduplicated findings.
async function scanTarget(target, adapters = [createScaAdapter()], opts) {
  const startedAt = new Date().toISOString();
  const scanners = await runAdapters(adapters, target, opts);
  const findings = dedupeFindings(scanners.flatMap((s) => s.findings));
  return {
    target: { path: target.path },
    startedAt,
    scanners: scanners.map(({ findings: found, raw, ...meta }) => ({ ...meta, findingCount: found.length })),
    raw: Object.fromEntries(scanners.map((s) => [s.scanner, s.raw])),
    findings,
  };
}

module.exports = { scanTarget, createScaAdapter, createSemgrepAdapter, createGitleaksAdapter, runAdapter, runAdapters, execTool };
