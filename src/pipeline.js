'use strict';

const { scanTarget, createScaAdapter, createSemgrepAdapter, createGitleaksAdapter } = require('./adapters');
const { createTrivyAdapter } = require('./adapters/trivy');
const { createCheckovAdapter } = require('./adapters/checkov');
const { rank } = require('./severity');

const SCANNERS = {
  sca: (o) => createScaAdapter({ options: { dev: o.dev } }),
  semgrep: (o) => createSemgrepAdapter({ config: o.semgrepConfig }),
  gitleaks: () => createGitleaksAdapter(),
  trivy: () => createTrivyAdapter({ mode: 'fs' }),
  'trivy-image': () => createTrivyAdapter({ mode: 'image' }),
  checkov: () => createCheckovAdapter(),
};
const DEFAULT_SCANNERS = ['sca', 'semgrep', 'gitleaks'];

function buildAdapters(names = DEFAULT_SCANNERS, options = {}) {
  return names.map((n) => {
    if (!SCANNERS[n]) throw new Error(`Unknown scanner "${n}". Available: ${Object.keys(SCANNERS).join(', ')}`);
    return SCANNERS[n](options);
  });
}

// Drops findings below a severity threshold ('unknown' only passes at the lowest level).
function filterBySeverity(findings, threshold = 'low') {
  const min = rank(threshold);
  return findings.filter((f) => (f.severity === 'unknown' ? min <= rank('low') : rank(f.severity) >= min));
}

async function runPipeline(target, { scanners = DEFAULT_SCANNERS, threshold = 'low', adapters, timeoutMs, ...options } = {}) {
  const report = await scanTarget(target, adapters || buildAdapters(scanners, options), { timeoutMs });
  report.findings = filterBySeverity(report.findings, threshold);
  return report;
}

module.exports = { runPipeline, buildAdapters, filterBySeverity, SCANNERS, DEFAULT_SCANNERS };
