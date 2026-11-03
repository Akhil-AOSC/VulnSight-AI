'use strict';

const { LEVELS } = require('./severity');

const BASE = { critical: 10, high: 7.5, medium: 4.5, low: 1.5, unknown: 2 };

// 0-10 risk for one finding. Starts from severity and adjusts for how reachable and how fixable
// the issue is. Scanner severity is never rewritten; this is a separate, explainable number.
function findingRisk(f) {
  let score = f.cvssScore != null ? Math.max(f.cvssScore, BASE[f.severity] - 1) : BASE[f.severity];
  const factors = [];
  if (f.category === 'secret') { score += 1; factors.push('exposed credential'); }
  if (f.category === 'sca' && f.location.direct === true) { score += 0.5; factors.push('direct dependency'); }
  if (f.category === 'sca' && f.location.direct === false) { score -= 0.5; factors.push('transitive dependency'); }
  if (f.remediation && f.remediation.fixedIn) { score -= 0.25; factors.push('fix available'); }
  if (f.sources && f.sources.length > 1) { score += 0.5; factors.push(`confirmed by ${f.sources.length} scanners`); }
  if (f.status === 'suppressed' || f.status === 'fixed') score = 0;
  return { score: Math.round(Math.min(10, Math.max(0, score)) * 10) / 10, factors };
}

function countBySeverity(findings) {
  const counts = Object.fromEntries(LEVELS.map((l) => [l, 0]));
  for (const f of findings) counts[f.severity]++;
  return counts;
}

// 0-100 posture score for a set of open findings (100 = clean). Each finding costs points by
// severity with diminishing returns, so one critical matters more than a pile of lows and
// the score never goes negative.
const COST = { critical: 25, high: 10, medium: 3, low: 1, unknown: 1 };
function postureScore(findings) {
  const open = findings.filter((f) => f.status !== 'suppressed' && f.status !== 'fixed');
  let penalty = 0;
  for (const level of LEVELS) {
    const n = open.filter((f) => f.severity === level).length;
    penalty += COST[level] * Math.sqrt(n);
  }
  const score = Math.max(0, Math.round(100 - penalty));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade };
}

function summarize(findings) {
  const open = findings.filter((f) => f.status !== 'suppressed' && f.status !== 'fixed');
  const byCategory = {};
  for (const f of open) byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  return {
    total: open.length,
    bySeverity: countBySeverity(open),
    byCategory,
    fixable: open.filter((f) => f.remediation && f.remediation.fixedIn).length,
    posture: postureScore(findings),
  };
}

module.exports = { findingRisk, postureScore, summarize, countBySeverity };
