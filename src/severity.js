'use strict';

const LEVELS = ['unknown', 'low', 'medium', 'high', 'critical'];

const LABELS = { LOW: 'low', MODERATE: 'medium', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };

function rank(level) {
  return Math.max(0, LEVELS.indexOf(level));
}

function levelFromScore(score) {
  if (score === null || score === undefined) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

// CVSS v3.x "round up" as defined in the spec (avoids floating point drift).
function roundUp(value) {
  const int = Math.round(value * 100000);
  if (int % 10000 === 0) return int / 100000;
  return (Math.floor(int / 10000) + 1) / 10;
}

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
};

// Base score from a CVSS v3.0/v3.1 vector, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
function cvss3Score(vector) {
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:3')) return null;
  const m = {};
  for (const part of vector.split('/').slice(1)) {
    const [key, value] = part.split(':');
    m[key] = value;
  }
  const scope = m.S;
  const av = WEIGHTS.AV[m.AV];
  const ac = WEIGHTS.AC[m.AC];
  const ui = WEIGHTS.UI[m.UI];
  const pr = scope && WEIGHTS.PR[scope] && WEIGHTS.PR[scope][m.PR];
  const c = WEIGHTS.CIA[m.C];
  const i = WEIGHTS.CIA[m.I];
  const a = WEIGHTS.CIA[m.A];
  if ([av, ac, ui, pr, c, i, a].some((w) => w === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scope === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scope === 'U' ? impact + exploitability : 1.08 * (impact + exploitability);
  return roundUp(Math.min(raw, 10));
}

// Prefers the advisory's own rating (e.g. GitHub's), falling back to the CVSS score.
function severityOf(vuln) {
  let score = null;
  for (const s of vuln.severity || []) {
    if (s.type === 'CVSS_V3') {
      score = cvss3Score(s.score);
      if (score !== null) break;
    }
  }

  let level = LABELS[String((vuln.database_specific || {}).severity).toUpperCase()];
  for (const affected of vuln.affected || []) {
    if (level) break;
    level = LABELS[String((affected.ecosystem_specific || {}).severity).toUpperCase()]
      || LABELS[String((affected.database_specific || {}).severity).toUpperCase()];
  }

  return { level: level || levelFromScore(score), score };
}

module.exports = { LEVELS, rank, levelFromScore, cvss3Score, severityOf };
