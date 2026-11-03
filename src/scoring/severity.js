/**
 * Severity calculation and normalization for OSV vulnerabilities.
 */

export const SEVERITY_LEVELS = {
  CRITICAL: { name: 'CRITICAL', rank: 4, minScore: 9.0 },
  HIGH: { name: 'HIGH', rank: 3, minScore: 7.0 },
  MEDIUM: { name: 'MEDIUM', rank: 2, minScore: 4.0 },
  LOW: { name: 'LOW', rank: 1, minScore: 0.1 },
  UNKNOWN: { name: 'UNKNOWN', rank: 0, minScore: 0.0 },
};

/**
 * Parses CVSS 3.x vector to calculate Base Score according to FIRST specification.
 */
function calculateCvss3BaseScore(vector) {
  if (!vector || typeof vector !== 'string') return null;

  const parts = vector.split('/');
  const metrics = {};
  for (const part of parts) {
    const [key, val] = part.split(':');
    if (key && val) {
      metrics[key] = val;
    }
  }

  // Mandatory Base metrics
  const avMap = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const acMap = { L: 0.77, H: 0.44 };
  const prMap = {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.5 },
  };
  const uiMap = { N: 0.85, R: 0.62 };
  const sMap = { U: 'U', C: 'C' };
  const impactMap = { H: 0.56, L: 0.22, N: 0 };

  const s = sMap[metrics.S] || 'U';
  const av = avMap[metrics.AV];
  const ac = acMap[metrics.AC];
  const prScope = prMap[s];
  const pr = prScope ? prScope[metrics.PR] : 0.85;
  const ui = uiMap[metrics.UI];

  const c = impactMap[metrics.C] ?? 0;
  const i = impactMap[metrics.I] ?? 0;
  const a = impactMap[metrics.A] ?? 0;

  if (av === undefined || ac === undefined || pr === undefined || ui === undefined) {
    return null;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact = 0;
  if (s === 'U') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) {
    return 0.0;
  }

  let score = 0;
  if (s === 'U') {
    score = Math.min(impact + exploitability, 10);
  } else {
    score = Math.min(1.08 * (impact + exploitability), 10);
  }

  // CVSS 3.1 rounding (round up to nearest 0.1)
  return Math.ceil(score * 10) / 10;
}

/**
 * Normalizes severity string (e.g. MODERATE -> MEDIUM)
 */
function normalizeSeverityLabel(label) {
  if (!label || typeof label !== 'string') return null;
  const upper = label.toUpperCase().trim();
  if (upper === 'MODERATE') return 'MEDIUM';
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(upper)) return upper;
  return null;
}

/**
 * Determines normalized severity and numeric CVSS score from an OSV vulnerability record.
 *
 * @param {object} vuln - OSV vulnerability record
 * @returns {{ level: string, score: number | null, vector: string | null, rank: number }}
 */
export function extractSeverity(vuln) {
  let score = null;
  let vector = null;
  let level = null;

  // 1. Check vuln.severity array (e.g., CVSS_V3, CVSS_V4)
  if (Array.isArray(vuln.severity)) {
    for (const sev of vuln.severity) {
      if (sev.score && typeof sev.score === 'string' && sev.score.startsWith('CVSS:')) {
        vector = sev.score;
        score = calculateCvss3BaseScore(sev.score);
        break;
      } else if (typeof sev.score === 'number') {
        score = sev.score;
        break;
      }
    }
  }

  // 2. Check database_specific field
  const dbSpec = vuln.database_specific;
  if (dbSpec) {
    if (!level && dbSpec.severity) {
      level = normalizeSeverityLabel(dbSpec.severity);
    }
    if (score === null && typeof dbSpec.cvss_score === 'number') {
      score = dbSpec.cvss_score;
    }
    if (score === null && typeof dbSpec.score === 'number') {
      score = dbSpec.score;
    }
  }

  // 3. Derive level from score if level is not set
  if (!level && score !== null) {
    if (score >= 9.0) level = 'CRITICAL';
    else if (score >= 7.0) level = 'HIGH';
    else if (score >= 4.0) level = 'MEDIUM';
    else if (score > 0.0) level = 'LOW';
  }

  // 4. Derive score from level if score is not set
  if (score === null && level) {
    if (level === 'CRITICAL') score = 9.5;
    else if (level === 'HIGH') score = 7.5;
    else if (level === 'MEDIUM') score = 5.5;
    else if (level === 'LOW') score = 2.5;
  }

  const finalLevel = level || 'UNKNOWN';
  const rank = SEVERITY_LEVELS[finalLevel]?.rank ?? 0;

  return {
    level: finalLevel,
    score: score !== null ? Number(score.toFixed(1)) : null,
    vector,
    rank,
  };
}

/**
 * Checks if a vulnerability level meets or exceeds the given failure threshold.
 *
 * @param {string} vulnLevel - Vulnerability level ('CRITICAL', 'HIGH', etc.)
 * @param {string} threshold - Threshold string ('critical', 'high', 'medium', 'low', 'none')
 * @returns {boolean} True if threshold is breached
 */
export function meetsThreshold(vulnLevel, threshold = 'low') {
  const normThreshold = (threshold || 'low').toLowerCase();
  if (normThreshold === 'none') {
    return false;
  }

  const thresholdRank = {
    critical: 4,
    high: 3,
    medium: 2,
    moderate: 2,
    low: 1,
    any: 1,
  }[normThreshold] ?? 1;

  const currentRank = SEVERITY_LEVELS[vulnLevel]?.rank ?? 0;
  return currentRank >= thresholdRank;
}
