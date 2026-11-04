'use strict';

const crypto = require('crypto');
const { LEVELS, rank } = require('./severity');

// Unified finding model shared by every scanner adapter.
//
//   id           stable fingerprint (same issue in the same place -> same id)
//   category     sca | sast | secret | container | iac
//   scanner      { name, version, ruleId }  original scanner provenance
//   title, description
//   severity     one of LEVELS; cvssScore is null when the scanner gave none
//   identifiers  { primary, aliases[], cwe[] }  CVE / GHSA / OSV / CWE ids
//   location     { file, line, endLine, package, version, ecosystem, direct, paths[] }
//   remediation  { fixedIn, advice }
//   evidence     scanner-provided snippet or detail. Secrets must already be redacted.
//   url          link to the source advisory
//   status       open | acknowledged | suppressed | fixed (lifecycle, set by the platform)
//   aiAnalysis   always null here: AI commentary is stored separately, never mixed
//                with scanner facts
const CATEGORIES = ['sca', 'sast', 'secret', 'container', 'iac', 'dast'];
const STATUSES = ['open', 'acknowledged', 'suppressed', 'fixed'];

function fingerprint(parts) {
  const text = parts.map((p) => (p == null ? '' : String(p))).join('|');
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, 16);
}

function createFinding(input) {
  const f = {
    category: input.category,
    scanner: { name: null, version: null, ruleId: null, ...input.scanner },
    title: input.title,
    description: input.description || null,
    severity: input.severity || 'unknown',
    cvssScore: input.cvssScore == null ? null : input.cvssScore,
    identifiers: { primary: null, aliases: [], cwe: [], ...input.identifiers },
    location: {
      file: null, line: null, endLine: null, package: null, version: null,
      ecosystem: null, direct: null, paths: [], url: null, method: null, parameter: null,
      ...input.location,
    },
    remediation: { fixedIn: null, advice: null, ...input.remediation },
    evidence: input.evidence == null ? null : input.evidence,
    url: input.url || null,
    status: input.status || 'open',
    aiAnalysis: null,
  };

  if (!CATEGORIES.includes(f.category)) throw new Error(`Invalid finding category: ${f.category}`);
  if (!LEVELS.includes(f.severity)) throw new Error(`Invalid finding severity: ${f.severity}`);
  if (!STATUSES.includes(f.status)) throw new Error(`Invalid finding status: ${f.status}`);
  if (!f.title) throw new Error('A finding needs a title');

  const loc = f.location;
  f.id = fingerprint([
    f.category, f.identifiers.primary || f.scanner.ruleId,
    loc.file, loc.line, loc.package, loc.version, loc.ecosystem, loc.url, loc.parameter,
  ]);
  return f;
}

// SCA scanner issue (from src/scanner.js) -> unified Finding.
function fromScaIssue(issue, { file, scannerVersion = null } = {}) {
  return createFinding({
    category: 'sca',
    scanner: { name: 'osv', version: scannerVersion, ruleId: issue.id },
    title: issue.title,
    severity: issue.severity,
    cvssScore: issue.cvssScore,
    identifiers: { primary: issue.id, aliases: issue.aliases },
    location: {
      file,
      package: issue.package,
      version: issue.version,
      ecosystem: issue.ecosystem,
      direct: issue.direct,
      paths: issue.paths || [],
    },
    remediation: { fixedIn: issue.fixedIn },
    url: issue.url,
  });
}

// The same issue reported by several scanners/runs becomes one finding. Alias overlap counts,
// so a GHSA from one scanner merges with the CVE from another at the same place. The first
// finding's fields win except severity (highest wins); every contributing scanner is kept in
// `sources`. Inputs are not mutated.
function dedupeFindings(findings) {
  const out = [];
  const byKey = new Map();
  const keysOf = (f) => {
    const loc = f.location;
    const place = [f.category, loc.file, loc.line, loc.package, loc.version].join('|');
    const ids = [f.identifiers.primary, ...f.identifiers.aliases].filter(Boolean);
    return [f.id, ...ids.map((i) => `${i}@${place}`)];
  };

  for (const f of findings) {
    const existing = keysOf(f).map((k) => byKey.get(k)).find(Boolean);
    if (existing) {
      if (rank(f.severity) > rank(existing.severity)) {
        existing.severity = f.severity;
        existing.cvssScore = f.cvssScore;
      }
      const ids = [...existing.identifiers.aliases, f.identifiers.primary, ...f.identifiers.aliases];
      existing.identifiers.aliases = [...new Set(ids)].filter((i) => i && i !== existing.identifiers.primary).sort();
      existing.remediation.fixedIn = existing.remediation.fixedIn || f.remediation.fixedIn;
      existing.sources.push(f.scanner);
      for (const k of keysOf(f)) byKey.set(k, existing);
    } else {
      const copy = {
        ...f,
        identifiers: { ...f.identifiers, aliases: [...f.identifiers.aliases] },
        remediation: { ...f.remediation },
        sources: [f.scanner],
      };
      out.push(copy);
      for (const k of keysOf(copy)) byKey.set(k, copy);
    }
  }
  return out;
}

module.exports = { CATEGORIES, STATUSES, createFinding, fromScaIssue, dedupeFindings, fingerprint };
