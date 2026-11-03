'use strict';

const { createClient } = require('./osv');
const { severityOf, rank } = require('./severity');
const { compareVersions } = require('./versions');
const { normalizeName } = require('./parsers/python');

function samePackage(ecosystem, a, b) {
  return ecosystem === 'PyPI' ? normalizeName(a) === normalizeName(b) : a === b;
}

// The lowest "fixed" version above the installed one, for this package only.
function findFixedVersion(vuln, dep) {
  const fixes = [];
  for (const affected of vuln.affected || []) {
    const pkg = affected.package || {};
    if (pkg.ecosystem !== dep.ecosystem || !samePackage(dep.ecosystem, pkg.name, dep.name)) continue;
    for (const range of affected.ranges || []) {
      if (range.type === 'GIT') continue;
      for (const event of range.events || []) {
        if (event.fixed) fixes.push(event.fixed);
      }
    }
  }
  return fixes.filter((f) => compareVersions(f, dep.version) > 0).sort(compareVersions)[0] || null;
}

// OSV often returns the same issue under several IDs (GHSA-..., PYSEC-..., CVE-...).
// Group them so each real issue is reported once.
function groupAliases(vulns) {
  const groups = [];
  const byKey = new Map();
  const keysOf = (v) => [v.id, ...(v.aliases || [])];

  for (const vuln of vulns) {
    const hits = [...new Set(keysOf(vuln).map((k) => byKey.get(k)).filter(Boolean))];
    let group;
    if (!hits.length) {
      group = [];
      groups.push(group);
    } else {
      group = hits[0];
      for (const other of hits.slice(1)) {
        group.push(...other);
        groups.splice(groups.indexOf(other), 1);
        for (const member of other) for (const k of keysOf(member)) byKey.set(k, group);
      }
    }
    group.push(vuln);
    for (const k of keysOf(vuln)) byKey.set(k, group);
  }
  return groups;
}

function titleOf(vuln) {
  if (vuln.summary) return vuln.summary.trim();
  const firstLine = (vuln.details || '').trim().split('\n')[0];
  return firstLine ? firstLine.slice(0, 120) : null;
}

function buildIssues(dep, vulns) {
  const live = vulns.filter((v) => !v.withdrawn);
  return groupAliases(live).map((group) => {
    const primary = group.find((v) => v.id.startsWith('GHSA-')) || group[0];
    const severities = group.map(severityOf);
    const best = severities.reduce((a, b) => (rank(b.level) > rank(a.level) ? b : a));
    const score = severities.map((s) => s.score).find((s) => s !== null);
    const fixes = group.map((v) => findFixedVersion(v, dep)).filter(Boolean).sort(compareVersions);
    const ids = new Set(group.flatMap((v) => [v.id, ...(v.aliases || [])]));
    ids.delete(primary.id);

    return {
      id: primary.id,
      aliases: [...ids].sort(),
      title: titleOf(primary) || group.map(titleOf).find(Boolean) || primary.id,
      severity: best.level,
      cvssScore: score === undefined ? null : score,
      package: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      fixedIn: fixes[0] || null,
      url: `https://osv.dev/vulnerability/${primary.id}`,
    };
  });
}

// Scans every project with a single batched OSV lookup.
async function scanProjects(projects, { client = createClient() } = {}) {
  const keyOf = (d) => `${d.ecosystem}|${d.name}|${d.version}`;
  const unique = new Map();
  for (const project of projects) {
    for (const dep of project.dependencies) unique.set(keyOf(dep), dep);
  }
  const deps = [...unique.values()];

  const idLists = deps.length
    ? await client.queryBatch(deps.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })))
    : [];
  const vulnMap = await client.getVulns(idLists.flat());

  const issuesByKey = new Map();
  deps.forEach((dep, i) => {
    const vulns = idLists[i].map((id) => vulnMap.get(id)).filter(Boolean);
    issuesByKey.set(keyOf(dep), buildIssues(dep, vulns));
  });

  return projects.map((project) => ({
    ...project,
    issues: project.dependencies.flatMap((dep) =>
      issuesByKey.get(keyOf(dep)).map((issue) => ({ ...issue, direct: dep.direct, paths: dep.paths }))),
  }));
}

// Drops issues below the threshold. Issues without a severity rating are
// only kept at the lowest threshold.
function applyThreshold(results, threshold = 'low') {
  const minRank = rank(threshold);
  return results.map((r) => ({
    ...r,
    issues: r.issues.filter((i) => (i.severity === 'unknown' ? minRank <= rank('low') : rank(i.severity) >= minRank)),
  }));
}

module.exports = { scanProjects, applyThreshold, buildIssues, findFixedVersion, groupAliases };
