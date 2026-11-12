'use strict';

// Matches front-end libraries detected on a website (from HTML or from the live browser runtime)
// against OSV.dev, so "outdated library" findings cite real advisories for the exact version
// instead of a hand-maintained version threshold.

const { createClient } = require('../../osv');
const { createFinding } = require('../../findings');

// Detected technology name -> npm package name used by OSV.
const NPM_PACKAGES = {
  jQuery: 'jquery',
  'jQuery UI': 'jquery-ui',
  Bootstrap: 'bootstrap',
  'Vue.js': 'vue',
  React: 'react',
  Angular: '@angular/core',
  AngularJS: 'angular',
  Lodash: 'lodash',
  'Moment.js': 'moment',
  Handlebars: 'handlebars',
  DOMPurify: 'dompurify',
  Underscore: 'underscore',
};

const VERSION = /^\d+(\.\d+){0,3}([-.][0-9A-Za-z.]+)?$/;

function osvSeverity(vuln) {
  const db = (vuln && vuln.database_specific && vuln.database_specific.severity) || '';
  const s = String(db).toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'moderate' || s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'medium';
}

const RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function fixedVersions(vuln, pkg) {
  const out = new Set();
  for (const aff of (vuln && vuln.affected) || []) {
    if (!aff.package || aff.package.name !== pkg) continue;
    for (const range of aff.ranges || []) {
      for (const ev of range.events || []) if (ev.fixed) out.add(ev.fixed);
    }
  }
  return [...out];
}

/**
 * libs: [{ name, version, source }] where source is 'html' or 'runtime'.
 * Returns findings (one per library version with known advisories). OSV failures return [].
 */
async function auditLibraries(libs, { osvClient = createClient(), pageUrl = null, scannerName = 'vulnsight-libraries' } = {}) {
  const seen = new Set();
  const targets = [];
  for (const lib of libs || []) {
    const pkg = NPM_PACKAGES[lib.name];
    const version = String(lib.version || '').trim();
    if (!pkg || !VERSION.test(version)) continue;
    const key = `${pkg}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({ lib, pkg, version });
  }
  if (!targets.length) return [];

  let idLists;
  let vulns;
  try {
    idLists = await osvClient.queryBatch(targets.map((t) => ({ package: { name: t.pkg, ecosystem: 'npm' }, version: t.version })));
    vulns = await osvClient.getVulns(idLists.flat());
  } catch {
    return [];
  }

  const findings = [];
  targets.forEach((t, i) => {
    const ids = (idLists[i] || []).filter((id) => vulns.has(id));
    if (!ids.length) return;
    const records = ids.map((id) => vulns.get(id));
    const severity = records.map(osvSeverity).sort((a, b) => RANK[b] - RANK[a])[0];
    const cves = [...new Set(records.flatMap((v) => [v.id, ...(v.aliases || [])]).filter((id) => /^CVE-/.test(id)))];
    const cwes = [...new Set(records.flatMap((v) => (v.database_specific && v.database_specific.cwe_ids) || []))];
    const fixes = [...new Set(records.flatMap((v) => fixedVersions(v, t.pkg)))];
    const summaries = records.map((v) => v.summary).filter(Boolean).slice(0, 3);
    findings.push(createFinding({
      category: 'dast',
      severity,
      title: `${t.lib.name} ${t.version} matches known CVEs (version-based, not a confirmed exploit)`,
      description: `Version-based CVE intelligence, not a confirmed exploitable vulnerability. The site loads ${t.lib.name} ${t.version} (detected from the ${t.lib.source === 'runtime' ? 'running page' : 'page HTML'}). OSV lists: ${summaries.join('; ') || ids.join(', ')}. Confirm whether the loaded build is actually vulnerable before treating this as an exploit.`,
      identifiers: { primary: cves[0] || ids[0], aliases: [...cves, ...ids].slice(0, 20), cwe: cwes, },
      location: { url: pageUrl, package: t.pkg, version: t.version, ecosystem: 'npm' },
      scanner: { name: scannerName, ruleId: `vulnerable-library-${t.pkg}`, version: '1.0' },
      remediation: {
        fixedIn: fixes.length ? fixes.sort().pop() : null,
        advice: fixes.length
          ? `Upgrade ${t.lib.name} to ${fixes.sort().pop()} or later, then retest.`
          : `Upgrade ${t.lib.name} to the latest supported release, then retest.`,
      },
      evidence: `${t.lib.name} ${t.version}; advisories: ${ids.slice(0, 8).join(', ')}`,
      confidence: 'potential',
    }));
  });
  return findings;
}

module.exports = { auditLibraries, NPM_PACKAGES };
