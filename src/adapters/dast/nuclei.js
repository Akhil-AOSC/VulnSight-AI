'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createFinding } = require('../../findings');
const { execTool } = require('../runner');
const { redactEvidence } = require('./net-guard');
const { urlInScope, normalizeUrl } = require('./scope');

const SAFE_ETAGS = 'dos,fuzz,intrusive,brute-force,oast,rce';
const FULL_ETAGS = 'dos,fuzz,brute-force,oast,rce';
const SAFE_TAGS = 'exposure,misconfig,tech,ssl,cve';

function nucleiArgs({ listFile, proxy, mode = 'safe', maxRps = 2 }) {
  const args = [
    '-list', listFile,
    '-jsonl',
    '-silent',
    '-omit-raw',
    '-no-interactsh',
    '-rate-limit', String(maxRps),
    '-c', '5',
    '-timeout', '8',
    '-retries', '0',
    '-lna',
    '-disable-update-check',
    '-tags', SAFE_TAGS,
    '-etags', mode === 'full' ? FULL_ETAGS : SAFE_ETAGS,
  ];
  if (proxy) args.push('-proxy', proxy);
  return args;
}

function normalizeCwe(id) {
  const s = String(id || '');
  if (!s) return null;
  return s.toUpperCase().startsWith('CWE-') ? s.toUpperCase() : `CWE-${s.replace(/^CWE-/i, '')}`;
}

function mapNucleiResult(row) {
  if (!row || typeof row !== 'object') return null;
  const info = row.info || {};
  const sevRaw = String(info.severity || 'info').toLowerCase();
  const severity = ['critical', 'high', 'medium', 'low'].includes(sevRaw) ? sevRaw : 'low';
  const classification = info.classification || {};
  const cwes = []
    .concat(classification['cwe-id'] || classification.cwe_id || [])
    .map(normalizeCwe)
    .filter(Boolean);
  const cves = []
    .concat(classification['cve-id'] || classification.cve_id || info.classification && info.classification['cve-id'] || [])
    .map(String)
    .filter((id) => /^CVE-\d{4}-\d+/i.test(id));
  const templateId = String(row['template-id'] || row.templateID || info.name || 'nuclei');
  const extracted = []
    .concat(row['extracted-results'] || row.extracted_results || [])
    .map(String)
    .join(' ');
  return createFinding({
    category: 'dast',
    severity,
    title: String(info.name || templateId).slice(0, 200),
    description: String(info.description || '').slice(0, 2000),
    identifiers: {
      primary: templateId,
      cwe: cwes,
      aliases: cves,
    },
    location: { url: row['matched-at'] || row.host || null },
    scanner: { name: 'nuclei', ruleId: templateId, version: row['template-path'] ? 'pinned' : '1.0' },
    remediation: { advice: String((info.remediation || 'Review the Nuclei template match and apply the documented fix.')).slice(0, 1000) },
    evidence: redactEvidence(extracted, 200),
  });
}

function isIntrusiveMatch(row) {
  const info = (row && row.info) || {};
  const tags = [].concat(info.tags || []).map((t) => String(t).toLowerCase());
  if (tags.some((t) => /intrusive|rce|dos|oast|fuzz|brute/.test(t))) return true;
  const req = String(row.request || row['curl-command'] || '');
  return /^(POST|PUT|PATCH|DELETE)\s/im.test(req);
}

function filterInScopeUrls(urls, { scope, verified, authorized } = {}) {
  if (!verified && !authorized) {
    throw new Error('Nuclei only runs against policy-authorized or DNS/HTTP-verified sites');
  }
  const out = [];
  const seen = new Set();
  for (const raw of urls || []) {
    try {
      const parsed = normalizeUrl(raw);
      if (scope && !urlInScope(parsed, scope)) continue;
      if (seen.has(parsed.href)) continue;
      seen.add(parsed.href);
      out.push(parsed.href);
    } catch {
      /* skip */
    }
  }
  return out;
}

async function runNuclei(urls, {
  limits = {},
  proxy,
  signal,
  mode = 'safe',
  scope,
  verified = false,
  authorized = false,
  exec = execTool,
  bin,
} = {}) {
  const allowed = filterInScopeUrls(urls, { scope, verified, authorized });
  if (!allowed.length) return { engine: 'nuclei', findings: [], version: null };

  let command = bin || process.env.NUCLEI_BIN;
  if (!command && exec !== execTool) command = 'nuclei';
  if (!command) {
    try {
      command = await require('../tools').ensureNuclei();
    } catch (err) {
      const skip = new Error(`Nuclei is not installed (${err.message})`);
      skip.code = 'ENGINE_SKIP';
      throw skip;
    }
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-nuclei-'));
  const listFile = path.join(dir, 'urls.txt');
  fs.writeFileSync(listFile, `${allowed.join('\n')}\n`);
  const args = nucleiArgs({ listFile, proxy, mode, maxRps: limits.maxRps || 2 });
  try {
    const { stdout } = await exec(command, args, { signal, okCodes: [0, 1, 2] });
    const findings = [];
    for (const line of String(stdout || '').split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let row;
      try {
        row = JSON.parse(trimmed);
      } catch {
        continue;
      }
      if (mode !== 'full' && isIntrusiveMatch(row)) continue;
      const finding = mapNucleiResult(row);
      if (finding) findings.push(finding);
    }
    return { engine: 'nuclei', findings, version: 'pinned', argv: args };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

module.exports = {
  runNuclei,
  mapNucleiResult,
  nucleiArgs,
  filterInScopeUrls,
  isIntrusiveMatch,
  SAFE_ETAGS,
  FULL_ETAGS,
};
