'use strict';

const ENGINES = {
  'vulnsight-passive': {
    label: 'Passive recon',
    does: 'Reads TLS, cookies, and security headers from this machine. No crawl and no attack payloads.',
  },
  'vulnsight-browser': {
    label: 'Browser crawl',
    does: 'Chromium loads JavaScript-rendered pages and records in-scope URLs. Forms are not submitted.',
  },
  'owasp-zap-spider': {
    label: 'ZAP spider',
    does: 'OWASP ZAP maps in-scope GET pages through its own HTTP client.',
  },
  'builtin-get': {
    label: 'GET crawler',
    does: 'Follows HTML links with GET only when ZAP is not configured.',
  },
  'vulnsight-checks': {
    label: 'Exposure checks',
    does: 'Requests known debug, API-doc, config-backup and directory-listing paths, and reviews crawled URLs and forms. GET only, rate-limited, authorized sites only.',
  },
  nuclei: {
    label: 'Nuclei templates',
    does: 'Runs pinned Nuclei templates on discovered URLs. Interactsh and DoS templates stay off.',
  },
  'owasp-zap-ascan': {
    label: 'ZAP active scan',
    does: 'Sends ZAP attack payloads at URLs already in the ZAP sites tree. Ownership verification is required.',
  },
};

function explainEngine(eng = {}) {
  const meta = ENGINES[eng.name] || { label: eng.name || 'Engine', does: 'Inspection engine.' };
  const err = String(eng.error || '');
  let why = 'Finished.';
  if (eng.status === 'skipped') {
    why = err || 'Not installed, or not selected for this profile.';
  } else if (eng.status === 'blocked') {
    if (eng.blockReason === 'connection_dropped' || /stopped answering|dropping connections/i.test(err)) {
      why = 'The host stopped answering this machine: connections timed out with no HTTP response. Its firewall has most likely banned the scanner IP, so results from this stage are missing or incomplete.';
    } else if (eng.blockReason === 'waf' || /^blocked by /i.test(err)) {
      const provider = err.replace(/^blocked by /i, '').trim();
      const named = provider && provider.toUpperCase() !== 'WAF' ? ` (${provider})` : '';
      why = `The site's firewall${named} answered with a bot challenge instead of the page, so header, cookie and technology checks were skipped. TLS results were kept. To scan your own site fully, allow the scanner IP in that firewall.`;
    } else {
      why = err || 'The origin blocked this engine.';
    }
  } else if (eng.status === 'partial') {
    why = err || 'Stopped before every check ran. Findings so far are real; the rest is untested.';
  } else if (eng.status === 'error') {
    if (/ETIMEDOUT|timed out|timeout/i.test(err)) {
      why = 'Requests to the host timed out. The host may be down or rate-limiting this machine.';
    } else if (/No page loaded/i.test(err)) {
      why = 'The engine ran but no page loaded, so its zero findings say nothing about the site.';
    } else if (/sites tree|scan tree|url_not_found/i.test(err)) {
      why = 'ZAP had no pages from this host in its sites tree, so no attack payloads were sent.';
    } else {
      why = err || 'Engine failed.';
    }
  }
  return {
    name: eng.name,
    label: meta.label,
    does: meta.does,
    status: eng.status || 'unknown',
    findings: eng.findings || 0,
    detail: err || null,
    why,
    durationMs: eng.durationMs || 0,
  };
}

function buildScanStory({
  engines = [],
  partial = false,
  blockedBy = null,
  profile = null,
  pages = 0,
  findings = 0,
} = {}) {
  const stages = (engines || []).map(explainEngine);
  const unfinished = stages.filter((s) => {
    if (!['error', 'blocked', 'skipped', 'partial'].includes(s.status)) return false;
    if (s.status === 'skipped' && /Public Website Assessment does not execute/i.test(s.detail || '')) return false;
    if (profile === 'public' && s.name === 'vulnsight-passive' && s.status === 'blocked') return false;
    return true;
  });
  if (!partial) {
    return {
      headline: 'Inspection finished',
      readout: `Profile ${profile || 'scan'} finished with ${findings} finding${findings === 1 ? '' : 's'} across ${pages} page${pages === 1 ? '' : 's'}.`,
      profile: profile || null,
      stages,
    };
  }
  let blockedBit = '';
  if (blockedBy === 'host firewall') {
    blockedBit = ' The host started dropping connections from this machine (likely a firewall IP ban), so the scan stopped early. Allowlist the scanner IP in the hosting firewall or wait for the ban to expire, then scan again.';
  } else if (blockedBy) {
    blockedBit = ` An engine stopped after a ${blockedBy} challenge.`;
  }
  return {
    headline: 'Incomplete inspection',
    readout: `${unfinished.length} engine${unfinished.length === 1 ? '' : 's'} did not finish.${blockedBit} Posture is not a clean bill of health.`,
    profile: profile || null,
    stages,
  };
}

module.exports = { ENGINES, explainEngine, buildScanStory };
