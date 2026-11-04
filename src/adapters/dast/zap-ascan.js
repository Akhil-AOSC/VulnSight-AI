'use strict';

const { createFinding } = require('../../findings');
const { redactEvidence } = require('./safe-fetch');

const RISK_TO_SEVERITY = {
  3: 'high',
  2: 'medium',
  1: 'low',
  0: 'low',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  Informational: 'low',
};

/**
 * OWASP ZAP active scan (ascan). Sends attack payloads. Requires ZAP_API_URL.
 * Do not call this without verified ownership and authorizeActiveTesting.
 */
async function runZapActiveScan(targetUrl, options = {}) {
  const zapUrl = process.env.ZAP_API_URL;
  if (!zapUrl) {
    throw new Error('Active exploit scanning needs OWASP ZAP. Start ZAP and set ZAP_API_URL (optional ZAP_API_KEY). The GET-only crawler cannot run exploits.');
  }

  const onProgress = options.onProgress || (async () => {});
  const shouldStop = options.shouldStop || (async () => false);
  const base = zapUrl.replace(/\/$/, '');
  const key = process.env.ZAP_API_KEY || '';
  const qs = (path, extra = {}) => {
    const u = new URL(path, `${base}/`);
    if (key) u.searchParams.set('apikey', key);
    for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, String(v));
    return u.href;
  };
  const getJson = async (path, extra) => {
    const res = await fetch(qs(path, extra), { method: 'GET' });
    if (!res.ok) throw new Error(`ZAP API ${path} returned ${res.status}`);
    return res.json();
  };

  await onProgress({ engine: 'zap-ascan', stage: 'ascan', percent: 0 });
  const started = await getJson('/JSON/ascan/action/scan/', { url: targetUrl, recurse: 'true' });
  const scanId = started.scan;
  const deadline = Date.now() + (options.maxDurationSec || 180) * 1000;

  while (true) {
    if (await shouldStop()) {
      await getJson('/JSON/ascan/action/stop/', { scanId }).catch(() => {});
      break;
    }
    const status = await getJson('/JSON/ascan/view/status/', { scanId });
    const pct = Number(status.status || 0);
    await onProgress({ engine: 'zap-ascan', stage: 'ascan', percent: pct });
    if (pct >= 100) break;
    if (Date.now() > deadline) {
      await getJson('/JSON/ascan/action/stop/', { scanId }).catch(() => {});
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }

  const raw = await getJson('/JSON/core/view/alerts/', { baseurl: targetUrl });
  const findings = (raw.alerts || []).map(mapZapAlert).filter(Boolean);
  return { engine: 'zap-ascan', findings };
}

function mapZapAlert(alert) {
  const risk = alert.risk || alert.riskdesc || 'Low';
  const severity = RISK_TO_SEVERITY[risk] || RISK_TO_SEVERITY[String(risk).split(' ')[0]] || 'low';
  const pluginId = String(alert.pluginId || alert.alertRef || 'zap');
  return createFinding({
    category: 'dast',
    severity,
    title: String(alert.alert || alert.name || 'ZAP alert').slice(0, 200),
    description: String(alert.description || alert.other || '').slice(0, 2000),
    identifiers: { cwe: alert.cweid ? [`CWE-${alert.cweid}`] : [], primary: pluginId },
    location: { url: alert.url || alert.uri, parameter: alert.param || null },
    scanner: { name: 'owasp-zap-ascan', ruleId: pluginId, version: '1.0' },
    remediation: { advice: String(alert.solution || 'Review the ZAP alert and apply the recommended server-side fix.').slice(0, 1000) },
    evidence: redactEvidence(String(alert.evidence || alert.attack || ''), 200),
  });
}

module.exports = { runZapActiveScan, mapZapAlert };
