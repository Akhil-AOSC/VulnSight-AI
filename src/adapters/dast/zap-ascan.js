'use strict';

const { createFinding } = require('../../findings');
const { redactEvidence, droppedMessage } = require('./net-guard');
const { elevateToCritical } = require('./severity-class');
const { isZapNoiseAlert } = require('./deep-options');
const {
  zapGet, withZapMutex, prepareZapSession, getZapSession, ensureInScanTree, countZapResponses,
} = require('./zap-client');

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
 * Pipeline must pass allowActive after stored allowActiveTesting is confirmed.
 */
async function runZapActiveScan(targetUrl, options = {}) {
  if (options.allowActive !== true) {
    const err = new Error('Active ZAP scanning requires stored allowActiveTesting on the current authorization');
    err.code = 'UNAUTHORIZED';
    throw err;
  }
  if (!process.env.ZAP_API_URL) {
    throw new Error('Active exploit scanning needs OWASP ZAP. Start ZAP and set ZAP_API_URL (optional ZAP_API_KEY). The GET-only crawler cannot run exploits.');
  }

  const onProgress = options.onProgress || (async () => {});
  const shouldStop = options.shouldStop || (async () => false);

  return withZapMutex(async () => {
    const session = options.zapSession || getZapSession() || await prepareZapSession({
      scope: options.scope,
      proxyUrl: options.proxy,
      maxRps: options.maxRps || 1,
      sessionCookie: options.sessionCookie,
      sessionHeader: options.sessionHeader,
    });
    const seeds = [...new Set([
      targetUrl,
      ...((session && session.urls) || []),
      ...(options.seedUrls || []),
    ])].filter(Boolean);

    await zapGet('/JSON/ascan/action/enableAllScanners/').catch(() => {});
    // Enable injection / SSRF / XSS / path-traversal scanners before the first ascan tick.
    await zapGet('/JSON/ascan/action/enableScanners/', {
      ids: '40018,40012,40014,40016,40017,40019,40026,40046,40047,6,7,41,40009,40032,40043,90019,90020',
    }).catch(() => {});
    await zapGet('/JSON/pscan/action/enableAllScanners/').catch(() => {});

    async function startScan(url) {
      const scanArgs = { url, recurse: 'true' };
      if (session && session.contextId) scanArgs.contextId = session.contextId;
      try {
        return await zapGet('/JSON/ascan/action/scan/', scanArgs);
      } catch (err) {
        if (!/400/.test(String(err.message))) throw err;
        return zapGet('/JSON/ascan/action/scan/', { url, recurse: 'true' });
      }
    }

    let started;
    let scanUrl;
    let lastErr;
    for (const url of seeds) {
      try {
        started = await startScan(url);
        scanUrl = url;
        break;
      } catch (err) {
        lastErr = err;
        if (!/400/.test(String(err.message))) throw err;
      }
    }
    if (!started) {
      scanUrl = await ensureInScanTree(targetUrl, { timeoutMs: 6000, seedUrls: seeds });
      if (scanUrl) {
        try {
          started = await startScan(scanUrl);
        } catch (err) {
          lastErr = err;
        }
      }
    }
    if (!started) {
      // Tell the user WHY there is nothing to attack. Zero stored responses means ZAP's requests
      // never got an answer: the host (usually its firewall) is dropping them.
      const responses = await countZapResponses(targetUrl);
      if (responses === 0) {
        let host = targetUrl;
        try { host = new URL(targetUrl).hostname; } catch { /* keep raw */ }
        const err = new Error(`${droppedMessage(host, 'ZAP stored no responses from the host')} No attack payloads were sent.`);
        err.code = 'HOST_DROPPED';
        throw err;
      }
      throw lastErr || new Error('ZAP sites tree still empty after spider. The origin may be blocking ZAP; active scan cannot start.');
    }

    await onProgress({ engine: 'zap-ascan', stage: 'ascan', percent: 0 });
    const scanId = started.scan;
    let percent = 0;

    while (true) {
      if (await shouldStop()) {
        await zapGet('/JSON/ascan/action/stop/', { scanId }).catch(() => {});
        break;
      }
      const status = await zapGet('/JSON/ascan/view/status/', { scanId });
      const pct = Number(status.status || 0);
      percent = pct;
      await onProgress({ engine: 'zap-ascan', stage: 'ascan', percent: pct });
      if (pct >= 100) break;
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }

    const raw = await zapGet('/JSON/core/view/alerts/', {
      baseurl: targetUrl,
      contextId: session.contextId,
    });
    const findings = (raw.alerts || []).map(mapZapAlert).filter(Boolean);
    return {
      engine: 'zap-ascan',
      findings,
      version: 'owasp-zap',
      percent,
    };
  });
}

function mapZapAlert(alert) {
  if (isZapNoiseAlert(alert)) return null;
  const risk = alert.risk || alert.riskdesc || 'Low';
  const title = String(alert.alert || alert.name || 'ZAP alert').slice(0, 200);
  const cwes = alert.cweid && String(alert.cweid) !== '0' ? [`CWE-${alert.cweid}`] : [];
  const severity = elevateToCritical(
    RISK_TO_SEVERITY[risk] || RISK_TO_SEVERITY[String(risk).split(' ')[0]] || 'low',
    { cwes, title },
  );
  const pluginId = String(alert.pluginId || alert.alertRef || 'zap');
  const zapUid = [pluginId, alert.id, alert.url || alert.uri, alert.param, String(alert.evidence || alert.attack || '').slice(0, 48)].join(':');
  return createFinding({
    category: 'dast',
    severity,
    title,
    description: String(alert.description || alert.other || '').slice(0, 2000),
    identifiers: { cwe: cwes, primary: zapUid },
    location: { url: alert.url || alert.uri, parameter: alert.param || null },
    scanner: { name: 'owasp-zap-ascan', ruleId: pluginId, version: '1.0' },
    remediation: { advice: String(alert.solution || 'Review the ZAP alert and apply the recommended server-side fix.').slice(0, 1000) },
    evidence: redactEvidence(String(alert.evidence || alert.attack || ''), 200),
  });
}

module.exports = { runZapActiveScan, mapZapAlert };
