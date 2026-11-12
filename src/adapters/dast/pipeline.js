'use strict';

const { runPassiveScan } = require('./passive');
const { runWebsiteCrawl } = require('./zap-spider');
const { runZapActiveScan } = require('./zap-ascan');
const { normalizeProfile, normalizeLimits, normalizeScope, urlInScope, normalizeUrl, profileNeeds, PUBLIC_DISCOVERY_LIMITS } = require('./scope');
const { evaluateScanAuthorization, scopeFromAccess } = require('../../platform/authorization-policy');
const { createEgressProxy } = require('../../platform/egress-proxy');
const { buildScanStory } = require('./scan-story');
const { classifyNetworkError, droppedMessage, probeReachable, HOST_FIREWALL } = require('./net-guard');

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const VERIFY_TTL_MS = 90 * 24 * 3600 * 1000;

function isVerificationFresh(verifiedAt, now = Date.now()) {
  if (!verifiedAt) return false;
  const t = Date.parse(verifiedAt);
  if (!Number.isFinite(t)) return false;
  return (now - t) < VERIFY_TTL_MS;
}

function findingKey(f) {
  const id = f.identifiers || {};
  const cwe = (id.cwe && id.cwe[0]) || '';
  const family = String(id.primary || (f.scanner && f.scanner.ruleId) || f.title || '')
    .replace(/[-_]\d+$/, '')
    .toLowerCase();
  const loc = f.location || {};
  let path = loc.path || '';
  try {
    if (loc.url) path = new URL(loc.url).pathname || path;
  } catch {
    /* keep path */
  }
  return `${cwe || family}|${path}|${loc.parameter || ''}`;
}

function dedupeDastFindings(findings) {
  const map = new Map();
  for (const f of findings || []) {
    const key = findingKey(f);
    const name = f.scanner && f.scanner.name;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, { ...f, confirmedBy: name ? [name] : [] });
      continue;
    }
    const names = new Set([...(existing.confirmedBy || []), name].filter(Boolean));
    const keep = (SEV_RANK[f.severity] || 0) > (SEV_RANK[existing.severity] || 0) ? { ...f } : existing;
    map.set(key, { ...keep, confirmedBy: [...names] });
  }
  return [...map.values()];
}

function collectUrls(inventory, fallback, scope, maxPages) {
  const out = [];
  const seen = new Set();
  const add = (raw) => {
    if (!raw || out.length >= (maxPages || 80)) return;
    try {
      const parsed = normalizeUrl(raw);
      if (scope && !urlInScope(parsed, scope)) return;
      if (seen.has(parsed.href)) return;
      seen.add(parsed.href);
      out.push(parsed.href);
    } catch {
      /* skip */
    }
  };
  add(fallback);
  for (const page of (inventory && inventory.pages) || []) add(page.url);
  for (const ep of (inventory && inventory.endpoints) || []) add(ep.url);
  return out;
}

/**
 * Runs one engine and turns its outcome into an engine status row.
 *   ok       the engine got responses from the host
 *   blocked  a WAF challenge, or the host dropped our connections (likely an IP ban)
 *   error    the engine failed, or ran but never got a single response
 *   skipped  not installed / not applicable
 * An engine that "finished" without one successful response is never reported as ok, because
 * zero findings from zero responses says nothing about the site.
 */
async function runStage(name, fn) {
  const t0 = Date.now();
  try {
    const result = await fn();
    const count = (result && result.findings && result.findings.length) || 0;
    const reach = result && result.reachability;
    const nothingLoaded = Boolean(reach && reach.attempted > 0 && reach.loaded === 0);
    let status = 'ok';
    let error = null;
    let blockReason = null;
    if (result && result.blocked) {
      status = 'blocked';
      error = `blocked by ${blockerOf(result)}`;
      blockReason = 'waf';
    } else if (nothingLoaded) {
      const kind = classifyNetworkError(reach.lastError || '');
      if (kind === 'dropped') {
        status = 'blocked';
        blockReason = 'connection_dropped';
        error = droppedMessage(null, reach.lastError);
      } else {
        status = 'error';
        error = `No page loaded (${reach.attempted} tried): ${String(reach.lastError || 'no response').slice(0, 160)}`;
      }
    } else if (result && result.fetchError) {
      status = 'error';
      error = result.fetchError;
    } else if (result && result.timedOut) {
      // Ran, but its time limit stopped it before all checks ran: findings so far are real,
      // the rest of the attack surface is untested.
      status = 'partial';
      const pct = Number.isFinite(Number(result.percent)) ? `${Math.round(Number(result.percent))}%` : 'part way';
      error = `Stopped at ${pct} when it reached its ${result.maxDurationSec || '?'}-second time limit. `
        + 'The remaining checks did not run. Raise the scan duration (up to 900 seconds) in the website settings to cover them.';
    }
    return {
      engine: {
        name,
        version: (result && (result.version || result.engine)) || null,
        status,
        durationMs: Date.now() - t0,
        findings: count,
        error,
        ...(blockReason ? { blockReason } : {}),
      },
      result,
    };
  } catch (err) {
    const skipped = err && err.code === 'ENGINE_SKIP';
    const dropped = !skipped && (err.code === 'HOST_DROPPED' || classifyNetworkError(err) === 'dropped');
    return {
      engine: {
        name,
        version: null,
        status: skipped ? 'skipped' : (dropped ? 'blocked' : 'error'),
        durationMs: Date.now() - t0,
        findings: 0,
        error: dropped && err.code !== 'HOST_DROPPED'
          ? droppedMessage(null, err.code || err.message)
          : String(err.message || err).slice(0, 400),
        ...(dropped ? { blockReason: 'connection_dropped' } : {}),
      },
      result: null,
    };
  }
}

const isDropped = (engine) => Boolean(engine && engine.blockReason === 'connection_dropped');

/**
 * Name of whatever blocked an engine. Engines report it as `blockedBy: 'Cloudflare'`; older
 * results carry `blocked: { by }` instead. Falls back to 'WAF' when no provider was recognised.
 */
function blockerOf(result) {
  if (!result) return 'WAF';
  if (typeof result.blockedBy === 'string' && result.blockedBy) return result.blockedBy;
  if (result.blocked && typeof result.blocked === 'object' && result.blocked.by) return result.blocked.by;
  return 'WAF';
}

/**
 * Authorized-site checks: well-known exposed paths (debug endpoints, API docs, config backups,
 * directory listing) plus a review of the crawled URLs and forms. Returns the engine-result shape.
 */
async function runSiteChecks(target, { inventory, shouldStop } = {}) {
  const { probeSensitivePaths } = require('./crawler');
  const { reviewInventory } = require('./skill-checks');
  const probed = await probeSensitivePaths(target, { shouldStop: shouldStop || (async () => false) });
  const findings = [...probed.findings, ...reviewInventory(inventory)];
  return {
    engine: 'vulnsight-checks',
    version: '1.0',
    findings,
    ...(probed.blocked ? { blocked: true, blockedBy: probed.blocked.by || 'WAF' } : {}),
  };
}

function notRun(name, reason) {
  return { name, version: null, status: 'skipped', durationMs: 0, findings: 0, error: reason };
}

async function startEgress(scope) {
  const allow = [...new Set([...(scope.allowHosts || []), ...(scope.extraHosts || [])])];
  const server = createEgressProxy({
    allow,
    ports: [80, 443],
    extraAllow: () => [],
    allowPlainGet: true,
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  return {
    proxyUrl: `http://127.0.0.1:${addr.port}`,
    stop: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

function loadOptional(loader) {
  try {
    return loader();
  } catch {
    return null;
  }
}

async function runDastPipeline(site, scan, deps = {}) {
  const dastPassive = deps.dastPassive || runPassiveScan;
  const dastCrawl = deps.dastCrawl || runWebsiteCrawl;
  const dastAscan = deps.dastAscan || runZapActiveScan;
  const dastBrowser = deps.dastBrowser === undefined
    ? loadOptional(() => require('./browser-crawl').runBrowserCrawl)
    : deps.dastBrowser;
  const dastNuclei = deps.dastNuclei === undefined
    ? loadOptional(() => require('./nuclei').runNuclei)
    : deps.dastNuclei;

  const profile = (() => {
    try {
      return normalizeProfile(scan.profile, {
        allowAscan: Boolean(scan.authorizeActiveTesting) || scan.profile === 'ascan' || scan.profile === 'deep',
      });
    } catch {
      return scan.profile;
    }
  })();
  const siteConfig = scan.siteConfig || {};
  const limits = normalizeLimits({ ...siteConfig, ...(scan.limits || {}) });
  let scope = normalizeScope(site.hostname, siteConfig);
  const stages = profileNeeds(profile);

  async function resolveAccess() {
    if (deps.resolveAccess) return deps.resolveAccess({ site, scan, profile, scope });
    return evaluateScanAuthorization({
      site,
      profile,
      grant: scan.grant || null,
      orgPolicies: scan.orgPolicies || [],
    });
  }

  let access;
  let accessError = null;
  try {
    access = await resolveAccess();
  } catch (err) {
    accessError = err;
    access = { allowed: false, source: null, allowActive: false, nucleiMode: null };
    if (stages.crawl && err.code !== 'UNAUTHORIZED' && err.code !== 'CANCELLED') throw err;
  }
  if (stages.publicDiscovery || !stages.crawl) {
    access = {
      ...access,
      allowActive: false,
      nucleiMode: null,
      assessmentKind: access.allowed === false ? access.assessmentKind : 'public_assessment',
    };
  }
  if (access.grant || access.policy) scope = scopeFromAccess(scope, access, site.hostname);

  const verified = access.source === 'dns_http';
  const AUTH_SOURCES = new Set(['dns_http', 'client_grant', 'org_engagement', 'lab']);
  const authorized = Boolean(access.allowed && AUTH_SOURCES.has(access.source));
  const engines = [];
  let findings = [];
  let inventory = null;
  let blockedBy = null;
  let partial = false;

  const passive = await runStage('vulnsight-passive', () => dastPassive(site.target_url || site.targetUrl, {
    timeoutMs: 25000,
    verified,
  }));
  engines.push(passive.engine);

  // Once the host starts dropping our connections (usually a firewall IP ban), every further
  // request only extends the ban and produces empty "ok" results. Check between stages and stop.
  const target = site.target_url || site.targetUrl;
  // Real runs probe the network; runs with injected fake engines (tests) don't, unless given a probe.
  const fakeEngines = Boolean(deps.dastPassive && deps.dastPassive !== runPassiveScan);
  const probe = deps.probeReachable || (fakeEngines ? async () => ({ ok: true }) : probeReachable);
  const dastChecks = deps.dastChecks !== undefined ? deps.dastChecks : (fakeEngines ? null : runSiteChecks);
  let hostDropped = isDropped(passive.engine);
  async function stillAnswering(engine) {
    if (hostDropped) return false;
    if (isDropped(engine)) {
      hostDropped = true;
      return false;
    }
    const check = await probe(target);
    if (!check.ok && check.kind === 'dropped') {
      hostDropped = true;
      if (engine && engine.status === 'ok') {
        engine.status = 'blocked';
        engine.blockReason = 'connection_dropped';
        engine.error = `The host started dropping connections during this stage, so its results are incomplete. ${check.message}`;
      }
      return false;
    }
    return true;
  }
  const stopReason = () => 'Not run: the host was dropping connections from this machine (likely a firewall IP ban). Allowlist the scanner IP or wait for the ban to expire, then scan again.';

  if (passive.result) {
    if (passive.result.blocked) {
      partial = true;
      blockedBy = blockerOf(passive.result);
      // When the page is a WAF challenge, passive recon skips everything read from that page.
      // What it still returns comes from the TLS handshake and a separate plain-HTTP check, which
      // the challenge doesn't affect, so those findings stay.
      findings = findings.concat(passive.result.findings || []);
    } else {
      findings = findings.concat(passive.result.findings || []);
      inventory = passive.result.inventory || inventory;
    }
  }

  const publicSkip = 'Not run: Public Website Assessment does not execute ZAP Spider, Nuclei, or ZAP Active Scan.';
  if (stages.publicDiscovery) {
    if (access.allowed === false) {
      const denied = (accessError && accessError.message)
        || 'This hostname is denied by an organization authorization policy';
      engines.push(notRun('vulnsight-browser', denied));
    } else if (hostDropped) {
      engines.push(notRun('vulnsight-browser', stopReason()));
    } else if (!dastBrowser) {
      engines.push(notRun('vulnsight-browser', 'Playwright is not available for public page discovery'));
      partial = true;
    } else {
      const publicLimits = {
        maxPages: Math.min(limits.maxPages || PUBLIC_DISCOVERY_LIMITS.maxPages, PUBLIC_DISCOVERY_LIMITS.maxPages),
        maxDepth: Math.min(limits.maxDepth || PUBLIC_DISCOVERY_LIMITS.maxDepth, PUBLIC_DISCOVERY_LIMITS.maxDepth),
        maxDurationSec: Math.min(limits.maxDurationSec || PUBLIC_DISCOVERY_LIMITS.maxDurationSec, PUBLIC_DISCOVERY_LIMITS.maxDurationSec),
        maxRps: PUBLIC_DISCOVERY_LIMITS.maxRps,
      };
      if (typeof deps.onProgress === 'function') {
        await deps.onProgress({ stage: 'crawling', engine: 'vulnsight-browser', pages: 0 });
      }
      const br = await runStage('vulnsight-browser', () => dastBrowser(target, {
        scope,
        ...publicLimits,
        publicMode: true,
        onProgress: deps.onProgress,
        shouldStop: deps.shouldStop,
      }));
      engines.push(br.engine);
      if (br.result) {
        if (br.result.pages && br.result.pages.length && !(br.result.reachability && br.result.reachability.loaded === 0)) {
          inventory = br.result;
        }
        findings = findings.concat(br.result.findings || []);
        if (br.result.blocked) {
          partial = true;
          blockedBy = blockerOf(br.result);
        }
      }
      await stillAnswering(br.engine);
    }
    engines.push(notRun(process.env.ZAP_API_URL ? 'owasp-zap-spider' : 'builtin-get', publicSkip));
    engines.push(notRun('nuclei', publicSkip));
    engines.push(notRun('owasp-zap-ascan', publicSkip));
  }

  const wantsCrawl = Boolean(stages.crawl);
  if (wantsCrawl && !authorized) {
    const msg = (accessError && accessError.message)
      || 'Website crawling requires an organization engagement policy, lab allowlist, site grant, or optional DNS/HTTP verification covering this host';
    if (stages.browser) engines.push(notRun('vulnsight-browser', msg));
    engines.push(notRun(process.env.ZAP_API_URL ? 'owasp-zap-spider' : 'builtin-get', msg));
    if (stages.nuclei) engines.push(notRun('nuclei', msg));
    if (stages.ascan) engines.push(notRun('owasp-zap-ascan', msg));
    partial = true;
  }

  let egress = null;
  try {
    if (authorized && wantsCrawl) {
      const useEgress = process.env.VULNSIGHT_DAST_EGRESS === '1';
      if (useEgress) egress = await startEgress(scope);
      const crawlOpts = {
        scope,
        ...limits,
        proxy: useEgress && egress ? egress.proxyUrl : undefined,
        skipBrowser: true,
        clientSpider: false,
        onProgress: deps.onProgress,
        shouldStop: deps.shouldStop,
      };

      const crawlName = process.env.ZAP_API_URL ? 'owasp-zap-spider' : 'builtin-get';
      const wantsBrowser = Boolean(dastBrowser && stages.browser);
      const wantsAscan = Boolean(stages.ascan && dastAscan);
      const hasPages = (inv) => Boolean(inv && (inv.pages || []).length && !(inv.reachability && inv.reachability.loaded === 0));
      let cr = { result: null };

      async function stillAuthorized(stageName) {
        try {
          access = await resolveAccess();
          if (!access.allowed || !AUTH_SOURCES.has(access.source)) {
            throw new Error('Authorization was revoked or expired');
          }
          if (access.grant || access.policy) {
            scope = scopeFromAccess(normalizeScope(site.hostname, siteConfig), access, site.hostname);
            crawlOpts.scope = scope;
          }
          return true;
        } catch (err) {
          engines.push(notRun(stageName, err.message || 'Authorization was revoked or expired'));
          partial = true;
          return false;
        }
      }

      async function reportStage(stage, engine) {
        if (typeof deps.onProgress === 'function') {
          await deps.onProgress({ stage, engine, pages: (inventory && inventory.pages && inventory.pages.length) || 0 });
        }
      }

      let authStopped = false;

      // Browser crawl
      if (wantsBrowser) {
        if (!(await stillAuthorized('vulnsight-browser'))) {
          authStopped = true;
        } else if (hostDropped) {
          engines.push(notRun('vulnsight-browser', stopReason()));
        } else {
          await reportStage('crawling', 'vulnsight-browser');
          const br = await runStage('vulnsight-browser', () => dastBrowser(target, crawlOpts));
          engines.push(br.engine);
          if (br.result) {
            if (hasPages(br.result)) inventory = br.result;
            findings = findings.concat(br.result.findings || []);
            if (br.result.blocked) {
              partial = true;
              blockedBy = blockerOf(br.result);
            }
          }
          await stillAnswering(br.engine);
        }
      }

      // Spider / GET crawl
      if (authStopped) {
        engines.push(notRun(crawlName, 'Authorization was revoked or expired'));
      } else if (hostDropped) {
        engines.push(notRun(crawlName, stopReason()));
      } else if (!(await stillAuthorized(crawlName))) {
        authStopped = true;
      } else {
        await reportStage(process.env.ZAP_API_URL ? 'zap-spider' : 'crawling', crawlName);
        cr = await runStage(crawlName, () => dastCrawl(target, crawlOpts));
        engines.push(cr.engine);
        if (cr.result) {
          if (hasPages(cr.result)) {
            inventory = hasPages(inventory) ? mergeInventory(inventory, cr.result) : cr.result;
          } else if (inventory && cr.result.zapSession) {
            inventory.zapSession = cr.result.zapSession;
          }
          findings = findings.concat(cr.result.findings || []);
        }
        await stillAnswering(cr.engine);
      }

      // Nuclei
      if (dastNuclei && stages.nuclei) {
        if (authStopped) {
          engines.push(notRun('nuclei', 'Authorization was revoked or expired'));
        } else if (hostDropped) {
          engines.push(notRun('nuclei', stopReason()));
        } else if (!(await stillAuthorized('nuclei'))) {
          authStopped = true;
        } else {
          await reportStage('nuclei', 'nuclei');
          const urls = collectUrls(inventory, target, scope, limits.maxPages);
          const nu = await runStage('nuclei', () => dastNuclei(urls, {
            limits,
            proxy: egress && egress.proxyUrl,
            mode: access.nucleiMode || (stages.nuclei === 'full' && access.allowActive ? 'full' : 'safe'),
            scope,
            verified: access.source === 'dns_http',
            authorized: Boolean(access.allowed && AUTH_SOURCES.has(access.source)),
          }));
          engines.push(nu.engine);
          if (nu.result) {
            findings = findings.concat(nu.result.findings || []);
            if (nu.result.blocked) {
              partial = true;
              blockedBy = blockerOf(nu.result);
            }
          }
          await stillAnswering(nu.engine);
        }
      }

      // Exposed-path probes and crawl-inventory review (skill-checks.js / crawler.js). Authorized
      // sites only, GET-only and rate-limited, and run before the active scan so a firewall ban
      // triggered by attack payloads can't hide them.
      if (dastChecks) {
        if (authStopped) {
          engines.push(notRun('vulnsight-checks', 'Authorization was revoked or expired'));
        } else if (hostDropped) {
          engines.push(notRun('vulnsight-checks', stopReason()));
        } else if (!(await stillAuthorized('vulnsight-checks'))) {
          authStopped = true;
        } else {
          await reportStage('checks', 'vulnsight-checks');
          const ck = await runStage('vulnsight-checks', () => dastChecks(target, { inventory, shouldStop: deps.shouldStop }));
          engines.push(ck.engine);
          if (ck.result) {
            findings = findings.concat(ck.result.findings || []);
            if (ck.result.blocked) {
              partial = true;
              blockedBy = blockerOf(ck.result);
            }
          }
          await stillAnswering(ck.engine);
        }
      }

      // ZAP active scan
      if (wantsAscan) {
        if (authStopped) {
          engines.push(notRun('owasp-zap-ascan', 'Authorization was revoked or expired. No attack payloads were sent.'));
        } else if (!(await stillAuthorized('owasp-zap-ascan'))) {
          authStopped = true;
        } else if (!access.allowActive) {
          engines.push(notRun('owasp-zap-ascan', 'Active ZAP scanning is not permitted by the current authorization.'));
          partial = true;
        } else if (hostDropped) {
          engines.push(notRun('owasp-zap-ascan', `${stopReason()} No attack payloads were sent.`));
        } else {
          await reportStage('zap-ascan', 'owasp-zap-ascan');
          const seedUrls = collectUrls(inventory, target, scope, limits.maxPages);
          const as = await runStage('owasp-zap-ascan', () => dastAscan(target, {
            scope,
            ...limits,
            proxy: egress && egress.proxyUrl,
            zapSession: (cr.result && cr.result.zapSession) || (inventory && inventory.zapSession),
            seedUrls,
            allowActive: true,
            onProgress: deps.onProgress,
            shouldStop: deps.shouldStop,
          }));
          engines.push(as.engine);
          if (as.result) findings = findings.concat(as.result.findings || []);
          if (isDropped(as.engine)) hostDropped = true;
        }
      }
    }
  } finally {
    if (egress) await egress.stop().catch(() => {});
  }

  if (hostDropped) {
    partial = true;
    blockedBy = blockedBy || HOST_FIREWALL;
  }
  findings = dedupeDastFindings(findings);
  const expected = new Set(['vulnsight-passive']);
  if (stages.publicDiscovery || (stages.crawl && stages.browser)) expected.add('vulnsight-browser');
  if (stages.crawl) expected.add(process.env.ZAP_API_URL ? 'owasp-zap-spider' : 'builtin-get');
  if (stages.nuclei) expected.add('nuclei');
  if (stages.ascan) expected.add('owasp-zap-ascan');
  if (engines.some((e) => expected.has(e.name) && ['error', 'blocked', 'skipped', 'partial'].includes(e.status))) {
    partial = true;
  }
  const story = buildScanStory({
    engines,
    partial,
    blockedBy,
    profile,
    pages: (inventory && inventory.pages && inventory.pages.length) || 0,
    findings: findings.length,
  });
  return {
    findings,
    inventory,
    engines,
    partial,
    blockedBy,
    profile,
    limits,
    scope,
    passive: passive.result,
    verified,
    story,
    access: {
      allowed: Boolean(access.allowed),
      source: access.source || null,
      assessmentKind: access.assessmentKind || null,
      allowActive: Boolean(access.allowActive),
      nucleiMode: access.nucleiMode || null,
    },
  };
}

function mergeInventory(primary, extra) {
  if (!primary) return extra;
  if (!extra) return primary;
  const pages = [...(primary.pages || [])];
  const seen = new Set(pages.map((p) => p.urlHash || p.url));
  for (const page of extra.pages || []) {
    const key = page.urlHash || page.url;
    if (!seen.has(key)) {
      seen.add(key);
      pages.push(page);
    }
  }
  return {
    ...primary,
    engine: primary.engine || extra.engine,
    pages,
    endpoints: [...(primary.endpoints || []), ...(extra.endpoints || [])],
    forms: [...(primary.forms || []), ...(extra.forms || [])],
    links: [...(primary.links || []), ...(extra.links || [])],
    findings: [...(primary.findings || []), ...(extra.findings || [])],
    zapSession: extra.zapSession || primary.zapSession,
  };
}

module.exports = {
  runDastPipeline,
  dedupeDastFindings,
  isVerificationFresh,
  collectUrls,
  findingKey,
  VERIFY_TTL_MS,
};
