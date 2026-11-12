'use strict';

const { PRODUCT_PROFILES, profileNeeds, isVerifiedScopeHost, urlInScope, normalizeUrl } = require('../adapters/dast/scope');
const {
  EVIDENCE_KINDS,
  MAX_TTL_MS,
  MIN_TTL_MS,
  grantDocument,
  isGrantActive,
  grantCoversProfile,
  grantCoversHost,
  intersectScope,
  validateEvidence,
  ownershipAccess,
} = require('./dast-authorization');

const POLICY_KINDS = new Set(['engagement', 'lab']);

function parseJson(raw, fallback) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function normHost(value) {
  return String(value || '').toLowerCase().replace(/\.$/, '').trim();
}

function isAuthorizationRevoked(record) {
  return Boolean(record && (record.status === 'revoked' || record.revokedAt || record.revoked_at));
}

function isAuthorizationExpired(record, now = Date.now()) {
  if (!record) return true;
  const exp = Date.parse(record.expiresAt || record.expires_at);
  return !Number.isFinite(exp) || exp <= now;
}

function isPolicyActive(policy, now = Date.now()) {
  if (!policy || isAuthorizationRevoked(policy) || isAuthorizationExpired(policy, now)) return false;
  const start = Date.parse(policy.startsAt || policy.starts_at || 0);
  if (Number.isFinite(start) && start > now) return false;
  return true;
}

function isConcreteHostname(value) {
  const host = normHost(value);
  if (!host || host.includes('*') || host.startsWith('.')) return false;
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(host) && host !== 'localhost') return false;
  const labels = host.split('.');
  return labels.length >= 2 && labels.every((l) => l && !l.startsWith('-'));
}

function engagementHostMatches(listed, hostname) {
  const raw = normHost(listed);
  const host = normHost(hostname);
  if (!raw || !host) return false;
  if (raw.startsWith('*.')) {
    const base = raw.slice(2);
    if (!isConcreteHostname(base)) return false;
    return host === base || host.endsWith(`.${base}`);
  }
  if (!isConcreteHostname(raw)) return false;
  return isVerifiedScopeHost(raw, host);
}

function labHostMatches(listed, hostname) {
  return isConcreteHostname(listed) && normHost(listed) === normHost(hostname);
}

function isHostWithinApprovedScope(policy, hostname) {
  if (!policy) return false;
  const host = normHost(hostname);
  const deny = (policy.denyHosts || []).some((listed) => (
    policy.kind === 'lab' ? labHostMatches(listed, host) : engagementHostMatches(listed, host)
  ));
  if (deny) return false;
  const allow = policy.allowHosts || [];
  if (!allow.length) return false;
  return allow.some((listed) => (
    policy.kind === 'lab' ? labHostMatches(listed, host) : engagementHostMatches(listed, host)
  ));
}

function isProfileAuthorized(allowedProfiles, profile) {
  const key = String(profile || 'passive');
  if (key === 'passive') return true;
  const allowed = allowedProfiles || [];
  return allowed.includes(key) || (key === 'deep' && allowed.includes('ascan'));
}

function pathDenied(policy, pathname) {
  const path = pathname || '/';
  return (policy.denyPaths || []).some((prefix) => prefix && path.startsWith(prefix));
}

function pathAllowed(policy, pathname) {
  const path = pathname || '/';
  if (pathDenied(policy, path)) return false;
  const allows = (policy.allowPaths && policy.allowPaths.length) ? policy.allowPaths : ['/'];
  return allows.some((prefix) => path.startsWith(prefix));
}

function portAllowed(policy, port) {
  const allowed = (policy.ports || [80, 443]).map(Number);
  return allowed.includes(Number(port));
}

function policyDocument(row) {
  if (!row) return null;
  const expiresAt = row.expires_at;
  const revokedAt = row.revoked_at || null;
  let status = 'active';
  if (revokedAt) status = 'revoked';
  else if (Date.parse(expiresAt) <= Date.now()) status = 'expired';
  else if (row.starts_at && Date.parse(row.starts_at) > Date.now()) status = 'scheduled';
  return {
    id: row.id,
    orgId: row.org_id,
    kind: row.kind,
    grantedBy: row.granted_by,
    grantedAt: row.granted_at,
    startsAt: row.starts_at,
    expiresAt,
    revokedAt,
    revokedBy: row.revoked_by || null,
    revokeReason: row.revoke_reason || null,
    allowedProfiles: parseJson(row.allowed_profiles, []),
    allowActiveTesting: Boolean(row.allow_active_testing),
    allowHosts: parseJson(row.allow_hosts, []),
    denyHosts: parseJson(row.deny_hosts, []),
    allowPaths: parseJson(row.allow_paths, ['/']),
    denyPaths: parseJson(row.deny_paths, []),
    ports: parseJson(row.ports, [80, 443]),
    evidenceKind: row.evidence_kind,
    evidenceRef: row.evidence_ref,
    note: row.note || null,
    status,
  };
}

function validatePolicyInput(body = {}) {
  const kind = String(body.kind || '').trim();
  if (!POLICY_KINDS.has(kind)) return 'kind must be engagement or lab';
  const evidenceError = validateEvidence(body.evidenceKind, body.evidenceRef);
  if (evidenceError) return evidenceError;
  const exp = Date.parse(body.expiresAt);
  if (!Number.isFinite(exp)) return 'expiresAt is required';
  const delta = exp - Date.now();
  if (delta < MIN_TTL_MS) return 'Authorization must expire at least one hour in the future';
  if (delta > MAX_TTL_MS) return 'Authorization cannot last more than 90 days';
  if (body.startsAt) {
    const start = Date.parse(body.startsAt);
    if (!Number.isFinite(start)) return 'startsAt is invalid';
    if (start >= exp) return 'startsAt must be before expiresAt';
  }
  const profiles = Array.isArray(body.allowedProfiles) ? body.allowedProfiles : [];
  if (!profiles.length || profiles.some((p) => !PRODUCT_PROFILES[p] && p !== 'ascan')) {
    return 'allowedProfiles must be a non-empty subset of passive, discovery, standard, deep';
  }
  if (body.allowActiveTesting && !profiles.includes('deep') && !profiles.includes('ascan')) {
    return 'Active testing permission requires the deep profile';
  }
  const hosts = Array.isArray(body.allowHosts) ? body.allowHosts : [];
  if (!hosts.length) return 'allowHosts must list at least one hostname';
  for (const host of hosts) {
    if (kind === 'lab') {
      if (!isConcreteHostname(host)) {
        return `Lab allowlists only accept explicit hostnames (rejected ${host})`;
      }
    } else {
      const raw = normHost(host);
      const base = raw.startsWith('*.') ? raw.slice(2) : raw;
      if (!isConcreteHostname(base)) {
        return `Engagement host ${host} is not a concrete hostname`;
      }
    }
  }
  for (const host of body.denyHosts || []) {
    if (kind === 'lab' && !isConcreteHostname(host)) {
      return `Lab denyHosts only accept explicit hostnames (rejected ${host})`;
    }
  }
  return null;
}

function targetParts(site) {
  const hostname = site && (site.hostname || '');
  let pathname = '/';
  let port = 443;
  const raw = (site && (site.target_url || site.targetUrl)) || `https://${hostname}`;
  try {
    const parsed = new URL(raw);
    pathname = parsed.pathname || '/';
    port = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));
  } catch {
    /* keep defaults */
  }
  return { hostname: normHost(hostname), pathname, port };
}

function unauthorized(message, extra = {}) {
  const err = new Error(message);
  err.code = 'UNAUTHORIZED';
  Object.assign(err, extra);
  return err;
}

function candidateFromGrant(grant, hostname, now) {
  if (!isGrantActive(grant, now) || !grantCoversHost(grant, hostname, hostname)) return null;
  return {
    source: 'client_grant',
    record: grant,
    allowActive: Boolean(grant.allowActiveTesting),
    profiles: grant.allowedProfiles || [],
    ports: grant.ports || [80, 443],
    allowPaths: grant.allowPaths || ['/'],
    denyPaths: grant.denyPaths || [],
    denyHosts: [],
  };
}

function candidateFromPolicy(policy, hostname) {
  if (!isHostWithinApprovedScope(policy, hostname)) return null;
  return {
    source: policy.kind === 'lab' ? 'lab' : 'org_engagement',
    record: policy,
    allowActive: Boolean(policy.allowActiveTesting),
    profiles: policy.allowedProfiles || [],
    ports: policy.ports || [80, 443],
    allowPaths: policy.allowPaths || ['/'],
    denyPaths: policy.denyPaths || [],
    denyHosts: policy.denyHosts || [],
  };
}

function candidateFromOwnership(site, now) {
  if (!ownershipAccess(site, now)) return null;
  return {
    source: 'dns_http',
    record: null,
    allowActive: false,
    profiles: ['passive', 'discovery', 'standard'],
    ports: [80, 443],
    allowPaths: ['/'],
    denyPaths: [],
    denyHosts: [],
  };
}

function coversTarget(candidate, { profile, pathname, port }) {
  if (!isProfileAuthorized(candidate.profiles, profile)) return false;
  if (!portAllowed(candidate, port)) return false;
  if (pathDenied(candidate, pathname)) return false;
  const allows = (candidate.allowPaths && candidate.allowPaths.length) ? candidate.allowPaths : ['/'];
  if (!allows.some((prefix) => String(pathname || '/').startsWith(prefix))) return false;
  return true;
}

/**
 * Central scan authorization. Deny rules on any active policy win. Revoked and
 * expired records never grant. Deep assessment needs stored allowActiveTesting.
 */
function evaluateScanAuthorization({
  site,
  profile,
  grant = null,
  orgPolicies = [],
  now = Date.now(),
} = {}) {
  const needs = profileNeeds(profile);
  const { hostname, pathname, port } = targetParts(site || {});
  const activePolicies = (orgPolicies || []).filter((p) => isPolicyActive(p, now));

  for (const policy of activePolicies) {
    const denyHost = (policy.denyHosts || []).some((listed) => (
      policy.kind === 'lab' ? labHostMatches(listed, hostname) : engagementHostMatches(listed, hostname)
    ));
    if (denyHost) {
      throw unauthorized('This hostname is denied by an organization authorization policy', { denied: true });
    }
    if (isHostWithinApprovedScope(policy, hostname) && pathDenied(policy, pathname)) {
      throw unauthorized('This path is denied by an organization authorization policy', { denied: true });
    }
  }

  if (!needs.crawl) {
    return {
      allowed: true,
      source: needs.publicDiscovery ? 'public_assessment' : 'passive',
      assessmentKind: 'public_assessment',
      allowActive: false,
      nucleiMode: null,
      grant: null,
      policy: null,
      evidenceRequired: false,
    };
  }

  const candidates = [];
  const fromGrant = candidateFromGrant(grant, hostname, now);
  if (fromGrant) candidates.push(fromGrant);
  for (const policy of activePolicies) {
    const next = candidateFromPolicy(policy, hostname);
    if (next) candidates.push(next);
  }
  const fromDns = candidateFromOwnership(site, now);
  if (fromDns) candidates.push(fromDns);

  const covering = candidates.filter((c) => coversTarget(c, { profile, pathname, port }));
  if (!covering.length) {
    if (needs.ascan) {
      const crawlCovering = candidates.filter((c) => coversTarget(c, { profile: 'standard', pathname, port })
        || coversTarget(c, { profile: 'discovery', pathname, port }));
      if (crawlCovering.length) {
        throw unauthorized('Deep assessment requires stored allowActiveTesting on an engagement policy, lab allowlist, or site grant');
      }
    }
    throw unauthorized('Website crawling requires an organization engagement policy, lab allowlist, site grant, or optional DNS/HTTP verification covering this host');
  }

  const allowActive = covering.some((c) => c.allowActive && isProfileAuthorized(c.profiles, 'deep'));
  if (needs.ascan && !allowActive) {
    throw unauthorized('Deep assessment requires stored allowActiveTesting on an engagement policy, lab allowlist, or site grant');
  }

  const rank = { lab: 0, org_engagement: 1, client_grant: 2, dns_http: 3 };
  covering.sort((a, b) => (rank[a.source] ?? 9) - (rank[b.source] ?? 9));
  const chosen = covering[0];
  return {
    allowed: true,
    source: chosen.source,
    assessmentKind: 'authorized_dast',
    allowActive,
    nucleiMode: needs.nuclei === 'full' ? (allowActive ? 'full' : 'safe') : needs.nuclei,
    grant: chosen.source === 'client_grant' ? grant : null,
    policy: chosen.source === 'org_engagement' || chosen.source === 'lab' ? chosen.record : null,
  };
}

function getWebsiteAuthorization({ site, grant = null, orgPolicies = [], profile = 'standard', now = Date.now() } = {}) {
  try {
    const access = evaluateScanAuthorization({ site, profile, grant, orgPolicies, now });
    if (access.source === 'passive' || access.source === 'public_assessment' || access.assessmentKind === 'public_assessment') {
      const crawlTry = (() => {
        try {
          return evaluateScanAuthorization({ site, profile: 'standard', grant, orgPolicies, now });
        } catch (err) {
          return err;
        }
      })();
      if (crawlTry && crawlTry.allowed) {
        return {
          status: 'authorized',
          source: crawlTry.source,
          allowActiveTesting: crawlTry.allowActive,
          allowedProfiles: (crawlTry.policy && crawlTry.policy.allowedProfiles)
            || (crawlTry.grant && crawlTry.grant.allowedProfiles)
            || ['passive', 'discovery', 'standard'],
          expiresAt: (crawlTry.policy && crawlTry.policy.expiresAt) || (crawlTry.grant && crawlTry.grant.expiresAt) || null,
        };
      }
      if (crawlTry && crawlTry.denied) {
        return { status: 'denied', source: null, allowActiveTesting: false, reason: crawlTry.message };
      }
      const stale = (orgPolicies || []).find((p) => (p.allowHosts || []).length && (
        isAuthorizationRevoked(p) || isAuthorizationExpired(p, now)
      ) && (p.allowHosts || []).some((h) => engagementHostMatches(h, site && site.hostname)));
      if (stale && isAuthorizationRevoked(stale)) {
        return { status: 'revoked', source: stale.kind === 'lab' ? 'lab' : 'org_engagement', allowActiveTesting: false, expiresAt: stale.expiresAt };
      }
      if (stale && isAuthorizationExpired(stale, now)) {
        return { status: 'expired', source: stale.kind === 'lab' ? 'lab' : 'org_engagement', allowActiveTesting: false, expiresAt: stale.expiresAt };
      }
      if (grant && isAuthorizationRevoked(grant)) {
        return { status: 'revoked', source: 'client_grant', allowActiveTesting: false, expiresAt: grant.expiresAt };
      }
      if (grant && isAuthorizationExpired(grant, now)) {
        return { status: 'expired', source: 'client_grant', allowActiveTesting: false, expiresAt: grant.expiresAt };
      }
      return { status: 'none', source: null, allowActiveTesting: false };
    }
    return {
      status: 'authorized',
      source: access.source,
      allowActiveTesting: access.allowActive,
      allowedProfiles: (access.policy && access.policy.allowedProfiles)
        || (access.grant && access.grant.allowedProfiles)
        || (access.source === 'dns_http' ? ['passive', 'discovery', 'standard'] : null),
      expiresAt: (access.policy && access.policy.expiresAt) || (access.grant && access.grant.expiresAt) || null,
    };
  } catch (err) {
    if (err && err.denied) {
      return { status: 'denied', source: null, allowActiveTesting: false, reason: err.message };
    }
    return getWebsiteAuthorization({
      site, grant, orgPolicies, profile: 'passive', now,
    });
  }
}

function scopeFromAccess(baseScope, access, siteHostname) {
  if (access && access.grant) return intersectScope(baseScope, access.grant, siteHostname);
  if (access && access.policy) {
    return intersectScope(baseScope, {
      allowHosts: access.policy.allowHosts,
      allowPaths: access.policy.allowPaths,
      denyPaths: access.policy.denyPaths,
      ports: access.policy.ports,
    }, siteHostname);
  }
  return baseScope;
}

module.exports = {
  POLICY_KINDS,
  EVIDENCE_KINDS,
  policyDocument,
  validatePolicyInput,
  isAuthorizationExpired,
  isAuthorizationRevoked,
  isPolicyActive,
  isHostWithinApprovedScope,
  isProfileAuthorized,
  isConcreteHostname,
  evaluateScanAuthorization,
  getWebsiteAuthorization,
  scopeFromAccess,
  grantDocument,
  urlInScope,
  normalizeUrl,
};
