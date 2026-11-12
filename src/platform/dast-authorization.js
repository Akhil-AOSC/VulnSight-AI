'use strict';

const { isOwnershipProven } = require('./dast-verifier');
const { isVerifiedScopeHost, PRODUCT_PROFILES, profileNeeds } = require('../adapters/dast/scope');

const EVIDENCE_KINDS = new Set(['engagement_id', 'signed_document_sha256', 'change_ticket']);
const MAX_TTL_MS = 90 * 24 * 3600 * 1000;
const MIN_TTL_MS = 60 * 60 * 1000;
const VERIFY_TTL_MS = 90 * 24 * 3600 * 1000;

function parseJson(raw, fallback) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function isVerificationFresh(verifiedAt, now = Date.now()) {
  if (!verifiedAt) return false;
  const t = Date.parse(verifiedAt);
  if (!Number.isFinite(t)) return false;
  return (now - t) < VERIFY_TTL_MS;
}

function looksLikeUrlOrEmail(value) {
  const s = String(value || '').trim();
  return /https?:\/\//i.test(s) || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
}

function validateEvidence(kind, ref) {
  const k = String(kind || '').trim();
  const r = String(ref || '').trim();
  if (!EVIDENCE_KINDS.has(k)) {
    return 'evidenceKind must be engagement_id, signed_document_sha256, or change_ticket';
  }
  if (!r || r.length < 8) return 'evidenceRef is required and must identify the independent record';
  if (looksLikeUrlOrEmail(r)) return 'A public URL or email address is not sufficient authorization evidence';
  if (/^(yes|ok|true|i own this|confirmed)$/i.test(r)) return 'Self-attestation is not sufficient authorization evidence';
  if (k === 'signed_document_sha256' && !/^[a-f0-9]{64}$/i.test(r)) {
    return 'signed_document_sha256 must be a 64-character hex SHA-256 digest of the signed engagement document';
  }
  if ((k === 'engagement_id' || k === 'change_ticket') && !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,80}$/.test(r)) {
    return 'evidenceRef must be an engagement or ticket identifier, not a free-form statement';
  }
  return null;
}

function grantDocument(row) {
  if (!row) return null;
  const expiresAt = row.expires_at;
  const revokedAt = row.revoked_at || null;
  const expired = Date.parse(expiresAt) <= Date.now();
  let status = 'active';
  if (revokedAt) status = 'revoked';
  else if (expired) status = 'expired';
  return {
    id: row.id,
    orgId: row.org_id,
    websiteId: row.website_id,
    grantedBy: row.granted_by,
    grantedAt: row.granted_at,
    expiresAt,
    revokedAt,
    revokedBy: row.revoked_by || null,
    revokeReason: row.revoke_reason || null,
    allowedProfiles: parseJson(row.allowed_profiles, []),
    allowActiveTesting: Boolean(row.allow_active_testing),
    allowHosts: parseJson(row.allow_hosts, []),
    allowPaths: parseJson(row.allow_paths, ['/']),
    denyPaths: parseJson(row.deny_paths, []),
    ports: parseJson(row.ports, [80, 443]),
    evidenceKind: row.evidence_kind,
    evidenceRef: row.evidence_ref,
    note: row.note || null,
    status,
  };
}

function isGrantActive(grant, now = Date.now()) {
  if (!grant || grant.status === 'revoked' || grant.revokedAt) return false;
  const exp = Date.parse(grant.expiresAt);
  return Number.isFinite(exp) && exp > now;
}

function grantCoversProfile(grant, profile) {
  const allowed = grant.allowedProfiles || [];
  return allowed.includes(profile) || (profile === 'deep' && allowed.includes('ascan'));
}

function grantCoversHost(grant, hostname, siteHostname) {
  const host = String(hostname || '').toLowerCase();
  const site = String(siteHostname || '').toLowerCase();
  if (!isVerifiedScopeHost(site, host)) return false;
  const listed = (grant.allowHosts || []).map((h) => String(h).toLowerCase());
  if (!listed.length) return host === site;
  return listed.includes(host);
}

function intersectScope(baseScope, grant, siteHostname) {
  if (!grant) return baseScope;
  const grantHosts = (grant.allowHosts || []).filter((h) => isVerifiedScopeHost(siteHostname, h));
  const hosts = grantHosts.length
    ? grantHosts.filter((h) => (baseScope.allowHosts || []).includes(h) || (baseScope.extraHosts || []).includes(h) || h === siteHostname)
    : [siteHostname];
  const allowPaths = (grant.allowPaths || ['/']).length ? grant.allowPaths : (baseScope.allowPaths || ['/']);
  const denyPaths = [...new Set([...(baseScope.denyPaths || []), ...(grant.denyPaths || [])])];
  const ports = (grant.ports || [80, 443]).map(Number).filter((p) => p === 80 || p === 443);
  return {
    allowHosts: hosts.length ? hosts : [siteHostname],
    extraHosts: [],
    allowPaths: allowPaths.length ? allowPaths : ['/'],
    denyPaths,
    ports: ports.length ? ports : [80, 443],
  };
}

function ownershipAccess(site, now = Date.now()) {
  return isOwnershipProven(site) && isVerificationFresh(site.verified_at || site.verifiedAt, now);
}

/**
 * Decide whether a scan profile may run. DNS/HTTP ownership and a client grant are
 * independent; neither is a click-through self-attestation.
 */
function evaluateWebsiteAccess({
  site,
  profile,
  authorizeActiveTesting = false,
  grant = null,
  now = Date.now(),
} = {}) {
  const needs = profileNeeds(profile);
  const owned = ownershipAccess(site, now);
  const grantOk = isGrantActive(grant, now) && grantCoversProfile(grant, profile)
    && grantCoversHost(grant, site.hostname, site.hostname);

  if (!needs.crawl) {
    return {
      allowed: true,
      source: owned ? 'dns_http' : 'passive',
      allowActive: false,
      nucleiMode: null,
      grant: grantOk ? grant : null,
    };
  }

  if (!owned && !grantOk) {
    const err = new Error('Website crawling requires domain ownership verification or a valid client authorization grant');
    err.code = 'UNAUTHORIZED';
    throw err;
  }

  const allowActiveFromGrant = grantOk && Boolean(grant.allowActiveTesting);
  const allowActive = Boolean(needs.ascan && authorizeActiveTesting && (owned || allowActiveFromGrant));
  if (needs.ascan) {
    if (!authorizeActiveTesting) {
      const err = new Error('Active vulnerability testing requires an explicit authorizeActiveTesting confirmation on a site you are allowed to test');
      err.code = 'UNAUTHORIZED';
      throw err;
    }
    if (!owned && !allowActiveFromGrant) {
      const err = new Error('Active ZAP scanning requires domain ownership verification or a client grant that allows active testing');
      err.code = 'UNAUTHORIZED';
      throw err;
    }
  }

  const nucleiMode = needs.nuclei === 'full'
    ? (allowActive ? 'full' : 'safe')
    : needs.nuclei;

  return {
    allowed: true,
    source: owned ? 'dns_http' : 'client_grant',
    allowActive,
    nucleiMode,
    grant: grantOk ? grant : null,
  };
}

function authorizationSummary(site, grant) {
  if (ownershipAccess(site)) {
    return {
      status: 'verified',
      source: 'dns_http',
      method: site.verification_method || site.verificationMethod || null,
      expiresAt: null,
      allowActiveTesting: true,
    };
  }
  if (!grant) return { status: 'none', source: null, expiresAt: null, allowActiveTesting: false };
  return {
    status: grant.status,
    source: 'client_grant',
    method: grant.evidenceKind,
    expiresAt: grant.expiresAt,
    allowActiveTesting: Boolean(grant.allowActiveTesting) && grant.status === 'active',
    allowedProfiles: grant.allowedProfiles,
  };
}

function validateGrantInput({
  allowedProfiles,
  allowActiveTesting,
  expiresAt,
  evidenceKind,
  evidenceRef,
  allowHosts,
  siteHostname,
} = {}) {
  const evidenceError = validateEvidence(evidenceKind, evidenceRef);
  if (evidenceError) return evidenceError;
  const exp = Date.parse(expiresAt);
  if (!Number.isFinite(exp)) return 'expiresAt is required';
  const delta = exp - Date.now();
  if (delta < MIN_TTL_MS) return 'Authorization must expire at least one hour in the future';
  if (delta > MAX_TTL_MS) return 'Authorization cannot last more than 90 days';
  const profiles = Array.isArray(allowedProfiles) ? allowedProfiles : [];
  if (!profiles.length || profiles.some((p) => !PRODUCT_PROFILES[p] && p !== 'ascan')) {
    return 'allowedProfiles must be a non-empty subset of passive, discovery, standard, deep';
  }
  if (allowActiveTesting && !profiles.includes('deep') && !profiles.includes('ascan')) {
    return 'Active testing permission requires the deep profile';
  }
  for (const host of allowHosts || []) {
    if (!isVerifiedScopeHost(siteHostname, host)) {
      return `Host ${host} is outside the registered website hostname`;
    }
  }
  return null;
}

module.exports = {
  EVIDENCE_KINDS,
  MAX_TTL_MS,
  MIN_TTL_MS,
  grantDocument,
  isGrantActive,
  grantCoversProfile,
  grantCoversHost,
  intersectScope,
  evaluateWebsiteAccess,
  authorizationSummary,
  validateGrantInput,
  validateEvidence,
  ownershipAccess,
  isVerificationFresh,
};
