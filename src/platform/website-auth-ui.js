'use strict';

/**
 * Presentation helpers for website authorization. The backend is the authority;
 * this only maps a site.authorization summary plus the selected profile into
 * labels and a scan-start decision. Scan start never opens the DNS/HTTP modal.
 */

function isPublicAssessmentProfile(profile) {
  const key = String(profile || '');
  return key === 'public' || key === 'public_assessment' || key === 'PUBLIC_ASSESSMENT' || key === 'passive';
}

function profileNeedsCrawl(profile) {
  return !isPublicAssessmentProfile(profile);
}

function profileNeedsActive(profile) {
  return String(profile || '') === 'deep' || String(profile || '') === 'ascan';
}

function authorizationPresentation(site = {}, profile = 'standard') {
  const a = site.authorization || {};
  const status = a.status || 'none';
  if (status === 'denied' || a.denied) {
    return {
      status: 'denied',
      label: 'Outside approved scope',
      tone: 'sev-high',
      reason: a.reason || 'This hostname, path or profile is outside the approved engagement or lab scope.',
    };
  }
  if (isPublicAssessmentProfile(profile)) {
    return {
      status: 'public',
      label: 'Not required',
      tone: 'sev-low',
      reason: 'Public Website Assessment does not need an engagement ID, DNS/HTTP proof, or a site grant.',
      allowActiveTesting: false,
      allowedProfiles: null,
    };
  }
  if (status === 'revoked') {
    return {
      status: 'revoked',
      label: 'Revoked',
      tone: 'sev-high',
      reason: 'The authorization record for this target was revoked.',
    };
  }
  if (status === 'expired') {
    return {
      status: 'expired',
      label: 'Expired',
      tone: 'sev-medium',
      reason: 'The authorization record for this target has expired.',
    };
  }
  if (site.isVerified || status === 'verified' || status === 'active' || status === 'authorized') {
    const source = a.source === 'dns_http'
      ? 'Domain control verified (DNS/HTTP). Deep assessment still needs stored active-testing permission.'
      : a.source === 'lab'
        ? 'Covered by a lab allowlist.'
        : a.source === 'org_engagement'
          ? 'Covered by an organization engagement policy.'
          : 'Covered by a recorded authorization.';
    return {
      status: 'authorized',
      label: 'Authorized',
      tone: 'sev-low',
      reason: source,
      expiresAt: a.expiresAt || null,
      allowActiveTesting: Boolean(a.allowActiveTesting),
      allowedProfiles: a.allowedProfiles || null,
    };
  }
  return {
    status: 'none',
    label: 'Not configured',
    tone: 'sev-medium',
    reason: 'No engagement policy, lab allowlist, site grant, or optional DNS/HTTP verification covers this host.',
  };
}

function scanStartDecision(site = {}, profile = 'standard') {
  const presentation = authorizationPresentation(site, profile);
  const a = site.authorization || {};
  const allowedProfiles = a.allowedProfiles;
  const crawl = profileNeedsCrawl(profile);
  const active = profileNeedsActive(profile);

  if (!crawl) {
    if (presentation.status === 'denied') {
      return {
        allow: false,
        openVerifyModal: false,
        confirmActive: false,
        reason: presentation.reason,
        presentation,
      };
    }
    return {
      allow: true,
      openVerifyModal: false,
      confirmActive: false,
      reason: null,
      presentation,
    };
  }

  if (presentation.status === 'revoked' || presentation.status === 'expired' || presentation.status === 'denied') {
    return {
      allow: false,
      openVerifyModal: false,
      confirmActive: false,
      reason: presentation.reason,
      presentation,
    };
  }

  if (presentation.status !== 'authorized') {
    return {
      allow: false,
      openVerifyModal: false,
      confirmActive: false,
      reason: `${profile} assessment is not authorized for this host. ${presentation.reason}`,
      presentation,
    };
  }

  if (Array.isArray(allowedProfiles) && allowedProfiles.length && !allowedProfiles.includes(profile) && profile !== 'passive') {
    if (!(profile === 'deep' && allowedProfiles.includes('ascan'))) {
      return {
        allow: false,
        openVerifyModal: false,
        confirmActive: false,
        reason: `Profile ${profile} is not in the allowed profiles for this authorization.`,
        presentation,
      };
    }
  }

  if (active && !a.allowActiveTesting) {
    return {
      allow: false,
      openVerifyModal: false,
      confirmActive: false,
      reason: 'Deep assessment requires stored allowActiveTesting on an engagement, lab, or site grant. Domain ownership alone is not enough.',
      presentation,
    };
  }

  return {
    allow: true,
    openVerifyModal: false,
    confirmActive: false,
    reason: null,
    presentation,
  };
}

module.exports = {
  authorizationPresentation,
  scanStartDecision,
  profileNeedsCrawl,
  profileNeedsActive,
  isPublicAssessmentProfile,
};
