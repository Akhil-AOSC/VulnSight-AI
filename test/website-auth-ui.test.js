'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { scanStartDecision, authorizationPresentation, isPublicAssessmentProfile } = require('../src/platform/website-auth-ui');

test('register-and-scan UI never opens the DNS/HTTP modal', () => {
  const unverified = { isVerified: false, authorization: { status: 'none' } };
  const blocked = scanStartDecision(unverified, 'standard');
  assert.equal(blocked.allow, false);
  assert.equal(blocked.openVerifyModal, false);
  assert.match(blocked.reason, /not authorized/i);

  const passive = scanStartDecision(unverified, 'passive');
  assert.equal(passive.allow, true);
  assert.equal(passive.openVerifyModal, false);

  const pub = scanStartDecision(unverified, 'public');
  assert.equal(pub.allow, true);
  assert.equal(pub.openVerifyModal, false);
});

test('authorization presentation maps revoked, expired, missing and authorized', () => {
  assert.equal(authorizationPresentation({ authorization: { status: 'revoked' } }).status, 'revoked');
  assert.equal(authorizationPresentation({ authorization: { status: 'expired' } }).status, 'expired');
  assert.equal(authorizationPresentation({ authorization: { status: 'none' } }).status, 'none');
  assert.equal(authorizationPresentation({ authorization: { status: 'denied' } }).status, 'denied');
  assert.equal(authorizationPresentation({
    authorization: { status: 'active', source: 'org_engagement', allowActiveTesting: true },
  }).status, 'authorized');
});

test('deep scan is refused without stored allowActiveTesting even when the host is authorized', () => {
  const site = {
    isVerified: true,
    authorization: { status: 'verified', source: 'dns_http', allowActiveTesting: false },
  };
  const decision = scanStartDecision(site, 'deep');
  assert.equal(decision.allow, false);
  assert.equal(decision.openVerifyModal, false);
  assert.equal(decision.confirmActive, false);
  assert.match(decision.reason, /allowActiveTesting/);
});

test('public assessment presentation does not demand engagement evidence', () => {
  const unverified = { isVerified: false, authorization: { status: 'none' } };
  const view = authorizationPresentation(unverified, 'public');
  assert.equal(view.status, 'public');
  assert.equal(view.label, 'Not required');
  assert.match(view.reason, /does not need an engagement ID/i);
  assert.equal(view.allowActiveTesting, false);
  assert.equal(isPublicAssessmentProfile('public'), true);
  assert.equal(isPublicAssessmentProfile('standard'), false);
});

test('standard scan proceeds when a covering authorization exists, without a new approval prompt', () => {
  const site = {
    authorization: {
      status: 'active',
      source: 'org_engagement',
      allowActiveTesting: false,
      allowedProfiles: ['discovery', 'standard'],
    },
  };
  const decision = scanStartDecision(site, 'standard');
  assert.equal(decision.allow, true);
  assert.equal(decision.openVerifyModal, false);
  assert.equal(decision.confirmActive, false);
});
