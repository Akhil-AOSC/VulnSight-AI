'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { buildScanStory, explainEngine, livePipelineState } = require('../src/adapters/dast/scan-story');

test('scan story explains an incomplete ascan run in plain language', () => {
  const story = buildScanStory({
    profile: 'ascan',
    partial: true,
    pages: 3,
    findings: 0,
    engines: [
      { name: 'vulnsight-passive', status: 'error', error: 'connect ETIMEDOUT 192.250.232.1:443', findings: 0 },
      { name: 'vulnsight-browser', status: 'ok', findings: 0 },
      { name: 'owasp-zap-spider', status: 'ok', findings: 0 },
      { name: 'nuclei', status: 'ok', findings: 0 },
      { name: 'owasp-zap-ascan', status: 'error', error: 'ZAP sites tree still empty after spider', findings: 0 },
    ],
  });
  assert.equal(story.headline, 'Incomplete inspection');
  assert.match(story.readout, /not a clean bill of health/);
  const passive = explainEngine({ name: 'vulnsight-passive', status: 'error', error: 'connect ETIMEDOUT 1.2.3.4:443' });
  assert.match(passive.why, /timed out/);
  assert.doesNotMatch(passive.why, /different client/);
  const ascan = story.stages.find((s) => s.name === 'owasp-zap-ascan');
  assert.match(ascan.why, /no attack payloads were sent/i);
});

test('public assessment story does not count profile-skipped ZAP or Nuclei as unfinished', () => {
  const skip = 'Not run: Public Website Assessment does not execute ZAP Spider, Nuclei, or ZAP Active Scan.';
  const story = buildScanStory({
    profile: 'public',
    partial: false,
    blockedBy: 'Cloudflare',
    findings: 3,
    pages: 1,
    engines: [
      { name: 'vulnsight-passive', status: 'blocked', error: 'blocked by Cloudflare', findings: 4 },
      { name: 'vulnsight-browser', status: 'ok', findings: 0 },
      { name: 'owasp-zap-spider', status: 'skipped', error: skip },
      { name: 'nuclei', status: 'skipped', error: skip },
      { name: 'owasp-zap-ascan', status: 'skipped', error: skip },
    ],
  });
  assert.equal(story.headline, 'Inspection finished');
  assert.doesNotMatch(story.readout, /did not finish/);
});

test('scan story explains a firewall IP ban instead of reporting empty results as ok', () => {
  const story = buildScanStory({
    profile: 'ascan',
    partial: true,
    blockedBy: 'host firewall',
    engines: [
      { name: 'vulnsight-passive', status: 'blocked', blockReason: 'connection_dropped', error: 'The host stopped answering this machine (ETIMEDOUT).' },
      { name: 'nuclei', status: 'skipped', error: 'Not run: the host was dropping connections from this machine.' },
    ],
  });
  assert.match(story.readout, /dropping connections/);
  assert.match(story.readout, /Allowlist the scanner IP/);
  const passive = story.stages.find((s) => s.name === 'vulnsight-passive');
  assert.match(passive.why, /banned the scanner IP/);
  const nuclei = story.stages.find((s) => s.name === 'nuclei');
  assert.match(nuclei.why, /Not run/);
});

test('live pipeline marks ZAP ascan as current during deep', () => {
  const queued = livePipelineState('deep', { status: 'queued', progress: { stage: 'queued' } });
  assert.equal(queued[0].state, 'current');
  assert.equal(queued[1].state, 'waiting');
  const ascan = livePipelineState('deep', { status: 'running', progress: { stage: 'ascan', engine: 'owasp-zap-ascan', percent: 22 } });
  const zap = ascan.find((s) => s.id === 'ascan');
  assert.equal(zap.state, 'current');
  assert.equal(ascan.find((s) => s.id === 'passive').state, 'done');
});
