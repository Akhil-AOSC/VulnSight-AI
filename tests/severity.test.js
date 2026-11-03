import test from 'node:test';
import assert from 'node:assert/strict';
import { extractSeverity, meetsThreshold } from '../src/scoring/severity.js';

test('Severity: extracts CVSS 3.1 score and maps to CRITICAL', () => {
  const vuln = {
    severity: [
      {
        type: 'CVSS_V3',
        score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      },
    ],
  };

  const result = extractSeverity(vuln);
  assert.equal(result.level, 'CRITICAL');
  assert.equal(result.score, 9.8);
  assert.equal(result.rank, 4);
});

test('Severity: falls back to database_specific MODERATE -> MEDIUM', () => {
  const vuln = {
    database_specific: {
      severity: 'MODERATE',
    },
  };

  const result = extractSeverity(vuln);
  assert.equal(result.level, 'MEDIUM');
  assert.equal(result.rank, 2);
});

test('Severity: threshold evaluation matches severity ranks', () => {
  assert.equal(meetsThreshold('CRITICAL', 'critical'), true);
  assert.equal(meetsThreshold('HIGH', 'critical'), false);
  assert.equal(meetsThreshold('HIGH', 'high'), true);
  assert.equal(meetsThreshold('MEDIUM', 'high'), false);
  assert.equal(meetsThreshold('LOW', 'low'), true);
  assert.equal(meetsThreshold('CRITICAL', 'none'), false);
});
