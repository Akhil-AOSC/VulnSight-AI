import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { runScan } from '../src/scanner.js';

test('Integration: scan on vulnerable-npm-project detects known CVEs and breaches threshold', async () => {
  const targetDir = path.resolve('test-fixtures/vulnerable-npm-project');
  const result = await runScan(targetDir, { failThreshold: 'high' });

  assert.equal(result.projectName, 'sample-vulnerable-app');
  assert.equal(result.totalDependencies, 4);
  assert.ok(result.findings.length > 0, 'Should find vulnerabilities');
  assert.equal(result.thresholdBreached, true, 'Should breach high threshold');

  // Verify lodash findings
  const lodashFindings = result.findings.filter((f) => f.packageName === 'lodash');
  assert.ok(lodashFindings.length > 0);
  assert.ok(lodashFindings.some((f) => f.aliases.includes('CVE-2021-23337')));

  // Verify transitive qs findings
  const qsFindings = result.findings.filter((f) => f.packageName === 'qs');
  assert.ok(qsFindings.length > 0);
  assert.equal(qsFindings[0].isDirect, false);
});

test('Integration: scan on clean-npm-project passes with zero findings', async () => {
  const targetDir = path.resolve('test-fixtures/clean-npm-project');
  const result = await runScan(targetDir, { failThreshold: 'low' });

  assert.equal(result.projectName, 'sample-clean-app');
  assert.equal(result.findings.length, 0);
  assert.equal(result.thresholdBreached, false);
  assert.equal(result.summary.critical, 0);
  assert.equal(result.summary.high, 0);
});
