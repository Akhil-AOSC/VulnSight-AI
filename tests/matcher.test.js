import test from 'node:test';
import assert from 'node:assert/strict';
import { matchVulnerability } from '../src/matcher/matcher.js';

test('Matcher: matches version inside [introduced, fixed) range', () => {
  const vuln = {
    affected: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [
          {
            type: 'SEMVER',
            events: [{ introduced: '4.0.0' }, { fixed: '4.17.21' }],
          },
        ],
      },
    ],
  };

  const matchVulnerable = matchVulnerability('lodash', '4.17.15', vuln);
  assert.equal(matchVulnerable.isVulnerable, true);
  assert.equal(matchVulnerable.fixedVersion, '4.17.21');

  const matchFixed = matchVulnerability('lodash', '4.17.21', vuln);
  assert.equal(matchFixed.isVulnerable, false);

  const matchPrior = matchVulnerability('lodash', '3.10.1', vuln);
  assert.equal(matchPrior.isVulnerable, false);
});

test('Matcher: matches explicit version list', () => {
  const vuln = {
    affected: [
      {
        package: { name: 'example-pkg', ecosystem: 'npm' },
        versions: ['1.0.0', '1.0.1'],
      },
    ],
  };

  assert.equal(matchVulnerability('example-pkg', '1.0.1', vuln).isVulnerable, true);
  assert.equal(matchVulnerability('example-pkg', '1.0.2', vuln).isVulnerable, false);
});

test('Matcher: ignores vulnerabilities for different packages or ecosystems', () => {
  const vuln = {
    affected: [
      {
        package: { name: 'other-pkg', ecosystem: 'npm' },
        versions: ['1.0.0'],
      },
      {
        package: { name: 'example-pkg', ecosystem: 'PyPI' },
        versions: ['1.0.0'],
      },
    ],
  };

  assert.equal(matchVulnerability('example-pkg', '1.0.0', vuln).isVulnerable, false);
});
