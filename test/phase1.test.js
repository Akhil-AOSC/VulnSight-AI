'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { parseYarnLock, parsePnpmLock } = require('../src/parsers/js-lock');
const { parseGoSum } = require('../src/parsers/go');
const { parseTrivy, createTrivyAdapter } = require('../src/adapters/trivy');
const { parseCheckov } = require('../src/adapters/checkov');
const { createFinding, dedupeFindings } = require('../src/findings');
const { findingRisk, postureScore, summarize } = require('../src/risk');
const { renderCsv, renderMarkdown, renderCycloneDx, csvCell, purl } = require('../src/reports/export');

const ROOT = path.join(__dirname, '..', 'examples', 'npm-app');

const YARN_V1 = `# yarn lockfile v1

"@scope/util@^2.0.0":
  version "2.1.0"
  dependencies:
    lodash "^4.17.0"

lodash@^4.17.0, lodash@^4.17.15:
  version "4.17.15"

left-pad@^1.3.0:
  version "1.3.0"
`;

test('parseYarnLock (v1) builds paths from package.json roots', () => {
  const r = parseYarnLock(YARN_V1, {
    rootPackage: { name: 'app', version: '1.0.0', dependencies: { '@scope/util': '^2.0.0', 'left-pad': '^1.3.0' } },
  });
  const by = Object.fromEntries(r.dependencies.map((d) => [d.name, d]));
  assert.deepEqual(Object.keys(by).sort(), ['@scope/util', 'left-pad', 'lodash']);
  assert.equal(by.lodash.version, '4.17.15');
  assert.equal(by.lodash.direct, false);
  assert.deepEqual(by.lodash.paths[0], ['app@1.0.0', '@scope/util@2.1.0', 'lodash@4.17.15']);
  assert.equal(by['left-pad'].direct, true);
});

test('parseYarnLock (berry) understands npm: descriptors', () => {
  const berry = `__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: 4.17.21\n  resolution: "lodash@npm:4.17.21"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n`;
  const r = parseYarnLock(berry, { rootPackage: { name: 'app', dependencies: { lodash: '^4.17.0' } } });
  assert.deepEqual(r.dependencies.map((d) => `${d.name}@${d.version}`), ['lodash@4.17.21']);
});

test('parsePnpmLock (v9) reads importers and snapshots', () => {
  const lock = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2

packages:
  express@4.18.2:
    resolution: {integrity: sha512-x}
  qs@6.5.2:
    resolution: {integrity: sha512-y}

snapshots:
  express@4.18.2:
    dependencies:
      qs: 6.5.2
  qs@6.5.2: {}
`;
  const r = parsePnpmLock(lock, { rootPackage: { name: 'app', version: '1.0.0' } });
  const by = Object.fromEntries(r.dependencies.map((d) => [d.name, d]));
  assert.equal(by.express.direct, true);
  assert.equal(by.qs.direct, false);
  assert.deepEqual(by.qs.paths[0], ['app@1.0.0', 'express@4.18.2', 'qs@6.5.2']);
});

test('parseGoSum lists modules once and strips the v prefix', () => {
  const r = parseGoSum(`github.com/gin-gonic/gin v1.7.0 h1:abc=\ngithub.com/gin-gonic/gin v1.7.0/go.mod h1:def=\ngolang.org/x/text v0.3.5 h1:z=\n`);
  assert.deepEqual(r.dependencies.map((d) => `${d.name}@${d.version}`), ['github.com/gin-gonic/gin@1.7.0', 'golang.org/x/text@0.3.5']);
  assert.equal(r.dependencies[0].ecosystem, 'Go');
});

const TRIVY = JSON.stringify({
  Results: [
    {
      Target: 'package-lock.json', Class: 'lang-pkgs', Type: 'npm',
      Vulnerabilities: [{
        VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', InstalledVersion: '4.17.15', FixedVersion: '4.17.21, 5.0.0',
        Severity: 'HIGH', Title: 'Command injection', PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2021-23337',
        CweIDs: ['CWE-77'], CVSS: { nvd: { V3Score: 7.2 } },
      }],
    },
    {
      Target: 'main.tf', Class: 'config', Type: 'terraform',
      Misconfigurations: [{ ID: 'AVD-AWS-0086', Title: 'S3 public ACL', Message: 'Bucket has public ACL', Resolution: 'Set acl to private', Severity: 'CRITICAL', CauseMetadata: { StartLine: 4, EndLine: 9 } }],
    },
  ],
});

test('parseTrivy maps vulnerabilities and misconfigurations', () => {
  const found = parseTrivy(TRIVY, { root: ROOT, category: 'sca', version: '0.50.0', misconfig: true });
  assert.equal(found.length, 2);
  const [vuln, iac] = found;
  assert.deepEqual([vuln.category, vuln.severity, vuln.cvssScore], ['sca', 'high', 7.2]);
  assert.equal(vuln.location.ecosystem, 'npm');
  assert.equal(vuln.remediation.fixedIn, '4.17.21');
  assert.deepEqual(vuln.identifiers.cwe, ['CWE-77']);
  assert.deepEqual([iac.category, iac.severity, iac.location.file, iac.location.line], ['iac', 'critical', 'main.tf', 4]);
  assert.equal(parseTrivy(TRIVY, { root: ROOT, category: 'sca', version: '1', misconfig: false }).length, 1);
});

test('trivy image mode validates image names and reports container findings', async () => {
  const calls = [];
  const exec = async (cmd, args) => {
    calls.push(args);
    return { stdout: args[0] === '--version' ? 'Version: 0.50.0\n' : TRIVY };
  };
  const adapter = createTrivyAdapter({ mode: 'image', exec });
  assert.equal(await adapter.supports({ image: 'nginx:1.25' }), true);
  assert.equal(await adapter.supports({ image: '--output=/etc/passwd' }), false);
  assert.equal(await adapter.supports({ image: 'a b' }), false);
  const out = await adapter.run({ image: 'nginx:1.25' });
  assert.ok(calls.some((a) => a[0] === 'image' && a.includes('nginx:1.25')));
  assert.equal(out.findings[0].category, 'container');
});

test('trivy and OSV findings for the same package deduplicate', () => {
  const trivy = parseTrivy(TRIVY, { root: ROOT, category: 'sca', version: '1', misconfig: false })[0];
  const osv = createFinding({
    category: 'sca', scanner: { name: 'osv', ruleId: 'GHSA-35jh-r3h4-6jhm' }, title: 'Command injection in lodash', severity: 'high',
    identifiers: { primary: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'] },
    location: { file: 'package-lock.json', package: 'lodash', version: '4.17.15', ecosystem: 'npm' },
  });
  const out = dedupeFindings([osv, trivy]);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].sources.map((s) => s.name), ['osv', 'trivy']);
});

test('parseCheckov handles single and per-framework output', () => {
  const failed = { check_id: 'CKV_AWS_20', check_name: 'S3 bucket has public ACL', file_path: '/main.tf', file_line_range: [1, 8], resource: 'aws_s3_bucket.b', guideline: 'https://docs.example/ckv20', severity: null };
  const one = parseCheckov(JSON.stringify({ results: { failed_checks: [failed] } }), ROOT, '3.0');
  const many = parseCheckov(JSON.stringify([{ results: { failed_checks: [failed] } }, { results: { failed_checks: [] } }]), ROOT, '3.0');
  assert.equal(one.length, 1);
  assert.equal(many.length, 1);
  assert.deepEqual([one[0].category, one[0].severity, one[0].location.file, one[0].location.line], ['iac', 'medium', 'main.tf', 1]);
  assert.deepEqual(parseCheckov('', ROOT, '3'), []);
});

test('risk scoring adjusts without changing scanner severity', () => {
  const base = { category: 'sca', scanner: { name: 'osv' }, title: 't', severity: 'high', identifiers: { primary: 'X' }, location: { package: 'a', version: '1', direct: true }, remediation: { fixedIn: '2' } };
  const direct = createFinding(base);
  const transitive = createFinding({ ...base, location: { ...base.location, direct: false } });
  assert.ok(findingRisk(direct).score > findingRisk(transitive).score);
  assert.equal(direct.severity, 'high');
  assert.equal(findingRisk({ ...direct, status: 'suppressed' }).score, 0);
  assert.ok(findingRisk(createFinding({ category: 'secret', scanner: {}, title: 's', severity: 'high', identifiers: { primary: 'k' } })).factors.includes('exposed credential'));
});

test('postureScore falls with severity, never goes below 0 and ignores suppressed', () => {
  const mk = (severity, status) => createFinding({ category: 'sast', scanner: { ruleId: Math.random() }, title: 't', severity, status, identifiers: { primary: String(Math.random()) } });
  assert.deepEqual(postureScore([]), { score: 100, grade: 'A' });
  assert.ok(postureScore([mk('critical')]).score < postureScore([mk('low')]).score);
  assert.equal(postureScore(Array.from({ length: 50 }, () => mk('critical'))).score, 0);
  assert.equal(postureScore([mk('critical', 'suppressed')]).score, 100);
  assert.equal(summarize([mk('high'), mk('low', 'fixed')]).total, 1);
});

test('CSV neutralises spreadsheet formulas and quotes properly', () => {
  assert.equal(csvCell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"');
  assert.equal(csvCell('+1'), "'+1");
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell(null), '');
  const f = createFinding({ category: 'sca', scanner: { name: 'osv' }, title: '=cmd|calc', severity: 'low', identifiers: { primary: 'X' }, location: { package: 'p', version: '1' } });
  const csv = renderCsv([f]).split('\r\n');
  assert.ok(csv[0].startsWith('id,category,severity'));
  assert.ok(csv[1].includes("'=cmd|calc"));
});

test('CycloneDX SBOM has purls, dependency edges and vulnerabilities', () => {
  assert.equal(purl({ ecosystem: 'npm', name: '@scope/util', version: '2.1.0' }), 'pkg:npm/%40scope/util@2.1.0');
  assert.equal(purl({ ecosystem: 'PyPI', name: 'Django_Rest', version: '3.0' }), 'pkg:pypi/django-rest@3.0');

  const finding = createFinding({ category: 'sca', scanner: { name: 'osv' }, title: 'Proto', severity: 'high', cvssScore: 7.5, identifiers: { primary: 'GHSA-x' }, location: { file: 'package-lock.json', package: 'lodash', version: '4.17.15', ecosystem: 'npm' }, remediation: { fixedIn: '4.17.21' } });
  const report = {
    findings: [finding],
    raw: { osv: { projects: [{ dependencies: [
      { name: 'express', version: '4.0.0', ecosystem: 'npm', paths: [['app@1', 'express@4.0.0']] },
      { name: 'lodash', version: '4.17.15', ecosystem: 'npm', paths: [['app@1', 'express@4.0.0', 'lodash@4.17.15']] },
    ] }] } },
  };
  const bom = JSON.parse(renderCycloneDx(report, { name: 'app' }));
  assert.equal(bom.specVersion, '1.5');
  assert.equal(bom.components.length, 2);
  const edge = bom.dependencies.find((d) => d.ref === 'pkg:npm/express@4.0.0');
  assert.deepEqual(edge.dependsOn, ['pkg:npm/lodash@4.17.15']);
  assert.equal(bom.vulnerabilities[0].affects[0].ref, 'pkg:npm/lodash@4.17.15');
  assert.equal(bom.vulnerabilities[0].recommendation, 'Upgrade to 4.17.21');
});

test('markdown report escapes table cells', () => {
  const f = createFinding({ category: 'sast', scanner: { name: 'semgrep' }, title: 'bad | title\nline', severity: 'high', identifiers: { primary: 'r' }, location: { file: 'a.js', line: 3 } });
  const md = renderMarkdown({ target: { path: '/x' }, findings: [f], scanners: [{ scanner: 'semgrep', status: 'ok', version: '1', findingCount: 1, durationMs: 5 }] });
  assert.ok(md.includes('bad \\| title line'));
  assert.ok(md.includes('a.js:3'));
});
