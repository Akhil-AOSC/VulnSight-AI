'use strict';

// A small version comparator that handles both semver (npm) and the common
// PEP 440 forms (PyPI): 1.2.3, 1.2.3-beta.1, 1.0a1, 1.0rc2, 1.0.post1, 1.0.dev3.
// It is not a full implementation of either spec, but it orders the versions
// that appear in OSV "fixed" events correctly.

const SUFFIX_RANK = [
  [/^dev/, -4],
  [/^(a|alpha)/, -3],
  [/^(b|beta)/, -2],
  [/^(rc|c|pre|preview)/, -1],
  [/^(post|rev|r)/, 1],
];

function parse(version) {
  const v = String(version).trim().toLowerCase()
    .replace(/^v/, '')
    .replace(/^\d+!/, '') // PEP 440 epoch
    .replace(/\+.*$/, ''); // build metadata / local version
  const match = v.match(/^(\d+(?:\.\d+)*)(.*)$/);
  if (!match) return { release: [], suffixRank: 0, suffixNum: 0, rest: v };

  const release = match[1].split('.').map(Number);
  const rest = match[2].replace(/^[-._]/, '');
  if (!rest) return { release, suffixRank: 0, suffixNum: 0, rest: '' };

  const entry = SUFFIX_RANK.find(([re]) => re.test(rest));
  // Unknown semver prerelease tags (e.g. "-next.1") still sort before the release.
  const suffixRank = entry ? entry[1] : -1;
  const num = rest.match(/(\d+)/);
  return { release, suffixRank, suffixNum: num ? Number(num[1]) : 0, rest };
}

function compareVersions(a, b) {
  const pa = parse(a);
  const pb = parse(b);
  const len = Math.max(pa.release.length, pb.release.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa.release[i] || 0) - (pb.release[i] || 0);
    if (diff) return Math.sign(diff);
  }
  if (pa.suffixRank !== pb.suffixRank) return Math.sign(pa.suffixRank - pb.suffixRank);
  if (pa.suffixNum !== pb.suffixNum) return Math.sign(pa.suffixNum - pb.suffixNum);
  return pa.rest < pb.rest ? -1 : pa.rest > pb.rest ? 1 : 0;
}

module.exports = { compareVersions };
