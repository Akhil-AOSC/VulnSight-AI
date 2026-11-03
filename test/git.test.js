'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { isGitUrl, parseGitUrl } = require('../src/git');

test('isGitUrl detects remote git repository URLs and rejects local paths', () => {
  assert.equal(isGitUrl('https://github.com/Akhil-AOSC/VulnSight-AI.git'), true);
  assert.equal(isGitUrl('https://github.com/Akhil-AOSC/VulnSight-AI'), true);
  assert.equal(isGitUrl('http://gitlab.com/group/project.git'), true);
  assert.equal(isGitUrl('git@github.com:owner/repo.git'), true);
  assert.equal(isGitUrl('github.com/owner/repo'), true);
  assert.equal(isGitUrl('https://github.com/owner/repo/tree/main/examples/npm-app'), true);

  assert.equal(isGitUrl('.'), false);
  assert.equal(isGitUrl('./examples/npm-app'), false);
  assert.equal(isGitUrl('C:\\Users\\hp\\Downloads\\VulnSight-AI'), false);
  assert.equal(isGitUrl('/home/user/project'), false);
  assert.equal(isGitUrl(''), false);
  assert.equal(isGitUrl(null), false);
});

test('parseGitUrl handles standard and tree URLs with branch/subpath', () => {
  const standard = parseGitUrl('https://github.com/owner/repo.git');
  assert.equal(standard.cloneUrl, 'https://github.com/owner/repo.git');
  assert.equal(standard.branch, null);
  assert.equal(standard.subpath, null);

  const shortcut = parseGitUrl('github.com/owner/repo');
  assert.equal(shortcut.cloneUrl, 'https://github.com/owner/repo');

  const tree = parseGitUrl('https://github.com/owner/repo/tree/develop/services/auth');
  assert.equal(tree.cloneUrl, 'https://github.com/owner/repo.git');
  assert.equal(tree.branch, 'develop');
  assert.equal(tree.subpath, 'services/auth');
});
