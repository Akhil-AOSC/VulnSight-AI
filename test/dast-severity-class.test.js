'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { elevateToCritical } = require('../src/adapters/dast/severity-class');

test('high injection and access-control classes promote to critical', () => {
  assert.equal(elevateToCritical('high', { cwes: ['CWE-89'], title: 'SQL Injection' }), 'critical');
  assert.equal(elevateToCritical('high', { cwes: ['CWE-78'], title: 'Remote OS Command Injection' }), 'critical');
  assert.equal(elevateToCritical('high', { cwes: ['CWE-918'], title: 'Server Side Request Forgery' }), 'critical');
  assert.equal(elevateToCritical('high', { cwes: ['CWE-639'], title: 'Insecure Direct Object References' }), 'critical');
  assert.equal(elevateToCritical('high', { title: 'Authentication Bypass' }), 'critical');
});

test('medium SQL injection and disclosure promote to high; CSP stays medium', () => {
  assert.equal(elevateToCritical('medium', { cwes: ['CWE-89'], title: 'SQL Injection' }), 'high');
  assert.equal(elevateToCritical('medium', { cwes: ['CWE-200'], title: 'Information Disclosure' }), 'high');
  assert.equal(elevateToCritical('medium', { title: 'Cross Site Scripting (Stored)' }), 'high');
  assert.equal(elevateToCritical('high', { cwes: ['CWE-79'], title: 'Cross Site Scripting (Reflected)' }), 'high');
  assert.equal(elevateToCritical('medium', { cwes: ['CWE-352'], title: 'Absence of Anti-CSRF Tokens' }), 'high');
  assert.equal(elevateToCritical('high', { title: 'Server Side Request Forgery' }), 'critical');
  assert.equal(elevateToCritical('medium', { cwes: ['CWE-693'], title: 'CSP: style-src unsafe-inline' }), 'medium');
  assert.equal(elevateToCritical('low', { title: 'User Agent Fuzzer' }), 'low');
});
