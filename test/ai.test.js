'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { cleanJsonString, generateAiAnalysis } = require('../src/ai');

test('cleanJsonString removes markdown code blocks', () => {
  const withMarkdown = '```json\n{"key": "value"}\n```';
  assert.equal(cleanJsonString(withMarkdown), '{"key": "value"}');

  const withPlain = '```\n{"key": "value"}\n```';
  assert.equal(cleanJsonString(withPlain), '{"key": "value"}');

  const alreadyClean = '{"key": "value"}';
  assert.equal(cleanJsonString(alreadyClean), '{"key": "value"}');
});

test('generateAiAnalysis returns null when no API key is provided', async () => {
  const res = await generateAiAnalysis({ summary: { issues: 1 } }, { apiKey: '' });
  assert.equal(res, null);
});

test('generateAiAnalysis returns clean report when zero issues exist', async () => {
  const res = await generateAiAnalysis({ summary: { issues: 0 } }, { apiKey: 'fake_key' });
  assert.equal(res.riskLevel, 'None');
  assert.match(res.executiveSummary, /No known security vulnerabilities/);
});

