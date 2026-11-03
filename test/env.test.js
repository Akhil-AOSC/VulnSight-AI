'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseEnvString, loadEnvFile, initEnv } = require('../src/env');

test('parseEnvString extracts key-value pairs and strips quotes and comments', () => {
  const content = `
    # Comment line
    PORT=5000
    API_URL="https://example.com/api"
    SECRET='super_secret_value'
    EMPTY=
  `;
  const parsed = parseEnvString(content);
  assert.equal(parsed.PORT, '5000');
  assert.equal(parsed.API_URL, 'https://example.com/api');
  assert.equal(parsed.SECRET, 'super_secret_value');
  assert.equal(parsed.EMPTY, '');
});

test('initEnv loads .env and respects .env.local overrides', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-env-'));
  try {
    fs.writeFileSync(path.join(tempDir, '.env'), 'TEST_VAR=base\nTEST_SHARED=base_val\n');
    fs.writeFileSync(path.join(tempDir, '.env.local'), 'TEST_VAR=local_override\n');

    const loaded = initEnv(tempDir);
    assert.equal(loaded.TEST_VAR, 'local_override');
    assert.equal(loaded.TEST_SHARED, 'base_val');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

