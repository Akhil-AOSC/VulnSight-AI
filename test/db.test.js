'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isMongoConfigured } = require('../src/db');

test('isMongoConfigured accurately detects presence of URI', () => {
  const orig = process.env.MONGODB_URI;
  try {
    process.env.MONGODB_URI = 'mongodb+srv://user:pass@cluster.mongodb.net';
    assert.equal(isMongoConfigured(), true);

    process.env.MONGODB_URI = '';
    assert.equal(isMongoConfigured(), false);
  } finally {
    process.env.MONGODB_URI = orig;
  }
});

