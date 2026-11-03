'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { hashPassword, hashPasswordAsync, verifyPasswordAsync, verifyPassword } = require('../src/platform/crypto');

test('async hashing is compatible with the synchronous format', async () => {
  const h = await hashPasswordAsync('Correct-Horse-9');
  assert.ok(h.startsWith('scrypt$'));
  assert.equal(verifyPassword('Correct-Horse-9', h), true, 'sync verify accepts an async hash');
  assert.equal(await verifyPasswordAsync('Correct-Horse-9', hashPassword('Correct-Horse-9')), true, 'async verify accepts a sync hash');
  assert.equal(await verifyPasswordAsync('wrong', h), false);
  assert.equal(await verifyPasswordAsync('x', 'not-a-hash'), false);
});

test('concurrent logins do not freeze the event loop', async () => {
  const hash = hashPassword('Correct-Horse-9');
  let worstGap = 0;
  let last = Date.now();
  const timer = setInterval(() => { const now = Date.now(); worstGap = Math.max(worstGap, now - last); last = now; }, 5);
  // The synchronous version stalls the loop for ~35 ms per call: ~350 ms for these ten.
  const results = await Promise.all(Array.from({ length: 10 }, () => verifyPasswordAsync('Correct-Horse-9', hash)));
  clearInterval(timer);
  assert.ok(results.every(Boolean));
  assert.ok(worstGap < 120, `event loop was blocked for ${worstGap} ms`);
});

test('a flood of hashing requests is shed with a 503 instead of queuing without limit', async () => {
  const hash = hashPassword('Correct-Horse-9');
  const outcomes = await Promise.allSettled(Array.from({ length: 200 }, () => verifyPasswordAsync('Correct-Horse-9', hash)));
  const rejected = outcomes.filter((o) => o.status === 'rejected');
  assert.ok(rejected.length > 0, 'some requests were refused');
  assert.ok(rejected.every((o) => o.reason.status === 503));
  assert.ok(outcomes.some((o) => o.status === 'fulfilled' && o.value === true), 'the rest were served');
  // and the limiter recovers afterwards
  assert.equal(await verifyPasswordAsync('Correct-Horse-9', hash), true);
});
