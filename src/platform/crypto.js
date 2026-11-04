'use strict';

const crypto = require('crypto');

// --- Passwords: scrypt with a per-user salt -------------------------------------------------
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts[0] !== 'scrypt' || parts.length !== 6) return false;
  const [, N, r, p, salt, hash] = parts;
  const expected = Buffer.from(hash, 'base64');
  const actual = crypto.scryptSync(password, Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p });
  return crypto.timingSafeEqual(actual, expected);
}

// Hashing off the event loop. scryptSync takes ~35 ms per call and blocks every other request while it
// runs, so a burst of logins would freeze the whole server. These run on libuv's thread pool instead,
// capped at MAX_HASHING at once: the pool is shared with DNS lookups (repository validation), so an
// unbounded login flood must not be able to starve them. Excess attempts fail fast with a 503.
const MAX_HASHING = 2;
const MAX_HASH_QUEUE = 50;
let hashing = 0;
const hashQueue = [];

function withHashSlot(fn) {
  return new Promise((resolve, reject) => {
    const run = () => {
      hashing++;
      fn().then(resolve, reject).finally(() => {
        hashing--;
        const next = hashQueue.shift();
        if (next) next();
      });
    };
    if (hashing < MAX_HASHING) return run();
    if (hashQueue.length >= MAX_HASH_QUEUE) return reject(Object.assign(new Error('The server is busy. Try again shortly'), { status: 503 }));
    hashQueue.push(run);
  });
}

const scryptAsync = (password, salt, keylen, opts) => new Promise((resolve, reject) => {
  crypto.scrypt(password, salt, keylen, opts, (err, key) => (err ? reject(err) : resolve(key)));
});

function hashPasswordAsync(password) {
  return withHashSlot(async () => {
    const salt = crypto.randomBytes(16);
    const hash = await scryptAsync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
    return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
  });
}

function verifyPasswordAsync(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts[0] !== 'scrypt' || parts.length !== 6) return Promise.resolve(false);
  const [, N, r, p, salt, hash] = parts;
  const expected = Buffer.from(hash, 'base64');
  return withHashSlot(async () => {
    const actual = await scryptAsync(password, Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p });
    return crypto.timingSafeEqual(actual, expected);
  });
}

function checkPasswordPolicy(password) {
  if (typeof password !== 'string' || !password.length) return 'Password is required';
  if (password.length > 200) return 'Password is too long';
  return null;
}

// --- Tokens: random, only the SHA-256 is stored ----------------------------------------------
const newToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

// --- Secrets at rest (Git provider tokens): AES-256-GCM ----------------------------------------
// The key comes from a SecretProvider so it can live in Azure Key Vault in production. The
// envelope is versioned so the key can be rotated.
function createSecretBox(key) {
  const buf = Buffer.isBuffer(key) ? key : Buffer.from(String(key || ''), 'base64');
  if (buf.length !== 32) throw new Error('Master key must be 32 bytes (base64-encoded)');
  return {
    encrypt(plain) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', buf, iv);
      const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
      return `v1.${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${enc.toString('base64')}`;
    },
    decrypt(envelope) {
      const [v, iv, tag, enc] = String(envelope).split('.');
      if (v !== 'v1') throw new Error('Unknown secret envelope version');
      const tagBuf = Buffer.from(tag, 'base64');
      if (tagBuf.length !== 16) throw new Error('Invalid authentication tag length');
      const d = crypto.createDecipheriv('aes-256-gcm', buf, Buffer.from(iv, 'base64'), { authTagLength: 16 });
      d.setAuthTag(tagBuf);
      return Buffer.concat([d.update(Buffer.from(enc, 'base64')), d.final()]).toString('utf8');
    },
  };
}

const generateMasterKey = () => crypto.randomBytes(32).toString('base64');

// Constant-time comparison for webhook signatures and similar.
function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

module.exports = { hashPassword, verifyPassword, hashPasswordAsync, verifyPasswordAsync, checkPasswordPolicy, newToken, sha256, createSecretBox, generateMasterKey, safeEqual };
