'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { openDatabase, transaction } = require('./db');
const { createSecretBox } = require('./crypto');

// Operational tooling: backup, verified restore, master-key rotation and account lockout. Used by
// scripts/ops.js and by the recovery drills in the tests. None of it needs the API to be running.

// A consistent online backup (safe while the platform is running). VACUUM INTO writes a complete,
// defragmented copy and refuses to overwrite an existing file.
function backup(dbPath, destFile) {
  if (!fs.existsSync(dbPath)) throw new Error(`Database not found: ${dbPath}`);
  if (fs.existsSync(destFile)) throw new Error(`Refusing to overwrite an existing backup: ${destFile}`);
  fs.mkdirSync(path.dirname(path.resolve(destFile)), { recursive: true });
  const db = new DatabaseSync(dbPath);
  try {
    db.exec(`VACUUM INTO '${destFile.replace(/'/g, "''")}'`);
  } finally {
    db.close();
  }
  return verify(destFile);
}

// Integrity check plus a count of what the file contains. Throws on a corrupt or foreign file.
function verify(file) {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const integrity = db.prepare('PRAGMA integrity_check').get().integrity_check;
    if (integrity !== 'ok') throw new Error(`Integrity check failed: ${integrity}`);
    const fk = db.prepare('PRAGMA foreign_key_check').all();
    if (fk.length) throw new Error(`Foreign key violations: ${fk.length}`);
    const count = (t) => db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n;
    return {
      ok: true,
      schemaVersion: db.prepare('SELECT MAX(version) AS v FROM schema_version').get().v,
      users: count('users'), orgs: count('orgs'), repositories: count('repositories'),
      scans: count('scans'), findings: count('findings'),
    };
  } finally {
    db.close();
  }
}

// Restores a backup to targetPath. The backup is verified first; an existing database is kept aside
// (never deleted) so a bad restore can be undone. Returns the path of the kept-aside copy, if any.
function restore(backupFile, targetPath) {
  const info = verify(backupFile);
  let keptAside = null;
  if (fs.existsSync(targetPath)) {
    keptAside = `${targetPath}.before-restore-${Date.now()}`;
    fs.renameSync(targetPath, keptAside);
    for (const ext of ['-wal', '-shm']) if (fs.existsSync(targetPath + ext)) fs.renameSync(targetPath + ext, keptAside + ext);
  }
  fs.mkdirSync(path.dirname(path.resolve(targetPath)), { recursive: true });
  fs.copyFileSync(backupFile, targetPath);
  verify(targetPath);
  openDatabase(targetPath).close(); // applies any newer migrations
  return { restored: info, keptAside };
}

// Re-encrypts every stored secret (Git provider tokens, webhook secrets, pending scan grants) under
// a new master key, in one transaction: either everything moves or nothing does. Use after a suspected
// key exposure. The old key is needed to read the data, so rotate BEFORE destroying it.
function rotateMasterKey(dbPath, oldKey, newKey) {
  const from = createSecretBox(oldKey);
  const to = createSecretBox(newKey);
  const db = openDatabase(dbPath);
  try {
    let rotated = 0;
    transaction(db, () => {
      for (const [table, column, id] of [['provider_connections', 'token_enc', 'id'], ['repositories', 'webhook_secret', 'id'], ['scan_grants', 'payload_enc', 'scan_id']]) {
        for (const row of db.prepare(`SELECT ${id} AS id, ${column} AS value FROM ${table} WHERE ${column} IS NOT NULL`).all()) {
          db.prepare(`UPDATE ${table} SET ${column} = ? WHERE ${id} = ?`).run(to.encrypt(from.decrypt(row.value)), row.id);
          rotated++;
        }
      }
    });
    return { rotated };
  } finally {
    db.close();
  }
}

// Incident response: stop an account immediately. Disables login and revokes every session.
function disableUser(dbPath, email) {
  const db = openDatabase(dbPath);
  try {
    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(String(email).trim().toLowerCase());
    if (!user) throw new Error('No such user');
    transaction(db, () => {
      db.prepare('UPDATE users SET disabled = 1 WHERE id = ?').run(user.id);
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
    });
    return { userId: user.id };
  } finally {
    db.close();
  }
}

// Incident response: end every session (for example after a suspected token theft).
function revokeAllSessions(dbPath) {
  const db = openDatabase(dbPath);
  try {
    return { revoked: Number(db.prepare('DELETE FROM sessions').run().changes) };
  } finally {
    db.close();
  }
}

module.exports = { backup, verify, restore, rotateMasterKey, disableUser, revokeAllSessions };
