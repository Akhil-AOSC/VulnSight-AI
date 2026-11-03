'use strict';

const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');

// Storage layer. SQLite (built into Node) keeps the platform self-contained; the schema and the
// small query surface below map directly onto PostgreSQL for the hosted deployment.
//
// Every table that holds customer data carries org_id, and every query in the service layer
// filters on it. Raw scanner output (scan_raw) is stored apart from normalized findings,
// AI commentary (ai_history) apart from both.
const MIGRATIONS = [
  `
  CREATE TABLE users (
    id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
  CREATE TABLE orgs (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
    settings TEXT NOT NULL DEFAULT '{}');
  CREATE TABLE memberships (
    org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (org_id, user_id));
  CREATE TABLE teams (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE (org_id, name));
  CREATE TABLE team_members (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (team_id, user_id));
  CREATE TABLE provider_connections (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, label TEXT, token_enc TEXT NOT NULL, account TEXT,
    created_by TEXT, created_at TEXT NOT NULL);
  CREATE TABLE repositories (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    team_id TEXT REFERENCES teams(id) ON DELETE SET NULL,
    connection_id TEXT REFERENCES provider_connections(id) ON DELETE SET NULL,
    provider TEXT NOT NULL, full_name TEXT NOT NULL, clone_url TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main', config TEXT NOT NULL DEFAULT '{}',
    webhook_secret TEXT, schedule TEXT, next_scan_at TEXT, created_at TEXT NOT NULL,
    UNIQUE (org_id, clone_url));
  CREATE TABLE scans (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    repo_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    branch TEXT NOT NULL, commit_sha TEXT, trigger TEXT NOT NULL, status TEXT NOT NULL,
    scanners TEXT, summary TEXT, error TEXT, requested_by TEXT,
    created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT);
  CREATE INDEX scans_org_repo ON scans (org_id, repo_id, created_at);
  CREATE TABLE scan_raw (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL, data TEXT NOT NULL);
  CREATE TABLE findings (
    id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL, repo_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL, category TEXT NOT NULL, data TEXT NOT NULL);
  CREATE INDEX findings_scan ON findings (org_id, scan_id);
  CREATE INDEX findings_fp ON findings (org_id, repo_id, fingerprint);
  CREATE TABLE finding_states (
    org_id TEXT NOT NULL, repo_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', assignee_id TEXT, note TEXT,
    updated_by TEXT, updated_at TEXT NOT NULL, PRIMARY KEY (org_id, repo_id, fingerprint));
  CREATE TABLE finding_reviews (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, repo_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
    user_id TEXT, action TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL);
  CREATE TABLE ai_history (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, repo_id TEXT, finding_id TEXT, user_id TEXT,
    kind TEXT NOT NULL, provider TEXT, question TEXT, answer TEXT NOT NULL, created_at TEXT NOT NULL);
  CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, action TEXT NOT NULL, target TEXT,
    detail TEXT, ip TEXT, created_at TEXT NOT NULL);
  CREATE INDEX audit_org ON audit_logs (org_id, created_at);
  CREATE TABLE notifications (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT, kind TEXT NOT NULL,
    title TEXT NOT NULL, body TEXT, read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
  CREATE TABLE jobs (
    id TEXT PRIMARY KEY, type TEXT NOT NULL, payload TEXT NOT NULL, org_id TEXT,
    status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
    run_at TEXT NOT NULL, locked_at TEXT, error TEXT, created_at TEXT NOT NULL);
  CREATE INDEX jobs_ready ON jobs (status, run_at);
  `,
  // 2: single-use grants that hand a repository credential to a scan job without putting it in the
  // job-start request. Only a hash of the secret is stored; the credential itself is encrypted.
  `
  CREATE TABLE scan_grants (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL, secret_hash TEXT NOT NULL, payload_enc TEXT NOT NULL,
    expires_at TEXT NOT NULL, used_at TEXT);
  `,
  // 3: token expiration and scopes for git provider connections
  `
  ALTER TABLE provider_connections ADD COLUMN expires_at TEXT;
  ALTER TABLE provider_connections ADD COLUMN scopes TEXT;
  `,
];

function openDatabase(file = ':memory:') {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
  db.exec('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)');
  const row = db.prepare('SELECT MAX(version) AS v FROM schema_version').get();
  let current = row && row.v ? row.v : 0;
  while (current < MIGRATIONS.length) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[current]);
      current += 1;
      db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(current);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
  return db;
}

const uuid = () => crypto.randomUUID();
const now = () => new Date().toISOString();

// Runs fn inside a transaction.
function transaction(db, fn) {
  db.exec('BEGIN');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = { openDatabase, uuid, now, transaction };
