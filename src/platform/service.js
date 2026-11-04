'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { uuid, now, transaction } = require('./db');
const {
  hashPassword, hashPasswordAsync, verifyPasswordAsync, checkPasswordPolicy, newToken, sha256, safeEqual,
  createSecretBox, generateMasterKey,
} = require('./crypto');
const {
  ROLES, can, assertCan, ForbiddenError, NotFoundError, ValidationError, AuthError,
} = require('./rbac');
const { validateRepoUrl, validateBranch, cloneRepo } = require('./git');
const { PROVIDERS, providerForHost } = require('./providers');
const { runSandboxed } = require('./sandbox');
const { createLocalExecutor } = require('./executors');
const { NonRetryableError } = require('./queue');
const { DEFAULT_SCANNERS, SCANNERS } = require('../pipeline');
const { summarize, postureScore } = require('../risk');
const exporters = require('../reports/export');
const ai = require('../ai/assistant');
const { providerFromEnv } = require('../ai/providers');
const { generateAiAnalysis } = require('../ai');
const { fromScaIssue, createFinding } = require('../findings');
const { upgradePlan } = require('../report');
const { usagesForFinding } = require('../code-context');
const { runPassiveScan, validateTargetUrl } = require('../adapters/dast/passive');
const { crawlWebsite } = require('../adapters/dast/crawler');
const { generateVerificationToken, checkOwnership } = require('./dast-verifier');
const {
  isMongoConfigured,
  getMongoStatus,
  saveScanToMongo,
  listFullScansFromMongo,
  saveGitConnectionToMongo,
  getGitConnectionFromMongo,
  listGitConnectionsFromMongo,
  deleteGitConnectionFromMongo,
  saveUserToMongo,
  getUserFromMongoByEmail,
  saveRepoToMongo,
  listReposFromMongo,
  deleteRepoFromMongo,
  saveOrganisationToMongo,
  getOrganisationFromMongo,
  saveTeamToMongo,
  listTeamsFromMongo,
  deleteTeamFromMongo,
  saveNotificationToMongo,
  listNotificationsFromMongo,
  saveAuditToMongo,
  listAuditFromMongo,
  deleteOrgScopedFromMongo,
  saveWebsiteToMongo,
  listWebsitesFromMongo,
  getWebsiteFromMongo,
  deleteWebsiteFromMongo,
  saveWebsiteScanToMongo,
  listWebsiteScansFromMongo,
  getWebsiteScanFromMongo} = require('../db');

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const GRANT_TTL_MS = 10 * 60 * 1000;
const DEFAULT_SETTINGS = { aiEnabled: false, aiSendCode: false, retentionDays: 90 };
const SCHEDULES = { hourly: 3600e3, daily: 86400e3, weekly: 7 * 86400e3 };
const STATUSES = ['open', 'acknowledged', 'suppressed', 'fixed'];
const LIMITS = { reposPerOrg: 100, activeScansPerOrg: 10, aiRequestsPerHour: 60, pageSize: 200 };
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const DUMMY_HASH = hashPassword('dummy-password-for-timing-A1');

const parse = (s, fallback = null) => { try { return JSON.parse(s); } catch { return fallback; } };

  function createPlatform({
  db, secretBox, queue,
  fetchImpl = fetch,
  validateUrl = validateRepoUrl,
  clone = cloneRepo,
  runScan = runSandboxed,
  sandboxMode = 'process',
  executor = createLocalExecutor({ clone, runScan, mode: sandboxMode }),
  aiProviderFactory = () => providerFromEnv(),
  allowHosts = ['github.com', 'gitlab.com', 'bitbucket.org'],
  clock = () => Date.now(),
  enableMongo = false,
  enableAutoAi = false,
  gitPatStore = null,
  userStore = null,
  repoStore = null,
  orgSyncStore = null,
} = {}) {
  const nowIso = () => new Date(clock()).toISOString();

  // ---------- helpers ----------------------------------------------------------------------
  function roleOf(userId, orgId) {
    const row = db.prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId);
    // Non-members get "not found" so organisation ids can't be probed.
    if (!row) throw new NotFoundError('Organisation not found');
    return row.role;
  }

  // Authorizes ctx for a permission in its org and returns the role.
  function authorize(ctx, permission) {
    if (!ctx || !ctx.userId || !ctx.orgId) throw new AuthError();
    const role = roleOf(ctx.userId, ctx.orgId);
    assertCan(role, permission);
    return role;
  }

  function audit(ctx, action, target = null, detail = null) {
    const id = uuid();
    const orgId = (ctx && ctx.orgId) || null;
    const userId = (ctx && ctx.userId) || null;
    const createdAt = nowIso();
    const detailJson = detail ? JSON.stringify(detail) : null;
    const ip = (ctx && ctx.ip) || null;
    db.prepare('INSERT INTO audit_logs (id, org_id, user_id, action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, orgId, userId, action, target, detailJson, ip, createdAt);
    if (orgId) persistAudit({ id, orgId, userId, action, target, detail, ip, createdAt }).catch(() => {});
  }

  function notify(orgId, kind, title, body, roles = ['owner', 'admin']) {
    const users = db.prepare(`SELECT user_id FROM memberships WHERE org_id = ? AND role IN (${roles.map(() => '?').join(',')})`).all(orgId, ...roles);
    const stmt = db.prepare('INSERT INTO notifications (id, org_id, user_id, kind, title, body, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
    for (const u of users) {
      const id = uuid();
      const createdAt = nowIso();
      stmt.run(id, orgId, u.user_id, kind, title, body, createdAt);
      persistNotification({ id, orgId, userId: u.user_id, kind, title, body, read: false, createdAt }).catch(() => {});
    }
  }

  function settingsOf(orgId) {
    const row = db.prepare('SELECT settings FROM orgs WHERE id = ?').get(orgId);
    if (!row) throw new NotFoundError('Organisation not found');
    const parsed = parse(row.settings, {});
    const defaultAi = Boolean(enableAutoAi && (process.env.GROQ_API_KEY || process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY));
    return { ...DEFAULT_SETTINGS, aiEnabled: defaultAi, ...parsed };
  }

  function getRepo(orgId, repoId) {
    const repo = db.prepare('SELECT * FROM repositories WHERE id = ? AND org_id = ?').get(repoId, orgId);
    if (!repo) throw new NotFoundError('Repository not found');
    return repo;
  }

  const publicRepo = (r) => ({
    id: r.id, provider: r.provider, fullName: r.full_name, cloneUrl: r.clone_url, defaultBranch: r.default_branch,
    teamId: r.team_id, connectionId: r.connection_id, config: parse(r.config, {}), schedule: r.schedule,
    nextScanAt: r.next_scan_at, createdAt: r.created_at,
  });

  const publicScan = (s) => {
    const rawRow = s.id ? db.prepare('SELECT data FROM scan_raw WHERE scan_id = ?').get(s.id) : null;
    const raw = rawRow ? parse(rawRow.data, {}) : {};
    return {
      id: s.id, repoId: s.repo_id, branch: s.branch, commit: s.commit_sha, trigger: s.trigger, status: s.status,
      scanners: parse(s.scanners, []), summary: parse(s.summary, null), error: s.error,
      createdAt: s.created_at, startedAt: s.started_at, finishedAt: s.finished_at,
      ai: raw.ai || null,
      projects: (raw.osv && Array.isArray(raw.osv.projects)) ? raw.osv.projects : (Array.isArray(raw.projects) ? raw.projects : []),
      warnings: (raw.osv && Array.isArray(raw.osv.warnings)) ? raw.osv.warnings : (Array.isArray(raw.warnings) ? raw.warnings : []),
      source: raw.source || (isMongoConfigured() ? 'mongodb' : 'local'),
      target: raw.target || null,
    };
  };

  function getScan(orgId, scanId) {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ? AND org_id = ?').get(scanId, orgId);
    if (!scan) throw new NotFoundError('Scan not found');
    return scan;
  }

  const states = (orgId, repoId) => new Map(
    db.prepare('SELECT * FROM finding_states WHERE org_id = ? AND repo_id = ?').all(orgId, repoId).map((s) => [s.fingerprint, s]));

  function hydrateFindings(orgId, scan) {
    const st = states(orgId, scan.repo_id);
    return db.prepare('SELECT id, data, fingerprint FROM findings WHERE org_id = ? AND scan_id = ?').all(orgId, scan.id).map((row) => {
      const f = parse(row.data);
      const s = st.get(row.fingerprint);
      f.rowId = row.id;
      if (s) { f.status = s.status; f.assigneeId = s.assignee_id; f.note = s.note; }
      return f;
    });
  }

  function userDocument(userId) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return null;
    const orgs = db.prepare(`SELECT o.id, o.name, o.settings, o.created_at AS createdAt, m.role, m.created_at AS joinedAt
      FROM memberships m JOIN orgs o ON o.id = m.org_id WHERE m.user_id = ?`).all(userId);
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      passwordHash: user.password_hash,
      disabled: !!user.disabled,
      createdAt: user.created_at,
      orgs: orgs.map((o) => ({
        id: o.id, name: o.name, role: o.role, settings: o.settings, createdAt: o.createdAt, joinedAt: o.joinedAt,
      })),
    };
  }

  const orgWrapKeys = new Map();
  const userThemes = new Map();

  function usesOrgSync() {
    return Boolean(orgSyncStore || (enableMongo && isMongoConfigured()));
  }

  async function persistUser(userId) {
    const doc = userDocument(userId);
    if (!doc) return false;
    const previous = await loadUserByEmail(doc.email);
    const prevOrgs = new Map((previous && previous.orgs ? previous.orgs : []).map((o) => [o.id, o]));
    doc.orgs = doc.orgs.map((o) => {
      const wrapKey = (prevOrgs.get(o.id) && prevOrgs.get(o.id).wrapKey) || orgWrapKeys.get(o.id) || generateMasterKey();
      orgWrapKeys.set(o.id, wrapKey);
      return { ...o, wrapKey };
    });
    const theme = userThemes.get(userId) || (previous && previous.theme) || 'light';
    userThemes.set(userId, theme);
    doc.theme = theme;
    if (userStore) { await userStore.save(doc); return true; }
    if (enableMongo && isMongoConfigured()) return saveUserToMongo(doc);
    return false;
  }

  async function loadUserByEmail(email) {
    if (userStore) return userStore.getByEmail(email);
    if (enableMongo && isMongoConfigured()) return getUserFromMongoByEmail(email);
    return null;
  }

  function hydrateUserFromRemote(doc) {
    if (!doc || !doc.id || !doc.email || !doc.passwordHash) return null;
    transaction(db, () => {
      if (!db.prepare('SELECT 1 FROM users WHERE id = ? OR email = ?').get(doc.id, doc.email)) {
        db.prepare('INSERT INTO users (id, email, name, password_hash, created_at, disabled) VALUES (?, ?, ?, ?, ?, ?)')
          .run(doc.id, doc.email, doc.name || doc.email.split('@')[0], doc.passwordHash, doc.createdAt || nowIso(), doc.disabled ? 1 : 0);
      }
      for (const org of doc.orgs || []) {
        if (!org.id) continue;
        if (!db.prepare('SELECT 1 FROM orgs WHERE id = ?').get(org.id)) {
          db.prepare('INSERT INTO orgs (id, name, created_at, settings) VALUES (?, ?, ?, ?)')
            .run(org.id, org.name || 'Organisation', org.createdAt || nowIso(), org.settings || '{}');
        } else if (org.name || org.settings) {
          db.prepare('UPDATE orgs SET name = COALESCE(?, name), settings = COALESCE(?, settings) WHERE id = ?')
            .run(org.name || null, org.settings || null, org.id);
        }
        const membership = db.prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?').get(org.id, doc.id);
        if (!membership) {
          db.prepare('INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)')
            .run(org.id, doc.id, org.role || 'developer', org.joinedAt || nowIso());
        } else if (org.role && membership.role !== org.role) {
          db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(org.role, org.id, doc.id);
        }
      }
    });
    for (const org of doc.orgs || []) {
      if (org.id && org.wrapKey) orgWrapKeys.set(org.id, org.wrapKey);
    }
    if (doc.id && doc.theme) userThemes.set(doc.id, doc.theme);
    return db.prepare('SELECT * FROM users WHERE email = ?').get(doc.email);
  }

  // ---------- auth ------------------------------------------------------------------------
  const auth = {
    async signup({ email, name, password, orgName }, ctx = {}) {
      email = String(email || '').trim().toLowerCase();
      if (!EMAIL.test(email)) throw new ValidationError('Enter a valid email address');
      const policy = checkPasswordPolicy(password);
      if (policy) throw new ValidationError(policy);
      const cleanName = String(name || '').trim().slice(0, 100) || email.split('@')[0];
      const cleanOrg = String(orgName || '').trim().slice(0, 100) || `${cleanName}'s organisation`;
      if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) throw new ValidationError('Unable to create an account with those details');
      const remoteExisting = await loadUserByEmail(email);
      if (remoteExisting) throw new ValidationError('Unable to create an account with those details');

      const passwordHash = await hashPasswordAsync(password); // off the event loop
      // Re-check after the await: a concurrent signup with the same email may have won the race.
      if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) throw new ValidationError('Unable to create an account with those details');
      const userId = uuid();
      const orgId = uuid();
      transaction(db, () => {
        db.prepare('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)').run(userId, email, cleanName, passwordHash, nowIso());
        db.prepare('INSERT INTO orgs (id, name, created_at, settings) VALUES (?, ?, ?, ?)').run(orgId, cleanOrg, nowIso(), '{}');
        db.prepare('INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)').run(orgId, userId, 'owner', nowIso());
      });
      await persistUser(userId);
      if (enableMongo && !mongoSyncedOrgs.has(orgId)) {
        mongoSyncedOrgs.add(orgId);
        try { await dashboard.syncMongo(orgId); } catch { /* best effort */ }
      }
      audit({ ...ctx, userId, orgId }, 'user.signup', userId);
      return { ...auth.createSession(userId), user: { id: userId, email, name: cleanName }, orgId };
    },

    async login({ email, password }, ctx = {}) {
      email = String(email || '').trim().toLowerCase();
      const remote = await loadUserByEmail(email);
      let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (remote) user = hydrateUserFromRemote(remote) || user;
      // Always run a hash comparison so response time doesn't reveal whether the email exists.
      const ok = await verifyPasswordAsync(String(password || ''), user ? user.password_hash : DUMMY_HASH);
      if (!user || !ok || user.disabled) {
        audit({ ...ctx }, 'user.login_failed', null, { email });
        throw new AuthError('Incorrect email or password');
      }
      await persistUser(user.id);
      const orgIds = db.prepare('SELECT org_id AS id FROM memberships WHERE user_id = ?').all(user.id).map((o) => o.id);
      for (const orgId of orgIds) {
        await applyRemoteOrganisation(orgId);
        await applyRemoteTeams(orgId);
        await applyRemoteConnections(orgId);
        await applyRemoteRepos(orgId);
        await applyRemoteNotifications(orgId);
        await applyRemoteAudit(orgId);
      }
      audit({ ...ctx, userId: user.id }, 'user.login', user.id);
      return { ...auth.createSession(user.id), user: { id: user.id, email: user.email, name: user.name } };
    },

    createSession(userId) {
      const token = newToken();
      db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
        .run(sha256(token), userId, nowIso(), new Date(clock() + SESSION_TTL_MS).toISOString());
      return { token };
    },

    authenticate(token) {
      if (!token) throw new AuthError();
      const row = db.prepare('SELECT s.user_id, s.expires_at, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').get(sha256(String(token)));
      if (!row || row.disabled || new Date(row.expires_at).getTime() < clock()) throw new AuthError('Session expired. Please sign in again');
      return { userId: row.user_id };
    },

    logout(token) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(String(token || '')));
    },

    async me(userId) {
      const user = db.prepare('SELECT id, email, name, created_at FROM users WHERE id = ?').get(userId);
      if (!user) throw new AuthError();
      await persistUser(userId);
      const orgs = db.prepare('SELECT o.id, o.name, m.role FROM memberships m JOIN orgs o ON o.id = m.org_id WHERE m.user_id = ? ORDER BY o.name').all(userId);
      const { PERMISSIONS } = require('./rbac');
      return {
        ...user,
        theme: userThemes.get(userId) || 'light',
        orgs: orgs.map((o) => ({ ...o, permissions: PERMISSIONS[o.role] || [] })),
      };
    },

    async setTheme(userId, theme) {
      const allowed = ['light', 'dark', 'auto'];
      const next = allowed.includes(theme) ? theme : 'light';
      userThemes.set(userId, next);
      await persistUser(userId);
      return { theme: next };
    },
  };

  function organisationDocument(orgId) {
    const org = db.prepare('SELECT * FROM orgs WHERE id = ?').get(orgId);
    if (!org) return null;
    const members = db.prepare('SELECT u.id AS userId, u.email, u.name, m.role, m.created_at AS joinedAt FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ?').all(orgId);
    return { id: org.id, name: org.name, settings: parse(org.settings, {}), createdAt: org.created_at, members };
  }

  function teamDocument(orgId, teamId) {
    const team = db.prepare('SELECT * FROM teams WHERE id = ? AND org_id = ?').get(teamId, orgId);
    if (!team) return null;
    const members = db.prepare('SELECT user_id AS userId FROM team_members WHERE team_id = ?').all(teamId).map((m) => m.userId);
    return { id: team.id, orgId, name: team.name, createdAt: team.created_at, members };
  }

  async function persistOrganisation(orgId) {
    const doc = organisationDocument(orgId);
    if (!doc) return false;
    if (orgSyncStore) { await orgSyncStore.saveOrg(doc); return true; }
    if (enableMongo && isMongoConfigured()) return saveOrganisationToMongo(doc);
    return false;
  }

  async function persistTeam(orgId, teamId) {
    const doc = teamDocument(orgId, teamId);
    if (!doc) return false;
    if (orgSyncStore) { await orgSyncStore.saveTeam(doc); return true; }
    if (enableMongo && isMongoConfigured()) return saveTeamToMongo(doc);
    return false;
  }

  async function forgetTeam(orgId, teamId) {
    if (orgSyncStore) return orgSyncStore.removeTeam(orgId, teamId);
    if (enableMongo && isMongoConfigured()) return deleteTeamFromMongo(orgId, teamId);
    return false;
  }

  async function persistNotification(doc) {
    if (orgSyncStore) { await orgSyncStore.saveNotification(doc); return true; }
    if (enableMongo && isMongoConfigured()) return saveNotificationToMongo(doc);
    return false;
  }

  async function persistAudit(doc) {
    if (orgSyncStore) { await orgSyncStore.saveAudit(doc); return true; }
    if (enableMongo && isMongoConfigured()) return saveAuditToMongo(doc);
    return false;
  }

  async function applyRemoteOrganisation(orgId) {
    if (!usesOrgSync()) return null;
    const remote = orgSyncStore ? await orgSyncStore.getOrg(orgId) : await getOrganisationFromMongo(orgId);
    if (!remote || !remote.id) return null;
    if (!db.prepare('SELECT 1 FROM orgs WHERE id = ?').get(orgId)) {
      db.prepare('INSERT INTO orgs (id, name, created_at, settings) VALUES (?, ?, ?, ?)')
        .run(orgId, remote.name || 'Organisation', remote.createdAt || nowIso(), JSON.stringify(remote.settings || {}));
    } else {
      db.prepare('UPDATE orgs SET name = ?, settings = ? WHERE id = ?')
        .run(remote.name || 'Organisation', JSON.stringify(remote.settings || {}), orgId);
    }
    for (const member of remote.members || []) {
      if (!member.userId || !db.prepare('SELECT 1 FROM users WHERE id = ?').get(member.userId)) continue;
      const existing = db.prepare('SELECT role FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, member.userId);
      if (!existing) {
        db.prepare('INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)')
          .run(orgId, member.userId, member.role || 'developer', member.joinedAt || nowIso());
      } else if (member.role && existing.role !== member.role) {
        db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(member.role, orgId, member.userId);
      }
    }
    return remote;
  }

  async function applyRemoteTeams(orgId) {
    if (!usesOrgSync()) return null;
    const remote = orgSyncStore ? await orgSyncStore.listTeams(orgId) : await listTeamsFromMongo(orgId);
    if (remote == null) return null;
    const keep = new Set();
    for (const doc of remote) {
      if (!doc.id || doc.orgId !== orgId) continue;
      keep.add(doc.id);
      if (!db.prepare('SELECT 1 FROM teams WHERE id = ? AND org_id = ?').get(doc.id, orgId)) {
        db.prepare('INSERT INTO teams (id, org_id, name, created_at) VALUES (?, ?, ?, ?)')
          .run(doc.id, orgId, doc.name, doc.createdAt || nowIso());
      } else {
        db.prepare('UPDATE teams SET name = ? WHERE id = ? AND org_id = ?').run(doc.name, doc.id, orgId);
      }
      db.prepare('DELETE FROM team_members WHERE team_id = ?').run(doc.id);
      for (const userId of doc.members || []) {
        if (db.prepare('SELECT 1 FROM users WHERE id = ?').get(userId)
          && db.prepare('SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, userId)) {
          db.prepare('INSERT OR IGNORE INTO team_members (team_id, user_id) VALUES (?, ?)').run(doc.id, userId);
        }
      }
    }
    for (const row of db.prepare('SELECT id FROM teams WHERE org_id = ?').all(orgId)) {
      if (!keep.has(row.id)) db.prepare('DELETE FROM teams WHERE id = ? AND org_id = ?').run(row.id, orgId);
    }
    return remote;
  }

  async function applyRemoteNotifications(orgId) {
    if (!usesOrgSync()) return null;
    const remote = orgSyncStore ? await orgSyncStore.listNotifications(orgId) : await listNotificationsFromMongo(orgId);
    if (remote == null) return null;
    for (const doc of remote) {
      if (!doc.id || doc.orgId !== orgId) continue;
      const existing = db.prepare('SELECT id FROM notifications WHERE id = ? AND org_id = ?').get(doc.id, orgId);
      if (existing) {
        db.prepare('UPDATE notifications SET kind = ?, title = ?, body = ?, read = ?, user_id = ? WHERE id = ? AND org_id = ?')
          .run(doc.kind, doc.title, doc.body || null, doc.read ? 1 : 0, doc.userId || null, doc.id, orgId);
      } else {
        db.prepare('INSERT INTO notifications (id, org_id, user_id, kind, title, body, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .run(doc.id, orgId, doc.userId || null, doc.kind, doc.title, doc.body || null, doc.read ? 1 : 0, doc.createdAt || nowIso());
      }
    }
    return remote;
  }

  async function applyRemoteAudit(orgId) {
    if (!usesOrgSync()) return null;
    const remote = orgSyncStore ? await orgSyncStore.listAudits(orgId) : await listAuditFromMongo(orgId);
    if (remote == null) return null;
    for (const doc of remote) {
      if (!doc.id || doc.orgId !== orgId) continue;
      if (db.prepare('SELECT 1 FROM audit_logs WHERE id = ?').get(doc.id)) continue;
      db.prepare('INSERT INTO audit_logs (id, org_id, user_id, action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(doc.id, orgId, doc.userId || null, doc.action, doc.target || null, doc.detail ? JSON.stringify(doc.detail) : null, doc.ip || null, doc.createdAt || nowIso());
    }
    return remote;
  }

  // ---------- organisations, members, teams ------------------------------------------------
  const orgs = {
    create(userId, { name }) {
      const clean = String(name || '').trim().slice(0, 100);
      if (!clean) throw new ValidationError('Organisation name is required');
      const orgId = uuid();
      transaction(db, () => {
        db.prepare('INSERT INTO orgs (id, name, created_at, settings) VALUES (?, ?, ?, ?)').run(orgId, clean, nowIso(), '{}');
        db.prepare('INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)').run(orgId, userId, 'owner', nowIso());
      });
      audit({ userId, orgId }, 'org.create', orgId);
      persistOrganisation(orgId).catch(() => {});
      persistUser(userId).catch(() => {});
      return { id: orgId, name: clean, role: 'owner' };
    },

    async getSettings(ctx) {
      authorize(ctx, 'repos:read');
      await persistOrganisation(ctx.orgId);
      await persistUser(ctx.userId);
      await applyRemoteOrganisation(ctx.orgId);
      return settingsOf(ctx.orgId);
    },

    async updateSettings(ctx, patch) {
      authorize(ctx, 'org:settings');
      const next = { ...settingsOf(ctx.orgId) };
      if (typeof patch.aiEnabled === 'boolean') next.aiEnabled = patch.aiEnabled;
      if (typeof patch.aiSendCode === 'boolean') next.aiSendCode = patch.aiSendCode && next.aiEnabled;
      if (!next.aiEnabled) next.aiSendCode = false;
      if (patch.retentionDays !== undefined) {
        const d = Number(patch.retentionDays);
        if (!Number.isInteger(d) || d < 1 || d > 3650) throw new ValidationError('Retention must be between 1 and 3650 days');
        next.retentionDays = d;
      }
      db.prepare('UPDATE orgs SET settings = ? WHERE id = ?').run(JSON.stringify(next), ctx.orgId);
      audit(ctx, 'org.settings', ctx.orgId, next);
      await persistOrganisation(ctx.orgId);
      await persistUser(ctx.userId);
      return next;
    },

    async rename(ctx, name) {
      authorize(ctx, 'org:settings');
      const clean = String(name || '').trim().slice(0, 100);
      if (!clean) throw new ValidationError('Organisation name is required');
      db.prepare('UPDATE orgs SET name = ? WHERE id = ?').run(clean, ctx.orgId);
      audit(ctx, 'org.rename', ctx.orgId);
      await persistOrganisation(ctx.orgId);
      await persistUser(ctx.userId);
      return { id: ctx.orgId, name: clean };
    },

    async delete(ctx) {
      authorize(ctx, 'org:delete');
      const orgId = ctx.orgId;
      transaction(db, () => {
        for (const t of ['finding_states', 'finding_reviews', 'ai_history', 'notifications', 'jobs', 'scan_raw', 'findings']) {
          db.prepare(`DELETE FROM ${t} WHERE org_id = ?`).run(orgId);
        }
        db.prepare('DELETE FROM orgs WHERE id = ?').run(orgId);
      });
      if (orgSyncStore) await orgSyncStore.removeOrg(orgId);
      else if (enableMongo && isMongoConfigured()) await deleteOrgScopedFromMongo(orgId);
      audit({ userId: ctx.userId, ip: ctx.ip }, 'org.delete', orgId);
    },

    async listMembers(ctx) {
      authorize(ctx, 'teams:read');
      await persistOrganisation(ctx.orgId);
      await applyRemoteOrganisation(ctx.orgId);
      return db.prepare('SELECT u.id, u.email, u.name, m.role, m.created_at AS joinedAt FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = ? ORDER BY u.email').all(ctx.orgId);
    },

    addMember(ctx, { email, role = 'developer' }) {
      const actorRole = authorize(ctx, 'members:manage');
      if (!ROLES.includes(role)) throw new ValidationError('Unknown role');
      if (role === 'owner' && actorRole !== 'owner') throw new ForbiddenError('Only owners can add owners');
      const user = db.prepare('SELECT id FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase());
      if (!user) throw new NotFoundError('No user with that email. They need to create an account first');
      if (db.prepare('SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, user.id)) throw new ValidationError('Already a member');
      db.prepare('INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)').run(ctx.orgId, user.id, role, nowIso());
      audit(ctx, 'member.add', user.id, { role });
      persistOrganisation(ctx.orgId).catch(() => {});
      persistUser(ctx.userId).catch(() => {});
      persistUser(user.id).catch(() => {});
      return { userId: user.id, role };
    },

    setMemberRole(ctx, userId, role) {
      const actorRole = authorize(ctx, 'members:manage');
      if (!ROLES.includes(role)) throw new ValidationError('Unknown role');
      const current = roleOf(userId, ctx.orgId);
      if ((role === 'owner' || current === 'owner') && actorRole !== 'owner') throw new ForbiddenError('Only owners can change owner roles');
      if (current === 'owner' && role !== 'owner') assertNotLastOwner(ctx.orgId);
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(role, ctx.orgId, userId);
      audit(ctx, 'member.role', userId, { from: current, to: role });
      persistOrganisation(ctx.orgId).catch(() => {});
      persistUser(ctx.userId).catch(() => {});
      persistUser(userId).catch(() => {});
      return { userId, role };
    },

    removeMember(ctx, userId) {
      const actorRole = authorize(ctx, 'members:manage');
      const current = roleOf(userId, ctx.orgId);
      if (current === 'owner') {
        if (actorRole !== 'owner') throw new ForbiddenError('Only owners can remove owners');
        assertNotLastOwner(ctx.orgId);
      }
      db.prepare('DELETE FROM memberships WHERE org_id = ? AND user_id = ?').run(ctx.orgId, userId);
      db.prepare('DELETE FROM team_members WHERE user_id = ? AND team_id IN (SELECT id FROM teams WHERE org_id = ?)').run(userId, ctx.orgId);
      audit(ctx, 'member.remove', userId);
      persistOrganisation(ctx.orgId).catch(() => {});
      persistUser(ctx.userId).catch(() => {});
      persistUser(userId).catch(() => {});
    },
  };

  function assertNotLastOwner(orgId) {
    const n = db.prepare("SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND role = 'owner'").get(orgId).n;
    if (n <= 1) throw new ValidationError('An organisation must keep at least one owner');
  }

  const teams = {
    async list(ctx) {
      authorize(ctx, 'teams:read');
      await applyRemoteTeams(ctx.orgId);
      for (const t of db.prepare('SELECT id FROM teams WHERE org_id = ?').all(ctx.orgId)) {
        await persistTeam(ctx.orgId, t.id);
      }
      return db.prepare('SELECT id, name, created_at AS createdAt FROM teams WHERE org_id = ? ORDER BY name').all(ctx.orgId).map((t) => ({
        ...t, members: db.prepare('SELECT user_id AS userId FROM team_members WHERE team_id = ?').all(t.id).map((m) => m.userId),
      }));
    },
    async create(ctx, { name }) {
      authorize(ctx, 'teams:manage');
      const clean = String(name || '').trim().slice(0, 100);
      if (!clean) throw new ValidationError('Team name is required');
      const id = uuid();
      try {
        db.prepare('INSERT INTO teams (id, org_id, name, created_at) VALUES (?, ?, ?, ?)').run(id, ctx.orgId, clean, nowIso());
      } catch {
        throw new ValidationError('A team with that name already exists');
      }
      audit(ctx, 'team.create', id);
      await persistTeam(ctx.orgId, id);
      return { id, name: clean };
    },
    async addMember(ctx, teamId, userId) {
      authorize(ctx, 'teams:manage');
      if (!db.prepare('SELECT 1 FROM teams WHERE id = ? AND org_id = ?').get(teamId, ctx.orgId)) throw new NotFoundError('Team not found');
      roleOf(userId, ctx.orgId);
      db.prepare('INSERT OR IGNORE INTO team_members (team_id, user_id) VALUES (?, ?)').run(teamId, userId);
      audit(ctx, 'team.member_add', teamId, { userId });
      await persistTeam(ctx.orgId, teamId);
    },
    async removeMember(ctx, teamId, userId) {
      authorize(ctx, 'teams:manage');
      if (!db.prepare('SELECT 1 FROM teams WHERE id = ? AND org_id = ?').get(teamId, ctx.orgId)) throw new NotFoundError('Team not found');
      db.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?').run(teamId, userId);
      audit(ctx, 'team.member_remove', teamId, { userId });
      await persistTeam(ctx.orgId, teamId);
    },
    async delete(ctx, teamId) {
      authorize(ctx, 'teams:manage');
      db.prepare('DELETE FROM teams WHERE id = ? AND org_id = ?').run(teamId, ctx.orgId);
      await forgetTeam(ctx.orgId, teamId);
      audit(ctx, 'team.delete', teamId);
    },
  };

  // ---------- git provider connections ------------------------------------------------------
  // Encrypted PAT lives in MongoDB (one document per GitHub/GitLab/Bitbucket account) so several
  // Git identities can be stored and loaded independently. SQLite keeps a copy for offline/FK use.
  function sqliteConnection(orgId, connectionId) {
    const c = db.prepare('SELECT * FROM provider_connections WHERE id = ? AND org_id = ?').get(connectionId, orgId);
    if (!c) throw new NotFoundError('Connection not found');
    return c;
  }

  function usesPortableWrap() {
    return Boolean(gitPatStore || (enableMongo && isMongoConfigured()));
  }

  function patBox(orgId) {
    const key = orgWrapKeys.get(orgId);
    return usesPortableWrap() && key ? createSecretBox(key) : secretBox;
  }

  function decryptPatEnvelope(orgId, envelope) {
    if (!envelope) throw new Error('missing token');
    const key = orgWrapKeys.get(orgId);
    if (key) {
      try { return createSecretBox(key).decrypt(envelope); } catch { /* try process key */ }
    }
    return secretBox.decrypt(envelope);
  }

  function patDocument(c, tokenEnc) {
    return {
      id: c.id,
      orgId: c.org_id,
      provider: c.provider,
      label: c.label,
      account: c.account,
      expiresAt: c.expires_at || null,
      scopes: c.scopes || null,
      createdBy: c.created_by,
      createdAt: c.created_at,
      tokenEnc,
    };
  }

  async function persistPat(c, tokenPlain) {
    const tokenEnc = patBox(c.org_id).encrypt(tokenPlain);
    const doc = patDocument(c, tokenEnc);
    if (gitPatStore) {
      await gitPatStore.save(doc);
      return true;
    }
    if (enableMongo && isMongoConfigured()) return saveGitConnectionToMongo(doc);
    return false;
  }

  async function loadPatDoc(orgId, connectionId) {
    if (gitPatStore) return gitPatStore.get(orgId, connectionId);
    if (enableMongo && isMongoConfigured()) return getGitConnectionFromMongo(orgId, connectionId);
    return null;
  }

  async function forgetPat(orgId, connectionId) {
    if (gitPatStore) return gitPatStore.remove(orgId, connectionId);
    if (enableMongo && isMongoConfigured()) return deleteGitConnectionFromMongo(orgId, connectionId);
    return false;
  }

  async function listRemotePats(orgId) {
    if (gitPatStore && typeof gitPatStore.list === 'function') return gitPatStore.list(orgId);
    if (enableMongo && isMongoConfigured()) return listGitConnectionsFromMongo(orgId);
    return null;
  }

  function accountKey(provider, account) {
    return `${String(provider || '').toLowerCase()}:${String(account || '').trim().toLowerCase()}`;
  }

  function connectionByAccount(orgId, provider, account) {
    if (!account) return null;
    const want = accountKey(provider, account);
    return db.prepare('SELECT * FROM provider_connections WHERE org_id = ? AND provider = ?').all(orgId, provider)
      .find((row) => accountKey(row.provider, row.account) === want) || null;
  }

  async function collapseDuplicateAccounts(orgId) {
    const rows = db.prepare('SELECT * FROM provider_connections WHERE org_id = ? ORDER BY created_at, id').all(orgId);
    const seen = new Set();
    for (const row of rows) {
      if (!row.account) continue;
      const key = accountKey(row.provider, row.account);
      if (seen.has(key)) {
        db.prepare('DELETE FROM provider_connections WHERE id = ? AND org_id = ?').run(row.id, orgId);
        await forgetPat(orgId, row.id);
      } else {
        seen.add(key);
      }
    }
  }

  async function applyRemoteConnections(orgId) {
    const remote = await listRemotePats(orgId);
    if (remote == null) return null;
    const keep = new Set();
    for (const doc of remote) {
      if (!doc.id || doc.orgId !== orgId) continue;
      keep.add(doc.id);
      const existing = db.prepare('SELECT id FROM provider_connections WHERE id = ? AND org_id = ?').get(doc.id, orgId);
      if (existing) {
        db.prepare('UPDATE provider_connections SET provider = ?, label = ?, account = ?, expires_at = ?, scopes = ?, token_enc = ? WHERE id = ? AND org_id = ?')
          .run(doc.provider, doc.label || doc.account, doc.account, doc.expiresAt || null, doc.scopes || null, doc.tokenEnc, doc.id, orgId);
      } else {
        db.prepare('INSERT INTO provider_connections (id, org_id, provider, label, token_enc, account, expires_at, scopes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .run(doc.id, orgId, doc.provider, doc.label || doc.account || doc.provider, doc.tokenEnc, doc.account, doc.expiresAt || null, doc.scopes || null, doc.createdBy || null, doc.createdAt || nowIso());
      }
    }
    const locals = db.prepare('SELECT id FROM provider_connections WHERE org_id = ?').all(orgId);
    for (const row of locals) {
      if (!keep.has(row.id)) {
        db.prepare('DELETE FROM provider_connections WHERE id = ? AND org_id = ?').run(row.id, orgId);
      }
    }
    await collapseDuplicateAccounts(orgId);
    return remote;
  }

  async function connectionToken(orgId, connectionId) {
    const c = sqliteConnection(orgId, connectionId);
    const remote = await loadPatDoc(orgId, connectionId);
    if (remote && remote.tokenEnc) {
      try {
        return { connection: c, token: decryptPatEnvelope(orgId, remote.tokenEnc), source: 'mongodb' };
      } catch { /* try local copy */ }
    }
    const token = decryptPatEnvelope(orgId, c.token_enc);
    await persistPat(c, token);
    return { connection: c, token, source: 'local' };
  }

  const connections = {
    async connect(ctx, { provider, token, label }) {
      authorize(ctx, 'providers:manage');
      const impl = PROVIDERS[provider];
      if (!impl) throw new ValidationError('Unsupported provider. Use github, gitlab or bitbucket');
      if (typeof token !== 'string' || token.length < 8 || token.length > 500) throw new ValidationError('Enter a valid access token');
      const { account, expiresAt = null, scopes = null } = await impl.validate(token, fetchImpl);
      await persistUser(ctx.userId);
      await applyRemoteConnections(ctx.orgId);
      if (connectionByAccount(ctx.orgId, provider, account)) {
        throw new ValidationError(`This ${provider} account is already connected`);
      }
      const id = uuid();
      const tokenEnc = patBox(ctx.orgId).encrypt(token);
      const createdAt = nowIso();
      const rowLabel = String(label || account || provider).slice(0, 100);
      db.prepare('INSERT INTO provider_connections (id, org_id, provider, label, token_enc, account, expires_at, scopes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(id, ctx.orgId, provider, rowLabel, tokenEnc, account, expiresAt, scopes, ctx.userId, createdAt);
      await persistPat({
        id, org_id: ctx.orgId, provider, label: rowLabel, account,
        expires_at: expiresAt, scopes, created_by: ctx.userId, created_at: createdAt,
      }, token);
      audit(ctx, 'provider.connect', id, { provider, account, expiresAt });
      return { id, provider, account, expiresAt, scopes };
    },
    async list(ctx) {
      authorize(ctx, 'repos:read');
      await persistUser(ctx.userId);
      const remote = await applyRemoteConnections(ctx.orgId);
      const locals = db.prepare('SELECT * FROM provider_connections WHERE org_id = ?').all(ctx.orgId);
      const keep = remote == null ? null : new Set(remote.filter((d) => d && d.id && d.orgId === ctx.orgId).map((d) => d.id));
      for (const row of locals) {
        if (keep && !keep.has(row.id)) continue;
        try { await persistPat(row, decryptPatEnvelope(ctx.orgId, row.token_enc)); } catch { /* leave as-is */ }
      }
      // Tokens are never returned.
      const rows = db.prepare('SELECT id, provider, label, account, expires_at AS expiresAt, scopes, created_at AS createdAt FROM provider_connections WHERE org_id = ? ORDER BY created_at').all(ctx.orgId);
      const now = new Date();
      return rows.map((r) => {
        const exp = r.expiresAt ? new Date(r.expiresAt) : null;
        const isExpired = exp ? exp <= now : false;
        const daysLeft = exp && !isExpired ? Math.ceil((exp - now) / 86400000) : null;
        return { ...r, isExpired, daysLeft };
      });
    },
    async check(ctx, connectionId) {
      authorize(ctx, 'providers:manage');
      const { connection, token } = await connectionToken(ctx.orgId, connectionId);
      const impl = PROVIDERS[connection.provider];
      if (!impl) throw new ValidationError('Unsupported provider');
      try {
        const { account, expiresAt = null, scopes = null } = await impl.validate(token, fetchImpl);
        db.prepare('UPDATE provider_connections SET account = ?, expires_at = ?, scopes = ? WHERE id = ? AND org_id = ?')
          .run(account, expiresAt, scopes, connectionId, ctx.orgId);
        const updated = db.prepare('SELECT * FROM provider_connections WHERE id = ? AND org_id = ?').get(connectionId, ctx.orgId);
        await persistPat(updated, token);
        const now = new Date();
        const exp = expiresAt ? new Date(expiresAt) : null;
        const isExpired = exp ? exp <= now : false;
        const daysLeft = exp && !isExpired ? Math.ceil((exp - now) / 86400000) : null;
        return { valid: true, account, expiresAt, isExpired, daysLeft, scopes };
      } catch (err) {
        return { valid: false, error: err.message, status: err.status || 400 };
      }
    },
    async listRemoteRepos(ctx, connectionId) {
      authorize(ctx, 'repos:write');
      const { connection, token } = await connectionToken(ctx.orgId, connectionId);
      return PROVIDERS[connection.provider].listRepos(token, fetchImpl);
    },
    async listBranches(ctx, connectionId, fullName) {
      authorize(ctx, 'repos:write');
      const { connection, token } = await connectionToken(ctx.orgId, connectionId);
      return PROVIDERS[connection.provider].listBranches(token, fullName, fetchImpl);
    },
    async remove(ctx, connectionId) {
      authorize(ctx, 'providers:manage');
      sqliteConnection(ctx.orgId, connectionId);
      db.prepare('DELETE FROM provider_connections WHERE id = ? AND org_id = ?').run(connectionId, ctx.orgId);
      await forgetPat(ctx.orgId, connectionId);
      audit(ctx, 'provider.disconnect', connectionId);
    },
  };

  // ---------- repositories ---------------------------------------------------------------------
  function validateConfig(config = {}) {
    const out = {};
    if (config.scanners !== undefined) {
      if (!Array.isArray(config.scanners) || !config.scanners.every((s) => SCANNERS[s] && s !== 'trivy-image')) throw new ValidationError('Invalid scanner list');
      out.scanners = [...new Set(config.scanners)];
    }
    if (config.threshold !== undefined) {
      if (!['low', 'medium', 'high', 'critical'].includes(config.threshold)) throw new ValidationError('Invalid severity threshold');
      out.threshold = config.threshold;
    }
    if (config.branches !== undefined) {
      if (!Array.isArray(config.branches) || config.branches.length > 20) throw new ValidationError('Invalid branch list');
      out.branches = config.branches.map(validateBranch);
    }
    return out;
  }

  function repoDocument(row) {
    return {
      id: row.id,
      orgId: row.org_id,
      teamId: row.team_id || null,
      connectionId: row.connection_id || null,
      provider: row.provider,
      fullName: row.full_name,
      cloneUrl: row.clone_url,
      defaultBranch: row.default_branch,
      config: parse(row.config, {}),
      schedule: row.schedule || null,
      nextScanAt: row.next_scan_at || null,
      createdAt: row.created_at,
    };
  }

  async function persistRepo(row) {
    const doc = repoDocument(row);
    if (repoStore) { await repoStore.save(doc); return true; }
    if (enableMongo && isMongoConfigured()) return saveRepoToMongo(doc);
    return false;
  }

  async function forgetRepo(orgId, repoId) {
    if (repoStore) return repoStore.remove(orgId, repoId);
    if (enableMongo && isMongoConfigured()) return deleteRepoFromMongo(orgId, repoId);
    return false;
  }

  async function listRemoteReposDocs(orgId) {
    if (repoStore && typeof repoStore.list === 'function') return repoStore.list(orgId);
    if (enableMongo && isMongoConfigured()) return listReposFromMongo(orgId);
    return null;
  }

  async function applyRemoteRepos(orgId) {
    const remote = await listRemoteReposDocs(orgId);
    if (remote == null) return null;
    const keep = new Set();
    for (const doc of remote) {
      if (!doc.id || doc.orgId !== orgId || !doc.cloneUrl) continue;
      keep.add(doc.id);
      const connOk = doc.connectionId && db.prepare('SELECT 1 FROM provider_connections WHERE id = ? AND org_id = ?').get(doc.connectionId, orgId);
      const connectionId = connOk ? doc.connectionId : null;
      const teamOk = doc.teamId && db.prepare('SELECT 1 FROM teams WHERE id = ? AND org_id = ?').get(doc.teamId, orgId);
      const teamId = teamOk ? doc.teamId : null;
      const config = typeof doc.config === 'string' ? doc.config : JSON.stringify(doc.config || {});
      const byUrl = db.prepare('SELECT id, webhook_secret FROM repositories WHERE org_id = ? AND clone_url = ?').get(orgId, doc.cloneUrl);
      if (byUrl && byUrl.id !== doc.id) {
        db.prepare('DELETE FROM repositories WHERE id = ? AND org_id = ?').run(byUrl.id, orgId);
      }
      const existing = db.prepare('SELECT id, webhook_secret FROM repositories WHERE id = ? AND org_id = ?').get(doc.id, orgId);
      const webhook = (existing && existing.webhook_secret) || (byUrl && byUrl.id === doc.id && byUrl.webhook_secret) || secretBox.encrypt(newToken(24));
      if (existing) {
        db.prepare('UPDATE repositories SET team_id = ?, connection_id = ?, provider = ?, full_name = ?, clone_url = ?, default_branch = ?, config = ?, schedule = ?, next_scan_at = ? WHERE id = ? AND org_id = ?')
          .run(teamId, connectionId, doc.provider, doc.fullName, doc.cloneUrl, doc.defaultBranch || 'main', config, doc.schedule || null, doc.nextScanAt || null, doc.id, orgId);
      } else {
        db.prepare(`INSERT INTO repositories (id, org_id, team_id, connection_id, provider, full_name, clone_url, default_branch, config, webhook_secret, schedule, next_scan_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(doc.id, orgId, teamId, connectionId, doc.provider, doc.fullName, doc.cloneUrl, doc.defaultBranch || 'main', config, webhook, doc.schedule || null, doc.nextScanAt || null, doc.createdAt || nowIso());
      }
    }
    const locals = db.prepare('SELECT id FROM repositories WHERE org_id = ?').all(orgId);
    for (const row of locals) {
      if (!keep.has(row.id)) db.prepare('DELETE FROM repositories WHERE id = ? AND org_id = ?').run(row.id, orgId);
    }
    return remote;
  }

  const repos = {
    async add(ctx, { url, branch, connectionId = null, teamId = null, config }) {
      authorize(ctx, 'repos:write');
      if (db.prepare('SELECT COUNT(*) AS n FROM repositories WHERE org_id = ?').get(ctx.orgId).n >= LIMITS.reposPerOrg) throw new ValidationError('Repository limit reached for this organisation');
      const rawUrl = String(url || '').trim();
      const isLocalPath = enableMongo && (path.isAbsolute(rawUrl) || /^[A-Za-z]:[\\/]/.test(rawUrl) || (rawUrl && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawUrl) && fs.existsSync(path.resolve(rawUrl))));
      let v;
      let provider;
      if (isLocalPath) {
        const resolved = path.resolve(rawUrl);
        if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) throw new ValidationError(`Local project directory not found: ${rawUrl}`);
        const parts = resolved.split(/[\\/]/).filter(Boolean);
        const fullName = parts.slice(-2).join('/') || parts[parts.length - 1] || 'local-project';
        v = { url: resolved, host: 'local', fullName };
        provider = 'local';
      } else {
        v = await validateUrl(url, { allowHosts });
        provider = providerForHost(v.host);
        if (!provider) throw new ValidationError('Unsupported Git host');
      }
      if (connectionId && provider !== 'local') {
        const { connection } = await connectionToken(ctx.orgId, connectionId);
        if (connection.provider !== provider) throw new ValidationError('That connection is for a different Git provider');
      }
      if (teamId && !db.prepare('SELECT 1 FROM teams WHERE id = ? AND org_id = ?').get(teamId, ctx.orgId)) throw new NotFoundError('Team not found');
      const defaultBranch = branch ? validateBranch(branch) : 'main';
      const cleanConfig = validateConfig(config);
      const id = uuid();
      try {
        db.prepare(`INSERT INTO repositories (id, org_id, team_id, connection_id, provider, full_name, clone_url, default_branch, config, webhook_secret, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(id, ctx.orgId, teamId, connectionId, provider, v.fullName, v.url, defaultBranch, JSON.stringify(cleanConfig), secretBox.encrypt(newToken(24)), nowIso());
      } catch {
        throw new ValidationError('That repository is already connected');
      }
      audit(ctx, 'repo.add', id, { url: v.url });
      await persistRepo(getRepo(ctx.orgId, id));
      return publicRepo(getRepo(ctx.orgId, id));
    },

    async list(ctx) {
      authorize(ctx, 'repos:read');
      await applyRemoteRepos(ctx.orgId);
      return db.prepare('SELECT * FROM repositories WHERE org_id = ? ORDER BY full_name').all(ctx.orgId).map((r) => {
        const last = db.prepare("SELECT * FROM scans WHERE org_id = ? AND repo_id = ? ORDER BY created_at DESC LIMIT 1").get(ctx.orgId, r.id);
        const lastDone = db.prepare("SELECT summary FROM scans WHERE org_id = ? AND repo_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1").get(ctx.orgId, r.id);
        return { ...publicRepo(r), lastScan: last ? publicScan(last) : null, security: lastDone ? parse(lastDone.summary) : null };
      });
    },

    get(ctx, repoId) {
      authorize(ctx, 'repos:read');
      return publicRepo(getRepo(ctx.orgId, repoId));
    },

    async update(ctx, repoId, patch) {
      authorize(ctx, 'repos:write');
      const repo = getRepo(ctx.orgId, repoId);
      const config = { ...parse(repo.config, {}), ...validateConfig(patch.config) };
      const branch = patch.defaultBranch ? validateBranch(patch.defaultBranch) : repo.default_branch;
      let teamId = repo.team_id;
      if (patch.teamId !== undefined) {
        if (patch.teamId && !db.prepare('SELECT 1 FROM teams WHERE id = ? AND org_id = ?').get(patch.teamId, ctx.orgId)) throw new NotFoundError('Team not found');
        teamId = patch.teamId || null;
      }
      db.prepare('UPDATE repositories SET config = ?, default_branch = ?, team_id = ? WHERE id = ?').run(JSON.stringify(config), branch, teamId, repoId);
      audit(ctx, 'repo.update', repoId);
      await persistRepo(getRepo(ctx.orgId, repoId));
      return publicRepo(getRepo(ctx.orgId, repoId));
    },

    async setSchedule(ctx, repoId, schedule) {
      authorize(ctx, 'repos:write');
      getRepo(ctx.orgId, repoId);
      if (schedule !== null && !SCHEDULES[schedule]) throw new ValidationError('Schedule must be hourly, daily, weekly or null');
      const next = schedule ? new Date(clock() + SCHEDULES[schedule]).toISOString() : null;
      db.prepare('UPDATE repositories SET schedule = ?, next_scan_at = ? WHERE id = ?').run(schedule, next, repoId);
      audit(ctx, 'repo.schedule', repoId, { schedule });
      await persistRepo(getRepo(ctx.orgId, repoId));
      return { schedule, nextScanAt: next };
    },

    async remove(ctx, repoId) {
      authorize(ctx, 'repos:write');
      getRepo(ctx.orgId, repoId);
      transaction(db, () => {
        for (const t of ['finding_states', 'finding_reviews', 'ai_history']) db.prepare(`DELETE FROM ${t} WHERE org_id = ? AND repo_id = ?`).run(ctx.orgId, repoId);
        db.prepare('DELETE FROM repositories WHERE id = ? AND org_id = ?').run(repoId, ctx.orgId);
      });
      await forgetRepo(ctx.orgId, repoId);
      audit(ctx, 'repo.remove', repoId);
    },

    async branches(ctx, repoId) {
      authorize(ctx, 'repos:read');
      const repo = getRepo(ctx.orgId, repoId);
      if (!repo.connection_id) return [repo.default_branch];
      const { token } = await connectionToken(ctx.orgId, repo.connection_id);
      return PROVIDERS[repo.provider].listBranches(token, repo.full_name, fetchImpl);
    },

    webhookSecret(ctx, repoId) {
      authorize(ctx, 'repos:write');
      return secretBox.decrypt(getRepo(ctx.orgId, repoId).webhook_secret);
    },
  };

  // ---------- scans ------------------------------------------------------------------------
  function createScan(orgId, repo, { branch, trigger, userId }) {
    const active = db.prepare("SELECT COUNT(*) AS n FROM scans WHERE org_id = ? AND status IN ('queued','running')").get(orgId).n;
    if (active >= LIMITS.activeScansPerOrg) throw new ValidationError('Too many scans are in progress. Try again shortly');
    if (db.prepare("SELECT 1 FROM scans WHERE repo_id = ? AND branch = ? AND status IN ('queued','running')").get(repo.id, branch)) {
      throw new ValidationError('A scan of that branch is already in progress');
    }
    const id = uuid();
    db.prepare('INSERT INTO scans (id, org_id, repo_id, branch, trigger, status, requested_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, orgId, repo.id, branch, trigger, 'queued', userId || null, nowIso());
    queue.enqueue('scan', { scanId: id }, { orgId });
    return id;
  }

  const scans = {
    start(ctx, repoId, { branch } = {}) {
      authorize(ctx, 'scans:run');
      const repo = getRepo(ctx.orgId, repoId);
      const b = validateBranch(branch || repo.default_branch);
      const id = createScan(ctx.orgId, repo, { branch: b, trigger: 'manual', userId: ctx.userId });
      audit(ctx, 'scan.start', id, { repo: repo.full_name, branch: b });
      return publicScan(getScan(ctx.orgId, id));
    },

    async quickScan(ctx, { target, branch, threshold = 'low' } = {}) {
      authorize(ctx, 'scans:run');
      const rawTarget = String(target || '').trim();
      if (!rawTarget) throw new ValidationError('Enter a repository URL or local project folder');

      let repo = db.prepare('SELECT * FROM repositories WHERE org_id = ? AND (clone_url = ? OR LOWER(full_name) = LOWER(?))').get(ctx.orgId, rawTarget, rawTarget);
      if (!repo) {
        const added = await repos.add(ctx, {
          url: rawTarget,
          branch: branch || 'main',
          config: { scanners: ['sca', 'semgrep', 'gitleaks'], threshold: ['low', 'medium', 'high', 'critical'].includes(threshold) ? threshold : 'low' },
        });
        repo = getRepo(ctx.orgId, added.id);
      } else if (threshold && ['low', 'medium', 'high', 'critical'].includes(threshold)) {
        const cfg = { ...parse(repo.config, {}), threshold };
        db.prepare('UPDATE repositories SET config = ? WHERE id = ?').run(JSON.stringify(cfg), repo.id);
        repo = getRepo(ctx.orgId, repo.id);
      }
      return scans.start(ctx, repo.id, { branch: branch || repo.default_branch });
    },

    list(ctx, { repoId, limit = 50 } = {}) {
      authorize(ctx, 'scans:read');
      const lim = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
      const rows = repoId
        ? db.prepare('SELECT * FROM scans WHERE org_id = ? AND repo_id = ? ORDER BY created_at DESC LIMIT ?').all(ctx.orgId, repoId, lim)
        : db.prepare('SELECT * FROM scans WHERE org_id = ? ORDER BY created_at DESC LIMIT ?').all(ctx.orgId, lim);
      return rows.map(publicScan);
    },

    get(ctx, scanId) {
      authorize(ctx, 'scans:read');
      return publicScan(getScan(ctx.orgId, scanId));
    },

    cancel(ctx, scanId) {
      authorize(ctx, 'scans:run');
      const scan = getScan(ctx.orgId, scanId);
      if (scan.status !== 'queued') throw new ValidationError('Only queued scans can be cancelled');
      queue.cancelWhere('scan', (p) => p.scanId === scanId);
      db.prepare("UPDATE scans SET status = 'cancelled', finished_at = ? WHERE id = ?").run(nowIso(), scanId);
      audit(ctx, 'scan.cancel', scanId);
      return publicScan(getScan(ctx.orgId, scanId));
    },

    findings(ctx, scanId, filters = {}) {
      authorize(ctx, 'findings:read');
      const scan = getScan(ctx.orgId, scanId);
      let list = hydrateFindings(ctx.orgId, scan);
      if (filters.severity) list = list.filter((f) => String(filters.severity).split(',').includes(f.severity));
      if (filters.category) list = list.filter((f) => f.category === filters.category);
      if (filters.status) list = list.filter((f) => f.status === filters.status);
      if (filters.assignee) list = list.filter((f) => f.assigneeId === filters.assignee);
      if (filters.q) {
        const q = String(filters.q).toLowerCase();
        list = list.filter((f) => [f.title, f.identifiers.primary, ...f.identifiers.aliases, f.location.package, f.location.file].some((v) => v && String(v).toLowerCase().includes(q)));
      }
      const sorted = exporters.sortFindings(list);
      if (filters.sort === 'package') sorted.sort((a, b) => String(a.location.package || a.location.file).localeCompare(String(b.location.package || b.location.file)));
      const pageSize = Math.min(Math.max(parseInt(filters.pageSize, 10) || 50, 1), LIMITS.pageSize);
      const page = Math.max(parseInt(filters.page, 10) || 1, 1);
      return { total: sorted.length, page, pageSize, items: sorted.slice((page - 1) * pageSize, page * pageSize) };
    },

    report(ctx, scanId, format) {
      authorize(ctx, 'reports:read');
      const scan = getScan(ctx.orgId, scanId);
      const repo = getRepo(ctx.orgId, scan.repo_id);
      const raw = db.prepare('SELECT data FROM scan_raw WHERE scan_id = ? AND org_id = ?').get(scanId, ctx.orgId);
      const report = {
        target: { path: `${repo.full_name}@${scan.branch}` },
        startedAt: scan.started_at || scan.created_at,
        scanners: parse(scan.scanners, []),
        raw: raw ? parse(raw.data, {}) : {},
        findings: hydrateFindings(ctx.orgId, scan),
      };
      audit(ctx, 'report.export', scanId, { format });
      switch (format) {
        case 'csv': return { type: 'text/csv; charset=utf-8', ext: 'csv', body: exporters.renderCsv(report.findings) };
        case 'markdown': return { type: 'text/markdown; charset=utf-8', ext: 'md', body: exporters.renderMarkdown(report, { title: `Security report: ${repo.full_name}` }) };
        case 'cyclonedx': return { type: 'application/json', ext: 'cdx.json', body: exporters.renderCycloneDx(report, { name: repo.full_name }) };
        case 'json': return { type: 'application/json', ext: 'json', body: exporters.renderJsonReport(report) };
        default: throw new ValidationError('Format must be csv, markdown, cyclonedx or json');
      }
    },
  };

  // ---------- scan grants: credential handoff to remote scan jobs ------------------------------------
  // A remote job must not receive the Git token in its start request (that request is readable by
  // anyone who can read job executions). Instead the request carries a random one-time secret; the
  // job exchanges it here, once, for the credential. Valid only while its scan is running.
  const grants = {
    issue(scanId, orgId, auth) {
      const secret = newToken(32);
      db.prepare(`INSERT INTO scan_grants (scan_id, org_id, secret_hash, payload_enc, expires_at) VALUES (?, ?, ?, ?, ?)
                  ON CONFLICT (scan_id) DO UPDATE SET secret_hash = excluded.secret_hash, payload_enc = excluded.payload_enc,
                  expires_at = excluded.expires_at, used_at = NULL`)
        .run(scanId, orgId, sha256(secret), secretBox.encrypt(JSON.stringify(auth)), new Date(clock() + GRANT_TTL_MS).toISOString());
      return secret;
    },

    // Returns the credential exactly once. Every failure looks the same to the caller.
    redeem(scanId, secret, ip = null) {
      const fail = (why) => {
        audit({ ip }, 'scan.grant_denied', String(scanId).slice(0, 80), { why });
        throw new ForbiddenError('Invalid or expired grant');
      };
      if (typeof scanId !== 'string' || typeof secret !== 'string' || secret.length < 20 || secret.length > 200) return fail('malformed');
      const row = db.prepare('SELECT * FROM scan_grants WHERE scan_id = ?').get(scanId);
      if (!row) return fail('unknown');
      if (!safeEqual(row.secret_hash, sha256(secret))) return fail('wrong secret');
      if (row.used_at) return fail('already used'); // a replay: someone else has seen the secret
      if (new Date(row.expires_at).getTime() < clock()) return fail('expired');
      const scan = db.prepare('SELECT status FROM scans WHERE id = ?').get(scanId);
      if (!scan || scan.status !== 'running') return fail('scan not running');
      // Atomic single use: only one caller can flip used_at from NULL.
      const claimed = db.prepare('UPDATE scan_grants SET used_at = ? WHERE scan_id = ? AND used_at IS NULL').run(nowIso(), scanId);
      if (Number(claimed.changes) !== 1) return fail('already used');
      audit({ orgId: row.org_id, ip }, 'scan.grant_used', scanId);
      return parse(secretBox.decrypt(row.payload_enc));
    },

    revoke(scanId) {
      db.prepare('DELETE FROM scan_grants WHERE scan_id = ?').run(scanId);
    },
  };

  // The worker's scan job.
  const NON_RETRYABLE = /access denied|not found|too large|too many|not allowed|non-public|invalid|resolve/i;

  async function handleScanJob({ scanId }, job = { attempts: 1, max_attempts: 1 }) {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    if (!scan || scan.status === 'cancelled') return;
    const repo = db.prepare('SELECT * FROM repositories WHERE id = ? AND org_id = ?').get(scan.repo_id, scan.org_id);
    if (!repo) {
      db.prepare("UPDATE scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ?").run('Repository was removed', nowIso(), scanId);
      return;
    }
    db.prepare("UPDATE scans SET status = 'running', started_at = ?, error = NULL WHERE id = ?").run(nowIso(), scanId);

    try {
      const config = parse(repo.config, {});
      let result;
      if (repo.provider === 'local') {
        const localDir = path.resolve(repo.clone_url);
        if (!fs.existsSync(localDir) || !fs.statSync(localDir).isDirectory()) {
          throw new NonRetryableError(`Local directory not found: ${repo.clone_url}`);
        }
        const report = await runScan(localDir, {
          scanners: config.scanners || DEFAULT_SCANNERS,
          threshold: config.threshold || 'low',
          mode: sandboxMode,
        });
        result = { report, commit: 'local', scrub: [localDir] };
      } else {
        const validated = await validateUrl(repo.clone_url, { allowHosts });
        let authInfo = null;
        if (repo.connection_id) {
          const { connection, token } = await connectionToken(scan.org_id, repo.connection_id);
          authInfo = PROVIDERS[connection.provider].cloneAuth(token);
        }
        const issueGrant = (auth) => grants.issue(scanId, scan.org_id, auth);
        result = await executor({ validated, branch: scan.branch, auth: authInfo, config, scanId, issueGrant });
      }
      await storeResults(scan, repo, result.report, { commit: result.commit, scrub: result.scrub || [] });
    } catch (err) {
      const message = String(err.message || err).replace(/vulnsight-[\w-]+/g, '<workspace>').slice(0, 300);
      const finalAttempt = job.attempts >= job.max_attempts;
      const retryable = !NON_RETRYABLE.test(message) && !finalAttempt;
      if (retryable) {
        db.prepare("UPDATE scans SET status = 'queued', error = ? WHERE id = ?").run(message, scanId);
        throw err;
      }
      db.prepare("UPDATE scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ?").run(message, nowIso(), scanId);
      notify(scan.org_id, 'scan.failed', `Scan failed: ${repo.full_name}`, message);
      throw new NonRetryableError(message);
    } finally {
      grants.revoke(scanId); // the credential never outlives the scan
    }
  }

  function buildAiReportInput(findings, rawData) {
    const osvProjects = (rawData && rawData.osv && Array.isArray(rawData.osv.projects)) ? rawData.osv.projects : [];
    const byCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const f of findings) {
      byCounts[f.severity] = (byCounts[f.severity] || 0) + 1;
    }
    const totalDeps = osvProjects.reduce((acc, p) => acc + (p.dependencyCount || (p.dependencies ? p.dependencies.length : 0)), 0);
    const vulns = findings.map((f) => ({
      id: (f.identifiers && f.identifiers.primary) || f.id,
      aliases: (f.identifiers && f.identifiers.aliases) || [],
      title: f.title,
      severity: f.severity,
      cvssScore: f.cvssScore,
      package: (f.location && f.location.package) || (f.location && f.location.file) || f.category,
      version: (f.location && f.location.version) || (f.location && f.location.line ? `line ${f.location.line}` : 'source'),
      ecosystem: (f.location && f.location.ecosystem) || f.category,
      fixedIn: (f.remediation && f.remediation.fixedIn) || null,
      url: f.url || null,
      direct: f.location ? f.location.direct : null,
      paths: (f.location && f.location.paths) || [],
      remediation: (f.remediation && (f.remediation.advice || (f.remediation.fixedIn ? `Upgrade ${(f.location && f.location.package) || ''} to ${f.remediation.fixedIn}`.trim() : 'Review finding details'))) || 'Review finding details',
    }));

    const projects = osvProjects.length ? osvProjects.map((p) => {
      const pVulns = Array.isArray(p.vulnerabilities) && p.vulnerabilities.length
        ? p.vulnerabilities
        : vulns.filter((v) => v.package && p.dependencies && p.dependencies.some((d) => d.name === v.package));
      return {
        file: p.file,
        packageManager: p.packageManager || p.type || 'npm',
        ecosystem: p.ecosystem || 'npm',
        projectName: p.projectName || p.name || p.file,
        dependencyCount: p.dependencyCount != null ? p.dependencyCount : (p.dependencies ? p.dependencies.length : 0),
        skipped: p.skipped || [],
        summary: p.summary || byCounts,
        upgradePlan: p.upgradePlan || upgradePlan(pVulns),
        vulnerabilities: pVulns,
      };
    }) : [{
      file: 'repository',
      packageManager: 'scanner',
      ecosystem: 'multi',
      projectName: 'repository',
      dependencyCount: totalDeps,
      skipped: [],
      summary: byCounts,
      upgradePlan: upgradePlan(vulns.filter((v) => v.fixedIn)),
      vulnerabilities: vulns,
    }];

    return {
      ok: findings.length === 0,
      warnings: (rawData && rawData.osv && rawData.osv.warnings) || [],
      summary: {
        issues: findings.length,
        dependencies: totalDeps,
        ...byCounts,
      },
      projects,
    };
  }

  async function storeResults(scan, repo, report, workspace) {
    const scrub = (s) => (typeof s === 'string' ? workspace.scrub.filter(Boolean).reduce((acc, dir) => acc.split(dir).join('<repo>'), s) : s);
    const scanners = (report.scanners || []).map((s) => ({ ...s, error: scrub(s.error) }));
    const everyFailed = scanners.length > 0 && scanners.every((s) => s.status === 'error' || s.status === 'timeout');
    if (everyFailed) throw new Error(`All scanners failed: ${scanners[0].error}`);

    const prev = db.prepare("SELECT id FROM scans WHERE org_id = ? AND repo_id = ? AND branch = ? AND status = 'completed' AND id != ? ORDER BY created_at DESC LIMIT 1")
      .get(scan.org_id, repo.id, scan.branch, scan.id);
    const prevFps = new Set(prev ? db.prepare('SELECT fingerprint FROM findings WHERE scan_id = ?').all(prev.id).map((r) => r.fingerprint) : []);
    const findings = report.findings || [];
    const currentFps = new Set(findings.map((f) => f.id));
    const fixed = [...prevFps].filter((fp) => !currentFps.has(fp));
    const added = findings.filter((f) => !prevFps.has(f.id));

    const rawData = { ...(report.raw || {}) };
    const aiInput = buildAiReportInput(findings, rawData);

    // Enhance findings with Groq Open-Source LLM when enabled
    let aiBriefing = null;
    if (enableAutoAi && process.env.GROQ_API_KEY) {
      try {
        aiBriefing = await generateAiAnalysis(aiInput);
        if (aiBriefing && aiBriefing.packageExplanations) {
          for (const f of findings) {
            const key = (f.location && f.location.package) || (f.location && f.location.file) || f.category;
            if (key && aiBriefing.packageExplanations[key]) {
              f.aiExplanation = aiBriefing.packageExplanations[key];
            }
          }
          for (const proj of aiInput.projects) {
            for (const vuln of proj.vulnerabilities || []) {
              if (aiBriefing.packageExplanations[vuln.package]) {
                vuln.aiExplanation = aiBriefing.packageExplanations[vuln.package];
              }
            }
          }
        }
      } catch (err) {
        console.warn('[AI Warning] Could not generate AI analysis:', err.message);
      }
    }

    rawData.ai = aiBriefing;
    rawData.projects = aiInput.projects;
    rawData.warnings = aiInput.warnings;
    rawData.target = repo.clone_url || repo.full_name;
    rawData.source = (enableMongo && isMongoConfigured()) ? 'mongodb' : 'local';

    let finalSummary = null;
    const finishedAt = nowIso();

    transaction(db, () => {
      const insert = db.prepare('INSERT INTO findings (id, scan_id, org_id, repo_id, fingerprint, severity, category, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
      for (const f of findings) insert.run(uuid(), scan.id, scan.org_id, repo.id, f.id, f.severity, f.category, JSON.stringify(f));
      db.prepare('INSERT INTO scan_raw (scan_id, org_id, data) VALUES (?, ?, ?)').run(scan.id, scan.org_id, JSON.stringify(rawData));

      if (aiBriefing && aiBriefing.executiveSummary) {
        db.prepare('INSERT INTO ai_history (id, org_id, repo_id, finding_id, user_id, kind, provider, question, answer, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .run(uuid(), scan.org_id, repo.id, null, scan.requested_by || null, 'summary', aiBriefing.provider || 'groq', 'Automated Scan Security Briefing', aiBriefing.executiveSummary, finishedAt);
      }

      // Lifecycle: findings that disappeared are marked fixed; findings that come back reopen.
      const upsert = db.prepare(`INSERT INTO finding_states (org_id, repo_id, fingerprint, status, updated_by, updated_at) VALUES (?, ?, ?, ?, NULL, ?)
                                 ON CONFLICT (org_id, repo_id, fingerprint) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at`);
      const review = db.prepare('INSERT INTO finding_reviews (id, org_id, repo_id, fingerprint, user_id, action, detail, created_at) VALUES (?, ?, ?, ?, NULL, ?, ?, ?)');
      const cur = (fp) => db.prepare('SELECT status FROM finding_states WHERE org_id = ? AND repo_id = ? AND fingerprint = ?').get(scan.org_id, repo.id, fp);
      for (const fp of fixed) {
        const s = cur(fp);
        if (!s || s.status === 'open' || s.status === 'acknowledged') {
          upsert.run(scan.org_id, repo.id, fp, 'fixed', finishedAt);
          review.run(uuid(), scan.org_id, repo.id, fp, 'auto-fixed', `Not present in scan ${scan.id}`, finishedAt);
        }
      }
      for (const f of findings) {
        const s = cur(f.id);
        if (s && s.status === 'fixed') {
          upsert.run(scan.org_id, repo.id, f.id, 'open', finishedAt);
          review.run(uuid(), scan.org_id, repo.id, f.id, 'reopened', `Detected again in scan ${scan.id}`, finishedAt);
        }
      }

      const hydrated = hydrateFindings(scan.org_id, { ...scan, repo_id: repo.id });
      finalSummary = { ...summarize(hydrated), new: added.length, fixed: fixed.length, totalDetected: findings.length, dependencies: aiInput.summary.dependencies };
      db.prepare("UPDATE scans SET status = 'completed', commit_sha = ?, scanners = ?, summary = ?, finished_at = ?, error = NULL WHERE id = ?")
        .run(workspace.commit, JSON.stringify(scanners), JSON.stringify(finalSummary), finishedAt, scan.id);
    });

    if (enableMongo && isMongoConfigured()) {
      const mongoRecord = {
        id: scan.id,
        orgId: scan.org_id,
        repoId: repo.id,
        fullName: repo.full_name,
        branch: scan.branch,
        commit: workspace.commit,
        trigger: scan.trigger,
        status: 'completed',
        scannedAt: finishedAt,
        createdAt: scan.created_at,
        startedAt: scan.started_at,
        finishedAt,
        target: repo.clone_url || repo.full_name,
        options: parse(repo.config, {}),
        ai: aiBriefing,
        ok: findings.length === 0,
        warnings: aiInput.warnings,
        summary: {
          ...aiInput.summary,
          ...finalSummary,
        },
        scanners,
        projects: aiInput.projects,
        findings,
      };
      await saveScanToMongo(mongoRecord);
    }

    const newSevere = added.filter((f) => f.severity === 'critical' || f.severity === 'high');
    if (newSevere.length) {
      notify(scan.org_id, 'findings.new', `${newSevere.length} new high/critical finding(s) in ${repo.full_name}`,
        newSevere.slice(0, 5).map((f) => f.title).join('; '), ['owner', 'admin', 'developer']);
    }
  }

  // ---------- finding workflow -------------------------------------------------------------------
  const findingsApi = {
    update(ctx, repoId, fingerprint, { status, assigneeId, note }) {
      authorize(ctx, 'findings:write');
      getRepo(ctx.orgId, repoId);
      if (!db.prepare('SELECT 1 FROM findings WHERE org_id = ? AND repo_id = ? AND fingerprint = ? LIMIT 1').get(ctx.orgId, repoId, fingerprint)) throw new NotFoundError('Finding not found');
      if (status !== undefined && !STATUSES.includes(status)) throw new ValidationError('Invalid status');
      if (assigneeId) roleOf(assigneeId, ctx.orgId);
      const cur = db.prepare('SELECT * FROM finding_states WHERE org_id = ? AND repo_id = ? AND fingerprint = ?').get(ctx.orgId, repoId, fingerprint) || { status: 'open', assignee_id: null, note: null };
      if (status === 'suppressed' && cur.status !== 'suppressed' && !String(note || cur.note || '').trim()) {
        throw new ValidationError('Add a note explaining why this finding is suppressed');
      }
      const next = {
        status: status === undefined ? cur.status : status,
        assignee: assigneeId === undefined ? cur.assignee_id : (assigneeId || null),
        note: note === undefined ? cur.note : String(note).slice(0, 1000),
      };
      transaction(db, () => {
        db.prepare(`INSERT INTO finding_states (org_id, repo_id, fingerprint, status, assignee_id, note, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (org_id, repo_id, fingerprint) DO UPDATE SET status = excluded.status, assignee_id = excluded.assignee_id, note = excluded.note, updated_by = excluded.updated_by, updated_at = excluded.updated_at`)
          .run(ctx.orgId, repoId, fingerprint, next.status, next.assignee, next.note, ctx.userId, nowIso());
        const changes = [];
        if (next.status !== cur.status) changes.push(`status ${cur.status} -> ${next.status}`);
        if (next.assignee !== cur.assignee_id) changes.push(`assignee -> ${next.assignee || 'none'}`);
        if (note !== undefined && next.note !== cur.note) changes.push('note updated');
        if (changes.length) {
          db.prepare('INSERT INTO finding_reviews (id, org_id, repo_id, fingerprint, user_id, action, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
            .run(uuid(), ctx.orgId, repoId, fingerprint, ctx.userId, 'update', `${changes.join('; ')}${next.note ? ` (${next.note})` : ''}`, nowIso());
        }
      });
      audit(ctx, 'finding.update', fingerprint, { status: next.status });
      return { fingerprint, ...next };
    },

    history(ctx, repoId, fingerprint) {
      authorize(ctx, 'findings:read');
      getRepo(ctx.orgId, repoId);
      return db.prepare(`SELECT r.action, r.detail, r.created_at AS createdAt, u.email AS user FROM finding_reviews r LEFT JOIN users u ON u.id = r.user_id
                         WHERE r.org_id = ? AND r.repo_id = ? AND r.fingerprint = ? ORDER BY r.created_at`).all(ctx.orgId, repoId, fingerprint);
    },
  };


  // ---------- websites (DAST) ------------------------------------------------------------------------
  function websiteDocument(row, latestScan = null) {
    return {
      id: row.id,
      orgId: row.org_id,
      targetUrl: row.target_url,
      hostname: row.hostname,
      name: row.name,
      isVerified: Boolean(row.is_verified),
      verificationToken: row.verification_token,
      verificationMethod: row.verification_method || null,
      config: parse(row.config, {}),
      schedule: row.schedule || null,
      createdAt: row.created_at,
      latestScan: latestScan ? {
        id: latestScan.id,
        profile: latestScan.profile,
        status: latestScan.status,
        postureScore: latestScan.posture_score,
        summary: parse(latestScan.summary, null),
        startedAt: latestScan.started_at,
        finishedAt: latestScan.finished_at,
      } : null,
    };
  }

  function websiteScanDocument(row) {
    return {
      id: row.id,
      orgId: row.org_id,
      websiteId: row.website_id,
      profile: row.profile,
      status: row.status,
      summary: parse(row.summary, {}),
      postureScore: row.posture_score,
      passiveResults: parse(row.passive_results, {}),
      aiAnalysis: parse(row.ai_analysis, null),
      error: row.error || null,
      requestedBy: row.requested_by || null,
      createdAt: row.created_at,
      startedAt: row.started_at,
      finishedAt: row.finished_at,
    };
  }

  function getWebsite(orgId, websiteId) {
    const row = db.prepare('SELECT * FROM websites WHERE org_id = ? AND id = ?').get(orgId, websiteId);
    if (!row) throw new NotFoundError('Website not found');
    const latestScan = db.prepare('SELECT * FROM website_scans WHERE org_id = ? AND website_id = ? ORDER BY created_at DESC LIMIT 1').get(orgId, websiteId);
    return websiteDocument(row, latestScan);
  }

  function getWebsiteScan(orgId, websiteId, scanId) {
    const row = db.prepare('SELECT * FROM website_scans WHERE org_id = ? AND website_id = ? AND id = ?').get(orgId, websiteId, scanId);
    if (!row) throw new NotFoundError('Website scan not found');
    return websiteScanDocument(row);
  }

  async function handleWebsiteScanJob({ scanId }, job = { attempts: 1, max_attempts: 1 }) {
    const scan = db.prepare('SELECT * FROM website_scans WHERE id = ?').get(scanId);
    if (!scan || scan.status === 'cancelled') return;
    const site = db.prepare('SELECT * FROM websites WHERE id = ? AND org_id = ?').get(scan.website_id, scan.org_id);
    if (!site) {
      db.prepare("UPDATE website_scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ?")
        .run('Website was removed', nowIso(), scanId);
      return;
    }
    db.prepare("UPDATE website_scans SET status = 'running', started_at = ?, error = NULL WHERE id = ?").run(nowIso(), scanId);

    try {
      // 1. Passive DAST inspection
      const passive = await runPassiveScan(site.target_url);
      let findings = [...(passive.findings || [])];
      let crawlResult = null;

      // 2. Active crawl if requested and site is verified
      if (scan.profile === 'standard' || scan.profile === 'deep') {
        if (!site.is_verified) {
          throw new ValidationError('Active scanning requires domain ownership verification');
        }
        crawlResult = await crawlWebsite(site.target_url, { maxPages: scan.profile === 'deep' ? 25 : 10 });
        if (crawlResult && crawlResult.findings) {
          findings = findings.concat(crawlResult.findings);
        }
      }

      // 3. Posture score & summary
      const posture = postureScore(findings);
      const sum = summarize(findings);
      const summary = {
        total: findings.length,
        critical: sum.bySeverity.critical || 0,
        high: sum.bySeverity.high || 0,
        medium: sum.bySeverity.medium || 0,
        low: sum.bySeverity.low || 0,
        grade: posture.grade,
        endpoints: crawlResult ? crawlResult.crawledUrls.length : 1,
        forms: crawlResult ? crawlResult.forms.length : 0,
      };

      // 4. AI correlation
      let aiAnalysis = null;
      const orgSettings = settingsOf(scan.org_id);
      if ((orgSettings.aiEnabled || enableAutoAi) && process.env.GROQ_API_KEY) {
        try {
          const aiPayload = {
            targetUrl: site.target_url,
            technologies: passive.technologies || [],
            telemetry: {
              tls: passive.tls,
              headers: passive.headers,
              cookies: passive.cookies,
              cors: passive.cors,
              responseStatus: passive.responseStatus,
              endpoints: crawlResult ? crawlResult.crawledUrls : [site.target_url],
              forms: crawlResult ? crawlResult.forms : [],
              exposedFiles: crawlResult ? crawlResult.exposedFiles : [],
            },
            findings,
          };
          aiAnalysis = await ai.summarizeWebsiteDast(aiPayload, {
            provider: aiProviderFactory(),
            consent: { aiEnabled: true, aiSendCode: orgSettings.aiSendCode },
          });
        } catch (err) {
          console.warn('[AI DAST Warning] Could not correlate findings with AI:', err.message);
        }
      }

      const finishedAt = nowIso();
      const passiveResultsData = {
        targetUrl: passive.targetUrl,
        reachable: passive.reachable,
        responseStatus: passive.responseStatus,
        headers: passive.headers,
        cookies: passive.cookies,
        cors: passive.cors,
        tls: passive.tls,
        technologies: passive.technologies,
        crawledUrls: crawlResult ? crawlResult.crawledUrls : [site.target_url],
        forms: crawlResult ? crawlResult.forms : [],
        exposedFiles: crawlResult ? crawlResult.exposedFiles : [],
        findings,
      };

      transaction(db, () => {
        db.prepare(`UPDATE website_scans SET status = 'completed', summary = ?, posture_score = ?, passive_results = ?, ai_analysis = ?, finished_at = ?, error = NULL WHERE id = ?`)
          .run(JSON.stringify(summary), posture.score, JSON.stringify(passiveResultsData), JSON.stringify(aiAnalysis), finishedAt, scanId);

        if (aiAnalysis && aiAnalysis.executiveSummary) {
          db.prepare('INSERT INTO ai_history (id, org_id, repo_id, finding_id, user_id, kind, provider, question, answer, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
            .run(uuid(), scan.org_id, null, null, scan.requested_by || null, 'dast_summary', aiAnalysis.provider || 'groq', `Website Security Assessment for ${site.target_url}`, aiAnalysis.executiveSummary, finishedAt);
        }
      });

      if (enableMongo && isMongoConfigured()) {
        await saveWebsiteScanToMongo({
          id: scan.id,
          orgId: scan.org_id,
          websiteId: site.id,
          targetUrl: site.target_url,
          profile: scan.profile,
          status: 'completed',
          postureScore: posture.score,
          summary,
          passiveResults: passiveResultsData,
          aiAnalysis,
          startedAt: scan.started_at,
          finishedAt,
        });
      }

      const severe = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
      if (severe.length) {
        notify(scan.org_id, 'findings.new', `${severe.length} new high/critical finding(s) on ${site.hostname}`,
          severe.slice(0, 5).map((f) => f.title).join('; '), ['owner', 'admin', 'developer']);
      }
    } catch (err) {
      const message = String(err.message || err).slice(0, 300);
      const finishedAt = nowIso();
      db.prepare("UPDATE website_scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ?")
        .run(message, finishedAt, scanId);
      if (enableMongo && isMongoConfigured()) {
        await saveWebsiteScanToMongo({
          id: scan.id,
          orgId: scan.org_id,
          websiteId: site.id,
          targetUrl: site.target_url,
          profile: scan.profile,
          status: 'failed',
          error: message,
          startedAt: scan.started_at,
          finishedAt,
        });
      }
    }
  }

  const websites = {
    async create(ctx, { url, name, config = {} } = {}) {
      authorize(ctx, 'repos:write');
      const rawUrl = String(url || '').trim();
      if (!rawUrl) throw new ValidationError('Website URL is required');

      const validated = await validateTargetUrl(rawUrl);
      const targetUrl = validated.parsed.origin;
      const hostname = validated.parsed.hostname;
      const siteName = String(name || hostname).trim().slice(0, 100);

      const existing = db.prepare('SELECT id FROM websites WHERE org_id = ? AND target_url = ?').get(ctx.orgId, targetUrl);
      if (existing) throw new ValidationError('This website URL is already registered in this organisation');

      const id = uuid();
      const token = generateVerificationToken();
      const nowStr = nowIso();

      db.prepare(`INSERT INTO websites (id, org_id, target_url, hostname, name, is_verified, verification_token, verification_method, config, created_at)
                  VALUES (?, ?, ?, ?, ?, 0, ?, NULL, ?, ?)`)
        .run(id, ctx.orgId, targetUrl, hostname, siteName, token, JSON.stringify(config), nowStr);

      const doc = getWebsite(ctx.orgId, id);
      if (enableMongo && isMongoConfigured()) {
        await saveWebsiteToMongo({
          id,
          orgId: ctx.orgId,
          targetUrl,
          hostname,
          name: siteName,
          verified: false,
          verificationToken: token,
          verificationMethod: null,
          config,
          createdAt: nowStr,
        });
      }
      audit(ctx, 'website.create', id, { targetUrl, hostname });
      return doc;
    },

    async list(ctx) {
      authorize(ctx, 'repos:read');
      if (enableMongo && isMongoConfigured()) {
        try {
          const remote = await listWebsitesFromMongo(ctx.orgId);
          if (Array.isArray(remote)) {
            for (const doc of remote) {
              if (!doc.id || doc.orgId !== ctx.orgId) continue;
              const exists = db.prepare('SELECT 1 FROM websites WHERE id = ? AND org_id = ?').get(doc.id, ctx.orgId);
              if (!exists) {
                db.prepare(`INSERT INTO websites (id, org_id, target_url, hostname, name, is_verified, verification_token, verification_method, config, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                  .run(doc.id, ctx.orgId, doc.targetUrl, doc.hostname, doc.name, doc.verified ? 1 : 0, doc.verificationToken, doc.verificationMethod || null, JSON.stringify(doc.config || {}), doc.createdAt || nowIso());
              }
            }
          }
        } catch (err) {
          console.warn('[Mongo Website Sync Warning]:', err.message);
        }
      }

      const rows = db.prepare('SELECT * FROM websites WHERE org_id = ? ORDER BY created_at DESC').all(ctx.orgId);
      return rows.map((row) => {
        const latestScan = db.prepare('SELECT * FROM website_scans WHERE org_id = ? AND website_id = ? ORDER BY created_at DESC LIMIT 1').get(ctx.orgId, row.id);
        return websiteDocument(row, latestScan);
      });
    },

    get(ctx, websiteId) {
      authorize(ctx, 'repos:read');
      return getWebsite(ctx.orgId, websiteId);
    },

    async remove(ctx, websiteId) {
      authorize(ctx, 'repos:write');
      getWebsite(ctx.orgId, websiteId);
      transaction(db, () => {
        db.prepare('DELETE FROM website_scans WHERE website_id = ? AND org_id = ?').run(websiteId, ctx.orgId);
        db.prepare('DELETE FROM websites WHERE id = ? AND org_id = ?').run(websiteId, ctx.orgId);
      });
      if (enableMongo && isMongoConfigured()) {
        await deleteWebsiteFromMongo(ctx.orgId, websiteId);
      }
      audit(ctx, 'website.remove', websiteId);
      return { ok: true };
    },

    async verify(ctx, websiteId, opts = {}) {
      authorize(ctx, 'repos:write');
      const site = getWebsite(ctx.orgId, websiteId);
      if (site.isVerified) {
        return { verified: true, method: site.verificationMethod };
      }

      if (opts && opts.manual) {
        db.prepare('UPDATE websites SET is_verified = 1, verification_method = ? WHERE id = ? AND org_id = ?')
          .run('manual_authorization', websiteId, ctx.orgId);
        if (enableMongo && isMongoConfigured()) {
          const updated = getWebsite(ctx.orgId, websiteId);
          await saveWebsiteToMongo({
            id: updated.id,
            orgId: updated.orgId,
            targetUrl: updated.targetUrl,
            hostname: updated.hostname,
            name: updated.name,
            verified: true,
            verificationToken: updated.verificationToken,
            verificationMethod: 'manual_authorization',
            config: updated.config,
            createdAt: updated.createdAt,
          });
        }
        audit(ctx, 'website.verify', websiteId, { method: 'manual_authorization' });
        return { verified: true, method: 'manual_authorization' };
      }

      const res = await checkOwnership(site.hostname, site.targetUrl, site.verificationToken);
      if (res && res.verified) {
        db.prepare('UPDATE websites SET is_verified = 1, verification_method = ? WHERE id = ? AND org_id = ?')
          .run(res.method, websiteId, ctx.orgId);
        if (enableMongo && isMongoConfigured()) {
          const updated = getWebsite(ctx.orgId, websiteId);
          await saveWebsiteToMongo({
            id: updated.id,
            orgId: updated.orgId,
            targetUrl: updated.targetUrl,
            hostname: updated.hostname,
            name: updated.name,
            verified: true,
            verificationToken: updated.verificationToken,
            verificationMethod: res.method,
            config: updated.config,
            createdAt: updated.createdAt,
          });
        }
        audit(ctx, 'website.verify', websiteId, { method: res.method });
        return { verified: true, method: res.method };
      }
      return { verified: false, error: res && res.error, dns: res && res.dns, http: res && res.http };
    },

    startScan(ctx, websiteId, { profile = 'passive' } = {}) {
      authorize(ctx, 'scans:run');
      const site = getWebsite(ctx.orgId, websiteId);
      const validProfiles = ['passive', 'standard', 'deep'];
      if (!validProfiles.includes(profile)) {
        throw new ValidationError(`Profile must be one of: ${validProfiles.join(', ')}`);
      }
      if (profile !== 'passive' && !site.isVerified) {
        throw new ValidationError('Active scanning (standard / deep) requires domain ownership verification. Please verify ownership first.');
      }
      const active = db.prepare("SELECT COUNT(*) AS n FROM website_scans WHERE org_id = ? AND status IN ('queued', 'running')").get(ctx.orgId).n;
      if (active >= 5) {
        throw new ValidationError('Too many website scans are currently running. Please wait for one to finish.');
      }
      const scanId = uuid();
      const nowStr = nowIso();
      db.prepare(`INSERT INTO website_scans (id, org_id, website_id, profile, status, requested_by, created_at)
                  VALUES (?, ?, ?, ?, 'queued', ?, ?)`)
        .run(scanId, ctx.orgId, websiteId, profile, ctx.userId || null, nowStr);

      queue.enqueue('website_scan', { scanId }, { orgId: ctx.orgId });
      audit(ctx, 'website_scan.start', scanId, { websiteId, profile });
      return websiteScanDocument(db.prepare('SELECT * FROM website_scans WHERE id = ?').get(scanId));
    },

    listScans(ctx, websiteId, { limit = 50 } = {}) {
      authorize(ctx, 'scans:read');
      getWebsite(ctx.orgId, websiteId);
      const lim = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 100);
      const rows = db.prepare('SELECT * FROM website_scans WHERE org_id = ? AND website_id = ? ORDER BY created_at DESC LIMIT ?')
        .all(ctx.orgId, websiteId, lim);
      return rows.map(websiteScanDocument);
    },

    getScan(ctx, websiteId, scanId) {
      authorize(ctx, 'scans:read');
      return getWebsiteScan(ctx.orgId, websiteId, scanId);
    },

    report(ctx, websiteId, scanId, format = 'json') {
      authorize(ctx, 'reports:read');
      const site = getWebsite(ctx.orgId, websiteId);
      const scan = getWebsiteScan(ctx.orgId, websiteId, scanId);
      audit(ctx, 'website_report.export', scanId, { format, websiteId });

      const findings = (scan.passiveResults && scan.passiveResults.findings) || [];
      const title = `Website Security Assessment: ${site.targetUrl}`;

      switch (format) {
        case 'csv':
          return { type: 'text/csv; charset=utf-8', ext: 'csv', body: exporters.renderCsv(findings) };
        case 'markdown': {
          const s = scan.summary || {};
          const lines = [
            `# ${title}`,
            '',
            `Target: \`${site.targetUrl}\`  `,
            `Hostname: \`${site.hostname}\`  `,
            `Profile: \`${scan.profile}\`  `,
            `Status: \`${scan.status}\`  `,
            `Generated: ${scan.finishedAt || scan.createdAt}`,
            '',
            `**Security Posture Score: ${scan.postureScore != null ? scan.postureScore : 'N/A'}/100 (Grade ${s.grade || 'N/A'})** · ${s.total || findings.length} findings detected`,
            '',
            '| Critical | High | Medium | Low |',
            '|---|---|---|---|',
            `| ${s.critical || 0} | ${s.high || 0} | ${s.medium || 0} | ${s.low || 0} |`,
            '',
          ];

          if (scan.aiAnalysis && scan.aiAnalysis.executiveSummary) {
            lines.push('## AI Executive Summary', '', scan.aiAnalysis.executiveSummary, '');
          }

          if (scan.aiAnalysis && scan.aiAnalysis.riskNarrative) {
            lines.push('### Risk Narrative', '', scan.aiAnalysis.riskNarrative, '');
          }

          const tech = (scan.passiveResults && scan.passiveResults.technologies) || [];
          if (tech.length) {
            lines.push('## Detected Technologies', '');
            for (const t of tech) {
              lines.push(`- **${t.name}** (${t.category})${t.version ? ` v${t.version}` : ''}`);
            }
            lines.push('');
          }

          const tls = (scan.passiveResults && scan.passiveResults.tls);
          if (tls) {
            lines.push('## TLS / SSL Configuration', '');
            lines.push(`- **Authorized:** ${tls.authorized ? 'Yes' : 'No'}`);
            if (tls.protocol) lines.push(`- **Protocol:** ${tls.protocol}`);
            if (tls.cipher) lines.push(`- **Cipher:** ${tls.cipher.name || tls.cipher}`);
            if (tls.validTo) lines.push(`- **Certificate Expiry:** ${tls.validTo} (${tls.daysRemaining} days remaining)`);
            if (tls.issuer) lines.push(`- **Issuer:** ${typeof tls.issuer === 'object' ? (tls.issuer.O || tls.issuer.CN || JSON.stringify(tls.issuer)) : tls.issuer}`);
            lines.push('');
          }

          lines.push('## Vulnerabilities and Security Gaps', '');
          if (!findings.length) {
            lines.push('No vulnerabilities or configuration weaknesses detected.');
          } else {
            lines.push('| Severity | Title | Location | Remediation |', '|---|---|---|---|');
            for (const f of exporters.sortFindings(findings)) {
              const loc = (f.location && (f.location.url || f.location.path || f.location.parameter)) || site.targetUrl;
              const rem = (f.remediation && (f.remediation.advice || f.remediation.fixedIn)) || 'Review configuration';
              lines.push(`| ${f.severity} | ${f.title.replace(/[|\\]/g, '\\  // ---------- dashboard')} | ${String(loc).replace(/[|\\]/g, '\\  // ---------- dashboard')} | ${String(rem).replace(/[|\\]/g, '\\  // ---------- dashboard')} |`);
            }
          }

          return { type: 'text/markdown; charset=utf-8', ext: 'md', body: lines.join('\n') + '\n' };
        }
        case 'json':
        default:
          return { type: 'application/json', ext: 'json', body: JSON.stringify({ website: site, scan }, null, 2) };
      }
    },
  };

  // ---------- dashboard ------------------------------------------------------------------------------
  let mongoSyncedOrgs = new Set();
  const dashboard = {
    async overview(ctx) {
      authorize(ctx, 'repos:read');
      await applyRemoteConnections(ctx.orgId);
      await applyRemoteRepos(ctx.orgId);
      const repoRows = db.prepare('SELECT * FROM repositories WHERE org_id = ? ORDER BY full_name').all(ctx.orgId);
      const websiteRows = db.prepare('SELECT * FROM websites WHERE org_id = ? ORDER BY name').all(ctx.orgId);
      const websitesOverview = websiteRows.map((site) => {
        const lastScan = db.prepare('SELECT status, posture_score, summary, finished_at FROM website_scans WHERE org_id = ? AND website_id = ? ORDER BY created_at DESC LIMIT 1').get(ctx.orgId, site.id);
        return {
          id: site.id,
          name: site.name,
          targetUrl: site.target_url,
          isVerified: Boolean(site.is_verified),
          postureScore: lastScan ? lastScan.posture_score : null,
          lastStatus: lastScan ? lastScan.status : null,
          lastScanAt: lastScan ? lastScan.finished_at : null,
        };
      });
      const totals = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
      let scoreSum = 0;
      let scored = 0;
      const repositories = repoRows.map((r) => {
        const done = db.prepare("SELECT id, summary FROM scans WHERE org_id = ? AND repo_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1").get(ctx.orgId, r.id);
        const last = db.prepare('SELECT status, finished_at FROM scans WHERE org_id = ? AND repo_id = ? ORDER BY created_at DESC LIMIT 1').get(ctx.orgId, r.id);
        const summary = done ? parse(done.summary) : null;
        if (summary) {
          totals.total += summary.total;
          for (const l of ['critical', 'high', 'medium', 'low']) totals[l] += summary.bySeverity[l];
          scoreSum += summary.posture.score;
          scored++;
        }
        return { id: r.id, fullName: r.full_name, posture: summary && summary.posture, total: summary ? summary.total : null, bySeverity: summary && summary.bySeverity, lastStatus: last && last.status, lastScanAt: last && last.finished_at };
      });

      // Organisation-wide trend: at each completed scan, sum the latest known result of every
      // repository (so scans of different repositories add up rather than overwrite each other).
      const latestByRepo = new Map();
      const trend = db.prepare("SELECT repo_id, COALESCE(finished_at, created_at) AS at, summary FROM scans WHERE org_id = ? AND status = 'completed' ORDER BY COALESCE(finished_at, created_at) DESC, rowid DESC LIMIT 60").all(ctx.orgId)
        .reverse().map((s) => {
          latestByRepo.set(s.repo_id, pickTrend(parse(s.summary)));
          const sum = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
          for (const t of latestByRepo.values()) for (const k of Object.keys(sum)) sum[k] += t[k] || 0;
          return { at: s.at, ...sum };
        });

      const stateCounts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
      for (const row of db.prepare('SELECT status, COUNT(*) AS n FROM finding_states WHERE org_id = ? GROUP BY status').all(ctx.orgId)) stateCounts[row.status] = row.n;

      return {
        totals,
        riskScore: scored ? Math.round(100 - scoreSum / scored) : 0,
        posture: scored ? Math.round(scoreSum / scored) : null,
        repositories,
        websites: websitesOverview,
        trend,
        recentScans: db.prepare('SELECT * FROM scans WHERE org_id = ? ORDER BY created_at DESC LIMIT 10').all(ctx.orgId).map(publicScan),
        failedScans: db.prepare("SELECT * FROM scans WHERE org_id = ? AND status = 'failed' ORDER BY created_at DESC LIMIT 5").all(ctx.orgId).map(publicScan),
        remediation: { ...stateCounts, fixRate: (stateCounts.fixed + stateCounts.open + stateCounts.acknowledged) ? Math.round(100 * stateCounts.fixed / (stateCounts.fixed + stateCounts.open + stateCounts.acknowledged)) : null },
        mongo: getMongoStatus(),
        aiEnabled: Boolean(process.env.GROQ_API_KEY || process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY),
      };
    },

    async syncMongo(orgId) {
      if (!enableMongo || !isMongoConfigured()) return { imported: 0 };
      const docs = await listFullScansFromMongo(100);
      if (!docs || !docs.length) return { imported: 0 };

      let imported = 0;
      const sorted = [...docs].sort((a, b) => new Date(a.scannedAt || a.createdAt || 0).getTime() - new Date(b.scannedAt || b.createdAt || 0).getTime());

      for (const doc of sorted) {
        if (!doc || !doc.id) continue;
        if (db.prepare('SELECT 1 FROM scans WHERE id = ?').get(doc.id)) continue;

        const rawTarget = String(doc.target || doc.fullName || 'local/project').trim();
        let fullName = doc.fullName || null;
        let cloneUrl = rawTarget;
        let provider = 'github';

        const urlMatch = rawTarget.match(/^(?:https?:\/\/)?(github\.com|gitlab\.com|bitbucket\.org)\/([^/]+\/[^/]+?)(?:\.git)?$/i);
        if (urlMatch) {
          const host = urlMatch[1].toLowerCase();
          provider = host.startsWith('gitlab') ? 'gitlab' : host.startsWith('bitbucket') ? 'bitbucket' : 'github';
          fullName = urlMatch[2];
          cloneUrl = `https://${host}/${fullName}.git`;
        } else {
          const parts = rawTarget.replace(/\.git$/i, '').split(/[\\/]/).filter(Boolean);
          const namePart = parts.slice(-2).join('/') || parts[parts.length - 1] || 'project';
          fullName = doc.fullName || namePart;
          cloneUrl = rawTarget;
          provider = 'local';
        }

        let repo = db.prepare('SELECT * FROM repositories WHERE org_id = ? AND (clone_url = ? OR LOWER(full_name) = LOWER(?))').get(orgId, cloneUrl, fullName);
        if (!repo) {
          const repoId = uuid();
          try {
            db.prepare(`INSERT INTO repositories (id, org_id, team_id, connection_id, provider, full_name, clone_url, default_branch, config, webhook_secret, created_at)
                        VALUES (?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?)`)
              .run(repoId, orgId, provider, fullName, cloneUrl, doc.branch || 'main', JSON.stringify(doc.options || {}), secretBox.encrypt(newToken(24)), doc.scannedAt || nowIso());
            repo = db.prepare('SELECT * FROM repositories WHERE id = ?').get(repoId);
          } catch {
            repo = db.prepare('SELECT * FROM repositories WHERE org_id = ?').get(orgId);
          }
        }
        if (!repo) continue;

        let findings = [];
        if (Array.isArray(doc.findings) && doc.findings.length) {
          findings = doc.findings.map((f) => {
            const copy = createFinding({
              category: f.category || 'sca',
              scanner: f.scanner || { name: 'osv', version: 'osv.dev-api-v1', ruleId: (f.identifiers && f.identifiers.primary) || f.id },
              title: f.title || 'Vulnerability finding',
              description: f.description || null,
              severity: f.severity || 'unknown',
              cvssScore: f.cvssScore != null ? f.cvssScore : null,
              identifiers: f.identifiers || { primary: f.id, aliases: f.aliases || [], cwe: [] },
              location: f.location || { file: 'package-lock.json', package: f.package, version: f.version, ecosystem: f.ecosystem || 'npm', direct: f.direct, paths: f.paths || [] },
              remediation: f.remediation && typeof f.remediation === 'object' ? f.remediation : { fixedIn: f.fixedIn || null, advice: typeof f.remediation === 'string' ? f.remediation : null },
              url: f.url || null,
            });
            if (f.aiExplanation) copy.aiExplanation = f.aiExplanation;
            return copy;
          });
        } else if (Array.isArray(doc.projects)) {
          for (const proj of doc.projects) {
            const relFile = path.basename(proj.file || 'package-lock.json');
            for (const v of proj.vulnerabilities || []) {
              const f = fromScaIssue(v, { file: relFile, scannerVersion: 'osv.dev-api-v1' });
              if (v.remediation && typeof v.remediation === 'string') f.remediation.advice = v.remediation;
              if (v.aiExplanation) {
                f.aiExplanation = v.aiExplanation;
              } else if (doc.ai && doc.ai.packageExplanations && doc.ai.packageExplanations[v.package]) {
                f.aiExplanation = doc.ai.packageExplanations[v.package];
              }
              findings.push(f);
            }
          }
        }

        const scannedAt = doc.scannedAt || doc.finishedAt || doc.createdAt || nowIso();
        const totalDeps = (doc.summary && doc.summary.dependencies) || (Array.isArray(doc.projects) ? doc.projects.reduce((a, p) => a + (p.dependencyCount || 0), 0) : 0);
        const scanners = Array.isArray(doc.scanners) && doc.scanners.length ? doc.scanners : [
          { scanner: 'osv', status: 'ok', version: 'osv.dev-api-v1', findingCount: findings.length, durationMs: 0 },
        ];

        const rawData = {
          ai: doc.ai || null,
          projects: doc.projects || [],
          warnings: doc.warnings || [],
          target: rawTarget,
          source: 'mongodb',
          osv: {
            warnings: doc.warnings || [],
            projects: (doc.projects || []).map((p) => ({
              file: p.file || 'package-lock.json',
              type: p.packageManager || p.type || 'npm',
              packageManager: p.packageManager || p.type || 'npm',
              ecosystem: p.ecosystem || 'npm',
              name: p.projectName || p.name || 'project',
              projectName: p.projectName || p.name || 'project',
              dependencyCount: p.dependencyCount || 0,
              skipped: p.skipped || [],
              summary: p.summary || {},
              upgradePlan: p.upgradePlan || [],
              vulnerabilities: p.vulnerabilities || [],
              dependencies: p.dependencies || [],
            })),
          },
        };

        const prev = db.prepare("SELECT id FROM scans WHERE org_id = ? AND repo_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1")
          .get(orgId, repo.id);
        const prevFps = new Set(prev ? db.prepare('SELECT fingerprint FROM findings WHERE scan_id = ?').all(prev.id).map((r) => r.fingerprint) : []);
        const currentFps = new Set(findings.map((f) => f.id));
        const fixed = [...prevFps].filter((fp) => !currentFps.has(fp));
        const added = findings.filter((f) => !prevFps.has(f.id));

        transaction(db, () => {
          db.prepare(`INSERT INTO scans (id, org_id, repo_id, branch, commit_sha, trigger, status, scanners, summary, error, requested_by, created_at, started_at, finished_at)
                      VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?, NULL, NULL, ?, ?, ?)`)
            .run(doc.id, orgId, repo.id, doc.branch || repo.default_branch || 'main', doc.commit || null, doc.trigger || 'mongodb-history',
              JSON.stringify(scanners), '{}', scannedAt, scannedAt, scannedAt);

          const insertFinding = db.prepare('INSERT INTO findings (id, scan_id, org_id, repo_id, fingerprint, severity, category, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
          for (const f of findings) {
            insertFinding.run(uuid(), doc.id, orgId, repo.id, f.id, f.severity, f.category, JSON.stringify(f));
          }
          db.prepare('INSERT INTO scan_raw (scan_id, org_id, data) VALUES (?, ?, ?)').run(doc.id, orgId, JSON.stringify(rawData));

          const upsertState = db.prepare(`INSERT INTO finding_states (org_id, repo_id, fingerprint, status, updated_by, updated_at) VALUES (?, ?, ?, 'open', NULL, ?)
                                          ON CONFLICT (org_id, repo_id, fingerprint) DO NOTHING`);
          for (const f of findings) {
            upsertState.run(orgId, repo.id, f.id, scannedAt);
          }

          if (doc.ai && doc.ai.executiveSummary) {
            db.prepare('INSERT INTO ai_history (id, org_id, repo_id, finding_id, user_id, kind, provider, question, answer, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
              .run(uuid(), orgId, repo.id, null, null, 'summary', doc.ai.provider || 'groq', 'Automated Scan Security Briefing', doc.ai.executiveSummary, scannedAt);
          }

          const hydrated = hydrateFindings(orgId, { id: doc.id, repo_id: repo.id });
          const summary = { ...summarize(hydrated), new: added.length, fixed: fixed.length, totalDetected: findings.length, dependencies: totalDeps };
          db.prepare('UPDATE scans SET summary = ? WHERE id = ?').run(JSON.stringify(summary), doc.id);
        });

        imported++;
      }

      return { imported };
    },
  };
  const pickTrend = (s) => (s ? { total: s.total, critical: s.bySeverity.critical, high: s.bySeverity.high, medium: s.bySeverity.medium, low: s.bySeverity.low } : {});

  // ---------- AI assistant ------------------------------------------------------------------------------
  function aiContext(ctx) {
    authorize(ctx, 'ai:use');
    const settings = settingsOf(ctx.orgId);
    if (!settings.aiEnabled) throw new ValidationError('AI analysis is turned off for this organisation. An admin can enable it in settings');
    const recent = db.prepare("SELECT COUNT(*) AS n FROM ai_history WHERE org_id = ? AND user_id = ? AND created_at > ?").get(ctx.orgId, ctx.userId, new Date(clock() - 3600e3).toISOString()).n;
    if (recent >= LIMITS.aiRequestsPerHour) throw Object.assign(new ValidationError('AI request limit reached. Try again later'), { status: 429 });
    const provider = aiProviderFactory();
    if (!provider) throw new ValidationError('No AI provider is configured on this server');
    return { provider, consent: { aiEnabled: true, sendCode: settings.aiSendCode === true } };
  }

  function saveAi(ctx, { repoId = null, findingId = null, kind, provider, question = null, answer }) {
    db.prepare('INSERT INTO ai_history (id, org_id, repo_id, finding_id, user_id, kind, provider, question, answer, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(uuid(), ctx.orgId, repoId, findingId, ctx.userId, kind, provider, question, answer, nowIso());
  }

  function findingByRowId(ctx, rowId) {
    const row = db.prepare('SELECT f.data, f.repo_id, f.scan_id FROM findings f WHERE f.id = ? AND f.org_id = ?').get(rowId, ctx.orgId);
    if (!row) throw new NotFoundError('Finding not found');
    return { finding: parse(row.data), repoId: row.repo_id };
  }

  function withCodeContext(finding, repo) {
    const usages = usagesForFinding(finding, repo && repo.clone_url);
    if (!usages.length) return finding;
    return { ...finding, location: { ...(finding.location || {}), usages } };
  }

  const aiApi = {
    async explain(ctx, rowId) {
      const { provider, consent } = aiContext(ctx);
      const { finding, repoId } = findingByRowId(ctx, rowId);
      const repo = getRepo(ctx.orgId, repoId);
      const out = await ai.explainFinding(withCodeContext(finding, repo), { provider, consent });
      saveAi(ctx, { repoId, findingId: finding.id, kind: 'explanation', provider: provider.name, answer: out.text });
      return out;
    },
    async fix(ctx, rowId) {
      const { provider, consent } = aiContext(ctx);
      const { finding, repoId } = findingByRowId(ctx, rowId);
      const repo = getRepo(ctx.orgId, repoId);
      const out = await ai.suggestFix(withCodeContext(finding, repo), { provider, consent });
      saveAi(ctx, { repoId, findingId: finding.id, kind: 'remediation', provider: provider.name, answer: out.text });
      return out;
    },
    async ask(ctx, repoId, question, history = []) {
      const { provider, consent } = aiContext(ctx);
      getRepo(ctx.orgId, repoId);
      if (typeof question !== 'string' || !question.trim() || question.length > 2000) throw new ValidationError('Ask a question of up to 2000 characters');
      const latest = db.prepare("SELECT * FROM scans WHERE org_id = ? AND repo_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1").get(ctx.orgId, repoId);
      const findings = latest ? hydrateFindings(ctx.orgId, latest).filter((f) => f.status !== 'suppressed' && f.status !== 'fixed') : [];
      const out = await ai.askQuestion(question, findings, { provider, consent, history });
      saveAi(ctx, { repoId, kind: 'question', provider: provider.name, question, answer: out.text });
      return out;
    },
    async summary(ctx, repoId) {
      const { provider, consent } = aiContext(ctx);
      getRepo(ctx.orgId, repoId);
      const latest = db.prepare("SELECT * FROM scans WHERE org_id = ? AND repo_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1").get(ctx.orgId, repoId);
      if (!latest) throw new ValidationError('Run a scan first');
      const out = await ai.summarizePosture(hydrateFindings(ctx.orgId, latest), { provider, consent });
      saveAi(ctx, { repoId, kind: 'summary', provider: provider.name, answer: out.text });
      return out;
    },
    history(ctx, repoId) {
      authorize(ctx, 'ai:use');
      getRepo(ctx.orgId, repoId);
      return db.prepare('SELECT id, kind, provider, question, answer, finding_id AS findingId, created_at AS createdAt FROM ai_history WHERE org_id = ? AND repo_id = ? ORDER BY created_at DESC LIMIT 50').all(ctx.orgId, repoId);
    },
  };

  // ---------- audit log, notifications ---------------------------------------------------------------------
  const auditApi = {
    async list(ctx, { limit = 100, action } = {}) {
      authorize(ctx, 'audit:read');
      await applyRemoteAudit(ctx.orgId);
      const locals = db.prepare('SELECT * FROM audit_logs WHERE org_id = ? ORDER BY created_at DESC LIMIT 500').all(ctx.orgId);
      for (const row of locals) {
        await persistAudit({
          id: row.id, orgId: row.org_id, userId: row.user_id, action: row.action, target: row.target,
          detail: parse(row.detail), ip: row.ip, createdAt: row.created_at,
        });
      }
      const lim = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 500);
      const rows = action
        ? db.prepare('SELECT a.id, a.action, a.target, a.detail, a.ip, a.created_at AS createdAt, u.email AS user FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id WHERE a.org_id = ? AND a.action = ? ORDER BY a.created_at DESC LIMIT ?').all(ctx.orgId, action, lim)
        : db.prepare('SELECT a.id, a.action, a.target, a.detail, a.ip, a.created_at AS createdAt, u.email AS user FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id WHERE a.org_id = ? ORDER BY a.created_at DESC LIMIT ?').all(ctx.orgId, lim);
      return rows.map((r) => ({ ...r, detail: parse(r.detail) }));
    },
  };

  const notifications = {
    async list(ctx) {
      authorize(ctx, 'repos:read');
      await applyRemoteNotifications(ctx.orgId);
      const locals = db.prepare('SELECT * FROM notifications WHERE org_id = ? ORDER BY created_at DESC LIMIT 200').all(ctx.orgId);
      for (const row of locals) {
        await persistNotification({
          id: row.id, orgId: row.org_id, userId: row.user_id, kind: row.kind, title: row.title,
          body: row.body, read: !!row.read, createdAt: row.created_at,
        });
      }
      return db.prepare('SELECT id, kind, title, body, read, created_at AS createdAt FROM notifications WHERE org_id = ? AND (user_id = ? OR user_id IS NULL) ORDER BY created_at DESC LIMIT 100').all(ctx.orgId, ctx.userId);
    },
    async markRead(ctx, id) {
      authorize(ctx, 'repos:read');
      db.prepare('UPDATE notifications SET read = 1 WHERE org_id = ? AND user_id = ? AND (id = ? OR ? IS NULL)').run(ctx.orgId, ctx.userId, id || null, id || null);
      const rows = id
        ? db.prepare('SELECT * FROM notifications WHERE id = ? AND org_id = ?').all(id, ctx.orgId)
        : db.prepare('SELECT * FROM notifications WHERE org_id = ? AND user_id = ?').all(ctx.orgId, ctx.userId);
      for (const row of rows) {
        await persistNotification({
          id: row.id, orgId: row.org_id, userId: row.user_id, kind: row.kind, title: row.title,
          body: row.body, read: !!row.read, createdAt: row.created_at,
        });
      }
    },
  };

  // ---------- automation: schedules, webhooks, retention -------------------------------------------------------
  const automation = {
    // Enqueues scans for repositories whose schedule is due. Called on an interval by the server.
    tickSchedules() {
      const due = db.prepare('SELECT * FROM repositories WHERE schedule IS NOT NULL AND next_scan_at IS NOT NULL AND next_scan_at <= ?').all(nowIso());
      const started = [];
      for (const repo of due) {
        db.prepare('UPDATE repositories SET next_scan_at = ? WHERE id = ?').run(new Date(clock() + SCHEDULES[repo.schedule]).toISOString(), repo.id);
        try {
          started.push(createScan(repo.org_id, repo, { branch: repo.default_branch, trigger: 'schedule' }));
        } catch { /* a scan is already running or the org is at its limit: skip this round */ }
      }
      return started;
    },

    // Verifies the provider's signature, then scans pushed branches. Returns what it did.
    handleWebhook(repoId, headers, rawBody) {
      const repo = db.prepare('SELECT * FROM repositories WHERE id = ?').get(repoId);
      if (!repo) throw new NotFoundError('Not found');
      const secret = secretBox.decrypt(repo.webhook_secret);
      const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
      const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody));

      let verified = false;
      if (lower['x-hub-signature-256']) {
        const expected = `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`;
        verified = safeEqual(lower['x-hub-signature-256'], expected);
      } else if (lower['x-gitlab-token'] || lower['x-webhook-token']) {
        verified = safeEqual(lower['x-gitlab-token'] || lower['x-webhook-token'], secret);
      }
      if (!verified) throw new ForbiddenError('Invalid webhook signature');

      const event = parse(body.toString('utf8'), null);
      if (!event) throw new ValidationError('Invalid payload');
      const kind = lower['x-github-event'] || lower['x-gitlab-event'] || lower['x-event-key'] || 'push';
      let branch = null;
      if (typeof event.ref === 'string' && event.ref.startsWith('refs/heads/')) branch = event.ref.slice('refs/heads/'.length);
      if (!branch && event.pull_request && event.pull_request.head && event.pull_request.head.repo
        && event.pull_request.head.repo.full_name === repo.full_name && ['opened', 'synchronize', 'reopened'].includes(event.action)) {
        branch = event.pull_request.head.ref;
      }
      if (!branch) return { scanned: false, reason: `ignored ${kind} event` };

      const config = parse(repo.config, {});
      const watched = config.branches && config.branches.length ? config.branches : [repo.default_branch];
      if (!event.pull_request && !watched.includes(branch)) return { scanned: false, reason: 'branch not monitored' };
      try {
        validateBranch(branch);
        const id = createScan(repo.org_id, repo, { branch, trigger: 'webhook' });
        audit({ orgId: repo.org_id }, 'scan.webhook', id, { branch });
        return { scanned: true, scanId: id };
      } catch (err) {
        return { scanned: false, reason: err.message };
      }
    },

    // Deletes scan data past each organisation's retention period, plus expired sessions and old jobs.
    purge() {
      let scansDeleted = 0;
      for (const org of db.prepare('SELECT id FROM orgs').all()) {
        const cutoff = new Date(clock() - settingsOf(org.id).retentionDays * 86400e3).toISOString();
        const r = db.prepare("DELETE FROM scans WHERE org_id = ? AND created_at < ? AND status IN ('completed','failed','cancelled')").run(org.id, cutoff);
        db.prepare("DELETE FROM website_scans WHERE org_id = ? AND created_at < ? AND status IN ('completed','failed','cancelled')").run(org.id, cutoff);
        scansDeleted += Number(r.changes);
        db.prepare('DELETE FROM notifications WHERE org_id = ? AND created_at < ?').run(org.id, cutoff);
        db.prepare('DELETE FROM ai_history WHERE org_id = ? AND created_at < ?').run(org.id, cutoff);
      }
      db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(nowIso());
      db.prepare('DELETE FROM scan_grants WHERE expires_at < ?').run(nowIso());
      db.prepare("DELETE FROM jobs WHERE status IN ('done','cancelled','failed') AND created_at < ?").run(new Date(clock() - 7 * 86400e3).toISOString());
      return { scansDeleted };
    },
  };

  return {
    auth, orgs, teams, connections, repos, scans, findings: findingsApi, websites, dashboard, ai: aiApi,
    audit: auditApi, notifications, automation, grants, handlers: { scan: handleScanJob, website_scan: handleWebsiteScanJob }, authorize, can,
  };
}

module.exports = { createPlatform, LIMITS, DEFAULT_SETTINGS };
