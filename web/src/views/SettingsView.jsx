import React, { useEffect, useState } from 'react';
import { api, session, hasPermission, themeStore, toast, fmtDate, ago } from '../api.js';
import { PageHead, DataTable } from '../components/Common.jsx';

const TABS = [
  ['profile', 'Profile'],
  ['organisation', 'Organisation'],
  ['members', 'Members'],
  ['teams', 'Teams'],
  ['providers', 'Git providers'],
  ['notifications', 'Notifications'],
  ['audit', 'Audit log'],
];

function ProfileTab({ onThemeChange }) {
  const me = session.me;
  const [currentTheme, setCurrentTheme] = useState(themeStore.get());

  function handleTheme(val) {
    setCurrentTheme(val);
    themeStore.set(val);
    if (onThemeChange) onThemeChange(val);
  }

  return (
    <section className="card">
      <h2>Your profile</h2>
      <dl className="kv">
        <dt>Name</dt>
        <dd>{me.name}</dd>
        <dt>Email</dt>
        <dd>{me.email}</dd>
        <dt>Member since</dt>
        <dd>{fmtDate(me.created_at)}</dd>
      </dl>
      <div className="row">
        <label>
          Appearance
          <select
            aria-label="Theme"
            value={currentTheme}
            onChange={(e) => handleTheme(e.target.value)}
          >
            <option value="light">Light</option>
            <option value="dark">Dark</option>
            <option value="auto">Match system</option>
          </select>
        </label>
      </div>
    </section>
  );
}

function OrganisationTab({ onMeUpdated }) {
  const org = session.me.orgs.find((o) => o.id === session.orgId);
  const ro = !hasPermission(session.me, session.orgId, 'org:settings');
  const [name, setName] = useState(org ? org.name : '');
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiSendCode, setAiSendCode] = useState(false);
  const [retentionDays, setRetentionDays] = useState(90);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .get(api.org('/settings'))
      .then((s) => {
        setAiEnabled(Boolean(s.aiEnabled));
        setAiSendCode(Boolean(s.aiSendCode));
        setRetentionDays(s.retentionDays || 90);
      })
      .catch((err) => toast(err.message, 'error'));
  }, [session.orgId]);

  async function handleSave(e) {
    e.preventDefault();
    setBusy(true);
    try {
      if (org && name.trim() !== org.name) {
        await api.patch(api.org(''), { name: name.trim() });
      }
      await api.patch(api.org('/settings'), {
        aiEnabled,
        aiSendCode,
        retentionDays: Number(retentionDays),
      });
      toast('Settings saved');
      session.me = await api.get('/me');
      if (onMeUpdated) onMeUpdated();
    } catch (err) {
      toast(err.message || 'Failed to save settings', 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteOrg() {
    if (!org) return;
    if (
      prompt(`Type the organisation name (${org.name}) to permanently delete it and all of its data:`) ===
      org.name
    ) {
      setBusy(true);
      try {
        await api.del(api.org(''));
        session.orgId = null;
        location.hash = '#/overview';
        location.reload();
      } catch (err) {
        toast(err.message || 'Failed to delete organisation', 'error');
        setBusy(false);
      }
    }
  }

  return (
    <>
      <section className="card">
        <h2>Organisation</h2>
        <form className="stack" onSubmit={handleSave}>
          <label>
            Organisation name
            <input
              type="text"
              value={name}
              disabled={ro}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={aiEnabled}
              disabled={ro}
              onChange={(e) => setAiEnabled(e.target.checked)}
            />
            Enable AI analysis (sends finding metadata to the AI provider)
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={aiSendCode}
              disabled={ro}
              onChange={(e) => setAiSendCode(e.target.checked)}
            />
            Also allow code snippets from scanners to be sent to the AI provider (secrets are never
            sent)
          </label>
          <label>
            Keep scan data for (days)
            <input
              type="number"
              min={1}
              max={3650}
              value={retentionDays}
              disabled={ro}
              onChange={(e) => setRetentionDays(e.target.value)}
            />
          </label>
          <button className="primary" type="submit" disabled={ro || busy}>
            Save
          </button>
        </form>
      </section>

      {org && org.role === 'owner' && (
        <section className="card">
          <h2>Danger zone</h2>
          <button className="danger" type="button" onClick={handleDeleteOrg} disabled={busy}>
            Delete organisation
          </button>
        </section>
      )}
    </>
  );
}

function MembersTab() {
  const [list, setList] = useState([]);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('developer');
  const [busy, setBusy] = useState(false);

  const manage = hasPermission(session.me, session.orgId, 'members:manage');
  const roles = ['viewer', 'developer', 'admin', 'owner'];

  async function load() {
    try {
      setList(await api.get(api.org('/members')));
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  useEffect(() => {
    load();
  }, [session.orgId]);

  async function handleRoleChange(memberId, newRole) {
    try {
      await api.patch(api.org(`/members/${memberId}`), { role: newRole });
      toast('Role updated');
      await load();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function handleRemove(member) {
    if (!confirm(`Remove ${member.email}?`)) return;
    try {
      await api.del(api.org(`/members/${member.id}`));
      await load();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function handleAdd(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post(api.org('/members'), { email, role });
      toast('Member added');
      setEmail('');
      await load();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <section className="card">
        <h2>Members</h2>
        <DataTable
          headers={['Name', 'Email', 'Role', '']}
          rows={list.map((m) => ({
            id: m.id,
            cells: [
              m.name,
              m.email,
              manage ? (
                <select
                  aria-label={`Role for ${m.email}`}
                  value={m.role}
                  onChange={(e) => handleRoleChange(m.id, e.target.value)}
                >
                  {roles.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              ) : (
                m.role
              ),
              manage && m.id !== session.me.id ? (
                <button className="danger" type="button" onClick={() => handleRemove(m)}>
                  Remove
                </button>
              ) : null,
            ],
          }))}
        />
      </section>

      {manage && (
        <section className="card">
          <h2>Add a member</h2>
          <form className="inline" onSubmit={handleAdd}>
            <label>
              Email (must already have an account)
              <input
                type="email"
                required
                placeholder="colleague@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </label>
            <label>
              Role
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                {roles.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <button className="primary" type="submit" disabled={busy}>
              Add member
            </button>
          </form>
          <dl className="kv small">
            <dt>Viewer</dt>
            <dd>Read findings and reports</dd>
            <dt>Developer</dt>
            <dd>Run scans, triage findings, use the AI assistant</dd>
            <dt>Admin</dt>
            <dd>Manage repositories, members, Git providers and settings</dd>
            <dt>Owner</dt>
            <dd>Everything, including deleting the organisation</dd>
          </dl>
        </section>
      )}
    </>
  );
}

function TeamsTab() {
  const [teams, setTeams] = useState([]);
  const [members, setMembers] = useState([]);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);

  const manage = hasPermission(session.me, session.orgId, 'teams:manage');

  async function load() {
    try {
      const [t, m] = await Promise.all([
        api.get(api.org('/teams')),
        api.get(api.org('/members')),
      ]);
      setTeams(t);
      setMembers(m);
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  useEffect(() => {
    load();
  }, [session.orgId]);

  const emailOf = (id) => (members.find((m) => m.id === id) || {}).email || id;

  async function handleCreateTeam(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post(api.org('/teams'), { name });
      setName('');
      await load();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleAddMemberToTeam(teamId, userId) {
    if (!userId) return;
    try {
      await api.post(api.org(`/teams/${teamId}/members/${userId}`));
      await load();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function handleDeleteTeam(t) {
    if (!confirm(`Delete team ${t.name}?`)) return;
    try {
      await api.del(api.org(`/teams/${t.id}`));
      await load();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  return (
    <>
      <section className="card">
        <h2>Teams</h2>
        <DataTable
          headers={['Team', 'Members', '']}
          rows={teams.map((t) => ({
            id: t.id,
            cells: [
              t.name,
              t.members.map(emailOf).join(', ') || '-',
              manage ? (
                <div className="row">
                  <select
                    aria-label={`Add member to ${t.name}`}
                    value=""
                    onChange={(e) => handleAddMemberToTeam(t.id, e.target.value)}
                  >
                    <option value="">Add member...</option>
                    {members
                      .filter((m) => !t.members.includes(m.id))
                      .map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.email}
                        </option>
                      ))}
                  </select>
                  <button className="danger" type="button" onClick={() => handleDeleteTeam(t)}>
                    Delete
                  </button>
                </div>
              ) : null,
            ],
          }))}
          empty="No teams yet."
        />
      </section>

      {manage && (
        <section className="card">
          <form className="inline" onSubmit={handleCreateTeam}>
            <label>
              New team
              <input
                type="text"
                required
                placeholder="Team name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            <button className="primary" type="submit" disabled={busy}>
              Create team
            </button>
          </form>
        </section>
      )}
    </>
  );
}

function ProvidersTab() {
  const [list, setList] = useState([]);
  const [provider, setProvider] = useState('github');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);

  const manage = hasPermission(session.me, session.orgId, 'providers:manage');

  async function load() {
    try {
      setList(await api.get(api.org('/connections')));
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  useEffect(() => {
    load();
  }, [session.orgId]);

  async function handleConnect(e) {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await api.post(api.org('/connections'), { provider, token });
      setToken('');
      toast(`Connected as ${r.account}`);
      await load();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleDisconnect(id) {
    if (!confirm('Disconnect this provider? Repositories using it can no longer be scanned.')) return;
    try {
      await api.del(api.org(`/connections/${id}`));
      await load();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  return (
    <>
      <section className="card">
        <h2>Connected Git providers</h2>
        <DataTable
          headers={['Provider', 'Account', 'Added', '']}
          rows={list.map((c) => ({
            id: c.id,
            cells: [
              c.provider,
              c.account || c.label,
              fmtDate(c.createdAt),
              manage ? (
                <button className="danger" type="button" onClick={() => handleDisconnect(c.id)}>
                  Disconnect
                </button>
              ) : null,
            ],
          }))}
          empty="No providers connected."
        />
      </section>

      {manage && (
        <section className="card">
          <h2>Connect a provider</h2>
          <form className="inline" onSubmit={handleConnect}>
            <label>
              Provider
              <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="bitbucket">Bitbucket</option>
              </select>
            </label>
            <label>
              Access token
              <input
                type="password"
                required
                autoComplete="off"
                size={36}
                placeholder="Personal access token"
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
            </label>
            <button className="primary" type="submit" disabled={busy}>
              Connect
            </button>
          </form>
          <p className="muted small">
            Use a token with read-only repository access. It is validated against the provider,
            encrypted at rest and never shown again. Scans use it only to clone the repository.
          </p>
        </section>
      )}
    </>
  );
}

function NotificationsTab() {
  const [list, setList] = useState([]);

  async function load() {
    try {
      setList(await api.get(api.org('/notifications')));
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  useEffect(() => {
    load();
  }, [session.orgId]);

  async function handleMarkRead() {
    try {
      await api.post(api.org('/notifications/read'), {});
      await load();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  return (
    <section className="card">
      <div className="row">
        <h2 className="grow">Notifications</h2>
        {list.some((n) => !n.read) && (
          <button type="button" onClick={handleMarkRead}>
            Mark all as read
          </button>
        )}
      </div>
      <DataTable
        headers={['', 'Notification', 'When']}
        rows={list.map((n) => ({
          id: n.id,
          cells: [
            n.read ? '' : <span className="badge st-open">new</span>,
            <div>
              <strong>{n.title}</strong>
              {n.body && <div className="muted small">{n.body}</div>}
            </div>,
            ago(n.createdAt),
          ],
        }))}
        empty="No notifications."
      />
    </section>
  );
}

function AuditTab() {
  const [list, setList] = useState([]);
  const canAudit = hasPermission(session.me, session.orgId, 'audit:read');

  useEffect(() => {
    if (!canAudit) return;
    api
      .get(api.org('/audit?limit=200'))
      .then(setList)
      .catch((err) => toast(err.message, 'error'));
  }, [session.orgId, canAudit]);

  if (!canAudit) {
    return <div className="card empty">Only admins can view the audit log.</div>;
  }

  return (
    <section className="card">
      <h2>Audit log</h2>
      <DataTable
        headers={['When', 'User', 'Action', 'Target', 'IP']}
        rows={list.map((e) => ({
          id: e.id,
          cells: [
            fmtDate(e.createdAt),
            e.user || '-',
            e.action,
            <span className="mono">{e.target || ''}</span>,
            e.ip || '',
          ],
        }))}
        empty="No events."
      />
    </section>
  );
}

export function SettingsView({ tab = 'profile', onThemeChange, onMeUpdated }) {
  const activeTab = TABS.some(([k]) => k === tab) ? tab : 'profile';

  return (
    <>
      <PageHead title="Settings" />
      <nav className="tabs" aria-label="Settings sections">
        {TABS.map(([k, l]) => (
          <a
            key={k}
            href={`#/settings/${k}`}
            aria-current={k === activeTab ? 'page' : undefined}
          >
            {l}
          </a>
        ))}
      </nav>
      <div className="grid">
        {activeTab === 'profile' && <ProfileTab onThemeChange={onThemeChange} />}
        {activeTab === 'organisation' && <OrganisationTab onMeUpdated={onMeUpdated} />}
        {activeTab === 'members' && <MembersTab />}
        {activeTab === 'teams' && <TeamsTab />}
        {activeTab === 'providers' && <ProvidersTab />}
        {activeTab === 'notifications' && <NotificationsTab />}
        {activeTab === 'audit' && <AuditTab />}
      </div>
    </>
  );
}
