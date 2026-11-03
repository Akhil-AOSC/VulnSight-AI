import React, { useEffect, useState } from 'react';
import { api, session, hasPermission, toast, fmtDate, pad } from '../api.js';
import { PageHead, DataTable, StatusBadge } from '../components/Common.jsx';

const SCANNERS = [
  ['sca', 'Dependencies (OSV)'],
  ['semgrep', 'Code (Semgrep)'],
  ['gitleaks', 'Secrets (Gitleaks)'],
  ['trivy', 'Dependencies + IaC (Trivy)'],
  ['checkov', 'Infrastructure (Checkov)'],
];

export function ReposListView() {
  const [repos, setRepos] = useState([]);
  const [conns, setConns] = useState([]);
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);

  const [url, setUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [connId, setConnId] = useState('');
  const [teamId, setTeamId] = useState('');
  const [busy, setBusy] = useState(false);

  const canWrite = hasPermission(session.me, session.orgId, 'repos:write');
  const canScan = hasPermission(session.me, session.orgId, 'scans:run');

  async function loadAll() {
    try {
      setLoading(true);
      const [r, c, t] = await Promise.all([
        api.get(api.org('/repos')),
        api.get(api.org('/connections')),
        api.get(api.org('/teams')),
      ]);
      setRepos(r);
      setConns(c);
      setTeams(t);
    } catch (err) {
      toast(err.message || 'Failed to load repositories', 'error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
  }, [session.orgId]);

  async function handleAddRepo(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post(api.org('/repos'), {
        url: url.trim(),
        branch: branch.trim() || 'main',
        connectionId: connId || null,
        teamId: teamId || null,
      });
      toast('Repository added');
      setUrl('');
      await loadAll();
    } catch (err) {
      toast(err.message || 'Failed to add repository', 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleScanNow(repoId) {
    try {
      const s = await api.post(api.org(`/repos/${repoId}/scans`), {});
      toast('Scan queued');
      location.hash = `#/scans/${s.id}`;
    } catch (err) {
      toast(err.message || 'Failed to queue scan', 'error');
    }
  }

  if (loading && !repos.length) return <p className="muted">Loading...</p>;

  return (
    <>
      <PageHead title="Repositories" subtitle="Connect a repository and scan it" />

      {canWrite && (
        <section className="card">
          <h2>Add a repository</h2>
          <form className="inline" onSubmit={handleAddRepo}>
            <label>
              Repository URL or Local Folder
              <input
                type="text"
                required
                size={38}
                autoComplete="off"
                placeholder="https://github.com/owner/name or C:\path\to\project"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </label>
            <label>
              Branch
              <input
                type="text"
                size={12}
                placeholder="main"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
              />
            </label>
            <label>
              Git connection
              <select value={connId} onChange={(e) => setConnId(e.target.value)}>
                <option value="">Public repository (no connection)</option>
                {conns.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.provider}: {c.account || c.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Team
              <select value={teamId} onChange={(e) => setTeamId(e.target.value)}>
                <option value="">No team</option>
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </label>
            <button className="primary" type="submit" disabled={busy}>
              Add repository
            </button>
          </form>
          <p className="muted small">
            Enter a GitHub/GitLab/Bitbucket https URL or a local project folder path. Private
            repositories need a connection (Settings &gt; Git providers).
          </p>
        </section>
      )}

      <section className="card">
        <h2>Connected repositories</h2>
        <DataTable
          headers={['Repository', 'Provider', 'Branch', 'Status', 'Posture', 'Findings', 'Schedule', '']}
          rows={repos.map((r) => ({
            id: r.id,
            cells: [
              <a href={`#/repos/${r.id}`}>{r.fullName}</a>,
              r.provider,
              r.defaultBranch,
              r.lastScan ? (
                <StatusBadge status={r.lastScan.status} />
              ) : (
                <span className="muted">never</span>
              ),
              r.security ? `${r.security.posture.grade} (${r.security.posture.score})` : '-',
              pad(r.security && r.security.total),
              r.schedule || 'manual',
              canScan ? (
                <button type="button" onClick={() => handleScanNow(r.id)}>
                  Scan now
                </button>
              ) : null,
            ],
          }))}
          empty="No repositories connected yet."
          onRow={(r) => {
            location.hash = `#/repos/${r.id}`;
          }}
        />
      </section>
    </>
  );
}

export function RepoDetailView({ repoId }) {
  const [repo, setRepo] = useState(null);
  const [scans, setScans] = useState([]);
  const [branches, setBranches] = useState([]);
  const [selectedBranch, setSelectedBranch] = useState('main');
  const [webhook, setWebhook] = useState(null);
  const [loading, setLoading] = useState(true);

  const [activeScanners, setActiveScanners] = useState(new Set(['sca', 'semgrep', 'gitleaks']));
  const [threshold, setThreshold] = useState('low');
  const [schedule, setSchedule] = useState('');
  const [monitoredBranches, setMonitoredBranches] = useState('');
  const [busy, setBusy] = useState(false);

  const canScan = hasPermission(session.me, session.orgId, 'scans:run');
  const canWrite = hasPermission(session.me, session.orgId, 'repos:write');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        setLoading(true);
        const [r, s, b] = await Promise.all([
          api.get(api.org(`/repos/${repoId}`)),
          api.get(api.org(`/scans?repoId=${repoId}&limit=30`)),
          api.get(api.org(`/repos/${repoId}/branches`)).catch(() => []),
        ]);
        if (!mounted) return;
        setRepo(r);
        setScans(s);
        setBranches(b.length ? b : [r.defaultBranch]);
        setSelectedBranch(r.defaultBranch);
        const cfg = r.config || {};
        setActiveScanners(new Set(cfg.scanners || ['sca', 'semgrep', 'gitleaks']));
        setThreshold(cfg.threshold || 'low');
        setSchedule(r.schedule || '');
        setMonitoredBranches((cfg.branches || []).join(', '));

        if (canWrite) {
          api
            .get(api.org(`/repos/${repoId}/webhook`))
            .then((w) => {
              if (mounted) setWebhook(w);
            })
            .catch(() => {});
        }
      } catch (err) {
        toast(err.message || 'Failed to load repository details', 'error');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, [repoId, session.orgId]);

  async function handleScanNow() {
    setBusy(true);
    try {
      const s = await api.post(api.org(`/repos/${repoId}/scans`), { branch: selectedBranch });
      toast('Scan queued');
      location.hash = `#/scans/${s.id}`;
    } catch (err) {
      toast(err.message || 'Failed to start scan', 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveConfig(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.patch(api.org(`/repos/${repoId}`), {
        config: {
          scanners: [...activeScanners],
          threshold,
          branches: monitoredBranches
            .split(',')
            .map((x) => x.trim())
            .filter(Boolean),
        },
      });
      await api.put(api.org(`/repos/${repoId}/schedule`), { schedule: schedule || null });
      toast('Settings saved');
    } catch (err) {
      toast(err.message || 'Failed to save settings', 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleRemoveRepo() {
    if (!repo || !confirm(`Remove ${repo.fullName} and all of its scan data?`)) return;
    setBusy(true);
    try {
      await api.del(api.org(`/repos/${repoId}`));
      location.hash = '#/repos';
    } catch (err) {
      toast(err.message || 'Failed to remove repository', 'error');
      setBusy(false);
    }
  }

  function toggleScanner(key) {
    setActiveScanners((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  if (loading && !repo) return <p className="muted">Loading...</p>;
  if (!repo) return null;

  return (
    <>
      <PageHead title={repo.fullName} subtitle={repo.cloneUrl}>
        {canScan && (
          <>
            <select
              aria-label="Branch to scan"
              value={selectedBranch}
              onChange={(e) => setSelectedBranch(e.target.value)}
            >
              {branches.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
            <button className="primary" type="button" onClick={handleScanNow} disabled={busy}>
              Scan now
            </button>
          </>
        )}
      </PageHead>

      <section className="card">
        <h2>Scan history</h2>
        <DataTable
          headers={['Started', 'Branch', 'Commit', 'Trigger', 'Status', 'Findings', 'New', 'Fixed']}
          rows={scans.map((s) => ({
            id: s.id,
            cells: [
              fmtDate(s.createdAt),
              s.branch,
              s.commit ? s.commit.slice(0, 8) : '-',
              s.trigger,
              <StatusBadge status={s.status} />,
              pad(s.summary && (s.summary.total != null ? s.summary.total : s.summary.issues)),
              pad(s.summary && s.summary.new),
              pad(s.summary && s.summary.fixed),
            ],
          }))}
          empty='No scans yet. Press "Scan now".'
          onRow={(r) => {
            location.hash = `#/scans/${r.id}`;
          }}
        />
      </section>

      {canWrite && (
        <>
          <section className="card">
            <h2>Scan configuration</h2>
            <form className="stack" onSubmit={handleSaveConfig}>
              <div className="row">
                {SCANNERS.map(([key, label]) => (
                  <label key={key} className="inline">
                    <input
                      type="checkbox"
                      checked={activeScanners.has(key)}
                      onChange={() => toggleScanner(key)}
                    />
                    {label}
                  </label>
                ))}
              </div>
              <div className="row">
                <label>
                  Severity threshold
                  <select value={threshold} onChange={(e) => setThreshold(e.target.value)}>
                    {['low', 'medium', 'high', 'critical'].map((t) => (
                      <option key={t} value={t}>
                        Report {t} and above
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Scheduled scans
                  <select value={schedule} onChange={(e) => setSchedule(e.target.value)}>
                    <option value="">Manual only</option>
                    <option value="hourly">Every hour</option>
                    <option value="daily">Every day</option>
                    <option value="weekly">Every week</option>
                  </select>
                </label>
                <label>
                  Branches monitored by webhooks (comma separated)
                  <input
                    type="text"
                    size={30}
                    placeholder={repo.defaultBranch}
                    value={monitoredBranches}
                    onChange={(e) => setMonitoredBranches(e.target.value)}
                  />
                </label>
              </div>
              <div className="row">
                <button className="primary" type="submit" disabled={busy}>
                  Save settings
                </button>
              </div>
            </form>
          </section>

          <section className="card">
            <h2>Continuous monitoring (webhook)</h2>
            {webhook ? (
              <dl className="kv">
                <dt>Payload URL</dt>
                <dd>
                  <code>{`${location.origin}${webhook.url}`}</code>
                </dd>
                <dt>Secret</dt>
                <dd>
                  <code>{webhook.secret}</code>
                </dd>
              </dl>
            ) : (
              <div className="muted small">Loading webhook details...</div>
            )}
            <p className="muted small">
              Add this webhook to your Git provider (push events, content type JSON) to scan on
              every push to a monitored branch. The secret signs each delivery.
            </p>
          </section>

          <section className="card">
            <h2>Danger zone</h2>
            <button className="danger" type="button" onClick={handleRemoveRepo} disabled={busy}>
              Remove repository
            </button>
          </section>
        </>
      )}
    </>
  );
}
