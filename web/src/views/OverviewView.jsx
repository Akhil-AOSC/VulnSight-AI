import React, { useEffect, useState } from 'react';
import { api, session, hasPermission, toast, ago, pad } from '../api.js';
import {
  PageHead,
  StatCard,
  SeverityBar,
  TrendChart,
  DataTable,
  StatusBadge,
} from '../components/Common.jsx';

export function OverviewView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncBusy, setSyncBusy] = useState(false);

  const canRunScan = hasPermission(session.me, session.orgId, 'scans:run');

  async function loadOverview() {
    try {
      setLoading(true);
      const res = await api.get(api.org('/overview'));
      setData(res);
    } catch (err) {
      toast(err.message || 'Failed to load overview', 'error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadOverview();
  }, [session.orgId]);

  async function handleSyncMongo() {
    setSyncBusy(true);
    try {
      const res = await api.post(api.org('/mongo/sync'), {});
      toast(
        res && res.imported
          ? `Synced ${res.imported} scan(s) from MongoDB`
          : 'MongoDB history is up to date'
      );
      await loadOverview();
    } catch (err) {
      toast(err.message || 'MongoDB sync failed', 'error');
    } finally {
      setSyncBusy(false);
    }
  }

  async function handleRepoScanNow(repoId) {
    try {
      const s = await api.post(api.org(`/repos/${repoId}/scans`), {});
      toast('Scan queued');
      location.hash = `#/scans/${s.id}`;
    } catch (err) {
      toast(err.message || 'Could not queue scan', 'error');
    }
  }

  if (loading && !data) {
    return <p className="muted">Loading...</p>;
  }
  if (!data) return null;

  const t = data.totals || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  const rem = data.remediation || { open: 0, acknowledged: 0, fixed: 0, suppressed: 0, fixRate: null };

  const repoNameById = (id) =>
    ((data.repositories || []).find((r) => r.id === id) || {}).fullName || id;

  function renderScanTable(scans, showError = false) {
    return (
      <DataTable
        headers={['Repository', 'Branch', 'Status', showError ? 'Error' : 'Found', 'Source', 'When']}
        rows={(scans || []).map((s) => ({
          id: s.id,
          cells: [
            repoNameById(s.repoId),
            s.branch,
            <StatusBadge status={s.status} />,
            showError
              ? s.error
              : pad(s.summary && (s.summary.total != null ? s.summary.total : s.summary.issues)),
            <span>
              {s.source === 'mongodb' ? (
                <span className="mongo-badge" title="Stored in MongoDB Atlas">
                  MongoDB
                </span>
              ) : (
                'Local'
              )}
              {s.ai && <span className="ai-badge ai-badge-sm">AI</span>}
            </span>,
            ago(s.createdAt),
          ],
        }))}
        onRow={(r) => {
          location.hash = `#/scans/${r.id}`;
        }}
      />
    );
  }

  return (
    <>
      <PageHead
        title="Security overview"
        subtitle="Latest scan of each repository · Data from OSV.dev & MongoDB Atlas"
      >
        {data.mongo && data.mongo.connected && (
          <span
            className="db-indicator db-connected"
            title="History actively synced with MongoDB Atlas collection."
          >
            MongoDB Atlas
          </span>
        )}
        {data.mongo && !data.mongo.connected && data.mongo.configured && (
          <span className="db-indicator db-fallback" title="MongoDB Atlas fallback active">
            Local (Atlas Blocked)
          </span>
        )}
        {data.aiEnabled && <span className="ai-badge">Groq AI Powered</span>}
        {data.mongo && data.mongo.configured && (
          <button type="button" onClick={handleSyncMongo} disabled={syncBusy}>
            {syncBusy ? 'Syncing...' : 'Sync MongoDB History'}
          </button>
        )}
      </PageHead>

      {!data.repositories || !data.repositories.length ? (
        <div className="card empty">
          <p>No repositories yet.</p>
          <a className="btn primary" href="#/new-scan">
            Run your first scan
          </a>
        </div>
      ) : (
        <>
          <div className="grid stats">
            <StatCard num={t.total} label="Open findings" />
            <StatCard className="critical" num={t.critical} label="Critical" />
            <StatCard className="high" num={t.high} label="High" />
            <StatCard className="medium" num={t.medium} label="Medium" />
            <StatCard className="low" num={t.low} label="Low" />
            <div className="card stat">
              <div className="num gauge">{data.posture == null ? '-' : data.posture}</div>
              <div className="label">Posture score (100 = clean)</div>
            </div>
          </div>

          <div className="grid cols-2">
            <section className="card">
              <h2>Vulnerability trend</h2>
              {data.trend && data.trend.length ? (
                <>
                  <TrendChart
                    points={data.trend}
                    series={[
                      { key: 'total', cls: 'l-total', label: 'total' },
                      { key: 'critical', cls: 'l-critical', label: 'critical' },
                      { key: 'high', cls: 'l-high', label: 'high' },
                    ]}
                  />
                  <div className="legend">
                    <span>Total</span>
                    <span>Critical</span>
                    <span>High</span>
                  </div>
                </>
              ) : (
                <div className="empty">Run a scan to see trends.</div>
              )}
            </section>

            <section className="card">
              <h2>Remediation progress</h2>
              <p className="muted">
                {rem.fixRate == null
                  ? 'No tracked findings yet.'
                  : `${rem.fixRate}% of tracked findings are fixed`}
              </p>
              <dl className="kv">
                <dt>Open</dt>
                <dd>{rem.open}</dd>
                <dt>Acknowledged</dt>
                <dd>{rem.acknowledged}</dd>
                <dt>Fixed</dt>
                <dd>{rem.fixed}</dd>
                <dt>Suppressed</dt>
                <dd>{rem.suppressed}</dd>
              </dl>
            </section>
          </div>

          <section className="card">
            <h2>Repositories</h2>
            <DataTable
              headers={['Repository', 'Status', 'Posture', 'Findings', 'Severity', 'Last scan', '']}
              rows={data.repositories.map((r) => ({
                id: r.id,
                cells: [
                  <a href={`#/repos/${r.id}`}>{r.fullName}</a>,
                  r.lastStatus ? (
                    <StatusBadge status={r.lastStatus} />
                  ) : (
                    <span className="muted">never scanned</span>
                  ),
                  r.posture ? `${r.posture.grade} (${r.posture.score})` : '-',
                  pad(r.total),
                  r.bySeverity ? <SeverityBar counts={r.bySeverity} /> : '-',
                  ago(r.lastScanAt),
                  canRunScan ? (
                    <button type="button" onClick={() => handleRepoScanNow(r.id)}>
                      Scan now
                    </button>
                  ) : null,
                ],
              }))}
              onRow={(r) => {
                location.hash = `#/repos/${r.id}`;
              }}
            />
          </section>

          <div className="grid cols-2">
            <section className="card">
              <h2>Recent scans (MongoDB &amp; Local History)</h2>
              {renderScanTable(data.recentScans)}
            </section>
            <section className="card">
              <h2>Failed scans</h2>
              {data.failedScans && data.failedScans.length ? (
                renderScanTable(data.failedScans, true)
              ) : (
                <div className="empty">No failed scans.</div>
              )}
            </section>
          </div>
        </>
      )}
    </>
  );
}
