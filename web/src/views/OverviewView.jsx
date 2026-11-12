import React, { useEffect, useState } from 'react';
import { api, session, hasPermission, toast, ago, pad } from '../api.js';
import {
  PageHead,
  StatCard,
  SeverityBar,
  DataTable,
  StatusBadge,
  ScanSkeletonLoader,
  IconEmptyState,
} from '../components/Common.jsx';

function RepoBarChartSvg({ repos, sevFilter, maxVal }) {
  const W = 540;
  const H = 220;
  const P = { l: 36, r: 16, t: 26, b: 36 };
  const plotW = W - P.l - P.r;
  const plotH = H - P.t - P.b;

  const step = maxVal <= 5 ? 1 : maxVal <= 15 ? 5 : maxVal <= 30 ? 10 : Math.ceil(maxVal / 4 / 5) * 5;
  const topTick = Math.ceil(maxVal / step) * step || step;
  const ticks = [0, Math.round(topTick / 2), topTick];

  const y = (v) => H - P.b - (v / topTick) * plotH;

  const N = Math.max(1, repos.length);
  const repoSlotW = plotW / N;

  const SEVS = ['critical', 'high', 'medium', 'low'];
  const SEV_COLORS = {
    critical: 'var(--critical)',
    high: 'var(--high)',
    medium: 'var(--medium)',
    low: 'var(--low)',
  };

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="repo-svg-barchart"
      role="img"
      aria-label="Repository vulnerability bar chart"
    >
      {ticks.map((t) => (
        <React.Fragment key={t}>
          <line
            x1={P.l}
            x2={W - P.r}
            y1={y(t)}
            y2={y(t)}
            className="barchart-gridline"
          />
          <text
            x={P.l - 6}
            y={y(t) + 3}
            textAnchor="end"
            className="barchart-tick-label"
          >
            {t}
          </text>
        </React.Fragment>
      ))}

      {repos.map((r, i) => {
        const counts = r.bySeverity || { critical: 0, high: 0, medium: 0, low: 0 };
        const repoCenterX = P.l + i * repoSlotW + repoSlotW / 2;
        const shortName = (r.fullName || '').split('/').pop() || r.fullName || 'repo';

        if (sevFilter === 'all') {
          const barGap = 6;
          const barW = Math.max(14, Math.min(28, (repoSlotW * 0.7 - 3 * barGap) / 4));
          const totalGroupW = 4 * barW + 3 * barGap;
          const groupStartX = repoCenterX - totalGroupW / 2;

          return (
            <g key={r.id} className="barchart-repo-group">
              {SEVS.map((s, j) => {
                const val = counts[s] || 0;
                const barH = val > 0 ? Math.max(4, (val / topTick) * plotH) : 0;
                const barX = groupStartX + j * (barW + barGap);
                const barY = H - P.b - barH;

                return (
                  <g key={s} className={`bar-col bar-col-${s}`}>
                    <title>{`${shortName} - ${val} ${s}`}</title>
                    {val > 0 && (
                      <>
                        <rect
                          x={barX}
                          y={barY}
                          width={barW}
                          height={barH}
                          rx="3"
                          ry="3"
                          fill={SEV_COLORS[s]}
                          className="barchart-rect"
                        />
                        <text
                          x={barX + barW / 2}
                          y={barY - 5}
                          textAnchor="middle"
                          className="barchart-bar-value"
                        >
                          {val}
                        </text>
                      </>
                    )}
                  </g>
                );
              })}

              <a href={`#/repos/${r.id}`}>
                <text
                  x={repoCenterX}
                  y={H - 12}
                  textAnchor="middle"
                  className="barchart-x-label"
                >
                  {shortName.length > 20 ? shortName.slice(0, 18) + '…' : shortName}
                </text>
              </a>
            </g>
          );
        } else {
          const val = counts[sevFilter] || 0;
          const barW = Math.max(26, Math.min(56, repoSlotW * 0.45));
          const barH = val > 0 ? Math.max(4, (val / topTick) * plotH) : 0;
          const barX = repoCenterX - barW / 2;
          const barY = H - P.b - barH;

          return (
            <g key={r.id} className="barchart-repo-group">
              <title>{`${shortName} - ${val} ${sevFilter}`}</title>
              {val > 0 && (
                <>
                  <rect
                    x={barX}
                    y={barY}
                    width={barW}
                    height={barH}
                    rx="3"
                    ry="3"
                    fill={SEV_COLORS[sevFilter]}
                    className="barchart-rect"
                  />
                  <text
                    x={barX + barW / 2}
                    y={barY - 5}
                    textAnchor="middle"
                    className="barchart-bar-value"
                  >
                    {val}
                  </text>
                </>
              )}
              <a href={`#/repos/${r.id}`}>
                <text
                  x={repoCenterX}
                  y={H - 12}
                  textAnchor="middle"
                  className="barchart-x-label"
                >
                  {shortName.length > 20 ? shortName.slice(0, 18) + '…' : shortName}
                </text>
              </a>
            </g>
          );
        }
      })}
    </svg>
  );
}

function RepoSeverityBreakdown({ repositories }) {
  const [sevFilter, setSevFilter] = useState('all');
  const [sortBy, setSortBy] = useState('total');

  const scannedRepos = (repositories || []).filter(
    (r) => r.bySeverity && r.total != null
  );

  const sortedRepos = [...scannedRepos].sort((a, b) => {
    if (sortBy === 'critical') {
      const cA = (a.bySeverity && a.bySeverity.critical) || 0;
      const cB = (b.bySeverity && b.bySeverity.critical) || 0;
      return cB - cA || (b.total || 0) - (a.total || 0);
    }
    if (sortBy === 'name') {
      return (a.fullName || '').localeCompare(b.fullName || '');
    }
    const vA = sevFilter === 'all' ? (a.total || 0) : ((a.bySeverity && a.bySeverity[sevFilter]) || 0);
    const vB = sevFilter === 'all' ? (b.total || 0) : ((b.bySeverity && b.bySeverity[sevFilter]) || 0);
    return vB - vA;
  });

  const maxVal = Math.max(
    1,
    ...sortedRepos.flatMap((r) =>
      sevFilter === 'all'
        ? [
            r.bySeverity?.critical || 0,
            r.bySeverity?.high || 0,
            r.bySeverity?.medium || 0,
            r.bySeverity?.low || 0,
          ]
        : [(r.bySeverity && r.bySeverity[sevFilter]) || 0]
    )
  );

  return (
    <section className="card overview-chart-card">
      <div className="card-head">
        <div>
          <h2>Repository vulnerabilities</h2>
          <span className="muted small">
            Vertical bar comparison across scanned repositories
          </span>
        </div>
      </div>

      {!scannedRepos.length ? (
        <div className="overview-chart-empty">
          <div className="empty-icon">
            <IconEmptyState size={36} />
          </div>
          <h3>No scan data yet</h3>
          <p className="muted small">
            Run a scan on any repository to view vulnerability bar charts and severity distributions.
          </p>
          <a className="btn primary" href="#/new-scan">
            Scan a repository
          </a>
        </div>
      ) : (
        <div className="repo-chart-container">
          <div className="repo-chart-toolbar">
            <div className="repo-chart-filters">
              <span className="toolbar-label muted">Filter:</span>
              {[
                { key: 'all', label: 'All' },
                { key: 'critical', label: 'Critical' },
                { key: 'high', label: 'High' },
                { key: 'medium', label: 'Medium' },
                { key: 'low', label: 'Low' },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  type="button"
                  className={`filter-chip ${sevFilter === key ? 'active' : ''} ${key !== 'all' ? `chip-${key}` : ''}`}
                  onClick={() => setSevFilter(key)}
                >
                  {label}
                </button>
              ))}
            </div>
            <div className="repo-chart-options">
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="chart-select"
                aria-label="Sort repositories"
              >
                <option value="total">Sort: Total issues</option>
                <option value="critical">Sort: Critical first</option>
                <option value="name">Sort: Name</option>
              </select>
            </div>
          </div>

          <div className="barchart-canvas-wrap">
            <RepoBarChartSvg repos={sortedRepos} sevFilter={sevFilter} maxVal={maxVal} />
          </div>

          <div className="repo-chart-legend">
            <span className="legend-item">
              <span className="sev-dot sev-dot-critical" /> Critical
            </span>
            <span className="legend-item">
              <span className="sev-dot sev-dot-high" /> High
            </span>
            <span className="legend-item">
              <span className="sev-dot sev-dot-medium" /> Medium
            </span>
            <span className="legend-item">
              <span className="sev-dot sev-dot-low" /> Low
            </span>
          </div>

          <div className="repo-chips-summary">
            {sortedRepos.map((r) => {
              const c = r.bySeverity || { critical: 0, high: 0, medium: 0, low: 0 };
              const sName = (r.fullName || '').split('/').pop() || r.fullName;
              return (
                <div key={r.id} className="repo-chip-summary-row">
                  <a href={`#/repos/${r.id}`} className="repo-chip-summary-name" title={r.fullName}>
                    {sName}
                  </a>
                  <div className="sev-bar-inline">
                    {c.critical > 0 && (
                      <span className="sev-chip sev-chip-critical">
                        <span className="sev-dot sev-dot-critical" />
                        {c.critical}C
                      </span>
                    )}
                    {c.high > 0 && (
                      <span className="sev-chip sev-chip-high">
                        <span className="sev-dot sev-dot-high" />
                        {c.high}H
                      </span>
                    )}
                    {c.medium > 0 && (
                      <span className="sev-chip sev-chip-medium">
                        <span className="sev-dot sev-dot-medium" />
                        {c.medium}M
                      </span>
                    )}
                    {c.low > 0 && (
                      <span className="sev-chip sev-chip-low">
                        <span className="sev-dot sev-dot-low" />
                        {c.low}L
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}

export function OverviewView() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncBusy, setSyncBusy] = useState(false);
  const [selectedRemScanId, setSelectedRemScanId] = useState('all');

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
          ? `Loaded ${res.imported} past scan(s)`
          : 'Scan history is up to date'
      );
      await loadOverview();
    } catch (err) {
      toast(err.message || 'Could not refresh history', 'error');
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
    return (
      <div className="view">
        <PageHead title="Security Overview" subtitle="Loading organization posture and telemetry..." />
        <ScanSkeletonLoader cards={6} hasTabs={false} rows={4} />
      </div>
    );
  }
  if (!data) return null;

  const t = data.totals || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  const rem = data.remediation || { open: 0, acknowledged: 0, fixed: 0, suppressed: 0, fixRate: null };

  const repoNameById = (id) =>
    ((data.repositories || []).find((r) => r.id === id) || {}).fullName || id;

  // Deduplicate: Each repository gets exactly ONE entry in the dropdown (its latest scan)
  const repoLatestScans = (() => {
    const seenRepos = new Set();
    const result = [];

    for (const s of (data.recentScans || [])) {
      if (s.status === 'completed' && s.repoId && !seenRepos.has(s.repoId)) {
        seenRepos.add(s.repoId);
        result.push(s);
      }
    }

    for (const r of (data.repositories || [])) {
      if (!seenRepos.has(r.id) && r.total != null) {
        seenRepos.add(r.id);
        result.push({
          id: r.id,
          repoId: r.id,
          branch: 'main',
          summary: { total: r.total, bySeverity: r.bySeverity },
        });
      }
    }

    return result;
  })();

  const activeRem = (() => {
    if (selectedRemScanId !== 'all') {
      const match = repoLatestScans.find((s) => s.id === selectedRemScanId || s.repoId === selectedRemScanId);
      if (match) {
        const scanTotal = (match.summary && (match.summary.total != null ? match.summary.total : match.summary.issues)) || 0;
        const r = match.remediation || {};
        const ack = r.acknowledged || 0;
        const fixed = r.fixed || 0;
        const sup = r.suppressed || 0;
        const open = (r.open != null && r.open > 0) ? r.open : Math.max(0, scanTotal - ack - fixed - sup);
        const total = open + ack + fixed + sup;
        const fixRate = total > 0 ? Math.round((fixed / total) * 100) : null;
        return { open, acknowledged: ack, fixed, suppressed: sup, total, fixRate, scanId: match.id, repoId: match.repoId };
      }
    }
    const orgTotal = t.total || 0;
    const r = rem || {};
    const ack = r.acknowledged || 0;
    const fixed = r.fixed || 0;
    const sup = r.suppressed || 0;
    const open = (r.open != null && r.open > 0) ? r.open : Math.max(0, orgTotal - ack - fixed - sup);
    const total = open + ack + fixed + sup;
    const fixRate = total > 0 ? Math.round((fixed / total) * 100) : null;
    return { open, acknowledged: ack, fixed, suppressed: sup, total, fixRate };
  })();

  const totalRemTracked = activeRem.total != null
    ? activeRem.total
    : ((activeRem.open || 0) + (activeRem.acknowledged || 0) + (activeRem.fixed || 0) + (activeRem.suppressed || 0));

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
                <span className="mongo-badge" title="Saved in cloud history">
                  Cloud
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
        subtitle="Latest scan of each repository"
      >
        {data.mongo && data.mongo.connected && (
          <span
            className="db-indicator db-connected"
            title="Your scan history is automatically saved to the cloud."
          >
            Cloud Saved
          </span>
        )}
        {data.mongo && !data.mongo.connected && data.mongo.configured && (
          <span className="db-indicator db-fallback" title="Scans are saved on this computer">
            Saved Locally
          </span>
        )}
        {data.aiEnabled && <span className="ai-badge">AI Powered</span>}
        {data.mongo && data.mongo.configured && (
          <button type="button" onClick={handleSyncMongo} disabled={syncBusy}>
            {syncBusy ? 'Refreshing...' : 'Refresh History'}
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
            <RepoSeverityBreakdown repositories={data.repositories} />
            <section className="card overview-remediation-card">
              <div className="card-head overview-remediation-head">
                <div>
                  <h2>Remediation progress</h2>
                  <span className="muted small">Triage and vulnerability resolution status</span>
                </div>
                <div className="remediation-header-controls">
                  {repoLatestScans.length > 0 && (
                    <select
                      value={selectedRemScanId}
                      onChange={(e) => setSelectedRemScanId(e.target.value)}
                      className="chart-select remediation-scan-select"
                      aria-label="Filter remediation by repository"
                    >
                      <option value="all">All repositories (Combined)</option>
                      {repoLatestScans.map((s) => {
                        const rName = (repoNameById(s.repoId) || '').split('/').pop() || repoNameById(s.repoId);
                        const issuesCount = s.summary?.total != null ? `${s.summary.total} issues` : '';
                        return (
                          <option key={s.id || s.repoId} value={s.id || s.repoId}>
                            {rName} ({s.branch || 'main'}) {issuesCount ? `· ${issuesCount}` : ''}
                          </option>
                        );
                      })}
                    </select>
                  )}
                  <span className={`badge ${activeRem.fixRate > 0 ? 'st-completed' : (totalRemTracked > 0 ? 'st-queued' : 'st-unknown')}`}>
                    {totalRemTracked === 0
                      ? 'No tracked issues'
                      : (activeRem.fixRate != null ? `${activeRem.fixRate}% resolved` : '0% resolved')}
                  </span>
                </div>
              </div>

              <div className="triage-stats-grid">
                <div className="triage-stat-item st-open">
                  <span className="triage-stat-num">{activeRem.open || 0}</span>
                  <span className="triage-stat-label">Open</span>
                </div>
                <div className="triage-stat-item st-ack">
                  <span className="triage-stat-num">{activeRem.acknowledged || 0}</span>
                  <span className="triage-stat-label">Acknowledged</span>
                </div>
                <div className="triage-stat-item st-fixed">
                  <span className="triage-stat-num">{activeRem.fixed || 0}</span>
                  <span className="triage-stat-label">Fixed</span>
                </div>
                <div className="triage-stat-item st-suppressed">
                  <span className="triage-stat-num">{activeRem.suppressed || 0}</span>
                  <span className="triage-stat-label">Suppressed</span>
                </div>
              </div>

              <div className="triage-progress-box">
                <div className="triage-progress-header">
                  <span className="muted small">Triage status distribution</span>
                  <span className="triage-total-badge">
                    {totalRemTracked} tracked
                  </span>
                </div>
                <div className="triage-progress-track">
                  {totalRemTracked === 0 ? (
                    <div className="triage-bar-empty" />
                  ) : (
                    <div className="triage-bar-segments">
                      {activeRem.fixed > 0 && (
                        <div
                          className="triage-seg seg-fixed"
                          style={{ width: `${(activeRem.fixed / totalRemTracked) * 100}%` }}
                          title={`${activeRem.fixed} Fixed`}
                        />
                      )}
                      {activeRem.acknowledged > 0 && (
                        <div
                          className="triage-seg seg-ack"
                          style={{ width: `${(activeRem.acknowledged / totalRemTracked) * 100}%` }}
                          title={`${activeRem.acknowledged} Acknowledged`}
                        />
                      )}
                      {activeRem.open > 0 && (
                        <div
                          className="triage-seg seg-open"
                          style={{ width: `${(activeRem.open / totalRemTracked) * 100}%` }}
                          title={`${activeRem.open} Open`}
                        />
                      )}
                      {activeRem.suppressed > 0 && (
                        <div
                          className="triage-seg seg-suppressed"
                          style={{ width: `${(activeRem.suppressed / totalRemTracked) * 100}%` }}
                          title={`${activeRem.suppressed} Suppressed`}
                        />
                      )}
                    </div>
                  )}
                </div>
              </div>

              <div className="remediation-card-footer muted small">
                {selectedRemScanId !== 'all' ? (
                  <div className="remediation-footer-scan-row">
                    <span>Showing remediation data for selected repository.</span>
                    <a
                      href={activeRem.scanId && !String(activeRem.scanId).startsWith('repo-') ? `#/scans/${activeRem.scanId}` : `#/repos/${activeRem.repoId || selectedRemScanId}`}
                      className="remediation-scan-link"
                    >
                      View scan report →
                    </a>
                  </div>
                ) : (
                  'Triage findings in scan reports to assign status, suppress false positives, and track remediation progress.'
                )}
              </div>
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

          {data.websites && data.websites.length > 0 && (
            <section className="card">
              <div className="card-head">
                <div className="row" style={{ justifyContent: 'space-between', width: '100%' }}>
                  <h2 className="m-0">Monitored Websites</h2>
                  <a href="#/websites" className="small">View all websites &rarr;</a>
                </div>
              </div>
              <DataTable
                headers={['Target', 'Verification', 'Posture', 'Last status', 'Last scan', '']}
                rows={data.websites.map((w) => ({
                  id: w.id,
                  cells: [
                    <div key="target">
                      <strong>{w.name}</strong>
                      <div className="small muted">{w.targetUrl}</div>
                    </div>,
                    <span key="v" className={`badge ${w.isVerified ? 'sev-low' : 'sev-medium'}`}>
                      {w.isVerified ? 'Verified' : 'Unverified'}
                    </span>,
                    w.postureScore != null ? `${w.postureScore}/100` : '-',
                    w.lastStatus ? <StatusBadge key="s" status={w.lastStatus} /> : <span key="s" className="muted">Never scanned</span>,
                    ago(w.lastScanAt),
                    <a key="a" href="#/websites" className="btn btn-sm btn-subtle">
                      View
                    </a>,
                  ],
                }))}
                onRow={() => {
                  location.hash = '#/websites';
                }}
              />
            </section>
          )}

          <div className="grid cols-2">
            <section className="card">
              <h2>Recent scans</h2>
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
