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

function RepoSeverityBreakdown({ repositories, trend }) {
  const [sevFilter, setSevFilter] = useState('all');
  const [sortBy, setSortBy] = useState('total');
  const [viewMode, setViewMode] = useState('bars');

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
          <h2>{viewMode === 'bars' ? 'Repository vulnerabilities' : 'Vulnerability trend'}</h2>
          <span className="muted small">
            {viewMode === 'bars'
              ? 'Vertical bar comparison across scanned repositories'
              : 'Historical findings trend over consecutive scans'}
          </span>
        </div>
        {scannedRepos.length > 0 && (
          <div className="view-toggle-group" role="group" aria-label="Chart view mode">
            <button
              type="button"
              className={`view-toggle-btn ${viewMode === 'bars' ? 'active' : ''}`}
              onClick={() => setViewMode('bars')}
            >
              Bar chart
            </button>
            <button
              type="button"
              className={`view-toggle-btn ${viewMode === 'trend' ? 'active' : ''}`}
              onClick={() => setViewMode('trend')}
            >
              Trend line
            </button>
          </div>
        )}
      </div>

      {!scannedRepos.length ? (
        <div className="overview-chart-empty">
          <div className="empty-icon">📊</div>
          <h3>No scan data yet</h3>
          <p className="muted small">
            Run a scan on any repository to view vulnerability bar charts, severity distributions, and security trends.
          </p>
          <a className="btn primary" href="#/new-scan">
            Scan a repository
          </a>
        </div>
      ) : viewMode === 'trend' ? (
        trend && trend.length ? (
          <div className="trend-wrap">
            <TrendChart
              points={trend}
              series={[
                { key: 'total', cls: 'l-total', label: 'total' },
                { key: 'critical', cls: 'l-critical', label: 'critical' },
                { key: 'high', cls: 'l-high', label: 'high' },
              ]}
            />
            <div className="repo-chart-legend">
              <span className="legend-item">
                <span className="sev-dot" style={{ background: 'var(--brand)' }} /> Total
              </span>
              <span className="legend-item">
                <span className="sev-dot sev-dot-critical" /> Critical
              </span>
              <span className="legend-item">
                <span className="sev-dot sev-dot-high" /> High
              </span>
            </div>
          </div>
        ) : (
          <div className="empty">Run more scans to populate historical trends.</div>
        )
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
            <RepoSeverityBreakdown repositories={data.repositories} trend={data.trend} />

            <section className="card overview-remediation-card">
              <div className="card-head">
                <div>
                  <h2>Remediation progress</h2>
                  <span className="muted small">Triage and vulnerability resolution status</span>
                </div>
                <span className={`badge ${rem.fixRate > 0 ? 'st-completed' : 'st-unknown'}`}>
                  {rem.fixRate == null
                    ? 'No tracked issues'
                    : `${rem.fixRate}% resolved`}
                </span>
              </div>

              <div className="triage-stats-grid">
                <div className="triage-stat-item st-open">
                  <span className="triage-stat-num">{rem.open || 0}</span>
                  <span className="triage-stat-label">Open</span>
                </div>
                <div className="triage-stat-item st-ack">
                  <span className="triage-stat-num">{rem.acknowledged || 0}</span>
                  <span className="triage-stat-label">Acknowledged</span>
                </div>
                <div className="triage-stat-item st-fixed">
                  <span className="triage-stat-num">{rem.fixed || 0}</span>
                  <span className="triage-stat-label">Fixed</span>
                </div>
                <div className="triage-stat-item st-suppressed">
                  <span className="triage-stat-num">{rem.suppressed || 0}</span>
                  <span className="triage-stat-label">Suppressed</span>
                </div>
              </div>

              <div className="triage-progress-box">
                <div className="triage-progress-header">
                  <span className="muted small">Triage status distribution</span>
                  <span className="triage-total-badge">
                    {(rem.open || 0) + (rem.acknowledged || 0) + (rem.fixed || 0) + (rem.suppressed || 0)} tracked
                  </span>
                </div>
                <div className="triage-progress-track">
                  {(() => {
                    const totalTracked = (rem.open || 0) + (rem.acknowledged || 0) + (rem.fixed || 0) + (rem.suppressed || 0);
                    if (!totalTracked) {
                      return <div className="triage-bar-empty" />;
                    }
                    return (
                      <div className="triage-bar-segments">
                        {rem.fixed > 0 && (
                          <div
                            className="triage-seg seg-fixed"
                            style={{ width: `${(rem.fixed / totalTracked) * 100}%` }}
                            title={`${rem.fixed} Fixed`}
                          />
                        )}
                        {rem.acknowledged > 0 && (
                          <div
                            className="triage-seg seg-ack"
                            style={{ width: `${(rem.acknowledged / totalTracked) * 100}%` }}
                            title={`${rem.acknowledged} Acknowledged`}
                          />
                        )}
                        {rem.open > 0 && (
                          <div
                            className="triage-seg seg-open"
                            style={{ width: `${(rem.open / totalTracked) * 100}%` }}
                            title={`${rem.open} Open`}
                          />
                        )}
                        {rem.suppressed > 0 && (
                          <div
                            className="triage-seg seg-suppressed"
                            style={{ width: `${(rem.suppressed / totalTracked) * 100}%` }}
                            title={`${rem.suppressed} Suppressed`}
                          />
                        )}
                      </div>
                    );
                  })()}
                </div>
              </div>

              <div className="remediation-card-footer muted small">
                Triage findings in scan reports to assign status, suppress false positives, and track remediation progress.
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
