import React, { useEffect, useState, useCallback } from 'react';
import { api, session, hasPermission, toast, fmtDate, pad } from '../api.js';
import {
  PageHead,
  SevBadge,
  StatusBadge,
  AiBriefingCard,
  AiAnswer,
  DataTable,
} from '../components/Common.jsx';

function FindingDetail({ finding: f, repo, onReload }) {
  const [status, setStatus] = useState(f.status || 'open');
  const [note, setNote] = useState(f.note || '');
  const [saveBusy, setSaveBusy] = useState(false);
  const [history, setHistory] = useState(null);
  const [aiResult, setAiResult] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiKind, setAiKind] = useState(null);

  const canWriteFindings = hasPermission(session.me, session.orgId, 'findings:write');
  const canUseAi = hasPermission(session.me, session.orgId, 'ai:use');

  const ids = [
    f.identifiers && f.identifiers.primary,
    ...((f.identifiers && f.identifiers.aliases) || []),
    ...((f.identifiers && f.identifiers.cwe) || []),
  ].filter(Boolean);

  async function handleSaveTriage() {
    setSaveBusy(true);
    try {
      await api.patch(api.org(`/repos/${repo.id}/findings/${f.id}`), { status, note });
      toast('Finding updated');
      onReload();
    } catch (err) {
      toast(err.message || 'Failed to update finding', 'error');
    } finally {
      setSaveBusy(false);
    }
  }

  async function handleShowHistory() {
    try {
      const rows = await api.get(api.org(`/repos/${repo.id}/findings/${f.id}/history`));
      setHistory(rows);
    } catch (err) {
      toast(err.message || 'Failed to load review history', 'error');
    }
  }

  async function handleAiAction(path, kind) {
    setAiLoading(true);
    setAiKind(kind);
    setAiResult(null);
    try {
      const res = await api.post(api.org(path));
      setAiResult(res);
    } catch (err) {
      toast(err.message || 'AI request failed', 'error');
    } finally {
      setAiLoading(false);
    }
  }

  return (
    <div className="detail">
      <div>
        <h3>Details</h3>
        {f.description && <p>{f.description}</p>}
        <dl className="kv">
          {f.aiExplanation && (
            <>
              <dt>AI Explanation</dt>
              <dd className="ai-explanation">{f.aiExplanation}</dd>
            </>
          )}
          <dt>Identifiers</dt>
          <dd>{ids.join(', ') || '-'}</dd>
          <dt>Found by</dt>
          <dd>
            {(f.sources || [f.scanner])
              .filter(Boolean)
              .map((s) => `${s.name}${s.version ? ` ${s.version}` : ''}`)
              .join(', ')}
          </dd>
          {f.cvssScore != null && (
            <>
              <dt>CVSS</dt>
              <dd>{f.cvssScore}</dd>
            </>
          )}
          {f.location && f.location.file && (
            <>
              <dt>File</dt>
              <dd className="mono">
                {f.location.file}
                {f.location.line ? `:${f.location.line}` : ''}
              </dd>
            </>
          )}
          {f.location && f.location.package && (
            <>
              <dt>Package</dt>
              <dd>
                {f.location.package}@{f.location.version} ({f.location.ecosystem},{' '}
                {f.location.direct === true
                  ? 'direct'
                  : f.location.direct === false
                  ? 'transitive'
                  : 'unknown'}
                )
              </dd>
            </>
          )}
          {f.remediation && f.remediation.fixedIn && (
            <>
              <dt>Fixed in</dt>
              <dd>{f.remediation.fixedIn}</dd>
            </>
          )}
          {f.remediation && f.remediation.advice && (
            <>
              <dt>Advice</dt>
              <dd>{f.remediation.advice}</dd>
            </>
          )}
          {f.url && /^https:\/\//.test(f.url) && (
            <>
              <dt>Advisory</dt>
              <dd>
                <a href={f.url} target="_blank" rel="noopener noreferrer">
                  {f.url}
                </a>
              </dd>
            </>
          )}
        </dl>

        {f.location && Array.isArray(f.location.usages) && f.location.usages.length > 0 && (
          <>
            <h3>Used in your code</h3>
            <ul className="usage-list">
              {f.location.usages.map((u, i) => (
                <li key={`${u.file}:${u.line}:${i}`}>
                  <span className="mono small">
                    {u.file}:{u.line}
                  </span>
                  {u.snippet ? <pre className="evidence">{u.snippet}</pre> : null}
                </li>
              ))}
            </ul>
          </>
        )}

        {f.evidence && !(f.location && f.location.usages && f.location.usages.length) && (
          <>
            <h3>Evidence</h3>
            <pre className="evidence">{f.evidence}</pre>
          </>
        )}

        {f.location && f.location.paths && f.location.paths.length > 0 && (
          <>
            <h3>Dependency path</h3>
            {f.location.paths.slice(0, 3).map((p, i) => (
              <div key={i} className="mono small">
                {p.join('  >  ')}
              </div>
            ))}
          </>
        )}
      </div>

      <div>
        <div className="row triage-head">
          <h3 className="m-0">Triage</h3>
          {canUseAi && (
            <div className="row">
              <button
                type="button"
                aria-pressed={aiKind === 'explanation'}
                disabled={aiLoading}
                onClick={() => handleAiAction(`/findings/${f.rowId}/explain`, 'explanation')}
              >
                Explain with AI
              </button>
              <button
                type="button"
                aria-pressed={aiKind === 'remediation'}
                disabled={aiLoading}
                onClick={() => handleAiAction(`/findings/${f.rowId}/fix`, 'remediation')}
              >
                Suggest a fix
              </button>
            </div>
          )}
        </div>
        {canWriteFindings ? (
          <>
            <div className="row">
              <select
                aria-label="Status"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
              >
                {['open', 'acknowledged', 'suppressed', 'fixed'].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <textarea
              aria-label="Note"
              placeholder="Note (required to suppress)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <div className="row">
              <button
                type="button"
                className="primary"
                onClick={handleSaveTriage}
                disabled={saveBusy}
              >
                Save
              </button>
            </div>
          </>
        ) : (
          <p className="muted">Status: {f.status}</p>
        )}
        <button className="link" type="button" onClick={handleShowHistory}>
          Show review history
        </button>
        {history && (
          <div className="small muted">
            {history.length ? (
              history.map((r, i) => (
                <div key={i}>
                  {fmtDate(r.createdAt)} - {r.user || 'system'}: {r.action}
                  {r.detail ? ` (${r.detail})` : ''}
                </div>
              ))
            ) : (
              'No changes yet.'
            )}
          </div>
        )}
      </div>

      <AiAnswer
        result={aiResult}
        loading={aiLoading}
        loadingLabel={
          aiKind === 'remediation' ? 'Writing a suggested fix...' : 'Explaining this finding...'
        }
      />
    </div>
  );
}

export function ScanView({ scanId }) {
  const [scan, setScan] = useState(null);
  const [repo, setRepo] = useState(null);
  const [loading, setLoading] = useState(true);

  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);

  const [findingsData, setFindingsData] = useState({ items: [], total: 0, page: 1, pageSize: 25 });
  const [expandedRows, setExpandedRows] = useState(new Set());

  const canScan = hasPermission(session.me, session.orgId, 'scans:run');

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedQ(q.trim());
      setPage(1);
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  const loadScanAndRepo = useCallback(async () => {
    try {
      setLoading(true);
      const s = await api.get(api.org(`/scans/${scanId}`));
      const r = await api.get(api.org(`/repos/${s.repoId}`));
      setScan(s);
      setRepo(r);
    } catch (err) {
      toast(err.message || 'Failed to load scan', 'error');
    } finally {
      setLoading(false);
    }
  }, [scanId, session.orgId]);

  useEffect(() => {
    loadScanAndRepo();
  }, [loadScanAndRepo]);

  useEffect(() => {
    if (!scan || (scan.status !== 'queued' && scan.status !== 'running')) return;
    const timer = setInterval(async () => {
      const s = await api.get(api.org(`/scans/${scanId}`)).catch(() => null);
      if (s && s.status !== scan.status) {
        setScan(s);
      }
    }, 2500);
    return () => clearInterval(timer);
  }, [scan, scanId]);

  const loadFindings = useCallback(async () => {
    if (!scan || scan.status === 'queued' || scan.status === 'running' || scan.status === 'cancelled') {
      return;
    }
    try {
      const params = new URLSearchParams({ page: String(page), pageSize: '25' });
      if (severity) params.set('severity', severity);
      if (category) params.set('category', category);
      if (status) params.set('status', status);
      if (debouncedQ) params.set('q', debouncedQ);
      const res = await api.get(api.org(`/scans/${scanId}/findings?${params}`));
      setFindingsData(res);
    } catch (err) {
      toast(err.message || 'Failed to load findings', 'error');
    }
  }, [scan, scanId, page, severity, category, status, debouncedQ]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  async function handleCancelScan() {
    try {
      const updated = await api.post(api.org(`/scans/${scanId}/cancel`));
      setScan(updated);
    } catch (err) {
      toast(err.message || 'Failed to cancel scan', 'error');
    }
  }

  function toggleExpand(id) {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  if (loading && !scan) return <p className="muted">Loading...</p>;
  if (!scan || !repo) return null;

  const sum = scan.summary;
  const bySev = sum
    ? sum.bySeverity || {
        critical: sum.critical || 0,
        high: sum.high || 0,
        medium: sum.medium || 0,
        low: sum.low || 0,
      }
    : { critical: 0, high: 0, medium: 0, low: 0 };
  const totalIssues = sum ? (sum.total != null ? sum.total : sum.issues || 0) : 0;
  const depsText = sum && sum.dependencies ? `${sum.dependencies} dependencies tested` : 'Total open issues';

  const pages = Math.max(1, Math.ceil((findingsData.total || 0) / (findingsData.pageSize || 25)));
  const planSteps = Array.isArray(scan.projects)
    ? scan.projects.flatMap((p) => (p.upgradePlan || []).map((step) => ({ ...step, project: p })))
    : [];

  return (
    <>
      <PageHead
        title={`Scan of ${repo.fullName}`}
        subtitle={`${scan.branch}${scan.commit ? ` @ ${scan.commit.slice(0, 8)}` : ''} - ${scan.trigger} - ${fmtDate(scan.createdAt)}`}
      >
        {scan.source === 'mongodb' && (
          <span className="db-indicator db-connected" title="Saved in cloud history">
            Cloud Saved
          </span>
        )}
        <a className="btn" href={`#/repos/${repo.id}`}>
          Repository
        </a>
        <StatusBadge status={scan.status} />
      </PageHead>

      {(scan.status === 'queued' || scan.status === 'running') && (
        <div className="card empty">
          This scan is {scan.status}. The page refreshes automatically.
          {scan.status === 'queued' && canScan && (
            <p>
              <button type="button" onClick={handleCancelScan}>
                Cancel scan
              </button>
            </p>
          )}
        </div>
      )}

      {(scan.status === 'failed' || scan.status === 'cancelled') && (
        <div className="card">
          <p>{scan.error || `Scan ${scan.status}.`}</p>
        </div>
      )}

      {scan.status !== 'queued' && scan.status !== 'running' && scan.status !== 'cancelled' && (
        <>
          {scan.ai && <AiBriefingCard ai={scan.ai} />}

          {sum && (
            <div className="grid stats">
              <div className="card stat">
                <div className="num">{totalIssues}</div>
                <div className="label">{depsText}</div>
              </div>
              {['critical', 'high', 'medium', 'low'].map((s) => (
                <div key={s} className={`card stat ${s}`}>
                  <div className="num">{bySev[s] || 0}</div>
                  <div className="label">{s}</div>
                </div>
              ))}
              {sum.posture && (
                <div className="card stat">
                  <div className="num">{sum.posture.grade}</div>
                  <div className="label">Posture {sum.posture.score}/100</div>
                </div>
              )}
            </div>
          )}

          {Array.isArray(scan.warnings) && scan.warnings.length > 0 && (
            <div className="warnings">
              {scan.warnings.map((w, i) => (
                <div key={i} className="warning">
                  {w}
                </div>
              ))}
            </div>
          )}

          {Array.isArray(scan.projects) && scan.projects.length > 0 && (
            <div className="grid cols-2">
              <section className="card">
                <h2>Projects</h2>
                <ul className="projects-list">
                  {scan.projects.map((p, i) => {
                    const pName = p.projectName || p.name || p.file;
                    const pMeta = [
                      p.packageManager || p.type,
                      p.file,
                      `${p.dependencyCount || (p.dependencies ? p.dependencies.length : 0)} dependencies`,
                    ]
                      .filter(Boolean)
                      .join(' · ');
                    const pSum = p.summary || {};
                    const counts =
                      ['critical', 'high', 'medium', 'low']
                        .filter((l) => pSum[l] > 0)
                        .map((l) => `${pSum[l]} ${l}`)
                        .join(', ') || 'No issues';
                    return (
                      <li key={i}>
                        <div>
                          <div className="project-name">{pName}</div>
                          <div className="project-meta muted small">{pMeta}</div>
                        </div>
                        <span className="small muted">{counts}</span>
                      </li>
                    );
                  })}
                </ul>
              </section>

              <section className="card">
                <h2>Fix plan (One upgrade per vulnerable package)</h2>
                <ul className="plan-list">
                  {planSteps.length ? (
                    planSteps.map((step, i) => {
                      const label = `${step.package}@${step.version}`;
                      if (!step.target) {
                        return (
                          <li key={i}>
                            <span className="mono">{label}</span>
                            <span className="muted small">
                              No fix yet for {step.unfixed} issue(s)
                            </span>
                          </li>
                        );
                      }
                      return (
                        <li key={i}>
                          <span className="mono">
                            {label} → <strong className="plan-target">{step.target}</strong>
                          </span>
                          <span className="muted small">Fixes {step.fixes} issue(s)</span>
                        </li>
                      );
                    })
                  ) : (
                    <li className="muted small">Nothing to upgrade.</li>
                  )}
                </ul>
              </section>
            </div>
          )}

          {Array.isArray(scan.scanners) && scan.scanners.length > 0 && (
            <section className="card">
              <h2>Scanners</h2>
              <DataTable
                headers={['Scanner', 'Status', 'Version', 'Findings', 'Time', 'Message']}
                rows={scan.scanners.map((s, i) => ({
                  id: `${s.scanner}-${i}`,
                  cells: [
                    ({ osv: 'Dependencies (OSV)', semgrep: 'Code (Opengrep)', gitleaks: 'Secrets (Gitleaks)', trivy: 'Trivy', checkov: 'Checkov' }[s.scanner] || s.scanner),
                    <StatusBadge status={s.status} />,
                    s.version || '-',
                    pad(s.findingCount),
                    `${s.durationMs} ms`,
                    s.error || '',
                  ],
                }))}
              />
            </section>
          )}

          <section className="card">
            <div className="row">
              <h2 className="grow">Findings</h2>
              <div className="row">
                {[
                  ['csv', 'CSV', 'csv'],
                  ['markdown', 'Markdown', 'md'],
                  ['cyclonedx', 'SBOM (CycloneDX)', 'cdx.json'],
                  ['json', 'JSON', 'json'],
                ].map(([fmt, label, ext]) => (
                  <button
                    key={fmt}
                    type="button"
                    onClick={() =>
                      api
                        .download(
                          api.org(`/scans/${scanId}/report?format=${fmt}`),
                          `${repo.fullName.replace('/', '-')}-${scanId.slice(0, 8)}.${ext}`
                        )
                        .catch((err) => toast(err.message, 'error'))
                    }
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="row">
              <input
                type="search"
                placeholder="Search title, CVE, package, file"
                size={30}
                aria-label="Search findings"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
              <select
                aria-label="Severity"
                value={severity}
                onChange={(e) => {
                  setSeverity(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                aria-label="Category"
                value={category}
                onChange={(e) => {
                  setCategory(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">All types</option>
                <option value="sca">Dependencies</option>
                <option value="sast">Code</option>
                <option value="secret">Secrets</option>
                <option value="container">Containers</option>
                <option value="iac">Infrastructure</option>
              </select>
              <select
                aria-label="Status"
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">Any status</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="suppressed">Suppressed</option>
                <option value="fixed">Fixed</option>
              </select>
            </div>

            {!findingsData.items.length ? (
              <div className="empty">No findings match.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Severity</th>
                      <th scope="col">Finding</th>
                      <th scope="col">Type</th>
                      <th scope="col">Location</th>
                      <th scope="col">Fix</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findingsData.items.map((f) => {
                      const rowKey = f.rowId || f.id;
                      const isOpen = expandedRows.has(rowKey);
                      const typeLabel = {
                        sca: 'Dependencies',
                        sast: 'Code',
                        secret: 'Secrets',
                        container: 'Containers',
                        iac: 'Infrastructure',
                      }[f.category] || f.category;
                      const where = f.location.package
                        ? `${f.location.package}@${f.location.version}`
                        : `${f.location.file || ''}${f.location.line ? `:${f.location.line}` : ''}`;
                      return (
                        <React.Fragment key={rowKey}>
                          <tr>
                            <td>
                              <SevBadge severity={f.severity} />
                            </td>
                            <td>
                              <button
                                className="link"
                                type="button"
                                aria-expanded={String(isOpen)}
                                onClick={() => toggleExpand(rowKey)}
                              >
                                {f.title}
                              </button>
                            </td>
                            <td>{typeLabel}</td>
                            <td className="mono">{where}</td>
                            <td>
                              {f.remediation && f.remediation.fixedIn
                                ? `Upgrade to ${f.remediation.fixedIn}`
                                : f.remediation && f.remediation.advice
                                ? 'See details'
                                : '-'}
                            </td>
                            <td>
                              <StatusBadge status={f.status} />
                            </td>
                          </tr>
                          {isOpen && (
                            <tr>
                              <td colSpan={6}>
                                <FindingDetail finding={f} repo={repo} onReload={loadFindings} />
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            <div className="pager">
              <span className="muted">
                {findingsData.total} finding(s) - page {findingsData.page} of {pages}
              </span>
              <button
                type="button"
                disabled={findingsData.page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <button
                type="button"
                disabled={findingsData.page >= pages}
                onClick={() => setPage((p) => Math.min(pages, p + 1))}
              >
                Next
              </button>
            </div>
          </section>
        </>
      )}
    </>
  );
}
