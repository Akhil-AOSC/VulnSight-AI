import React, { useEffect, useState } from 'react';
import { api, session, toast, fmtDate } from '../api.js';
import { PageHead, DataTable } from '../components/Common.jsx';

export function ReportsView() {
  const [repos, setRepos] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        setLoading(true);
        const [r, s] = await Promise.all([
          api.get(api.org('/repos')),
          api.get(api.org('/scans?limit=100')),
        ]);
        if (!mounted) return;
        setRepos(r);
        setScans(s);
      } catch (err) {
        toast(err.message || 'Failed to load reports', 'error');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, [session.orgId]);

  if (loading && !scans.length) return <p className="muted">Loading...</p>;

  const nameOf = (id) => (repos.find((r) => r.id === id) || {}).fullName || id;
  const done = scans.filter((s) => s.status === 'completed' && s.summary);

  if (!done.length) {
    return (
      <>
        <PageHead
          title="Reports and analytics"
          subtitle="Export results and compare scans over time"
        />
        <div className="card empty">Complete a scan to see reports.</div>
      </>
    );
  }

  const prevMap = new Map();
  const rowsWithDelta = [...done]
    .reverse()
    .map((s) => {
      const key = `${s.repoId}|${s.branch}`;
      const before = prevMap.get(key);
      prevMap.set(key, s);
      const curTotal = s.summary.total != null ? s.summary.total : s.summary.issues || 0;
      const prevTotal =
        before && before.summary
          ? before.summary.total != null
            ? before.summary.total
            : before.summary.issues || 0
          : null;
      const delta = prevTotal != null ? curTotal - prevTotal : null;
      return { s, delta };
    })
    .reverse();

  const fixed = done.reduce((a, s) => a + (s.summary.fixed || 0), 0);
  const added = done.reduce((a, s) => a + (s.summary.new || 0), 0);
  const byRepo = repos
    .map((r) => ({ r, last: done.find((s) => s.repoId === r.id) }))
    .filter((x) => x.last);

  function renderExportButtons(s) {
    return (
      <div className="row">
        {[
          ['csv', 'CSV', 'csv'],
          ['markdown', 'Report', 'md'],
          ['cyclonedx', 'SBOM', 'cdx.json'],
        ].map(([fmt, label, ext]) => (
          <button
            key={fmt}
            type="button"
            onClick={() =>
              api
                .download(
                  api.org(`/scans/${s.id}/report?format=${fmt}`),
                  `${nameOf(s.repoId).replace('/', '-')}-${s.id.slice(0, 8)}.${ext}`
                )
                .catch((err) => toast(err.message, 'error'))
            }
          >
            {label}
          </button>
        ))}
      </div>
    );
  }

  return (
    <>
      <PageHead
        title="Reports and analytics"
        subtitle="Export results and compare scans over time"
      />

      <section className="card">
        <h2>Scan history and comparison</h2>
        <DataTable
          headers={[
            'Repository',
            'Branch',
            'Date',
            'Posture',
            { label: 'Critical', num: true },
            { label: 'High', num: true },
            { label: 'Medium', num: true },
            { label: 'Low', num: true },
            { label: 'Change', num: true },
            'Export',
          ]}
          rows={rowsWithDelta.map(({ s, delta }) => {
            const bySev = s.summary.bySeverity || {
              critical: s.summary.critical || 0,
              high: s.summary.high || 0,
              medium: s.summary.medium || 0,
              low: s.summary.low || 0,
            };
            return {
              id: s.id,
              cells: [
                <a href={`#/scans/${s.id}`}>{nameOf(s.repoId)}</a>,
                s.branch,
                fmtDate(s.finishedAt || s.createdAt),
                s.summary.posture
                  ? `${s.summary.posture.grade} (${s.summary.posture.score})`
                  : '-',
                bySev.critical,
                bySev.high,
                bySev.medium,
                bySev.low,
                delta == null ? '-' : delta === 0 ? '0' : delta > 0 ? `+${delta}` : String(delta),
                renderExportButtons(s),
              ],
            };
          })}
        />
      </section>

      <div className="grid cols-2">
        <section className="card">
          <h2>Remediation metrics</h2>
          <dl className="kv">
            <dt>Scans completed</dt>
            <dd>{done.length}</dd>
            <dt>Findings introduced</dt>
            <dd>{added}</dd>
            <dt>Findings fixed</dt>
            <dd>{fixed}</dd>
          </dl>
        </section>

        <section className="card">
          <h2>Compliance-oriented summary</h2>
          <p className="muted small">
            Evidence for dependency and secret hygiene controls (for example SOC 2 CC7.1, ISO 27001
            A.8.8, PCI DSS 6.3). This is supporting evidence, not a compliance certification.
          </p>
          <DataTable
            headers={['Repository', 'Open critical/high', 'Secrets found']}
            rows={byRepo.map(({ r, last }) => {
              const bySev = last.summary.bySeverity || {
                critical: last.summary.critical || 0,
                high: last.summary.high || 0,
              };
              const byCat = last.summary.byCategory || {};
              return {
                id: r.id,
                cells: [r.fullName, (bySev.critical || 0) + (bySev.high || 0), byCat.secret || 0],
              };
            })}
            empty="-"
          />
        </section>
      </div>
    </>
  );
}
