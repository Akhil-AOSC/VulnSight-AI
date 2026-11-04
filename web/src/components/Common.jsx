import React, { useEffect, useState } from 'react';
import { pad, subscribeToasts } from '../api.js';
import { Markdown } from './Markdown.jsx';

export function SevBadge({ severity }) {
  return <span className={`badge sev-${severity || 'unknown'}`}>{severity || 'unknown'}</span>;
}

export function StatusBadge({ status }) {
  return <span className={`badge st-${status || 'unknown'}`}>{status || 'unknown'}</span>;
}

export function RoleBadge({ role }) {
  const r = (role || 'viewer').toLowerCase();
  return <span className={`badge role-badge role-${r}`}>{r}</span>;
}

export function PageHead({ title, subtitle, children }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {subtitle && <div className="muted">{subtitle}</div>}
      </div>
      {children && <div className="row">{children}</div>}
    </div>
  );
}

export function StatCard({ className = '', num, label }) {
  return (
    <div className={`card stat ${className}`.trim()}>
      <div className="num">{pad(num)}</div>
      <div className="label">{label}</div>
    </div>
  );
}

const SEV_LEVELS = ['critical', 'high', 'medium', 'low'];
const SEV_SHORT = { critical: 'C', high: 'H', medium: 'M', low: 'L' };

export function SeverityBar({ counts }) {
  if (!counts) return <span>-</span>;
  const total = SEV_LEVELS.reduce((a, s) => a + (counts[s] || 0), 0);
  if (!total) return <span className="muted">0 findings</span>;
  const label = SEV_LEVELS.map((s) => `${counts[s] || 0} ${s}`).join(', ');
  return (
    <div className="sev-bar-inline" role="img" aria-label={label}>
      {SEV_LEVELS.map((s) => {
        const val = counts[s] || 0;
        if (!val) return null;
        return (
          <span key={s} className={`sev-chip sev-chip-${s}`}>
            <span className={`sev-dot sev-dot-${s}`} />
            {val}{SEV_SHORT[s]}
          </span>
        );
      })}
    </div>
  );
}

export function TrendChart({ points, series }) {
  const W = 600;
  const H = 180;
  const P = { l: 34, r: 8, t: 8, b: 20 };
  const max = Math.max(1, ...points.flatMap((p) => series.map((s) => p[s.key] || 0)));
  const x = (i) => P.l + (points.length === 1 ? (W - P.l - P.r) / 2 : (i * (W - P.l - P.r)) / (points.length - 1));
  const y = (v) => H - P.b - (v / max) * (H - P.t - P.b);

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="chart"
      role="img"
      aria-label={`Trend of ${series.map((s) => s.label).join(', ')} over the last ${points.length} scans`}
    >
      {[0, 0.5, 1].map((f) => (
        <React.Fragment key={f}>
          <line x1={P.l} x2={W - P.r} y1={y(max * f)} y2={y(max * f)} className="axis" />
          <text x={P.l - 6} y={y(max * f) + 3} textAnchor="end">
            {Math.round(max * f)}
          </text>
        </React.Fragment>
      ))}
      {series.map((s) => {
        const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[s.key] || 0).toFixed(1)}`).join(' ');
        return (
          <React.Fragment key={s.key}>
            <path d={d} fill="none" strokeWidth="2" className={s.cls} strokeLinejoin="round" />
            {points.map((p, i) => (
              <circle
                key={i}
                cx={x(i)}
                cy={y(p[s.key] || 0)}
                r="2.5"
                className={s.cls}
                fill="currentColor"
                stroke="none"
              />
            ))}
          </React.Fragment>
        );
      })}
    </svg>
  );
}

const AI_TITLES = {
  explanation: 'AI explanation',
  remediation: 'Suggested fix',
  summary: 'AI summary',
  answer: 'AI answer',
};

export function AiAnswer({ result, loading, loadingLabel = 'Writing an answer...' }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    if (!result || !result.text) return;
    try {
      await navigator.clipboard.writeText(result.text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* ignore */
    }
  }

  if (loading) {
    return (
      <div className="ai-box ai-answer" role="status">
        <div className="ai-loading">{loadingLabel}</div>
      </div>
    );
  }
  if (!result) return null;

  const kind = (result.meta && result.meta.kind) || 'answer';
  const title = AI_TITLES[kind] || 'AI answer';
  const provider = (result.meta && result.meta.provider) || 'AI';
  const impact = result.upgradeImpact;

  return (
    <div className="ai-box ai-answer">
      <div className="ai-answer-head">
        <div className="ai-head-title">
          <h3 className="m-0">{title}</h3>
          <span className="ai-badge">AI Powered</span>
        </div>
        <div className="row">
          <span className="badge ai-label">{provider}</span>
          <button type="button" className="link" onClick={handleCopy}>
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>
      <Markdown text={result.text} />
      {impact && (
        <div className="ai-callout">
          <strong>
            Upgrade impact: {impact.kind} {impact.from} → {impact.to}
          </strong>
          <p>{impact.note}</p>
        </div>
      )}
      {result.warnings && result.warnings.length > 0 && (
        <div className="warning">{result.warnings.join(' ')}</div>
      )}
      <p className="small muted ai-disclaimer">
        AI can be wrong. The scanner finding above is the source of truth.
      </p>
    </div>
  );
}

export function AiBriefingCard({ ai }) {
  if (!ai) return null;
  const risk = ai.riskLevel || 'Medium';
  return (
    <section className="card ai-card">
      <div className="card-head">
        <div className="ai-head-title">
          <h2 className="m-0">AI Security Summary</h2>
          <span className="ai-badge">AI Powered</span>
        </div>
        <span className={`ai-risk-tag ai-risk-${risk}`}>Risk: {risk}</span>
      </div>
      {ai.executiveSummary && <p className="ai-summary">{ai.executiveSummary}</p>}
      {ai.impactAnalysis && (
        <div className="ai-impact-box">
          <strong>Attack Vector &amp; Impact Analysis:</strong>
          <p>{ai.impactAnalysis}</p>
        </div>
      )}
      {Array.isArray(ai.keyRecommendations) && ai.keyRecommendations.length > 0 && (
        <div className="ai-rec-box">
          <strong>AI Prioritized Remediation Guidance:</strong>
          <ul className="ai-recs">
            {ai.keyRecommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

export function DataTable({ headers, rows, empty = 'Nothing here yet.', onRow }) {
  if (!rows || !rows.length) {
    return <div className="empty">{empty}</div>;
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {headers.map((h, i) => {
              const isObj = typeof h === 'object' && h !== null;
              return (
                <th key={i} scope="col" className={isObj && h.num ? 'num' : undefined}>
                  {isObj ? h.label : h}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, rowIdx) => (
            <tr
              key={r.id || rowIdx}
              className={onRow ? 'clickable' : undefined}
              tabIndex={onRow ? 0 : undefined}
              onClick={
                onRow
                  ? (e) => {
                      if (!e.target.closest('a,button,select,input')) onRow(r);
                    }
                  : undefined
              }
              onKeyDown={
                onRow
                  ? (e) => {
                      if (e.key === 'Enter' && !e.target.closest('a,button,select,input')) onRow(r);
                    }
                  : undefined
              }
            >
              {r.cells.map((cell, cellIdx) => {
                const h = headers[cellIdx];
                const isNum = typeof h === 'object' && h !== null && h.num;
                return (
                  <td key={cellIdx} className={isNum ? 'num' : undefined}>
                    {cell}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ToastContainer() {
  const [items, setItems] = useState([]);

  useEffect(() => {
    return subscribeToasts((item) => {
      setItems((prev) => [...prev, item]);
      const delay = item.kind === 'error' ? 7000 : 3500;
      setTimeout(() => {
        setItems((prev) => prev.filter((x) => x.id !== item.id));
      }, delay);
    });
  }, []);

  return (
    <div id="toasts" className="toasts" role="status" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`}>
          {t.message}
        </div>
      ))}
    </div>
  );
}


export function Skeleton({ width = '100%', height = '1rem', className = '', style = {}, radius = '4px' }) {
  return (
    <span
      className={`skeleton-loader ${className}`.trim()}
      style={{
        display: 'inline-block',
        width,
        height,
        borderRadius: radius,
        ...style,
      }}
      aria-hidden="true"
    />
  );
}

export function ScanSkeletonLoader({ cards = 5, hasTabs = true, rows = 5 }) {
  return (
    <div className="skeleton-container fade-in">
      <div className="skeleton-head">
        <Skeleton width="240px" height="1.8rem" radius="6px" />
        <Skeleton width="360px" height="1rem" style={{ marginTop: '0.4rem' }} radius="4px" />
      </div>

      <div className="skeleton-stats-grid">
        {Array.from({ length: cards }).map((_, i) => (
          <div key={i} className="card skeleton-stat-card">
            <Skeleton width="54px" height="2rem" style={{ marginBottom: '0.5rem' }} radius="4px" />
            <Skeleton width="75%" height="0.85rem" radius="4px" />
          </div>
        ))}
      </div>

      {hasTabs && (
        <div className="skeleton-tab-nav">
          {[130, 160, 100, 170, 140, 110].map((w, i) => (
            <Skeleton key={i} width={`${w}px`} height="2.2rem" radius="6px" />
          ))}
        </div>
      )}

      <div className="card skeleton-table-card">
        <div className="skeleton-table-header">
          <Skeleton width="180px" height="1.25rem" radius="4px" />
          <Skeleton width="220px" height="2rem" radius="6px" />
        </div>
        <div className="skeleton-table-rows">
          {Array.from({ length: rows }).map((_, i) => (
            <div key={i} className="skeleton-table-row">
              <Skeleton width="60px" height="1.2rem" radius="10px" />
              <Skeleton width="45%" height="1rem" radius="4px" />
              <Skeleton width="75px" height="1rem" radius="4px" />
              <Skeleton width="18%" height="1rem" radius="4px" />
              <Skeleton width="55px" height="1.5rem" radius="4px" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
