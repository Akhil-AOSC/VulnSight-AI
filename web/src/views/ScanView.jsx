import React, { useEffect, useState, useCallback } from 'react';
import { api, session, hasPermission, toast, fmtDate, pad } from '../api.js';
import {
  PageHead,
  SevBadge,
  StatusBadge,
  AiBriefingCard,
  AiAnswer,
  DataTable,
  Skeleton,
  ScanSkeletonLoader,
} from '../components/Common.jsx';
import { ExportPreviewModal } from '../components/ExportPreviewModal.jsx';

const GRADE_LABELS = {
  A: 'Clean',
  B: 'Good',
  C: 'Fair',
  D: 'Poor',
  F: 'Critical Risk',
};

function FindingDetail({ finding: f, repo, onReload, onClose }) {
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
      <div className="detail-banner">
        <div className="detail-banner-info">
          <span className="detail-tag">Finding Details</span>
          <span className="muted small">Vulnerability analysis, code location, and triage state</span>
        </div>
        {onClose && (
          <button
            type="button"
            className="btn-collapse"
            onClick={onClose}
            title="Collapse this details view"
          >
            <span>▲ Collapse</span>
          </button>
        )}
      </div>

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

      <div className="triage-pane">
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
          <div className="triage-form">
            <div className="triage-field">
              <label htmlFor={`status-${f.id || f.rowId}`} className="triage-label">
                Triage Status
              </label>
              <select
                id={`status-${f.id || f.rowId}`}
                aria-label="Status"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="triage-select"
              >
                {['open', 'acknowledged', 'suppressed', 'fixed'].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div className="triage-field">
              <label htmlFor={`note-${f.id || f.rowId}`} className="triage-label">
                Triage Note
              </label>
              <textarea
                id={`note-${f.id || f.rowId}`}
                aria-label="Note"
                placeholder="Note (required to suppress)"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                className="triage-textarea"
                rows={3}
              />
            </div>
            <div className="triage-actions">
              <button
                type="button"
                className="primary triage-save-btn"
                onClick={handleSaveTriage}
                disabled={saveBusy}
              >
                {saveBusy ? 'Saving...' : 'Save'}
              </button>
              <button className="link triage-history-btn" type="button" onClick={handleShowHistory}>
                Show review history
              </button>
            </div>
          </div>
        ) : (
          <p className="muted">Status: {f.status}</p>
        )}
        {history && (
          <div className="triage-history-box small muted">
            {history.length ? (
              history.map((r, i) => (
                <div key={i} className="history-entry">
                  <span className="history-date">{fmtDate(r.createdAt)}</span> - <strong>{r.user || 'system'}</strong>: {r.action}
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

      {onClose && (
        <div className="detail-footer">
          <button
            type="button"
            className="btn-collapse"
            onClick={onClose}
            title="Collapse finding details"
          >
            <span>▲ Collapse details</span>
          </button>
        </div>
      )}
    </div>
  );
}

function generateRemediationPrompt({ repo, scan, findings, severityFilter = 'all' }) {
  const bySeverity = { critical: [], high: [], medium: [], low: [] };
  (findings || []).forEach((f) => {
    const s = (f.severity || 'low').toLowerCase();
    if (bySeverity[s]) bySeverity[s].push(f);
    else bySeverity.low.push(f);
  });

  const planSteps = Array.isArray(scan.projects)
    ? scan.projects.flatMap((p) => (p.upgradePlan || []).map((step) => ({ ...step, project: p })))
    : [];

  const pkgManager = scan.projects?.[0]?.packageManager || scan.projects?.[0]?.type || 'npm';

  let prompt = '';

  if (severityFilter === 'all') {
    prompt += `# 🛡️ Complete Security Remediation Plan for ${repo.fullName}\n`;
    prompt += `**Repository**: ${repo.fullName} (branch: \`${scan.branch}\`)\n`;
    prompt += `**Total Vulnerabilities Identified**: ${findings.length}\n`;
    prompt += `**Severity Breakdown**: ${bySeverity.critical.length} Critical | ${bySeverity.high.length} High | ${bySeverity.medium.length} Medium | ${bySeverity.low.length} Low\n\n`;

    prompt += `## 🎯 Objective:\n`;
    prompt += `Act as an expert DevSecOps and Application Security Engineer. You are tasked with resolving all ${findings.length} security vulnerabilities listed below in a single, safe, and backwards-compatible remediation pass.\n\n`;

    if (planSteps.length > 0) {
      prompt += `## 📦 Step 1: Package Upgrades (${pkgManager})\n`;
      prompt += `Execute the following package upgrades in terminal to resolve dependency advisories:\n\n\`\`\`bash\n`;
      if (pkgManager === 'npm') {
        const upgradeArgs = planSteps
          .filter((s) => s.target)
          .map((s) => `${s.package}@${s.target}`)
          .join(' ');
        prompt += `npm install ${upgradeArgs}\n`;
      } else if (pkgManager === 'yarn') {
        const upgradeArgs = planSteps
          .filter((s) => s.target)
          .map((s) => `${s.package}@${s.target}`)
          .join(' ');
        prompt += `yarn upgrade ${upgradeArgs}\n`;
      } else if (pkgManager === 'pip' || pkgManager === 'requirements.txt') {
        planSteps.filter((s) => s.target).forEach((s) => {
          prompt += `pip install --upgrade ${s.package}==${s.target}\n`;
        });
      } else {
        planSteps.filter((s) => s.target).forEach((s) => {
          prompt += `# Upgrade ${s.package} to ${s.target}\n`;
        });
      }
      prompt += `\`\`\`\n\n`;
    }

    if (bySeverity.critical.length > 0) {
      prompt += `## 🚨 Step 2: Critical Severity Remediation (${bySeverity.critical.length} issues - Urgent P0)\n`;
      bySeverity.critical.forEach((f, idx) => {
        const id = f.identifiers?.primary || f.id;
        const loc = f.location?.package ? `${f.location.package}@${f.location.version || ''}` : `${f.location?.file || ''}:${f.location?.line || ''}`;
        const fix = f.remediation?.target ? `Upgrade ${f.location?.package || 'component'} to >= ${f.remediation.target}` : 'Inspect and patch';
        prompt += `${idx + 1}. **[${id}]** ${f.title}\n`;
        prompt += `   - Location: \`${loc}\`\n`;
        prompt += `   - Type: \`${f.category || 'sca'}\`\n`;
        prompt += `   - Fix: ${fix}\n\n`;
      });
    }

    if (bySeverity.high.length > 0) {
      prompt += `## ⚠️ Step 3: High Severity Remediation (${bySeverity.high.length} issues - P1)\n`;
      bySeverity.high.forEach((f, idx) => {
        const id = f.identifiers?.primary || f.id;
        const loc = f.location?.package ? `${f.location.package}@${f.location.version || ''}` : `${f.location?.file || ''}:${f.location?.line || ''}`;
        const fix = f.remediation?.target ? `Upgrade to >= ${f.remediation.target}` : 'Inspect and patch';
        prompt += `${idx + 1}. **[${id}]** ${f.title}\n`;
        prompt += `   - Location: \`${loc}\`\n`;
        prompt += `   - Fix: ${fix}\n\n`;
      });
    }

    if (bySeverity.medium.length > 0) {
      prompt += `## 🟡 Step 4: Medium Severity Remediation (${bySeverity.medium.length} issues - P2)\n`;
      bySeverity.medium.forEach((f, idx) => {
        const id = f.identifiers?.primary || f.id;
        const loc = f.location?.package ? `${f.location.package}@${f.location.version || ''}` : `${f.location?.file || ''}:${f.location?.line || ''}`;
        const fix = f.remediation?.target ? `Upgrade to >= ${f.remediation.target}` : 'Apply patch';
        prompt += `${idx + 1}. **[${id}]** ${f.title} (\`${loc}\`) -> ${fix}\n`;
      });
      prompt += `\n`;
    }

    if (bySeverity.low.length > 0) {
      prompt += `## ℹ️ Step 5: Low Severity Issues (${bySeverity.low.length} issues - P3)\n`;
      bySeverity.low.forEach((f, idx) => {
        const id = f.identifiers?.primary || f.id;
        const loc = f.location?.package ? `${f.location.package}@${f.location.version || ''}` : `${f.location?.file || ''}:${f.location?.line || ''}`;
        prompt += `${idx + 1}. **[${id}]** ${f.title} (\`${loc}\`)\n`;
      });
      prompt += `\n`;
    }

    prompt += `## 🔍 Step 6: Verification & Validation\n`;
    prompt += `1. Verify that all dependencies compile cleanly and all lockfiles are in sync.\n`;
    prompt += `2. Run unit and integration tests to ensure no regressions were introduced by upgraded APIs.\n`;
    prompt += `3. Confirm that the security posture score is restored to 100/100.\n`;
  } else {
    const sevList = bySeverity[severityFilter] || [];
    const sevUpper = severityFilter.toUpperCase();
    prompt += `# 🛡️ ${sevUpper} Severity Security Remediation for ${repo.fullName}\n`;
    prompt += `**Target**: ${repo.fullName} | **Severity**: ${sevUpper} (${sevList.length} issues)\n\n`;
    prompt += `Please provide exact terminal commands and code patches to eliminate these ${severityFilter} vulnerabilities:\n\n`;

    sevList.forEach((f, idx) => {
      const id = f.identifiers?.primary || f.id;
      const loc = f.location?.package ? `${f.location.package}@${f.location.version || ''}` : `${f.location?.file || ''}:${f.location?.line || ''}`;
      const fix = f.remediation?.target ? `Upgrade to >= ${f.remediation.target}` : 'Inspect and patch';
      prompt += `${idx + 1}. **[${id}]** ${f.title}\n`;
      prompt += `   - Target: \`${loc}\`\n`;
      prompt += `   - Action: ${fix}\n\n`;
    });

    prompt += `Provide step-by-step instructions and code diffs to verify the fix.\n`;
  }

  return prompt;
}

function AiPromptModal({ scan, repo, initialFindings = [], onClose }) {
  const [severityFilter, setSeverityFilter] = useState('all');
  const [copied, setCopied] = useState(false);
  const [allFindings, setAllFindings] = useState(initialFindings);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function fetchAll() {
      try {
        setLoading(true);
        const res = await api.get(api.org(`/scans/${scan.id}/findings?page=1&pageSize=200`));
        if (mounted && res && Array.isArray(res.items)) {
          setAllFindings(res.items);
        }
      } catch {
        // Fallback to initialFindings
      } finally {
        if (mounted) setLoading(false);
      }
    }
    fetchAll();
    return () => {
      mounted = false;
    };
  }, [scan.id]);

  useEffect(() => {
    // Prevent background scrolling while modal dialog is open
    const prevOverflow = document.body.style.overflow;
    const prevPaddingRight = document.body.style.paddingRight;
    const scrollBarWidth = window.innerWidth - document.documentElement.clientWidth;
    if (scrollBarWidth > 0) {
      document.body.style.paddingRight = `${scrollBarWidth}px`;
    }
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = prevOverflow;
      document.body.style.paddingRight = prevPaddingRight;
    };
  }, []);

  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const findings = allFindings.length ? allFindings : initialFindings;
  const promptText = generateRemediationPrompt({
    repo,
    scan,
    findings,
    severityFilter,
  });

  const counts = {
    critical: findings.filter((f) => (f.severity || '').toLowerCase() === 'critical').length,
    high: findings.filter((f) => (f.severity || '').toLowerCase() === 'high').length,
    medium: findings.filter((f) => (f.severity || '').toLowerCase() === 'medium').length,
    low: findings.filter((f) => (f.severity || '').toLowerCase() === 'low').length,
  };

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(promptText);
      setCopied(true);
      toast('Remediation prompt copied to clipboard!');
      setTimeout(() => setCopied(false), 2500);
    } catch {
      toast('Failed to copy to clipboard', 'error');
    }
  }

  function handleDownload() {
    const blob = new Blob([promptText], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${repo.fullName.replace('/', '-')}-ai-remediation-prompt.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Prompt downloaded');
  }

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true" aria-label="AI Remediation Prompt Generator">
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <h2>⚡ AI Remediation Master Prompt</h2>
            <div className="modal-subtitle">
              Universal prompt to fix all {findings.length} detected vulnerabilities in {repo.fullName} in 1 or 2 passes.
            </div>
          </div>
          <button
            type="button"
            className="btn-modal-close"
            onClick={onClose}
            aria-label="Close dialog"
            title="Close (Esc)"
          >
            ✕
          </button>
        </div>

        <div className="modal-body">
          <div className="modal-tabs">
            <button
              type="button"
              className={`modal-tab-btn ${severityFilter === 'all' ? 'active' : ''}`}
              onClick={() => setSeverityFilter('all')}
            >
              All Issues ({findings.length})
            </button>
            <button
              type="button"
              className={`modal-tab-btn ${severityFilter === 'critical' ? 'active' : ''}`}
              onClick={() => setSeverityFilter('critical')}
            >
              🔴 Critical ({counts.critical})
            </button>
            <button
              type="button"
              className={`modal-tab-btn ${severityFilter === 'high' ? 'active' : ''}`}
              onClick={() => setSeverityFilter('high')}
            >
              🟠 High ({counts.high})
            </button>
            <button
              type="button"
              className={`modal-tab-btn ${severityFilter === 'medium' ? 'active' : ''}`}
              onClick={() => setSeverityFilter('medium')}
            >
              🟡 Medium ({counts.medium})
            </button>
            <button
              type="button"
              className={`modal-tab-btn ${severityFilter === 'low' ? 'active' : ''}`}
              onClick={() => setSeverityFilter('low')}
            >
              🔵 Low ({counts.low})
            </button>
          </div>

          <div className="prompt-preview-wrap">
            {loading ? (
              <div className="muted small" style={{ padding: '1.5rem', textAlign: 'center' }}>
                Analyzing findings and synthesizing remediation instructions...
              </div>
            ) : (
              <pre className="prompt-pre">{promptText}</pre>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <div className="modal-footer-left muted small">
            Paste this prompt into Cursor, ChatGPT, Claude, or GitHub Copilot to fix all issues.
          </div>
          <div className="row">
            <button type="button" onClick={handleDownload} title="Download prompt as markdown">
              Download .md
            </button>
            <button
              type="button"
              className="primary btn-ai-prompt"
              onClick={handleCopy}
              title="Copy prompt to clipboard"
            >
              {copied ? '✓ Copied to Clipboard!' : '📋 Copy Fix Prompt'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function ScanView({ scanId }) {
  const [scan, setScan] = useState(null);
  const [repo, setRepo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showPromptModal, setShowPromptModal] = useState(false);
  const [exportModalState, setExportModalState] = useState({ isOpen: false, format: 'csv' });

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

  if (loading && !scan) return <ScanSkeletonLoader cards={6} hasTabs={false} rows={6} />;
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
        <div className="fade-in">
          <div className="card scan-progress-banner">
            <div className="scan-progress-top">
              <div className="scan-progress-title">
                <span className="scan-radar-dot" aria-hidden="true" />
                <span>
                  {scan.status === 'queued'
                    ? 'Repository scan queued · Preparing sandbox worker'
                    : 'Repository security scan in progress'}
                </span>
              </div>
              <div className="row" style={{ gap: '0.5rem', alignItems: 'center' }}>
                <span className="badge st-running">Live Scanner Active</span>
                {scan.status === 'queued' && canScan && (
                  <button type="button" className="btn btn-sm btn-subtle" onClick={handleCancelScan}>
                    Cancel scan
                  </button>
                )}
              </div>
            </div>
            <p className="muted small" style={{ margin: 0 }}>
              {scan.status === 'queued'
                ? 'The scan is queued in the platform worker queue. Analysis will begin momentarily...'
                : 'Inspecting dependencies, static code analysis (SAST), and secret scanning. The page updates automatically.'}
            </p>
            <div className="scan-progress-bar-wrap">
              <div className="scan-progress-bar-indeterminate" />
            </div>
          </div>

          <div className="stats skeleton-stats-grid" style={{ marginBottom: '1.5rem' }}>
            {['Total Findings', 'Critical', 'High', 'Medium', 'Low', 'Security Posture'].map((label, idx) => (
              <div key={idx} className="card skeleton-stat-card">
                <Skeleton width="48px" height="2rem" style={{ marginBottom: '0.4rem' }} radius="4px" />
                <span className="muted small">{label}</span>
              </div>
            ))}
          </div>

          <div className="card" style={{ padding: '2rem 1.5rem', textAlign: 'center' }}>
            <p className="muted" style={{ margin: 0 }}>
              Security findings, triage status, and fix recommendations will populate here as soon as scan finishes.
            </p>
          </div>
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
            <div className="grid stats scan-stats-grid">
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
                <div
                  className={`card stat stat-posture grade-${(sum.posture.grade || 'unknown').toLowerCase()}`}
                  title={`Security Posture Score: ${sum.posture.score}/100 (Grade ${sum.posture.grade} - ${GRADE_LABELS[sum.posture.grade] || 'Rating'})`}
                >
                  <div className="num posture-val">
                    <span className="posture-grade">{sum.posture.grade}</span>
                    <span className="posture-score">({sum.posture.score}/100)</span>
                  </div>
                  <div className="label">
                    Posture · {GRADE_LABELS[sum.posture.grade] || 'Rating'}
                  </div>
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
            <div className="grid cols-2 scan-subgrid">
              <section className="card scan-projects-card">
                <div className="card-head">
                  <h2>Projects</h2>
                  <span className="badge">{scan.projects.length} scanned</span>
                </div>
                <div className="projects-list-wrap">
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
                </div>
              </section>

              <section className="card scan-plan-card">
                <div className="card-head">
                  <div>
                    <h2>Fix plan</h2>
                    <span className="muted small">One upgrade per vulnerable package</span>
                  </div>
                  <span className="badge">
                    {planSteps.length ? `${planSteps.length} upgrade${planSteps.length === 1 ? '' : 's'}` : 'Clean'}
                  </span>
                </div>
                <div className="plan-list-wrap">
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
                            <span className="plan-fix-pill">Fixes {step.fixes} issue(s)</span>
                          </li>
                        );
                      })
                    ) : (
                      <li className="muted small">Nothing to upgrade.</li>
                    )}
                  </ul>
                </div>
              </section>
            </div>
          )}

          {Array.isArray(scan.scanners) && scan.scanners.length > 0 && (
            <section className="card scan-scanners-card">
              <h2>Scanners</h2>
              <DataTable
                headers={['Scanner', 'Status', 'Version', 'Findings', 'Time']}
                rows={scan.scanners.map((s, i) => ({
                  id: `${s.scanner}-${i}`,
                  cells: [
                    ({ osv: 'Dependencies (OSV)', semgrep: 'Code (Opengrep)', gitleaks: 'Secrets (Gitleaks)', trivy: 'Trivy', checkov: 'Checkov' }[s.scanner] || s.scanner),
                    <StatusBadge status={s.status} />,
                    s.version || '-',
                    pad(s.findingCount),
                    `${s.durationMs} ms`,
                  ],
                }))}
              />
            </section>
          )}

          <section className="card scan-findings-card">
            <div className="card-head findings-card-header">
              <div className="findings-title-group">
                <h2>Findings</h2>
                <span className="findings-count-badge">
                  {findingsData.total != null ? `${findingsData.total} issues` : ''}
                </span>
              </div>
              <div className="findings-header-actions">
                <button
                  type="button"
                  className="primary btn-ai-prompt"
                  onClick={() => setShowPromptModal(true)}
                  title="Generate a master prompt to fix all vulnerabilities in one go"
                >
                  ⚡ Generate AI Fix Prompt
                </button>
                <div className="findings-export-group" role="group" aria-label="Export findings">
                  {[
                    ['csv', 'CSV', 'csv'],
                    ['markdown', 'Markdown', 'md'],
                    ['cyclonedx', 'SBOM (CycloneDX)', 'cdx.json'],
                    ['json', 'JSON', 'json'],
                  ].map(([fmt, label, ext]) => (
                    <button
                      key={fmt}
                      type="button"
                      className="btn-export-item"
                      title={`Preview and generate ${label} export`}
                      onClick={() => setExportModalState({ isOpen: true, format: fmt })}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="findings-filter-bar">
              <div className="findings-search-wrapper">
                <span className="findings-search-icon" aria-hidden="true">🔍</span>
                <input
                  type="search"
                  className="findings-search-input"
                  placeholder="Search title, CVE, package, file..."
                  aria-label="Search findings"
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                />
                {q && (
                  <button
                    type="button"
                    className="btn-clear-search"
                    onClick={() => setQ('')}
                    title="Clear search"
                  >
                    ✕
                  </button>
                )}
              </div>
              <div className="findings-filter-controls">
                <select
                  aria-label="Severity"
                  value={severity}
                  onChange={(e) => {
                    setSeverity(e.target.value);
                    setPage(1);
                  }}
                >
                  <option value="">All severities</option>
                  <option value="critical">🚨 Critical</option>
                  <option value="high">⚠️ High</option>
                  <option value="medium">🟡 Medium</option>
                  <option value="low">🔵 Low</option>
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
                {(q || severity || category || status) && (
                  <button
                    type="button"
                    className="btn-reset-filters"
                    onClick={() => {
                      setQ('');
                      setSeverity('');
                      setCategory('');
                      setStatus('');
                      setPage(1);
                    }}
                    title="Reset all filters"
                  >
                    Reset
                  </button>
                )}
              </div>
            </div>

            {!findingsData.items.length ? (
              <div className="empty">No findings match.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col" style={{ width: '90px' }}>Severity</th>
                      <th scope="col">Finding</th>
                      <th scope="col" style={{ width: '130px' }}>Type</th>
                      <th scope="col" style={{ width: '100px' }}>Status</th>
                      <th scope="col" style={{ width: '95px', textAlign: 'center' }}>Details</th>
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
                          <tr
                            className={`finding-row ${isOpen ? 'is-expanded' : ''}`}
                            onClick={() => toggleExpand(rowKey)}
                            title={isOpen ? 'Click to collapse finding details' : 'Click to expand finding details & triage'}
                          >
                            <td>
                              <SevBadge severity={f.severity} />
                            </td>
                            <td>
                              <div className="finding-title-cell">
                                <span className={`finding-chevron ${isOpen ? 'open' : ''}`} aria-hidden="true">
                                  {isOpen ? '▼' : '▶'}
                                </span>
                                <div className="finding-title-content">
                                  <span className="finding-title-text">{f.title}</span>
                                  {where && <div className="finding-loc-sub mono">{where}</div>}
                                </div>
                              </div>
                            </td>
                            <td>{typeLabel}</td>
                            <td>
                              <StatusBadge status={f.status} />
                            </td>
                            <td style={{ textAlign: 'center' }}>
                              <button
                                type="button"
                                className={`btn-details-toggle ${isOpen ? 'open' : ''}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleExpand(rowKey);
                                }}
                                aria-expanded={isOpen}
                                title={isOpen ? 'Collapse details' : 'Expand details'}
                              >
                                <span>{isOpen ? 'Hide' : 'Details'}</span>
                                <span className="toggle-chevron-icon">{isOpen ? '▲' : '▼'}</span>
                              </button>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr className="finding-detail-row">
                              <td colSpan={5}>
                                <FindingDetail
                                  finding={f}
                                  repo={repo}
                                  onReload={loadFindings}
                                  onClose={() => toggleExpand(rowKey)}
                                />
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

          {showPromptModal && (
            <AiPromptModal
              scan={scan}
              repo={repo}
              initialFindings={findingsData.items || []}
              onClose={() => setShowPromptModal(false)}
            />
          )}

          {exportModalState.isOpen && (
            <ExportPreviewModal
              isOpen={exportModalState.isOpen}
              initialFormat={exportModalState.format}
              scanId={scanId}
              repo={repo}
              scan={scan}
              onClose={() => setExportModalState({ isOpen: false, format: 'csv' })}
            />
          )}
        </>
      )}
    </>
  );
}
