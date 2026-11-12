import React, { useEffect, useState } from 'react';
import { api, session, hasPermission, toast, fmtDate, pad } from '../api.js';
import { PageHead, DataTable, StatusBadge, SevBadge, SeverityBar, ScanSkeletonLoader } from '../components/Common.jsx';
import { scanStartDecision, authorizationPresentation, isPublicAssessmentProfile } from '../../../src/platform/website-auth-ui.js';

export function WebsitesView({ onSelectScan }) {
  const [websites, setWebsites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [verifyingSite, setVerifyingSite] = useState(null);
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [scanningSiteId, setScanningSiteId] = useState(null);
  const [scanProfile, setScanProfile] = useState('public');
  const [grantSite, setGrantSite] = useState(null);
  const [grantBusy, setGrantBusy] = useState(false);
  const [grantForm, setGrantForm] = useState({
    evidenceKind: 'engagement_id',
    evidenceRef: '',
    expiresAt: '',
    allowedProfiles: ['discovery', 'standard'],
    allowActiveTesting: false,
  });
  const [deepOpts, setDeepOpts] = useState({
    sessionCookie: '',
    sessionHeader: '',
    seedUrls: '',
    originUrl: '',
  });

  const canWrite = hasPermission(session.me, session.orgId, 'repos:write');
  const canScan = hasPermission(session.me, session.orgId, 'scans:run');
  const canAuthorize = hasPermission(session.me, session.orgId, 'org:settings');

  const PROFILES = [
    { id: 'public', label: 'Public Website Assessment' },
    { id: 'discovery', label: 'Discovery Assessment' },
    { id: 'standard', label: 'Standard Vulnerability Assessment' },
    { id: 'deep', label: 'Deep Security Assessment' },
  ];

  async function loadWebsites() {
    try {
      setLoading(true);
      const data = await api.get(api.org('/websites'));
      setWebsites(data);
    } catch (err) {
      toast(err.message || 'Failed to load websites', 'error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadWebsites();
  }, [session.orgId]);

  async function handleAddWebsite(e) {
    e.preventDefault();
    if (!url.trim()) return;
    try {
      setBusy(true);
      await api.post(api.org('/websites'), {
        url: url.trim(),
        name: name.trim() || undefined,
      });
      toast('Website registered successfully');
      setUrl('');
      setName('');
      await loadWebsites();
    } catch (err) {
      toast(err.message || 'Failed to add website', 'error');
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteWebsite(site) {
    if (!window.confirm(`Remove website target ${site.targetUrl}? All associated scans will be deleted.`)) {
      return;
    }
    try {
      await api.del(api.org(`/websites/${site.id}`));
      toast('Website removed');
      await loadWebsites();
    } catch (err) {
      toast(err.message || 'Failed to delete website', 'error');
    }
  }

  function authStatus(site) {
    const view = authorizationPresentation(site, scanProfile);
    if (view.status === 'authorized' && view.expiresAt) {
      return { label: `${view.label} until ${fmtDate(view.expiresAt)}`, cls: view.tone, reason: view.reason };
    }
    return { label: view.label, cls: view.tone, reason: view.reason };
  }

  async function handleStartScan(site) {
    const profile = scanProfile;
    const decision = scanStartDecision(site, profile);
    if (!decision.allow) {
      toast(decision.reason || 'This assessment is not authorized for this host.', 'error');
      return;
    }
    try {
      setScanningSiteId(site.id);
      const scan = await api.post(api.org(`/websites/${site.id}/scans`), { profile });
      toast(`${profile} scan queued`);
      await loadWebsites();
      if (onSelectScan) {
        onSelectScan(site.id, scan.id);
      } else {
        location.hash = `#/websites/${site.id}/scans/${scan.id}`;
      }
    } catch (err) {
      toast(err.message || 'Failed to start website scan', 'error');
    } finally {
      setScanningSiteId(null);
    }
  }

  async function handleVerify(site) {
    try {
      setVerifyLoading(true);
      const res = await api.post(api.org(`/websites/${site.id}/verify`), {});
      if (res.verified) {
        toast(`Domain verified successfully via ${res.method}!`);
        setVerifyingSite(null);
        await loadWebsites();
      } else {
        toast(res.error || 'Verification challenge not found. Please verify DNS or HTTP record and try again.', 'error');
      }
    } catch (err) {
      toast(err.message || 'Verification check failed', 'error');
    } finally {
      setVerifyLoading(false);
    }
  }

  async function handleCreateGrant(e) {
    e.preventDefault();
    if (!grantSite) return;
    try {
      setGrantBusy(true);
      await api.post(api.org(`/websites/${grantSite.id}/authorizations`), {
        ...grantForm,
        expiresAt: new Date(grantForm.expiresAt).toISOString(),
        allowActiveTesting: Boolean(grantForm.allowActiveTesting) && grantForm.allowedProfiles.includes('deep'),
      });
      toast('Client authorization grant recorded');
      setGrantSite(null);
      await loadWebsites();
    } catch (err) {
      toast(err.message || 'Could not record authorization', 'error');
    } finally {
      setGrantBusy(false);
    }
  }

  const headers = [
    'Website target',
    isPublicAssessmentProfile(scanProfile) ? 'Public assessment' : 'Authorized DAST',
    'Security posture',
    'Latest scan',
    { label: 'Actions', num: true },
  ];

  const rows = websites.map((site) => {
    const latest = site.latestScan;
    const summary = latest && latest.summary;
    const authView = authStatus(site);
    const startDecision = scanStartDecision(site, scanProfile);
    const counts = summary ? {
      critical: summary.critical || 0,
      high: summary.high || 0,
      medium: summary.medium || 0,
      low: summary.low || 0,
    } : null;

    return {
      id: site.id,
      cells: [
        <div key="target">
          <div className="repo-name">
            <strong>{site.name || site.hostname}</strong>
          </div>
          <div className="small muted">
            <a href={site.targetUrl} target="_blank" rel="noopener noreferrer">
              {site.targetUrl}
            </a>
          </div>
        </div>,

        <div key="verify">
          <span className={`badge ${authView.cls}`}>{authView.label}</span>
          <div className="small muted" style={{ marginTop: '0.25rem', maxWidth: '220px' }}>
            {startDecision.allow ? authView.reason : startDecision.reason}
          </div>
          <div className="row" style={{ gap: '0.4rem', marginTop: '0.3rem', flexWrap: 'wrap' }}>
            {canWrite && !site.isVerified && (
              <button type="button" className="btn btn-sm btn-subtle" onClick={() => setVerifyingSite(site)}>
                Optional DNS/HTTP
              </button>
            )}
            {canAuthorize && !isPublicAssessmentProfile(scanProfile) && (
              <button
                type="button"
                className="btn btn-sm btn-subtle"
                onClick={() => {
                  setGrantSite(site);
                  setGrantForm((f) => ({
                    ...f,
                    expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString().slice(0, 16),
                  }));
                }}
              >
                Record grant
              </button>
            )}
          </div>
        </div>,

        <div key="posture">
          {latest && latest.postureScore != null ? (
            <div>
              <span className={`badge ${latest.postureScore >= 80 ? 'sev-low' : latest.postureScore >= 50 ? 'sev-medium' : 'sev-critical'}`}>
                {latest.postureScore}/100 {summary && summary.grade ? `(${summary.grade})` : ''}
              </span>
              <div style={{ marginTop: '0.3rem' }}>
                <SeverityBar counts={counts} />
              </div>
            </div>
          ) : (
            <span className="muted">No scan yet</span>
          )}
        </div>,

        <div key="latest">
          {latest ? (
            <div>
              <StatusBadge status={latest.status} />
              <div className="small muted" style={{ marginTop: '0.2rem' }}>
                <a href={`#/websites/${site.id}/scans/${latest.id}`}>
                  {latest.profile} ({fmtDate(latest.finishedAt || latest.startedAt)})
                </a>
              </div>
            </div>
          ) : (
            <span className="muted">-</span>
          )}
        </div>,

        <div key="actions" className="website-actions-cell">
          {latest && (
            <a
              href={`#/websites/${site.id}/scans/${latest.id}`}
              className="btn btn-sm btn-subtle website-action-btn"
              title="View latest scan results and telemetry"
            >
              Results
            </a>
          )}
          {canScan && (
            <button
              type="button"
              className="website-scan-btn btn-active-primary"
              disabled={scanningSiteId === site.id}
              onClick={() => handleStartScan(site)}
              title={isPublicAssessmentProfile(scanProfile)
                ? 'Run Public Website Assessment without an engagement ID'
                : 'Run the selected assessment against this authorized target'}
            >
              {scanningSiteId === site.id ? 'Scanning...' : 'Scan website'}
            </button>
          )}
          {canWrite && (
            <button
              type="button"
              className="btn btn-sm btn-danger-subtle website-action-btn"
              onClick={() => handleDeleteWebsite(site)}
              title="Delete website target"
            >
              Delete
            </button>
          )}
        </div>,
      ],
    };
  });

  return (
    <div className="view">
      <PageHead
        title="Website Security Scanner"
        subtitle="Public Website Assessment needs no engagement ID and no DNS proof. Discovery, Standard and Deep use an org policy or site grant. Deep also needs stored active-testing permission."
      />

      {canWrite && (
        <section className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-head">
            <h2 className="m-0">Register Website Target</h2>
          </div>
          <form onSubmit={handleAddWebsite} className="row" style={{ flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end' }}>
            <div style={{ flex: '2 1 240px' }}>
              <label htmlFor="target-url" className="small muted">
                Website URL (HTTPS / HTTP)
              </label>
              <input
                id="target-url"
                type="url"
                required
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>
            <div style={{ flex: '1 1 180px' }}>
              <label htmlFor="target-name" className="small muted">
                Target Name (Optional)
              </label>
              <input
                id="target-name"
                type="text"
                placeholder="Production Portal"
                value={name}
                onChange={(e) => setName(e.target.value)}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>
            <div>
              <button type="submit" className="btn btn-primary" disabled={busy || !url.trim()}>
                {busy ? 'Registering...' : 'Add Website'}
              </button>
            </div>
          </form>
        </section>
      )}

      <section className="card">
        <div className="card-head">
          <div className="row" style={{ justifyContent: 'space-between', width: '100%' }}>
            <h2 className="m-0">Monitored Websites ({websites.length})</h2>
            <div className="row" style={{ gap: '0.5rem', alignItems: 'center' }}>
              <label className="small muted" htmlFor="scan-profile">Profile</label>
              <select
                id="scan-profile"
                value={scanProfile}
                onChange={(e) => setScanProfile(e.target.value)}
                style={{ height: '32px', borderRadius: '6px' }}
              >
                {PROFILES.map((p) => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
              <button
                type="button"
                className="btn btn-sm btn-subtle"
                onClick={loadWebsites}
                disabled={loading}
              >
                {loading ? 'Refreshing...' : 'Refresh'}
              </button>
            </div>
          </div>
        </div>

        {loading && !websites.length ? (
          <div style={{ padding: '1rem 0' }}>
            <ScanSkeletonLoader cards={4} hasTabs={false} rows={4} />
          </div>
        ) : (
          <DataTable
            headers={headers}
        {scanProfile === 'deep' && (
          <div className="deep-scan-opts">
            <p className="small muted" style={{ margin: '0 0 12px' }}>
              Authorized Deep only. Session values are sent with crawls and ZAP, never written to CSV or the scan JSON. Origin must be this host or a subdomain. A different Azure/Lambda host is its own website.
            </p>
            <div className="deep-scan-grid">
              <label className="small muted" htmlFor="deep-cookie">
                Session cookie
                <input
                  id="deep-cookie"
                  type="password"
                  autoComplete="off"
                  value={deepOpts.sessionCookie}
                  onChange={(e) => setDeepOpts({ ...deepOpts, sessionCookie: e.target.value })}
                  placeholder="name=value"
                />
              </label>
              <label className="small muted" htmlFor="deep-header">
                Session header
                <input
                  id="deep-header"
                  type="password"
                  autoComplete="off"
                  value={deepOpts.sessionHeader}
                  onChange={(e) => setDeepOpts({ ...deepOpts, sessionHeader: e.target.value })}
                  placeholder="Authorization: Bearer …"
                />
              </label>
              <label className="small muted" htmlFor="deep-origin">
                Origin URL
                <input
                  id="deep-origin"
                  type="url"
                  value={deepOpts.originUrl}
                  onChange={(e) => setDeepOpts({ ...deepOpts, originUrl: e.target.value })}
                  placeholder="https://origin.example.com"
                />
              </label>
              <label className="small muted" htmlFor="deep-seeds" style={{ gridColumn: '1 / -1' }}>
                API seed URLs
                <textarea
                  id="deep-seeds"
                  rows={3}
                  value={deepOpts.seedUrls}
                  onChange={(e) => setDeepOpts({ ...deepOpts, seedUrls: e.target.value })}
                  placeholder={'https://example.com/api/users\nhttps://example.com/openapi.json'}
                />
              </label>
            </div>
          </div>
        )}

            rows={rows}
            empty="No website targets registered yet. Add a URL above to start security scanning."
          />
        )}
      </section>

      {verifyingSite && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="card modal-card" style={{ maxWidth: '640px', width: '90%' }}>
            <div className="card-head">
              <h2 className="m-0">Domain Ownership Verification</h2>
              <button
                type="button"
                className="btn btn-sm btn-subtle"
                onClick={() => setVerifyingSite(null)}
              >
                Close
              </button>
            </div>

            <p className="small muted">
              Optional domain-control check for <strong>{verifyingSite.hostname}</strong>.
              DNS TXT or the HTTP token prove you control the name. They do not by themselves permit ZAP active scan.
            </p>

            <div style={{ margin: '1rem 0' }}>
              <h4>Option A: DNS TXT Record (Recommended)</h4>
              <p className="small muted">Add a DNS TXT record with these values:</p>
              <div className="code-block" style={{ background: 'var(--color-bg)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.85rem' }}>
                <div><strong>Host / Name:</strong> _vulnsight-challenge.{verifyingSite.hostname}</div>
                <div style={{ marginTop: '0.3rem' }}><strong>Value:</strong> {verifyingSite.verificationToken}</div>
              </div>
            </div>

            <div style={{ margin: '1rem 0' }}>
              <h4>Option B: HTTP Well-Known Token</h4>
              <p className="small muted">Host a plain text file at this exact URL:</p>
              <div className="code-block" style={{ background: 'var(--color-bg)', padding: '0.75rem', borderRadius: '6px', fontSize: '0.85rem' }}>
                <div><strong>URL:</strong> {verifyingSite.targetUrl}/.well-known/vulnsight-verify.txt</div>
                <div style={{ marginTop: '0.3rem' }}><strong>File Content:</strong> {verifyingSite.verificationToken}</div>
              </div>
            </div>

            <div className="row" style={{ justifyContent: 'flex-end', gap: '0.5rem', marginTop: '1.25rem', flexWrap: 'wrap' }}>
              <div className="row" style={{ gap: '0.5rem' }}>
                <button
                  type="button"
                  className="btn btn-subtle"
                  onClick={() => setVerifyingSite(null)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={verifyLoading}
                  onClick={() => handleVerify(verifyingSite)}
                >
                  {verifyLoading ? 'Checking...' : 'Check DNS / HTTP'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {grantSite && (
        <div className="modal-backdrop" role="dialog" aria-modal="true">
          <div className="card modal-card" style={{ maxWidth: '640px', width: '90%' }}>
            <div className="card-head">
              <h2 className="m-0">Record client authorization</h2>
              <button type="button" className="btn btn-sm btn-subtle" onClick={() => setGrantSite(null)}>Close</button>
            </div>
            <p className="small muted">
              Use this only when an independent engagement, signed document, or change ticket already authorizes testing of <strong>{grantSite.hostname}</strong>.
              A URL, email, or “I own this” click is not enough.
            </p>
            <form onSubmit={handleCreateGrant} style={{ display: 'grid', gap: '12px' }}>
              <div>
                <label className="small muted" htmlFor="ev-kind">Evidence type</label>
                <select
                  id="ev-kind"
                  value={grantForm.evidenceKind}
                  onChange={(e) => setGrantForm({ ...grantForm, evidenceKind: e.target.value })}
                  style={{ width: '100%', height: '32px' }}
                >
                  <option value="engagement_id">Engagement ID</option>
                  <option value="change_ticket">Change ticket</option>
                  <option value="signed_document_sha256">SHA-256 of signed document</option>
                </select>
              </div>
              <div>
                <label className="small muted" htmlFor="ev-ref">Evidence reference</label>
                <input
                  id="ev-ref"
                  required
                  minLength={8}
                  value={grantForm.evidenceRef}
                  onChange={(e) => setGrantForm({ ...grantForm, evidenceRef: e.target.value })}
                  placeholder="ENG-104821 or 64-char hex digest"
                  style={{ width: '100%' }}
                />
              </div>
              <div>
                <label className="small muted" htmlFor="ev-exp">Expires</label>
                <input
                  id="ev-exp"
                  type="datetime-local"
                  required
                  value={grantForm.expiresAt}
                  onChange={(e) => setGrantForm({ ...grantForm, expiresAt: e.target.value })}
                  style={{ width: '100%' }}
                />
              </div>
              <fieldset style={{ border: '1px solid var(--border)', borderRadius: '6px', padding: '8px 12px' }}>
                <legend className="small muted">Allowed profiles</legend>
                {PROFILES.filter((p) => p.id !== 'public').map((p) => (
                  <label key={p.id} className="small" style={{ display: 'block', marginBottom: '4px' }}>
                    <input
                      type="checkbox"
                      checked={grantForm.allowedProfiles.includes(p.id)}
                      onChange={(e) => {
                        const next = e.target.checked
                          ? [...grantForm.allowedProfiles, p.id]
                          : grantForm.allowedProfiles.filter((id) => id !== p.id);
                        setGrantForm({ ...grantForm, allowedProfiles: next });
                      }}
                    />{' '}
                    {p.label}
                  </label>
                ))}
                <label className="small" style={{ display: 'block', marginTop: '8px' }}>
                  <input
                    type="checkbox"
                    checked={grantForm.allowActiveTesting}
                    onChange={(e) => setGrantForm({
                      ...grantForm,
                      allowActiveTesting: e.target.checked,
                      allowedProfiles: e.target.checked
                        ? [...new Set([...grantForm.allowedProfiles, 'deep'])]
                        : grantForm.allowedProfiles,
                    })}
                  />{' '}
                  Allow ZAP active scan and intrusive Nuclei (deep only)
                </label>
              </fieldset>
              <div className="row" style={{ justifyContent: 'flex-end', gap: '8px' }}>
                <button type="button" className="btn btn-subtle" onClick={() => setGrantSite(null)}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={grantBusy}>
                  {grantBusy ? 'Saving...' : 'Record grant'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
