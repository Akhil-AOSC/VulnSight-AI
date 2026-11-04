import React, { useEffect, useState } from 'react';
import { api, session, hasPermission, toast, fmtDate, pad } from '../api.js';
import { PageHead, DataTable, StatusBadge, SevBadge, SeverityBar } from '../components/Common.jsx';

export function WebsitesView({ onSelectScan }) {
  const [websites, setWebsites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [verifyingSite, setVerifyingSite] = useState(null);
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [scanningSiteId, setScanningSiteId] = useState(null);

  const canWrite = hasPermission(session.me, session.orgId, 'repos:write');
  const canScan = hasPermission(session.me, session.orgId, 'scans:run');

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

  async function handleStartScan(site, profile) {
    try {
      setScanningSiteId(site.id);
      const scan = await api.post(api.org(`/websites/${site.id}/scans`), { profile });
      toast(`${profile.toUpperCase()} scan queued`);
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

  async function handleVerify(site, isManual = false) {
    try {
      setVerifyLoading(true);
      const res = await api.post(api.org(`/websites/${site.id}/verify`), { manual: isManual });
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

  const headers = [
    'Website target',
    'Verification',
    'Security posture',
    'Latest scan',
    { label: 'Actions', num: true },
  ];

  const rows = websites.map((site) => {
    const latest = site.latestScan;
    const summary = latest && latest.summary;
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
          {site.isVerified ? (
            <span className="badge sev-low" title={`Verified by ${site.verificationMethod || 'DNS/HTTP'}`}>
              Verified ({site.verificationMethod === 'dns_txt' ? 'DNS' : 'HTTP'})
            </span>
          ) : (
            <div className="row" style={{ gap: '0.4rem', alignItems: 'center' }}>
              <span className="badge sev-medium">Unverified</span>
              {canWrite && (
                <button
                  type="button"
                  className="btn btn-sm btn-subtle"
                  onClick={() => setVerifyingSite(site)}
                >
                  Verify
                </button>
              )}
            </div>
          )}
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

        <div key="actions" className="row" style={{ justifyContent: 'flex-end', gap: '0.4rem' }}>
          {latest && (
            <a
              href={`#/websites/${site.id}/scans/${latest.id}`}
              className="btn btn-sm btn-subtle"
            >
              Results
            </a>
          )}
          {canScan && (
            <div className="dropdown-inline" style={{ display: 'inline-flex', gap: '0.25rem' }}>
              <button
                type="button"
                className="btn btn-sm btn-primary"
                disabled={scanningSiteId === site.id}
                onClick={() => handleStartScan(site, 'passive')}
                title="Runs TLS, headers, cookies, and CORS inspection (no authorization token required)"
              >
                {scanningSiteId === site.id ? 'Starting...' : 'Passive Scan'}
              </button>
              {site.isVerified ? (
                <button
                  type="button"
                  className="btn btn-sm btn-subtle"
                  disabled={scanningSiteId === site.id}
                  onClick={() => handleStartScan(site, 'standard')}
                  title="Full crawl and endpoint analysis"
                >
                  Active Crawl
                </button>
              ) : null}
            </div>
          )}
          {canWrite && (
            <button
              type="button"
              className="btn btn-sm btn-danger-subtle"
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
        subtitle="DAST vulnerability scanning, TLS/SSL configuration, HTTP headers, CORS policies, and AI risk analysis"
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

        {loading && !websites.length ? (
          <div className="empty">Loading website targets...</div>
        ) : (
          <DataTable
            headers={headers}
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
              Active crawling and vulnerability probing require domain authorization to prevent unauthorized testing.
              Please complete one of the verification options below for <strong>{verifyingSite.hostname}</strong>:
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

            <div style={{ margin: '1rem 0' }}>
              <h4>Option C: Authorized Security Assessment (Self-Certified)</h4>
              <p className="small muted">
                If you are an authorised tester or domain administrator and cannot configure public DNS records or file uploads right now, you may confirm your testing authorization directly.
              </p>
            </div>

            <div className="row" style={{ justifyContent: 'space-between', gap: '0.5rem', marginTop: '1.25rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn btn-subtle"
                disabled={verifyLoading}
                onClick={() => handleVerify(verifyingSite, true)}
                title="Self-certify authorization for this domain"
              >
                Self-Certify Authorization
              </button>
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
                  onClick={() => handleVerify(verifyingSite, false)}
                >
                  {verifyLoading ? 'Checking...' : 'Check DNS / HTTP'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
