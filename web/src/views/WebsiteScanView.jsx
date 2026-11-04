import React, { useEffect, useState } from 'react';
import { api, fmtDate, pad, toast } from '../api.js';
import { PageHead, StatCard, SevBadge, StatusBadge, AiBriefingCard, DataTable } from '../components/Common.jsx';

export function WebsiteScanView({ websiteId, scanId }) {
  const [scan, setScan] = useState(null);
  const [site, setSite] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('findings');
  const [sevFilter, setSevFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFinding, setExpandedFinding] = useState(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [siteData, scanData] = await Promise.all([
          api.get(api.org(`/websites/${websiteId}`)),
          api.get(api.org(`/websites/${websiteId}/scans/${scanId}`)),
        ]);
        setSite(siteData);
        setScan(scanData);
      } catch (err) {
        toast(err.message || 'Failed to load website scan details', 'error');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [websiteId, scanId]);

  async function handleDownloadReport(format) {
    try {
      const res = await api.get(api.org(`/websites/${websiteId}/scans/${scanId}/report?format=${format}`));
      if (res && res.download) {
        const blob = new Blob([res.download.body], { type: res.download.type });
        const objUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = objUrl;
        a.download = `vulnsight-dast-${scanId}.${res.download.ext}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(objUrl);
        toast(`Downloaded report in ${format.toUpperCase()} format`);
      }
    } catch (err) {
      toast(err.message || 'Report download failed', 'error');
    }
  }

  if (loading) {
    return (
      <div className="view">
        <PageHead title="Website Security Scan" subtitle="Loading scan results..." />
        <div className="empty">Loading vulnerability report and security telemetry...</div>
      </div>
    );
  }

  if (!scan || !site) {
    return (
      <div className="view">
        <PageHead title="Website Security Scan" subtitle="Scan not found" />
        <div className="empty">
          <p>The requested website scan could not be located.</p>
          <a href="#/websites" className="btn btn-primary" style={{ marginTop: '0.75rem' }}>
            Back to Websites
          </a>
        </div>
      </div>
    );
  }

  const s = scan.summary || {};
  const passive = scan.passiveResults || {};
  const allFindings = passive.findings || [];
  const tech = passive.technologies || [];
  const tls = passive.tls;
  const headersData = passive.headers || {};
  const cookiesList = passive.cookies || [];
  const corsData = passive.cors || {};
  const endpoints = passive.crawledUrls || [];
  const forms = passive.forms || [];
  const exposedFiles = passive.exposedFiles || [];

  const filteredFindings = allFindings.filter((f) => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title && f.title.toLowerCase().includes(q);
      const matchDesc = f.description && f.description.toLowerCase().includes(q);
      const matchLoc = f.location && (f.location.url || f.location.parameter || f.location.path || '').toLowerCase().includes(q);
      if (!matchTitle && !matchDesc && !matchLoc) return false;
    }
    return true;
  });

  return (
    <div className="view">
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <a href="#/websites" className="small muted" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
            &larr; Back to Websites
          </a>
          <h1 style={{ margin: '0.25rem 0' }}>{site.name || site.hostname}</h1>
          <div className="small muted">
            <a href={site.targetUrl} target="_blank" rel="noopener noreferrer">
              {site.targetUrl}
            </a>
            {' '}&middot; Profile: <strong>{scan.profile}</strong> &middot; Status: <StatusBadge status={scan.status} /> &middot; Finished: {fmtDate(scan.finishedAt || scan.createdAt)}
          </div>
        </div>

        <div className="row" style={{ gap: '0.5rem' }}>
          <button
            type="button"
            className="btn btn-sm btn-subtle"
            onClick={() => handleDownloadReport('json')}
          >
            Export JSON
          </button>
          <button
            type="button"
            className="btn btn-sm btn-subtle"
            onClick={() => handleDownloadReport('markdown')}
          >
            Export Markdown
          </button>
          <button
            type="button"
            className="btn btn-sm btn-subtle"
            onClick={() => handleDownloadReport('csv')}
          >
            Export CSV
          </button>
        </div>
      </div>

      <div className="stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <StatCard
          num={scan.postureScore != null ? `${scan.postureScore}/100` : 'N/A'}
          label={`Security Posture (Grade ${s.grade || 'N/A'})`}
        />
        <StatCard
          className="stat-critical"
          num={pad(s.critical || 0)}
          label="Critical Severity"
        />
        <StatCard
          className="stat-high"
          num={pad(s.high || 0)}
          label="High Severity"
        />
        <StatCard
          className="stat-medium"
          num={pad((s.medium || 0) + (s.low || 0))}
          label="Medium &amp; Low"
        />
        <StatCard
          num={pad(endpoints.length || 1)}
          label="Endpoints Inspected"
        />
      </div>

      {scan.aiAnalysis && (
        <div style={{ marginBottom: '1.5rem' }}>
          <AiBriefingCard ai={scan.aiAnalysis} />
        </div>
      )}

      <div className="tab-nav" style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--color-border)', marginBottom: '1rem' }}>
        {[
          ['findings', `Vulnerabilities (${allFindings.length})`],
          ['headers', 'Security Headers & CORS'],
          ['cookies', `Cookies (${cookiesList.length})`],
          ['tls', 'TLS / SSL Configuration'],
          ['crawl', `Endpoints & Forms (${endpoints.length})`],
          ['technologies', `Technologies (${tech.length})`],
        ].map(([key, label]) => (
          <button
            key={key}
            type="button"
            className={`tab-btn ${activeTab === key ? 'active' : ''}`}
            onClick={() => setActiveTab(key)}
            style={{
              padding: '0.5rem 0.85rem',
              background: 'none',
              border: 'none',
              borderBottom: activeTab === key ? '2px solid var(--color-primary)' : '2px solid transparent',
              fontWeight: activeTab === key ? 600 : 400,
              cursor: 'pointer',
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {activeTab === 'findings' && (
        <section className="card">
          <div className="card-head">
            <div className="row" style={{ justifyContent: 'space-between', width: '100%', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div className="row" style={{ gap: '0.4rem', alignItems: 'center' }}>
                <span className="small muted">Filter severity:</span>
                {['all', 'critical', 'high', 'medium', 'low'].map((level) => (
                  <button
                    key={level}
                    type="button"
                    className={`btn btn-sm ${sevFilter === level ? 'btn-primary' : 'btn-subtle'}`}
                    onClick={() => setSevFilter(level)}
                  >
                    {level.toUpperCase()}
                  </button>
                ))}
              </div>
              <input
                type="search"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ minWidth: '220px' }}
              />
            </div>
          </div>

          {!filteredFindings.length ? (
            <div className="empty">No security findings match the selected filters.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col" style={{ width: '100px' }}>Severity</th>
                    <th scope="col">Vulnerability</th>
                    <th scope="col">Affected Location</th>
                    <th scope="col">Recommended Remediation</th>
                    <th scope="col" style={{ width: '80px' }}>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((f) => (
                    <React.Fragment key={f.id}>
                      <tr
                        className="clickable"
                        onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                      >
                        <td>
                          <SevBadge severity={f.severity} />
                        </td>
                        <td>
                          <strong>{f.title}</strong>
                          {f.scanner && (
                            <div className="small muted">{f.scanner.name || f.scanner}</div>
                          )}
                        </td>
                        <td>
                          <code className="small">
                            {(f.location && (f.location.url || f.location.parameter || f.location.path)) || site.targetUrl}
                          </code>
                        </td>
                        <td className="small">
                          {(f.remediation && (f.remediation.advice || f.remediation.fixedIn)) || 'Review configuration'}
                        </td>
                        <td>
                          <button type="button" className="btn btn-sm btn-subtle">
                            {expandedFinding === f.id ? 'Hide' : 'View'}
                          </button>
                        </td>
                      </tr>
                      {expandedFinding === f.id && (
                        <tr>
                          <td colSpan={5} style={{ background: 'var(--color-bg)', padding: '1rem' }}>
                            <div style={{ display: 'grid', gap: '0.5rem' }}>
                              <div>
                                <strong>Description:</strong>
                                <p style={{ margin: '0.25rem 0' }}>{f.description || 'No extended description available.'}</p>
                              </div>
                              {f.evidence && (
                                <div>
                                  <strong>Technical Evidence:</strong>
                                  <pre style={{ background: 'var(--color-surface)', padding: '0.5rem', borderRadius: '4px', overflowX: 'auto', fontSize: '0.8rem' }}>
                                    {typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : String(f.evidence)}
                                  </pre>
                                </div>
                              )}
                              {f.remediation && f.remediation.advice && (
                                <div>
                                  <strong>Remediation Steps:</strong>
                                  <p style={{ margin: '0.25rem 0' }}>{f.remediation.advice}</p>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {activeTab === 'headers' && (
        <div style={{ display: 'grid', gap: '1.5rem' }}>
          <section className="card">
            <div className="card-head">
              <h2 className="m-0">HTTP Security Headers Assessment</h2>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Security Header</th>
                    <th scope="col">Status</th>
                    <th scope="col">Value</th>
                    <th scope="col">Impact / Guidance</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['Strict-Transport-Security (HSTS)', headersData['strict-transport-security'], 'Enforces encrypted HTTPS connections'],
                    ['Content-Security-Policy (CSP)', headersData['content-security-policy'], 'Restricts script, stylesheet, and object origins against XSS'],
                    ['X-Frame-Options (XFO)', headersData['x-frame-options'], 'Defends against Clickjacking UI redress attacks'],
                    ['X-Content-Type-Options', headersData['x-content-type-options'], 'Blocks MIME-sniffing vulnerabilities (nosniff)'],
                    ['Referrer-Policy', headersData['referrer-policy'], 'Prevents leaking private query paths to external origins'],
                    ['Permissions-Policy', headersData['permissions-policy'], 'Disables unused browser hardware APIs (camera, geolocation)'],
                  ].map(([headerName, val, guidance], idx) => {
                    const isPresent = Boolean(val);
                    return (
                      <tr key={idx}>
                        <td><strong>{headerName}</strong></td>
                        <td>
                          <span className={`badge ${isPresent ? 'sev-low' : 'sev-high'}`}>
                            {isPresent ? 'Configured' : 'Missing'}
                          </span>
                        </td>
                        <td>
                          {isPresent ? (
                            <code className="small">{String(val).slice(0, 80)}</code>
                          ) : (
                            <span className="muted">Not returned by server</span>
                          )}
                        </td>
                        <td className="small muted">{guidance}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card">
            <div className="card-head">
              <h2 className="m-0">CORS Policy Configuration</h2>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', padding: '0.5rem 0' }}>
              <div>
                <span className="small muted">Access-Control-Allow-Origin:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <code>{corsData.allowOrigin || 'Not set (restricted)'}</code>
                </div>
              </div>
              <div>
                <span className="small muted">Access-Control-Allow-Credentials:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <code>{corsData.allowCredentials ? 'true' : 'false / not set'}</code>
                </div>
              </div>
              <div>
                <span className="small muted">Arbitrary Origin Reflection:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <span className={`badge ${corsData.arbitraryOriginReflected ? 'sev-critical' : 'sev-low'}`}>
                    {corsData.arbitraryOriginReflected ? 'Vulnerable (Reflected)' : 'Safe (Rejected)'}
                  </span>
                </div>
              </div>
            </div>
          </section>
        </div>
      )}

      {activeTab === 'cookies' && (
        <section className="card">
          <div className="card-head">
            <h2 className="m-0">Cookie Security Audit</h2>
          </div>
          {!cookiesList.length ? (
            <div className="empty">No cookies were set by the web server during inspection.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Cookie Name</th>
                    <th scope="col">Secure Flag</th>
                    <th scope="col">HttpOnly Flag</th>
                    <th scope="col">SameSite Policy</th>
                    <th scope="col">Path</th>
                  </tr>
                </thead>
                <tbody>
                  {cookiesList.map((c, i) => (
                    <tr key={i}>
                      <td><strong>{c.name}</strong></td>
                      <td>
                        <span className={`badge ${c.secure ? 'sev-low' : 'sev-high'}`}>
                          {c.secure ? 'Secure' : 'Missing Secure'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${c.httpOnly ? 'sev-low' : 'sev-medium'}`}>
                          {c.httpOnly ? 'HttpOnly' : 'Missing HttpOnly'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${c.sameSite ? 'sev-low' : 'sev-medium'}`}>
                          {c.sameSite ? `SameSite=${c.sameSite}` : 'None specified'}
                        </span>
                      </td>
                      <td className="small">{c.path || '/'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {activeTab === 'tls' && (
        <section className="card">
          <div className="card-head">
            <h2 className="m-0">TLS / SSL Configuration &amp; Certificate Status</h2>
          </div>
          {!tls ? (
            <div className="empty">Target was accessed over HTTP or TLS data is unavailable.</div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
              <div>
                <span className="small muted">Certificate Authority Trust:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <span className={`badge ${tls.authorized ? 'sev-low' : 'sev-critical'}`}>
                    {tls.authorized ? 'Trusted &amp; Valid' : `Untrusted: ${tls.authorizationError || 'Untrusted'}`}
                  </span>
                </div>
              </div>
              <div>
                <span className="small muted">Negotiated TLS Protocol:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <strong>{tls.protocol || 'Unknown'}</strong>
                </div>
              </div>
              <div>
                <span className="small muted">Cipher Suite:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <code>{tls.cipher ? (tls.cipher.name || JSON.stringify(tls.cipher)) : 'Unknown'}</code>
                </div>
              </div>
              <div>
                <span className="small muted">Certificate Expiry:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <strong>{tls.validTo ? fmtDate(tls.validTo) : 'N/A'}</strong>
                  {tls.daysRemaining != null && (
                    <span className="small muted"> ({tls.daysRemaining} days remaining)</span>
                  )}
                </div>
              </div>
              <div>
                <span className="small muted">Certificate Issuer:</span>
                <div style={{ marginTop: '0.25rem' }} className="small">
                  {typeof tls.issuer === 'object' ? (tls.issuer.O || tls.issuer.CN || JSON.stringify(tls.issuer)) : String(tls.issuer || 'N/A')}
                </div>
              </div>
              <div>
                <span className="small muted">Subject Domain (CN):</span>
                <div style={{ marginTop: '0.25rem' }} className="small">
                  {typeof tls.subject === 'object' ? (tls.subject.CN || JSON.stringify(tls.subject)) : String(tls.subject || 'N/A')}
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {activeTab === 'crawl' && (
        <div style={{ display: 'grid', gap: '1.5rem' }}>
          <section className="card">
            <div className="card-head">
              <h2 className="m-0">Discovered Endpoints ({endpoints.length})</h2>
            </div>
            {!endpoints.length ? (
              <div className="empty">Only root target was inspected. Run an Active Crawl to map endpoints.</div>
            ) : (
              <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.35rem' }}>
                {endpoints.map((ep, i) => (
                  <li key={i} className="small">
                    <a href={ep} target="_blank" rel="noopener noreferrer">
                      {ep}
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <div className="card-head">
              <h2 className="m-0">Discovered HTML Forms &amp; Inputs ({forms.length})</h2>
            </div>
            {!forms.length ? (
              <div className="empty">No HTML forms were detected on the crawled pages.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Page URL</th>
                      <th scope="col">Form Action</th>
                      <th scope="col">Method</th>
                      <th scope="col">Detected Input Parameters</th>
                    </tr>
                  </thead>
                  <tbody>
                    {forms.map((f, i) => (
                      <tr key={i}>
                        <td className="small">{f.pageUrl}</td>
                        <td className="small"><code>{f.action || '(self)'}</code></td>
                        <td><span className="badge">{f.method || 'GET'}</span></td>
                        <td>
                          {Array.isArray(f.inputs) && f.inputs.length ? (
                            <div className="row" style={{ gap: '0.25rem', flexWrap: 'wrap' }}>
                              {f.inputs.map((inp, idx) => (
                                <code key={idx} className="small">{inp.name || inp.type}</code>
                              ))}
                            </div>
                          ) : (
                            <span className="muted">None</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {exposedFiles.length > 0 && (
            <section className="card" style={{ borderColor: 'var(--color-critical)' }}>
              <div className="card-head">
                <h2 className="m-0" style={{ color: 'var(--color-critical)' }}>
                  Potentially Exposed Sensitive Files ({exposedFiles.length})
                </h2>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.35rem' }}>
                {exposedFiles.map((ef, i) => (
                  <li key={i} className="small">
                    <strong>{ef.path}:</strong> status {ef.status} ({ef.reason || 'Exposed'})
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}

      {activeTab === 'technologies' && (
        <section className="card">
          <div className="card-head">
            <h2 className="m-0">Technology Stack &amp; Fingerprints ({tech.length})</h2>
          </div>
          {!tech.length ? (
            <div className="empty">No specific technology signatures detected.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Technology</th>
                    <th scope="col">Category</th>
                    <th scope="col">Detected Version</th>
                    <th scope="col">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {tech.map((t, i) => (
                    <tr key={i}>
                      <td><strong>{t.name}</strong></td>
                      <td><span className="badge">{t.category}</span></td>
                      <td>{t.version ? <code>{t.version}</code> : <span className="muted">Undetermined</span>}</td>
                      <td>{t.confidence || 100}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
