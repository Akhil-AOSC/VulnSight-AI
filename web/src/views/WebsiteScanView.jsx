import React, { useEffect, useState } from 'react';
import { api, fmtDate, pad, toast } from '../api.js';
import { PageHead, StatCard, SevBadge, StatusBadge, AiBriefingCard, DataTable, Skeleton, ScanSkeletonLoader } from '../components/Common.jsx';
import { buildScanStory, livePipelineState } from '../../../src/adapters/dast/scan-story.js';

function TabSkeletonLoader({ tabKey }) {
  const titles = {
    findings: 'Vulnerability Analysis',
    headers: 'HTTP Security Headers Assessment',
    cookies: 'Cookie Security Audit',
    tls: 'TLS / SSL Configuration & Certificate Status',
    edge: 'Edge, CDN & DNS',
    crawl: 'Endpoints & Forms Inventory',
    pages: 'Discovered Pages',
    technologies: 'Technology Stack & Fingerprints',
  };
  return (
    <div className="card fade-in" style={{ padding: '1.5rem', minHeight: '320px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <h2 className="m-0" style={{ fontSize: '1.15rem' }}>{titles[tabKey] || 'Loading telemetry...'}</h2>
          <span className="small muted">Populating inspected security controls...</span>
        </div>
        <Skeleton width="120px" height="1.8rem" radius="4px" />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '0.5rem 0', borderBottom: '1px solid var(--border-subtle)' }}>
            <Skeleton width="90px" height="1.2rem" radius="4px" />
            <Skeleton width="40%" height="1rem" radius="4px" />
            <Skeleton width="22%" height="1rem" radius="4px" />
            <Skeleton width="18%" height="1rem" radius="4px" />
          </div>
        ))}
      </div>
    </div>
  );
}

// Who sits in front of the site (CDN / WAF), the evidence for it, and the domain's email and
// certificate DNS policy. Everything shown was observed by the scanner: DNS answers, IP ownership
// and what the edge itself returned. Cookie values are never stored, only their names.
function EdgeField({ label, children }) {
  return (
    <div>
      <span className="small muted">{label}</span>
      <div style={{ marginTop: '0.25rem' }}>{children}</div>
    </div>
  );
}

function SimpleTable({ head, rows, empty }) {
  if (!rows.length) return <div className="empty">{empty}</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{head.map((h) => <th key={h} scope="col">{h}</th>)}</tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  );
}

export function EdgePanel({ edge, emailDns, hostname }) {
  if (!edge && !emailDns) {
    return (
      <section className="card">
        <div className="card-head"><h2 className="m-0">Edge &amp; CDN</h2></div>
        <div className="empty">Edge and DNS details are recorded for scans run after this feature was added. Run a new scan to see them.</div>
      </section>
    );
  }
  const e = edge || { signals: [], dns: {}, edgeHeaders: {}, cookieNames: [], botProtection: {} };
  const bot = e.botProtection || {};
  const ray = e.edgeHeaders && e.edgeHeaders.ray;
  const records = [
    ...((e.dns && e.dns.nameservers) || []).map((v) => ({ type: 'NS', value: v, owner: e.dnsHost })),
    ...((e.dns && e.dns.ipv4) || []).map((r) => ({ type: 'A', value: r.ip, owner: r.owner })),
    ...((e.dns && e.dns.ipv6) || []).map((r) => ({ type: 'AAAA', value: r.ip, owner: r.owner })),
  ];
  const headerRows = [
    ['server', e.edgeHeaders && e.edgeHeaders.server],
    ['cf-ray', ray && (ray.code ? `${ray.id}-${ray.code}` : ray.id)],
    ['cf-cache-status', e.edgeHeaders && e.edgeHeaders.cacheStatus],
    ['cf-mitigated', e.edgeHeaders && e.edgeHeaders.mitigated],
    ['via', e.edgeHeaders && e.edgeHeaders.via],
  ].filter(([, v]) => v);
  const policyRows = emailDns ? [
    ['SPF', emailDns.domain, emailDns.spf],
    ['DMARC', `_dmarc.${emailDns.domain}`, emailDns.dmarc],
    ...((emailDns.caa && emailDns.caa.length) ? emailDns.caa.map((c) => ['CAA', emailDns.domain, c]) : [['CAA', emailDns.domain, null]]),
  ] : [];

  return (
    <div style={{ display: 'grid', gap: '1.5rem' }}>
      {edge && (
        <section className="card">
          <div className="card-head">
            <h2 className="m-0">Edge &amp; CDN</h2>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
            <EdgeField label="Provider in front of the site">
              {e.provider ? (
                <span><strong>{e.provider}</strong> <span className="badge">{e.confidence === 'confirmed' ? 'Confirmed' : 'Likely'}</span></span>
              ) : <span className="muted">No CDN or WAF detected</span>}
            </EdgeField>
            <EdgeField label="Origin server">
              {e.originHidden
                ? <span>Hidden behind {e.provider || 'the edge'}</span>
                : <span>Public addresses are not all in a known CDN range</span>}
            </EdgeField>
            <EdgeField label="Bot protection">
              {bot.challenged ? (
                <span>
                  <span className="badge st-blocked">{bot.kind || 'Challenged'}</span>
                  <span className="small muted"> HTTP {bot.statusCode}{bot.pageTitle ? ` · "${bot.pageTitle}"` : ''}</span>
                </span>
              ) : <span>Not challenged{bot.statusCode ? <span className="small muted"> · HTTP {bot.statusCode}</span> : null}</span>}
            </EdgeField>
            <EdgeField label="Data centre that answered">
              {ray && ray.code ? <span><code>{ray.code}</code>{ray.city ? ` ${ray.city}` : ''}</span> : <span className="muted">Not reported</span>}
            </EdgeField>
            <EdgeField label="DNS hosted by">
              {e.dnsHost ? <span>{e.dnsHost}</span> : <span className="muted">Unknown</span>}
            </EdgeField>
            <EdgeField label="Edge certificate">
              {e.tls ? (
                <span className="small">{e.tls.issuer || 'Unknown issuer'}{e.tls.protocol ? ` · ${e.tls.protocol}` : ''}</span>
              ) : <span className="muted">Not available</span>}
            </EdgeField>
          </div>
          {bot.challenged && (
            <p className="small muted" style={{ marginTop: '1.25rem', marginBottom: 0 }}>
              {bot.by || e.provider || 'The edge'} answered the scanner with a challenge, so checks that read the page were skipped.
              {' '}To scan {hostname || 'this site'} fully, allow the scanner IP in that firewall.
            </p>
          )}
        </section>
      )}

      {edge && (
        <section className="card">
          <div className="card-head"><h2 className="m-0">Evidence ({(e.signals || []).length})</h2></div>
          <SimpleTable
            head={['Source', 'What was observed']}
            empty="No CDN or WAF signals were observed."
            rows={(e.signals || []).map((sig, i) => (
              <tr key={i}><td>{sig.source}</td><td><code>{sig.detail}</code></td></tr>
            ))}
          />
        </section>
      )}

      {edge && (
        <section className="card">
          <div className="card-head"><h2 className="m-0">DNS records ({records.length})</h2></div>
          <SimpleTable
            head={['Type', 'Value', 'Belongs to']}
            empty="DNS records could not be resolved."
            rows={records.map((r, i) => (
              <tr key={i}>
                <td><span className="badge">{r.type}</span></td>
                <td><code>{r.value}</code></td>
                <td>{r.owner || <span className="muted">Not a known CDN range</span>}</td>
              </tr>
            ))}
          />
        </section>
      )}

      {emailDns && (
        <section className="card">
          <div className="card-head"><h2 className="m-0">Email and certificate policy ({emailDns.domain})</h2></div>
          <SimpleTable
            head={['Record', 'Name', 'Value']}
            empty="No policy records were checked."
            rows={policyRows.map(([type, name, value], i) => (
              <tr key={i}>
                <td><span className="badge">{type}</span></td>
                <td><code>{name}</code></td>
                <td>{value ? <code>{value}</code> : <span className="muted">Not published</span>}</td>
              </tr>
            ))}
          />
        </section>
      )}

      {edge && (
        <section className="card">
          <div className="card-head"><h2 className="m-0">Edge response</h2></div>
          <SimpleTable
            head={['Header or cookie', 'Value']}
            empty="The edge returned no identifying headers or cookies."
            rows={[
              ...headerRows.map(([name, value]) => (
                <tr key={name}><td><code>{name}</code></td><td><code>{value}</code></td></tr>
              )),
              ...(e.cookieNames || []).map((name) => (
                <tr key={`c-${name}`}><td><code>Set-Cookie: {name}</code></td><td className="muted">Value not stored</td></tr>
              )),
            ]}
          />
        </section>
      )}
    </div>
  );
}

export function WebsiteScanView({ websiteId, scanId }) {
  const [scan, setScan] = useState(null);
  const [site, setSite] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('findings');
  const [tabLoading, setTabLoading] = useState(false);
  const [sevFilter, setSevFilter] = useState('all');
  const [scannerFilter, setScannerFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [findingPage, setFindingPage] = useState(1);
  const FINDINGS_PAGE_SIZE = 30;
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [crawlPages, setCrawlPages] = useState([]);
  const [crawlEndpoints, setCrawlEndpoints] = useState([]);
  const [crawlForms, setCrawlForms] = useState([]);

  async function loadCrawlInventory(wid, sid, scanData) {
    const [pages, endpointsList, formsList] = await Promise.all([
      api.get(api.org(`/websites/${wid}/scans/${sid}/pages`)).catch(() => []),
      api.get(api.org(`/websites/${wid}/scans/${sid}/endpoints`)).catch(() => []),
      api.get(api.org(`/websites/${wid}/scans/${sid}/forms`)).catch(() => []),
    ]);
    let nextPages = pages || [];
    if (!nextPages.length) {
      const urls = (scanData && scanData.passiveResults && scanData.passiveResults.crawledUrls) || [];
      nextPages = urls.filter(Boolean).map((url) => ({ url, urlHash: url, depth: 0, statusCode: 0, title: '' }));
    }
    setCrawlPages(nextPages);
    setCrawlEndpoints(endpointsList || []);
    setCrawlForms(formsList || []);
  }
  const [explanations, setExplanations] = useState({});
  const [explainingId, setExplainingId] = useState(null);

  function handleTabChange(nextKey) {
    if (nextKey === activeTab) return;
    setTabLoading(true);
    setActiveTab(nextKey);
    setTimeout(() => {
      setTabLoading(false);
    }, 180);
  }

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
        if (scanData && !['queued', 'running', 'paused'].includes(scanData.status)) {
          await loadCrawlInventory(websiteId, scanId, scanData);
        }
      } catch (err) {
        toast(err.message || 'Failed to load website scan details', 'error');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [websiteId, scanId]);

  useEffect(() => {
    if (!scan || !['queued', 'running', 'paused'].includes(scan.status)) return;
    const timer = setInterval(async () => {
      try {
        const scanData = await api.get(api.org(`/websites/${websiteId}/scans/${scanId}`));
        if (scanData) {
          setScan(scanData);
          if (!['queued', 'running', 'paused'].includes(scanData.status)) {
            await loadCrawlInventory(websiteId, scanId, scanData);
            toast('Website security scan complete');
          }
        }
      } catch {}
    }, 1500);
    return () => clearInterval(timer);
  }, [scan, websiteId, scanId]);

  async function handleExplain(finding, event) {
    if (event) event.stopPropagation();
    if (!finding || !finding.id) return;
    if (explanations[finding.id]) {
      setExpandedFinding(finding.id);
      return;
    }
    try {
      setExplainingId(finding.id);
      const res = await api.post(
        api.org(`/websites/${websiteId}/scans/${scanId}/findings/${encodeURIComponent(finding.id)}/explain`)
      );
      setExplanations((prev) => ({ ...prev, [finding.id]: res }));
      setExpandedFinding(finding.id);
    } catch (err) {
      toast(err.message || 'Could not explain this finding', 'error');
    } finally {
      setExplainingId(null);
    }
  }

  async function handleDownloadReport(format) {
    const ext = format === 'markdown' ? 'md' : format;
    try {
      await api.download(
        api.org(`/websites/${websiteId}/scans/${scanId}/report?format=${format}`),
        `vulnsight-dast-${scanId}.${ext}`
      );
      toast(`Downloaded report in ${format.toUpperCase()} format`);
    } catch (err) {
      toast(err.message || 'Report download failed', 'error');
    }
  }

  if (loading && !scan) {
    return (
      <div className="view">
        <ScanSkeletonLoader cards={5} hasTabs={true} rows={5} />
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
  const zapEngine = (s.engines || []).find((eng) => eng && eng.name === 'owasp-zap-ascan') || null;
  const zapAlertCount = zapEngine && zapEngine.findings != null ? Number(zapEngine.findings) : 0;
  const zapBySeverity = zapEngine && zapEngine.bySeverity ? zapEngine.bySeverity : null;
  const tech = passive.technologies || [];
  const tls = passive.tls;
  const edge = passive.edgeIntel || null;
  const emailDns = passive.emailDns || null;
  const headersData = passive.headers || {};
  const cookiesList = passive.cookies || [];
  const corsData = passive.cors || {};
  const endpoints = passive.crawledUrls || [];
  const forms = passive.forms || [];
  const exposedFiles = passive.exposedFiles || [];

  const filteredFindings = allFindings.filter((f) => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
    if (scannerFilter === 'zap' && !(f.scanner && f.scanner.name === 'owasp-zap-ascan') && !(f.confirmedBy || []).includes('owasp-zap-ascan')) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title && f.title.toLowerCase().includes(q);
      const matchDesc = f.description && f.description.toLowerCase().includes(q);
      const matchLoc = f.location && (f.location.url || f.location.parameter || f.location.path || '').toLowerCase().includes(q);
      if (!matchTitle && !matchDesc && !matchLoc) return false;
    }
    return true;
  });
  const findingPages = Math.max(1, Math.ceil(filteredFindings.length / FINDINGS_PAGE_SIZE));
  const findingPageSafe = Math.min(findingPage, findingPages);
  const pagedFindings = filteredFindings.slice(
    (findingPageSafe - 1) * FINDINGS_PAGE_SIZE,
    findingPageSafe * FINDINGS_PAGE_SIZE,
  );

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
            {' '}&middot; Profile: <strong>{scan.profile}</strong>
            {' '}&middot; Status: <StatusBadge status={scan.status} />
            {' '}&middot; Auth: {(() => {
              const a = site.authorization || {};
              if (a.status === 'authorized' || a.status === 'verified' || a.status === 'active') {
                const src = a.source === 'dns_http' ? 'DNS/HTTP (no active testing unless stored)'
                  : a.source === 'lab' ? 'lab allowlist'
                    : a.source === 'org_engagement' ? 'org engagement'
                      : a.source === 'client_grant' ? 'site grant' : 'authorized';
                return `${src}${a.allowActiveTesting || scan.authorizeActiveTesting ? ', active testing permitted' : ''}`;
              }
              if (a.status === 'expired') return 'expired';
              if (a.status === 'revoked') return 'revoked';
              if (a.status === 'denied') return 'outside approved scope';
              const profile = String(scan.profile || '');
              if (profile === 'passive' || profile === 'public' || profile === 'public_assessment') {
                return 'not required for public assessment';
              }
              return 'not configured';
            })()}
            {' '}&middot; Finished: {fmtDate(scan.finishedAt || scan.createdAt)}
          </div>
        </div>

        <div className="row" style={{ gap: '0.5rem' }}>
          {['queued', 'running', 'paused'].includes(scan.status) && (
            <button
              type="button"
              className="btn btn-sm btn-subtle"
              onClick={async () => {
                try {
                  const next = await api.post(api.org(`/websites/${websiteId}/scans/${scanId}/cancel`));
                  setScan(next);
                  toast('Crawl cancelled');
                } catch (err) {
                  toast(err.message, 'error');
                }
              }}
            >
              Cancel crawl
            </button>
          )}
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

      {(scan.status === 'queued' || scan.status === 'running') ? (
        <div className="fade-in">
          {(() => {
            const progress = scan.progress || {};
            const pipeline = livePipelineState(scan.profile, { status: scan.status, progress });
            const log = Array.isArray(progress.log) ? progress.log : [];
            const percent = progress.percent != null ? Number(progress.percent) : null;
            const ahead = scan.queue && scan.queue.jobsAhead != null ? scan.queue.jobsAhead : 0;
            const current = pipeline.find((s) => s.state === 'current');
            const headline = scan.status === 'queued'
              ? (ahead > 0 ? `Queued behind ${ahead} other website job${ahead === 1 ? '' : 's'}` : 'Queued for the inspection worker')
              : (current ? current.label : 'Inspection running');
            const blocking = scan.queue && scan.queue.blocking;
            const detail = scan.status === 'queued'
              ? (blocking
                ? `Waiting on ${blocking.hostname} (${blocking.profile}${blocking.engine ? ` · ${blocking.engine}` : ''})`
                : 'One worker runs one website scan at a time. A long ZAP active scan holds the next job until it finishes.')
              : [
                progress.engine || scan.engine,
                progress.pages != null ? `${progress.pages} pages` : null,
                percent != null ? `${percent}% of ZAP ascan` : null,
              ].filter(Boolean).join(' · ');
            return (
              <div className="card scan-progress-banner">
                <div className="scan-progress-top">
                  <div className="scan-progress-title">
                    <span className="scan-radar-dot" aria-hidden="true" />
                    <span>{headline}</span>
                  </div>
                  <span className="badge st-running">{scan.status === 'queued' ? 'Queued' : 'Running'}</span>
                </div>
                <p className="muted small" style={{ margin: 0 }}>{detail}</p>
                <div className="scan-progress-bar-wrap">
                  {percent != null && scan.status === 'running' ? (
                    <div className="scan-progress-bar-fill" style={{ width: `${Math.max(0, Math.min(100, percent))}%` }} />
                  ) : (
                    <div className="scan-progress-bar-indeterminate" />
                  )}
                </div>
                <ol className="scan-live-pipeline">
                  {pipeline.map((step) => (
                    <li key={step.id} className={`scan-live-step is-${step.state}`}>
                      <span className="scan-live-tick" aria-hidden="true" />
                      <span className="scan-live-label">{step.label}</span>
                      <span className="scan-live-state">{step.state}</span>
                    </li>
                  ))}
                </ol>
                <div className="scan-live-log" role="log" aria-live="polite">
                  <div className="scan-live-log-head">Engine log</div>
                  {log.length ? log.slice().reverse().slice(0, 12).map((row, i) => (
                    <div key={`${row.at || 't'}-${i}`} className="scan-live-log-row">
                      <span className="scan-live-log-time">{row.at ? String(row.at).slice(11, 19) : '--:--:--'}</span>
                      <span className="scan-live-log-msg">{row.message || row.engine || row.stage}</span>
                    </div>
                  )) : (
                    <div className="scan-live-log-row">
                      <span className="scan-live-log-time">--:--:--</span>
                      <span className="scan-live-log-msg">Waiting for the first engine event</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          <div className="stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            {['Security Posture', 'Critical Severity', 'High Severity', 'Medium & Low', 'Endpoints Inspected'].map((label, idx) => (
              <div key={idx} className="card skeleton-stat-card">
                <Skeleton width="48px" height="2rem" style={{ marginBottom: '0.4rem' }} radius="4px" />
                <span className="muted small">{label}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <>
          {scan.status === 'failed' && scan.error && (
            <div className="card" style={{ marginBottom: '1rem', padding: '12px 16px', borderColor: 'var(--color-danger, #b42318)' }}>
              <strong>Scan failed</strong>
              <p className="small" style={{ margin: '4px 0 0' }}>{scan.error}</p>
            </div>
          )}
          {s.partial && (
            <div className="card" style={{ marginBottom: '16px', padding: '12px 16px', borderColor: 'var(--color-warning, #b54708)' }}>
              <strong>Incomplete assessment</strong>
              <p className="small" style={{ margin: '4px 0 0' }}>
                One or more engines were skipped, blocked, or stopped before finishing. Findings below are only from engines that ran.
                Any number shown as posture is a partial score, not a complete assessment.
              </p>
            </div>
          )}
          {(() => {
            const story = s.story && s.story.stages && s.story.stages.length
              ? s.story
              : (Array.isArray(s.engines) && s.engines.length
                ? buildScanStory({
                  engines: s.engines,
                  partial: Boolean(s.partial),
                  blockedBy: s.blockedBy,
                  profile: scan.profile,
                  pages: crawlPages.length || s.pages || 0,
                  findings: s.total || allFindings.length || 0,
                })
                : null);
            if (!story) return null;
            return (
              <section className={`card scan-story${s.partial ? ' is-incomplete' : ''}`}>
                <h2>{story.headline}</h2>
                <p className="scan-story-readout">{story.readout}</p>
                <div className="scan-story-stages">
                  {(story.stages || []).map((stage) => (
                    <div key={stage.name} className="scan-story-stage">
                      <span className={`scan-story-tick ${stage.status}`} aria-hidden="true" />
                      <div>
                        <span className="scan-story-label">{stage.label}</span>
                        <span className="scan-story-meta">{stage.status}{stage.findings ? ` · ${stage.findings} finding${stage.findings === 1 ? '' : 's'}` : ''}</span>
                      </div>
                      <div>
                        <p className="scan-story-why">{stage.why}</p>
                        <p className="scan-story-does">{stage.does}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            );
          })()}
          {Array.isArray(s.engines) && s.engines.length > 0 && (
            <section className="card" style={{ marginBottom: '16px' }}>
              <div className="card-head">
                <h2 className="m-0">Engines</h2>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">Version</th>
                      <th scope="col">Status</th>
                      <th scope="col">Findings</th>
                      <th scope="col">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.engines.map((eng) => (
                      <tr key={`${eng.name}-${eng.version || 'na'}`}>
                        <td>{eng.name}</td>
                        <td className="small muted">{eng.version || '-'}</td>
                        <td><StatusBadge status={eng.status} /></td>
                        <td className="num">
                          {eng.findings == null ? '-' : eng.findings}
                          {eng.bySeverity && (eng.findings || 0) > 0 && (
                            <div className="small muted">
                              {`C ${eng.bySeverity.critical || 0} · H ${eng.bySeverity.high || 0} · M ${eng.bySeverity.medium || 0} · L ${eng.bySeverity.low || 0}`}
                            </div>
                          )}
                        </td>
                        <td className="small muted">{eng.error || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
          <div className="stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            <StatCard
              num={scan.postureScore != null
                ? (s.partial ? `${scan.postureScore} partial` : `${scan.postureScore}/100`)
                : 'N/A'}
              label={s.partial
                ? 'Partial score, not a complete assessment'
                : `Security Posture (Grade ${s.grade || 'N/A'})`}
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
            {zapAlertCount > 0 && (
              <StatCard
                num={pad(zapAlertCount)}
                label={zapBySeverity
                  ? `ZAP alerts (C ${zapBySeverity.critical || 0} · H ${zapBySeverity.high || 0} · M ${zapBySeverity.medium || 0} · L ${zapBySeverity.low || 0})`
                  : 'ZAP active scan alerts'}
              />
            )}
          </div>

      {scan.aiAnalysis && (
        <div style={{ marginBottom: '1.5rem' }}>
          <AiBriefingCard ai={scan.aiAnalysis} />
        </div>
      )}

      <div className="tab-nav" style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--color-border)', marginBottom: '1rem' }}>
        {[
          ['findings', zapAlertCount > 0
            ? `Vulnerabilities (${allFindings.length} unique · ${zapAlertCount} ZAP alerts)`
            : `Vulnerabilities (${allFindings.length})`],
          ['headers', 'Security Headers & CORS'],
          ['cookies', `Cookies (${cookiesList.length})`],
          ['tls', 'TLS / SSL Configuration'],
          ['edge', edge && edge.provider ? `Edge & CDN (${edge.provider})` : 'Edge & CDN'],
          ['crawl', `Endpoints & Forms (${crawlEndpoints.length || endpoints.length})`],
          ['pages', `Pages (${crawlPages.length || s.pages || 0})`],
          ['technologies', `Technologies (${tech.length})`],
        ].map(([key, label]) => (
          <button
            key={key}
            type="button"
            className={`tab-btn ${activeTab === key ? 'active' : ''}`}
            onClick={() => handleTabChange(key)}
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

      {tabLoading ? (
        <TabSkeletonLoader tabKey={activeTab} />
      ) : (
        <>
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
                    onClick={() => { setSevFilter(level); setFindingPage(1); }}
                  >
                    {level.toUpperCase()}
                  </button>
                ))}
                {zapAlertCount > 0 && (
                  <button
                    type="button"
                    className={`btn btn-sm ${scannerFilter === 'zap' ? 'btn-primary' : 'btn-subtle'}`}
                    onClick={() => { setScannerFilter(scannerFilter === 'zap' ? 'all' : 'zap'); setFindingPage(1); }}
                  >
                    ZAP only
                  </button>
                )}
              </div>
              <input
                type="search"
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setFindingPage(1); }}
                style={{ minWidth: '220px' }}
              />
            </div>
          </div>

          {zapAlertCount > allFindings.length && (
            <p className="small muted" style={{ margin: '0 0 12px' }}>
              This saved scan stored {allFindings.length} unique issues. ZAP reported {zapAlertCount} alerts
              {zapBySeverity
                ? ` (critical ${zapBySeverity.critical || 0}, high ${zapBySeverity.high || 0}, medium ${zapBySeverity.medium || 0}, low ${zapBySeverity.low || 0})`
                : ''}
              . Re-run Deep to list every ZAP alert with its severity in this table.
            </p>
          )}
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
                    <th scope="col">Confirmed by</th>
                    <th scope="col">Recommended Remediation</th>
                    <th scope="col" style={{ width: '80px' }}>Details</th>
                    <th scope="col" style={{ width: '120px' }}>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedFindings.map((f) => (
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
                          {f.confidence === 'potential' && (
                            <div className="small muted">Version-based match · not a confirmed exploit</div>
                          )}
                          {f.scanner && (
                            <div className="small muted">{f.scanner.name || f.scanner}</div>
                          )}
                        </td>
                        <td>
                          <code className="small">
                            {(f.location && (f.location.url || f.location.parameter || f.location.path)) || site.targetUrl}
                          </code>
                        </td>
                        <td className="small muted">
                          {(f.confirmedBy && f.confirmedBy.length ? f.confirmedBy : [f.scanner && f.scanner.name].filter(Boolean)).join(', ') || '-'}
                        </td>
                        <td className="small">
                          {(f.remediation && (f.remediation.advice || f.remediation.fixedIn)) || 'Review configuration'}
                        </td>
                        <td>
                          <button type="button" className="btn btn-sm btn-subtle">
                            {expandedFinding === f.id ? 'Hide' : 'View'}
                          </button>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-sm btn-primary"
                            disabled={explainingId === f.id}
                            onClick={(e) => handleExplain(f, e)}
                          >
                            {explainingId === f.id ? 'Writing...' : explanations[f.id] ? 'Show' : 'Explain'}
                          </button>
                        </td>
                      </tr>
                      {expandedFinding === f.id && (
                        <tr>
                          <td colSpan={7} style={{ background: 'var(--color-bg)', padding: '1rem' }}>
                            <div style={{ display: 'grid', gap: '0.5rem' }}>
                              {explanations[f.id] && (
                                <div>
                                  <strong>In plain English</strong>
                                  <span className="small muted">
                                    {' '}({explanations[f.id].source === 'ai' ? 'AI' : 'built-in explainer'})
                                  </span>
                                  <p style={{ margin: '0.4rem 0 0.75rem' }}>{explanations[f.id].text}</p>
                                </div>
                              )}
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
          {filteredFindings.length > 0 && (
            <div className="pager" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', padding: '12px 16px', borderTop: '1px solid var(--color-border)' }}>
              <span className="small muted">
                {((findingPageSafe - 1) * FINDINGS_PAGE_SIZE) + 1}
                –
                {Math.min(findingPageSafe * FINDINGS_PAGE_SIZE, filteredFindings.length)}
                {' '}of {filteredFindings.length}
                {' '}· page {findingPageSafe} of {findingPages}
                {' '}({FINDINGS_PAGE_SIZE} per page)
              </span>
              <div className="row" style={{ gap: '8px' }}>
                <button
                  type="button"
                  className="btn btn-sm btn-subtle"
                  disabled={findingPageSafe <= 1}
                  onClick={() => setFindingPage((p) => Math.max(1, p - 1))}
                >
                  Previous
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-subtle"
                  disabled={findingPageSafe >= findingPages}
                  onClick={() => setFindingPage((p) => Math.min(findingPages, p + 1))}
                >
                  Next
                </button>
              </div>
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
                  <span className={`badge ${(tls.valid || tls.authorized) ? 'sev-low' : 'sev-critical'}`}>
                    {(tls.valid || tls.authorized)
                      ? 'Trusted and valid'
                      : `Untrusted${tls.authError || tls.authorizationError ? `: ${tls.authError || tls.authorizationError}` : ''}`}
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
                  <code>{typeof tls.cipher === 'string' ? tls.cipher : (tls.cipher && tls.cipher.name) || 'Unknown'}</code>
                </div>
              </div>
              <div>
                <span className="small muted">Certificate Expiry:</span>
                <div style={{ marginTop: '0.25rem' }}>
                  <strong>{tls.validTo ? fmtDate(tls.validTo) : 'N/A'}</strong>
                  {(tls.daysLeft != null || tls.daysRemaining != null) && (
                    <span className="small muted"> ({tls.daysLeft != null ? tls.daysLeft : tls.daysRemaining} days remaining)</span>
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

      {activeTab === 'edge' && (
        <EdgePanel edge={edge} emailDns={emailDns} hostname={site && site.hostname} />
      )}

      {activeTab === 'crawl' && (
        <div style={{ display: 'grid', gap: '1.5rem' }}>
          <section className="card">
            <div className="card-head">
              <h2 className="m-0">Discovered Endpoints ({(crawlEndpoints.length || endpoints.length)})</h2>
            </div>
            {!(crawlEndpoints.length || endpoints.length) ? (
              <div className="empty">Only the seed URL was inspected. Run Crawl site after verification to map GET endpoints.</div>
            ) : crawlEndpoints.length ? (
              <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.35rem' }}>
                {crawlEndpoints.map((ep, i) => (
                  <li key={i} className="small">
                    <span className="badge">{ep.method}</span>{' '}
                    <a href={ep.url} target="_blank" rel="noopener noreferrer">{ep.url}</a>
                    {ep.statusCode ? ` · ${ep.statusCode}` : ''}
                  </li>
                ))}
              </ul>
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
              <h2 className="m-0">Discovered HTML Forms ({crawlForms.length || forms.length}) (not submitted)</h2>
            </div>
            {!(crawlForms.length || forms.length) ? (
              <div className="empty">No HTML forms were detected. Forms are never submitted during this crawl.</div>
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

      {activeTab === 'pages' && (
        <section className="card">
          <div className="card-head">
            <h2 className="m-0">Discovered pages ({crawlPages.length})</h2>
          </div>
          {!crawlPages.length ? (
            <div className="empty">No page URLs were stored for this scan. The endpoint count above comes from the engine summary, not this list.</div>
          ) : (
            <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.35rem' }}>
              {crawlPages.map((page) => (
                <li key={page.urlHash || page.url} className="small">
                  depth {page.depth} · {page.statusCode || '-'} · {page.title || 'untitled'} ·{' '}
                  <a href={page.url} target="_blank" rel="noopener noreferrer">{page.url}</a>
                </li>
              ))}
            </ul>
          )}
          {(() => {
            const loadedScripts = (crawlEndpoints || []).filter((ep) => (
              /javascript|ecmascript/i.test(ep.contentType || '') || /\.js(\?|$)/i.test(ep.url || '')
            ));
            const unique = [...new Map(loadedScripts.map((ep) => [ep.url, ep])).values()];
            if (!unique.length) return null;
            return (
              <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--color-border)' }}>
                <h3 className="m-0" style={{ fontSize: '14px', marginBottom: '8px' }}>Loaded scripts ({unique.length})</h3>
                <p className="small muted" style={{ margin: '0 0 8px' }}>
                  In-scope JavaScript URLs from the headless browser (not Chrome DevTools, not edge challenge scripts).
                </p>
                <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.35rem' }}>
                  {unique.slice(0, 80).map((ep) => (
                    <li key={ep.url} className="small">
                      <a href={ep.url} target="_blank" rel="noopener noreferrer">{ep.url}</a>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })()}
        </section>
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
        </>
      )}
        </>
      )}
    </div>
  );
}
