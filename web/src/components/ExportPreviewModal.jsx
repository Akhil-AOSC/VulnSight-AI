import React, { useEffect, useState, useMemo } from 'react';
import { api, toast } from '../api.js';
import { Markdown } from './Markdown.jsx';
import { SevBadge, Skeleton, IconCopy, IconCheck, IconDownload, IconClose, IconTable, IconFileText, IconPackage } from './Common.jsx';

function FormatIcon({ format, size = 16 }) {
  if (format === 'csv') return <IconTable size={size} />;
  if (format === 'markdown') return <IconFileText size={size} />;
  if (format === 'cyclonedx') return <IconPackage size={size} />;
  return <span style={{ fontFamily: 'var(--font-mono)', fontSize: `${size * 0.75}px`, fontWeight: 600 }}>{'{ }'}</span>;
}

const EXPORT_FORMAT_META = {
  csv: {
    label: 'CSV',
    title: 'CSV Report Preview',
    ext: 'csv',
    desc: 'Spreadsheet-ready tabular vulnerability report containing severity, CVE IDs, package versions, code locations, and triage states.',
  },
  markdown: {
    label: 'Markdown',
    title: 'Markdown Report Preview',
    ext: 'md',
    desc: 'Executive summary report with vulnerability distributions, risk posture, and actionable remediation steps formatted for documentation.',
  },
  cyclonedx: {
    label: 'SBOM (CycloneDX)',
    title: 'CycloneDX SBOM Preview (v1.5)',
    ext: 'cdx.json',
    desc: 'Industry-standard Software Bill of Materials in CycloneDX JSON format listing all detected dependencies, metadata, and advisory links.',
  },
  json: {
    label: 'JSON',
    title: 'JSON Report Preview',
    ext: 'json',
    desc: 'Complete structured JSON report payload containing scan metadata, tool execution results, findings, and remediation telemetry.',
  },
};

function parseCsv(text, maxRows = 60) {
  if (!text) return { headers: [], rows: [], totalRows: 0 };
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (!lines.length) return { headers: [], rows: [], totalRows: 0 };

  const parseLine = (line) => {
    const cells = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQuotes && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (c === ',' && !inQuotes) {
        cells.push(cur.trim());
        cur = '';
      } else {
        cur += c;
      }
    }
    cells.push(cur.trim());
    return cells;
  };

  const headers = parseLine(lines[0]);
  const rows = lines.slice(1, maxRows + 1).map(parseLine);
  return { headers, rows, totalRows: lines.length - 1 };
}

export function ExportPreviewModal({ isOpen, onClose, initialFormat = 'csv', scanId, repo, scan }) {
  const [format, setFormat] = useState(initialFormat);
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [viewMode, setViewMode] = useState('preview');
  const [copied, setCopied] = useState(false);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (initialFormat) {
      setFormat(initialFormat);
    }
  }, [initialFormat]);

  useEffect(() => {
    if (!isOpen || !scanId) return;

    let mounted = true;
    async function fetchReport() {
      setLoading(true);
      setError(null);
      try {
        const text = await api.getText(api.org(`/scans/${scanId}/report?format=${format}`));
        if (mounted) {
          setContent(text || '');
        }
      } catch (err) {
        if (mounted) {
          setError(err.message || 'Failed to generate preview for this format');
        }
      } finally {
        if (mounted) setLoading(false);
      }
    }

    fetchReport();
    return () => {
      mounted = false;
    };
  }, [isOpen, scanId, format]);

  useEffect(() => {
    if (!isOpen) return;
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
    const origOverflow = document.body.style.overflow;
    const origPadding = document.body.style.paddingRight;
    document.body.style.overflow = 'hidden';
    if (scrollbarWidth > 0) {
      document.body.style.paddingRight = `${scrollbarWidth}px`;
    }

    const onKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      document.body.style.overflow = origOverflow;
      document.body.style.paddingRight = origPadding;
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const meta = EXPORT_FORMAT_META[format] || EXPORT_FORMAT_META.csv;
  const repoName = (repo && (repo.fullName || repo.name)) || 'repository';
  const cleanRepoName = repoName.replace(/[\/\\]/g, '-');
  const filename = `${cleanRepoName}-${scanId.slice(0, 8)}.${meta.ext}`;

  async function handleDownload() {
    setDownloading(true);
    try {
      await api.download(api.org(`/scans/${scanId}/report?format=${format}`), filename);
      toast(`Downloaded ${meta.label} report: ${filename}`);
      onClose();
    } catch (err) {
      toast(err.message || 'Failed to download report', 'error');
    } finally {
      setDownloading(false);
    }
  }

  function handleCopy() {
    if (!content) return;
    navigator.clipboard.writeText(content).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast('Copied report preview to clipboard');
    });
  }

  const csvData = useMemo(() => {
    if (format !== 'csv' || !content) return null;
    return parseCsv(content);
  }, [format, content]);

  const parsedJson = useMemo(() => {
    if ((format !== 'json' && format !== 'cyclonedx') || !content) return null;
    try {
      return JSON.parse(content);
    } catch {
      return null;
    }
  }, [format, content]);

  const prettyJson = useMemo(() => {
    if (!parsedJson) return content;
    return JSON.stringify(parsedJson, null, 2);
  }, [parsedJson, content]);

  const contentSizeKb = content ? (new Blob([content]).size / 1024).toFixed(1) : '0';
  const lineCount = content ? content.split('\n').length : 0;

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="export-modal-title">
      <div className="modal-dialog export-preview-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <h2 id="export-modal-title">
              <span className="export-format-icon" aria-hidden="true"><FormatIcon format={format} size={18} /></span>
              {meta.title}
            </h2>
            <div className="modal-subtitle">
              <span>{repoName}</span>
              <span> &middot; </span>
              <span>Scan {scanId.slice(0, 8)}</span>
              <span> &middot; </span>
              <span className="export-meta-badge">.{meta.ext}</span>
            </div>
          </div>
          <button type="button" className="btn-modal-close" onClick={onClose} title="Close dialog" aria-label="Close dialog">
            <IconClose size={16} />
          </button>
        </div>

        <div className="modal-body export-modal-body">
          <div className="export-format-selector-row">
            <div className="export-format-tabs" role="tablist" aria-label="Export format selection">
              {Object.entries(EXPORT_FORMAT_META).map(([fmtKey, fmtMeta]) => (
                <button
                  key={fmtKey}
                  type="button"
                  role="tab"
                  aria-selected={format === fmtKey}
                  className={`modal-tab-btn ${format === fmtKey ? 'active' : ''}`}
                  onClick={() => setFormat(fmtKey)}
                >
                  <span style={{ marginRight: '0.4rem', display: 'inline-flex', verticalAlign: 'middle' }}>
                    <FormatIcon format={fmtKey} size={14} />
                  </span>
                  {fmtMeta.label}
                </button>
              ))}
            </div>

            <div className="export-view-toggle">
              <button
                type="button"
                className={`btn btn-sm ${viewMode === 'preview' ? 'btn-primary' : 'btn-subtle'}`}
                onClick={() => setViewMode('preview')}
                title="Switch to formatted visual preview"
              >
                {format === 'csv' ? 'Table View' : format === 'markdown' ? 'Rendered' : 'Summary'}
              </button>
              <button
                type="button"
                className={`btn btn-sm ${viewMode === 'raw' ? 'btn-primary' : 'btn-subtle'}`}
                onClick={() => setViewMode('raw')}
                title="Switch to raw file text"
              >
                Raw Text
              </button>
            </div>
          </div>

          <div className="export-format-desc muted small">
            {meta.desc}
          </div>

          <div className="export-preview-container">
            {loading ? (
              <div className="export-loading-box">
                <Skeleton width="60%" height="1.5rem" radius="4px" style={{ marginBottom: '1rem' }} />
                <Skeleton width="100%" height="70px" radius="6px" style={{ marginBottom: '0.75rem' }} />
                <Skeleton width="90%" height="70px" radius="6px" />
                <p className="muted small" style={{ marginTop: '1rem', textAlign: 'center' }}>
                  Generating {meta.label} payload preview...
                </p>
              </div>
            ) : error ? (
              <div className="card empty" style={{ color: 'var(--sev-critical)' }}>
                <p>{error}</p>
                <button type="button" className="btn btn-sm" onClick={() => setFormat(format)}>
                  Retry
                </button>
              </div>
            ) : (
              <div className="export-preview-inner fade-in">
                {/* CSV Format */}
                {format === 'csv' && (
                  viewMode === 'preview' && csvData && csvData.headers.length > 0 ? (
                    <div className="export-table-wrap">
                      <table className="export-preview-table">
                        <thead>
                          <tr>
                            {csvData.headers.map((h, i) => (
                              <th key={i}>{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {csvData.rows.map((row, rIdx) => (
                            <tr key={rIdx}>
                              {row.map((cell, cIdx) => {
                                const hLower = (csvData.headers[cIdx] || '').toLowerCase();
                                const isSev = hLower === 'severity';
                                return (
                                  <td key={cIdx} title={cell}>
                                    {isSev ? (
                                      <SevBadge severity={cell.toLowerCase()} />
                                    ) : (
                                      cell || '-'
                                    )}
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {csvData.totalRows > csvData.rows.length && (
                        <div className="export-preview-truncated-note muted small">
                          Showing first {csvData.rows.length} of {csvData.totalRows} rows. Complete dataset will be exported upon generation.
                        </div>
                      )}
                    </div>
                  ) : (
                    <pre className="prompt-pre export-code-block">{content}</pre>
                  )
                )}

                {/* Markdown Format */}
                {format === 'markdown' && (
                  viewMode === 'preview' ? (
                    <div className="export-markdown-rendered">
                      <Markdown text={content} />
                    </div>
                  ) : (
                    <pre className="prompt-pre export-code-block">{content}</pre>
                  )
                )}

                {/* CycloneDX SBOM Format */}
                {format === 'cyclonedx' && (
                  viewMode === 'preview' && parsedJson ? (
                    <div className="export-sbom-summary">
                      <div className="export-sbom-header-card">
                        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <strong>BOM Format:</strong> CycloneDX v{parsedJson.specVersion || '1.5'}
                            <span className="export-pill" style={{ marginLeft: '0.5rem' }}>
                              {parsedJson.bomFormat || 'CycloneDX'}
                            </span>
                          </div>
                          <div className="muted small">
                            SerialNumber: {parsedJson.serialNumber ? parsedJson.serialNumber.slice(0, 18) + '...' : 'urn:uuid:...'}
                          </div>
                        </div>
                        <div className="row" style={{ gap: '1.5rem', marginTop: '0.5rem' }}>
                          <span className="small"><strong>Total Components:</strong> {(parsedJson.components || []).length}</span>
                          <span className="small"><strong>Vulnerabilities Documented:</strong> {(parsedJson.vulnerabilities || []).length}</span>
                        </div>
                      </div>

                      <div className="export-table-wrap" style={{ marginTop: '0.75rem' }}>
                        <table className="export-preview-table">
                          <thead>
                            <tr>
                              <th>Component Name</th>
                              <th>Version</th>
                              <th>Type</th>
                              <th>Package URL (PURL)</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(parsedJson.components || []).slice(0, 50).map((comp, idx) => (
                              <tr key={idx}>
                                <td><strong>{comp.name}</strong></td>
                                <td><code>{comp.version || 'unknown'}</code></td>
                                <td><span className="badge">{comp.type || 'library'}</span></td>
                                <td className="small muted" style={{ fontFamily: 'var(--font-mono)' }}>{comp.purl || '-'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : (
                    <pre className="prompt-pre export-code-block">{prettyJson}</pre>
                  )
                )}

                {/* Standard JSON Format */}
                {format === 'json' && (
                  viewMode === 'preview' && parsedJson ? (
                    <div className="export-json-summary">
                      <div className="export-sbom-header-card">
                        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                            <strong>Target:</strong> {parsedJson.target?.path || repoName}
                          </div>
                          <span className="export-pill">application/json</span>
                        </div>
                        <div className="row" style={{ gap: '1.5rem', marginTop: '0.5rem' }}>
                          <span className="small"><strong>Findings:</strong> {(parsedJson.findings || []).length}</span>
                          <span className="small"><strong>Scanners:</strong> {(parsedJson.scanners || []).join(', ') || 'all'}</span>
                        </div>
                      </div>
                      <pre className="prompt-pre export-code-block" style={{ marginTop: '0.75rem' }}>{prettyJson}</pre>
                    </div>
                  ) : (
                    <pre className="prompt-pre export-code-block">{prettyJson}</pre>
                  )
                )}
              </div>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <div className="export-modal-footer-meta muted small">
            <span>Size: {contentSizeKb} KB</span>
            <span> &middot; </span>
            <span>{lineCount} lines</span>
            <span> &middot; </span>
            <button
              type="button"
              className="btn btn-sm btn-subtle"
              onClick={handleCopy}
              disabled={loading || !content}
              title="Copy preview text to clipboard"
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                {copied ? <><IconCheck size={14} /> Copied</> : <><IconCopy size={14} /> Copy</>}
              </span>
            </button>
          </div>

          <div className="row" style={{ gap: '0.75rem' }}>
            <button type="button" onClick={onClose} className="btn">
              Cancel
            </button>
            <button
              type="button"
              className="btn primary btn-generate-export"
              onClick={handleDownload}
              disabled={loading || downloading}
              title={`Generate and download ${meta.label} file`}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                {downloading ? 'Generating...' : <><IconDownload size={14} /> Download {meta.label}</>}
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

