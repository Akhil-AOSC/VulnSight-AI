import React, { useState } from 'react';
import { api, session, hasPermission, toast } from '../api.js';
import { PageHead } from '../components/Common.jsx';

export function NewScanView() {
  const [target, setTarget] = useState('');
  const [branch, setBranch] = useState('main');
  const [threshold, setThreshold] = useState('low');
  const [scanBusy, setScanBusy] = useState(false);

  const canRunScan = hasPermission(session.me, session.orgId, 'scans:run');

  async function handleQuickScan(e) {
    e.preventDefault();
    if (!target.trim()) return;
    setScanBusy(true);
    try {
      const s = await api.post(api.org('/quick-scan'), {
        target: target.trim(),
        branch: branch.trim() || 'main',
        threshold,
      });
      toast('Scan started');
      location.hash = `#/scans/${s.id}`;
    } catch (err) {
      toast(err.message || 'Failed to start scan', 'error');
    } finally {
      setScanBusy(false);
    }
  }

  return (
    <>
      <PageHead
        title="New scan"
        subtitle="Scan a project folder or Git repository for known vulnerabilities."
      />

      {canRunScan ? (
        <section className="card">
          <h2>Run a vulnerability scan</h2>
          <p className="muted small scan-sub">
            Supported: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, go.sum,
            requirements*.txt, poetry.lock, Pipfile.lock
          </p>
          <form className="inline" onSubmit={handleQuickScan}>
            <label className="grow">
              Project folder or Git URL
              <input
                type="text"
                required
                autoFocus
                size={44}
                autoComplete="off"
                placeholder="C:\path\to\project or https://github.com/owner/repo"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </label>
            <label>
              Branch
              <input
                type="text"
                size={10}
                placeholder="main"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
              />
            </label>
            <label>
              Minimum severity
              <select value={threshold} onChange={(e) => setThreshold(e.target.value)}>
                <option value="low">Low and above</option>
                <option value="medium">Medium and above</option>
                <option value="high">High and above</option>
                <option value="critical">Critical only</option>
              </select>
            </label>
            <button className="primary" type="submit" disabled={scanBusy}>
              {scanBusy ? 'Starting...' : 'Run scan'}
            </button>
          </form>
        </section>
      ) : (
        <div className="card empty">
          You do not have permission to start scans in this organisation.
        </div>
      )}
    </>
  );
}
