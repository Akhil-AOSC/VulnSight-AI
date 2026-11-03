import React, { useEffect, useState, useCallback } from 'react';
import { api, session, themeStore, setUnauthorizedHandler } from './api.js';
import { ToastContainer } from './components/Common.jsx';
import { AuthView } from './views/AuthView.jsx';
import { OverviewView } from './views/OverviewView.jsx';
import { NewScanView } from './views/NewScanView.jsx';
import { ReposListView, RepoDetailView } from './views/ReposView.jsx';
import { ScanView } from './views/ScanView.jsx';
import { AssistantView } from './views/AssistantView.jsx';
import { ReportsView } from './views/ReportsView.jsx';
import { SettingsView } from './views/SettingsView.jsx';

const NAV = [
  ['overview', 'Overview'],
  ['new-scan', 'New scan'],
  ['repos', 'Repositories'],
  ['assistant', 'AI assistant'],
  ['reports', 'Reports'],
  ['settings', 'Settings'],
];

function parseHash() {
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  return { route: parts[0] || 'overview', param: parts[1] || null };
}

export function App() {
  const [me, setMe] = useState(session.me);
  const [orgId, setOrgId] = useState(session.orgId);
  const [authChecking, setAuthChecking] = useState(Boolean(session.token && !session.me));
  const [routeState, setRouteState] = useState(parseHash);
  const [currentTheme, setCurrentTheme] = useState(() => {
    const initial = themeStore.get();
    themeStore.set(initial);
    return initial;
  });

  const refreshMe = useCallback(async () => {
    if (!session.token) {
      session.me = null;
      setMe(null);
      setAuthChecking(false);
      return;
    }
    try {
      setAuthChecking(true);
      const profile = await api.get('/me');
      session.me = profile;
      if (!profile.orgs.some((o) => o.id === session.orgId)) {
        session.orgId = profile.orgs[0] && profile.orgs[0].id;
      }
      setOrgId(session.orgId);
      setMe(profile);
    } catch {
      session.token = null;
      session.me = null;
      setMe(null);
    } finally {
      setAuthChecking(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      session.token = null;
      session.me = null;
      setMe(null);
    });
    if (session.token && !session.me) {
      refreshMe();
    }
  }, [refreshMe]);

  useEffect(() => {
    const onHash = () => setRouteState(parseHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    const navLabel = (NAV.find(([k]) => k === routeState.route) || ['', 'VulnSight AI'])[1];
    document.title = `${navLabel} - VulnSight AI`;
  }, [routeState.route]);

  function handleToggleTheme() {
    const isDark =
      currentTheme === 'dark' ||
      (currentTheme === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
    const next = isDark ? 'light' : 'dark';
    themeStore.set(next);
    setCurrentTheme(next);
  }

  async function handleLogout() {
    await api.post('/auth/logout').catch(() => {});
    session.token = null;
    session.me = null;
    setMe(null);
  }

  function handleOrgChange(newOrgId) {
    session.orgId = newOrgId;
    setOrgId(newOrgId);
    location.hash = '#/overview';
  }

  if (!session.token) {
    return (
      <>
        <AuthView onAuthenticated={refreshMe} />
        <ToastContainer />
      </>
    );
  }

  if (authChecking || !me) {
    return (
      <>
        <div className="auth">
          <div className="card">Loading...</div>
        </div>
        <ToastContainer />
      </>
    );
  }

  if (!orgId) {
    return (
      <>
        <div className="auth">
          <div className="card">You are not a member of any organisation.</div>
        </div>
        <ToastContainer />
      </>
    );
  }

  const isDark =
    currentTheme === 'dark' ||
    (currentTheme === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);

  const { route, param } = routeState;

  return (
    <>
      <div className="shell">
        <aside className="sidebar">
          <div className="brand">
            <span className="brand-mark">VS</span>
            VulnSight AI
          </div>
          <nav className="nav" aria-label="Main">
            {NAV.map(([k, l]) => (
              <a
                key={k}
                href={`#/${k}`}
                aria-current={route === k ? 'page' : undefined}
              >
                {l}
              </a>
            ))}
          </nav>
          <div className="sidebar-foot">
            <select
              aria-label="Organisation"
              value={orgId}
              onChange={(e) => handleOrgChange(e.target.value)}
            >
              {me.orgs.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name} ({o.role})
                </option>
              ))}
            </select>
            <button type="button" onClick={handleToggleTheme}>
              {isDark ? 'Light mode' : 'Dark mode'}
            </button>
            <div className="small muted">{me.email}</div>
            <button type="button" onClick={handleLogout}>
              Sign out
            </button>
          </div>
        </aside>

        <main className="content" id="main" tabIndex={-1}>
          {route === 'overview' && <OverviewView key={orgId} />}
          {route === 'new-scan' && <NewScanView key={orgId} />}
          {route === 'repos' &&
            (param ? (
              <RepoDetailView key={`${orgId}-${param}`} repoId={param} />
            ) : (
              <ReposListView key={orgId} />
            ))}
          {route === 'scans' && param && <ScanView key={`${orgId}-${param}`} scanId={param} />}
          {route === 'assistant' && (
            <AssistantView key={`${orgId}-${param || ''}`} initialRepoId={param} />
          )}
          {route === 'reports' && <ReportsView key={orgId} />}
          {route === 'settings' && (
            <SettingsView
              key={`${orgId}-${param || 'profile'}`}
              tab={param || 'profile'}
              onThemeChange={setCurrentTheme}
              onMeUpdated={() => setMe({ ...session.me })}
            />
          )}
          {!['overview', 'new-scan', 'repos', 'scans', 'assistant', 'reports', 'settings'].includes(
            route
          ) && <OverviewView key={orgId} />}
        </main>
      </div>
      <ToastContainer />
    </>
  );
}
