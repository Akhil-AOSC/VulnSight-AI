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
            <div className="sidebar-user-card">
              <div className="user-avatar" aria-hidden="true">
                {(me.name || me.email || 'U')[0].toUpperCase()}
              </div>
              <div className="user-info">
                <span className="user-name" title={me.name || me.email}>
                  {me.name || me.email.split('@')[0]}
                </span>
                <span className="user-email" title={me.email}>
                  {me.email}
                </span>
              </div>
            </div>

            <div className="sidebar-org-group">
              <label htmlFor="sidebar-org-select" className="sidebar-section-label">
                <svg className="sidebar-icon" width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M1.75 2.5a.25.25 0 0 0-.25.25v10.5c0 .138.112.25.25.25h12.5a.25.25 0 0 0 .25-.25V2.75a.25.25 0 0 0-.25-.25H1.75ZM0 2.75C0 1.784.784 1 1.75 1h12.5c.966 0 1.75.784 1.75 1.75v10.5A1.75 1.75 0 0 1 14.25 15H1.75A1.75 1.75 0 0 1 0 13.25V2.75ZM4.5 4a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 4.5 4Zm0 4.5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 4.5 8.5ZM8 4a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 8 4Zm0 4.5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 8 8.5Zm3.5-4.5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 11.5 4Zm0 4.5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5a.75.75 0 0 1 .75-.75Z" />
                </svg>
                <span>Organisation</span>
              </label>
              <select
                id="sidebar-org-select"
                aria-label="Organisation"
                value={orgId}
                onChange={(e) => handleOrgChange(e.target.value)}
                className="sidebar-org-select"
              >
                {me.orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name} ({o.role})
                  </option>
                ))}
              </select>
            </div>

            <div className="sidebar-actions-row">
              <button
                type="button"
                className="sidebar-action-btn theme-toggle-btn"
                onClick={handleToggleTheme}
                title={isDark ? 'Switch to Light mode' : 'Switch to Dark mode'}
              >
                {isDark ? (
                  <>
                    <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6Zm0 1.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9ZM8 0a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0V.75A.75.75 0 0 1 8 0Zm0 13a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 8 13ZM2.343 2.343a.75.75 0 0 1 1.061 0l1.06 1.061a.75.75 0 0 1-1.06 1.06l-1.06-1.06a.75.75 0 0 1 0-1.061Zm9.193 9.193a.75.75 0 0 1 1.06 0l1.061 1.06a.75.75 0 0 1-1.06 1.061l-1.061-1.06a.75.75 0 0 1 0-1.061ZM0 8a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 0 1.5H.75A.75.75 0 0 1 0 8Zm13 0a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 0 1.5h-1.5A.75.75 0 0 1 13 8ZM2.343 13.657a.75.75 0 0 1 0-1.06l1.06-1.061a.75.75 0 1 1 1.061 1.06l-1.06 1.061a.75.75 0 0 1-1.061 0Zm9.193-9.193a.75.75 0 0 1 0-1.06l1.061-1.061a.75.75 0 1 1 1.06 1.06l-1.06 1.061a.75.75 0 0 1-1.061 0Z"/>
                    </svg>
                    <span>Light</span>
                  </>
                ) : (
                  <>
                    <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M9.598 1.591a.749.749 0 0 1 .785-.175 7.001 7.001 0 1 1-8.967 8.967.75.75 0 0 1 .961-.96 5.5 5.5 0 0 0 7.046-7.046.75.75 0 0 1 .175-.786Zm1.616 1.945a7 7 0 0 1-7.678 7.678A5.499 5.499 0 1 0 11.214 3.536Z"/>
                    </svg>
                    <span>Dark</span>
                  </>
                )}
              </button>
              <button
                type="button"
                className="sidebar-action-btn logout-btn"
                onClick={handleLogout}
                title="Sign out of VulnSight AI"
              >
                <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M2 2.75C2 1.784 2.784 1 3.75 1h2.5a.75.75 0 0 1 0 1.5h-2.5a.25.25 0 0 0-.25.25v10.5c0 .138.112.25.25.25h2.5a.75.75 0 0 1 0 1.5h-2.5A1.75 1.75 0 0 1 2 13.25V2.75Zm10.44 4.5-1.97-1.97a.749.749 0 0 1 .326-1.275.749.749 0 0 1 .734.215l3.25 3.25a.75.75 0 0 1 0 1.06l-3.25 3.25a.749.749 0 0 1-1.275-.326.749.749 0 0 1 .215-.734l1.97-1.97H6.75a.75.75 0 0 1 0-1.5h5.69Z"/>
                </svg>
                <span>Sign out</span>
              </button>
            </div>
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
