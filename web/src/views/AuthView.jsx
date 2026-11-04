import React, { useState } from 'react';
import { api, session } from '../api.js';

export function AuthView({ onAuthenticated }) {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const payload =
        mode === 'login'
          ? { email, password }
          : { email, password, name, orgName };
      const r = await api.post(mode === 'login' ? '/auth/login' : '/auth/signup', payload);
      session.token = r.token;
      session.orgId = r.orgId || null;
      onAuthenticated();
    } catch (ex) {
      setError(ex.message || 'Authentication failed');
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <main className="card" id="main">
        <div className="brand">
          <span className="brand-mark">VS</span>
          VulnSight AI
        </div>
        <h1>{mode === 'login' ? 'Sign in' : 'Create your account'}</h1>
        <form className="stack" onSubmit={handleSubmit}>
          {mode === 'signup' && (
            <>
              <label>
                Your name
                <input
                  type="text"
                  autoComplete="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
              <label>
                Organisation
                <input
                  type="text"
                  placeholder="Your company or team"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                />
              </label>
            </>
          )}
          <label>
            Email
            <input
              type="email"
              required
              autoFocus
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </label>
          <label>
            Password
            <input
              type="password"
              required
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {error && (
            <div className="muted" role="alert">
              {error}
            </div>
          )}
          <button className="primary" type="submit" disabled={busy}>
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
        </form>
        <p>
          <button
            className="link"
            type="button"
            onClick={() => {
              setMode(mode === 'login' ? 'signup' : 'login');
              setError('');
            }}
          >
            {mode === 'login' ? 'New here? Create an account' : 'Already have an account? Sign in'}
          </button>
        </p>
      </main>
    </div>
  );
}
