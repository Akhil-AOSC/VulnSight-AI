// API client, session state, theme management, and formatting helpers for the React frontend.

const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch { /* ignore */ } },
};

const prefs = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
};

export const session = {
  get token() { return store.get('vs.token'); },
  set token(v) { store.set('vs.token', v); },
  get orgId() { return prefs.get('vs.org'); },
  set orgId(v) { prefs.set('vs.org', v); },
  me: null,
};

export const themeStore = {
  get() { return prefs.get('vs.theme') || 'light'; },
  set(v) {
    prefs.set('vs.theme', v);
    if (v === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', v);
  },
};

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn; };

let toastListeners = [];
export function subscribeToasts(fn) {
  toastListeners.push(fn);
  return () => { toastListeners = toastListeners.filter((l) => l !== fn); };
}

export function toast(message, kind = 'info') {
  const item = { id: `${Date.now()}-${Math.random()}`, message, kind };
  toastListeners.forEach((fn) => fn(item));
}

async function request(method, path, body, { raw = false } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (session.token) headers.authorization = `Bearer ${session.token}`;
  let res;
  try {
    res = await fetch(`/api/v1${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError('Cannot reach the server', 0);
  }
  if (res.status === 401 && session.token) onUnauthorized();
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { msg = (await res.json()).error || msg; } catch { /* ignore */ }
    throw new ApiError(msg, res.status);
  }
  return raw ? res : res.json();
}

export const api = {
  get: (p) => request('GET', p),
  post: (p, b = {}) => request('POST', p, b),
  patch: (p, b = {}) => request('PATCH', p, b),
  put: (p, b = {}) => request('PUT', p, b),
  del: (p) => request('DELETE', p),
  delete: (p) => request('DELETE', p),
  org: (p) => `/orgs/${session.orgId}${p}`,
  async download(path, filename) {
    const res = await request('GET', path, undefined, { raw: true });
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  },
};

export function hasPermission(me, orgId, perm) {
  if (!me || !Array.isArray(me.orgs)) return false;
  const org = me.orgs.find((o) => o.id === orgId);
  return !!org && Array.isArray(org.permissions) && org.permissions.includes(perm);
}

export const fmtDate = (iso) => (
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '-'
);

export const ago = (iso) => {
  if (!iso) return '-';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
};

export const pad = (n) => (n == null ? '-' : String(n));
