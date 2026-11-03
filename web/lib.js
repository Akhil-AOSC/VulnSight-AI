// Shared helpers. All dynamic content goes through h() / text nodes, never innerHTML,
// so data from scans (package names, titles, code) can't inject markup.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export const clear = (el) => { while (el.firstChild) el.firstChild.remove(); return el; };

// ---- state ----
const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch { /* storage unavailable */ } },
};
const prefs = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
};
export const session = {
  get token() { return store.get('vs.token'); },
  set token(v) { store.set('vs.token', v); },
  get orgId() { return prefs.get('vs.org'); },
  set orgId(v) { prefs.set('vs.org', v); },
  me: null,
};
export const theme = {
  get() { return prefs.get('vs.theme') || 'auto'; },
  set(v) {
    prefs.set('vs.theme', v);
    if (v === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', v);
  },
};

// ---- API ----
export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn; };

async function request(method, path, body, { raw = false } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (session.token) headers.authorization = `Bearer ${session.token}`;
  let res;
  try {
    res = await fetch(`/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError('Cannot reach the server', 0);
  }
  if (res.status === 401 && session.token) onUnauthorized();
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try { msg = (await res.json()).error || msg; } catch { /* keep default */ }
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
  org: (p) => `/orgs/${session.orgId}${p}`,
  async download(path, filename) {
    const res = await request('GET', path, undefined, { raw: true });
    const url = URL.createObjectURL(await res.blob());
    const a = h('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  },
};

// ---- UI helpers ----
export function toast(message, kind = 'info') {
  const box = document.getElementById('toasts');
  const t = h('div', { class: `toast ${kind}` }, message);
  box.append(t);
  setTimeout(() => t.remove(), kind === 'error' ? 7000 : 3500);
}

export async function guard(fn, { busy } = {}) {
  if (busy) busy.disabled = true;
  try {
    return await fn();
  } catch (err) {
    toast(err.message || 'Something went wrong', 'error');
    return undefined;
  } finally {
    if (busy) busy.disabled = false;
  }
}

export const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '-');
export const ago = (iso) => {
  if (!iso) return '-';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
};
export const pad = (n) => (n == null ? '-' : String(n));

export const sevBadge = (s) => h('span', { class: `badge sev-${s}` }, s);
export const statusBadge = (s) => h('span', { class: `badge st-${s}` }, s);

export function field(label, control) {
  return h('label', null, label, control);
}

export function table(headers, rows, { empty = 'Nothing here yet.', onRow } = {}) {
  if (!rows.length) return h('div', { class: 'empty' }, empty);
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, headers.map((x) => h('th', { class: x.num ? 'num' : null, scope: 'col' }, x.label || x)))),
    h('tbody', null, rows.map((r) => {
      const tr = h('tr', { class: onRow ? 'clickable' : null, tabindex: onRow ? '0' : null }, r.cells.map((c, i) => h('td', { class: headers[i].num ? 'num' : null }, c)));
      if (onRow) {
        tr.addEventListener('click', (e) => { if (!e.target.closest('a,button')) onRow(r); });
        tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.target.closest('a,button')) onRow(r); });
      }
      return tr;
    }))));
}

const SEV = ['critical', 'high', 'medium', 'low'];
export function severityBar(counts) {
  const total = SEV.reduce((a, s) => a + (counts[s] || 0), 0);
  const bar = h('div', { class: 'bar', role: 'img', 'aria-label': SEV.map((s) => `${counts[s] || 0} ${s}`).join(', ') });
  for (const s of SEV) {
    if (!counts[s]) continue;
    const span = h('span', { class: `s-${s}` });
    span.style.width = `${(100 * counts[s]) / total}%`;
    bar.append(span);
  }
  return bar;
}

// Small dependency-free SVG line chart: series = [{key, cls}], points = [{at, ...values}]
export function trendChart(points, series) {
  const NS = 'http://www.w3.org/2000/svg';
  const W = 600;
  const H = 180;
  const P = { l: 34, r: 8, t: 8, b: 20 };
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('class', 'chart');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `Trend of ${series.map((s) => s.label).join(', ')} over the last ${points.length} scans`);
  const el = (name, attrs, text) => {
    const n = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text != null) n.textContent = text;
    return n;
  };
  const max = Math.max(1, ...points.flatMap((p) => series.map((s) => p[s.key] || 0)));
  const x = (i) => P.l + (points.length === 1 ? (W - P.l - P.r) / 2 : (i * (W - P.l - P.r)) / (points.length - 1));
  const y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
  for (const f of [0, 0.5, 1]) {
    svg.append(el('line', { x1: P.l, x2: W - P.r, y1: y(max * f), y2: y(max * f), class: 'axis' }));
    svg.append(el('text', { x: P.l - 6, y: y(max * f) + 3, 'text-anchor': 'end' }, Math.round(max * f)));
  }
  for (const s of series) {
    const d = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[s.key] || 0).toFixed(1)}`).join(' ');
    svg.append(el('path', { d, fill: 'none', 'stroke-width': 2, class: s.cls, 'stroke-linejoin': 'round' }));
    points.forEach((p, i) => svg.append(el('circle', { cx: x(i), cy: y(p[s.key] || 0), r: 2.5, class: s.cls, fill: 'currentColor', stroke: 'none' })));
  }
  return svg;
}

export function pageHead(title, subtitle, ...actions) {
  return h('div', { class: 'page-head' },
    h('div', null, h('h1', null, title), subtitle ? h('div', { class: 'muted' }, subtitle) : null),
    h('div', { class: 'row' }, actions));
}
