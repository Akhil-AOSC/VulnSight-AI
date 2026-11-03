import { h, clear, api, session, theme, toast, setUnauthorizedHandler, field } from './lib.js';
import * as main from './views-main.js';
import * as more from './views-more.js';

const app = document.getElementById('app');
theme.set(theme.get());

setUnauthorizedHandler(() => { session.token = null; session.me = null; render(); });

// ---------------------------------------------------------------- auth screens
function authScreen() {
  let mode = 'login';
  const box = h('div', { class: 'auth' });
  const draw = () => {
    const email = h('input', { type: 'email', required: true, autocomplete: 'email' });
    const pw = h('input', { type: 'password', required: true, autocomplete: mode === 'login' ? 'current-password' : 'new-password', minlength: mode === 'login' ? null : 12 });
    const name = h('input', { autocomplete: 'name' });
    const org = h('input', { placeholder: 'Your company or team' });
    const submit = h('button', { class: 'primary', type: 'submit' }, mode === 'login' ? 'Sign in' : 'Create account');
    const err = h('div', { class: 'muted', role: 'alert' });
    const form = h('form', { class: 'stack' },
      mode === 'signup' ? [field('Your name', name), field('Organisation', org)] : null,
      field('Email', email), field('Password', pw),
      mode === 'signup' ? h('div', { class: 'small muted' }, 'At least 12 characters with upper case, lower case and a number.') : null,
      err, submit);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      submit.disabled = true;
      try {
        const r = await api.post(mode === 'login' ? '/auth/login' : '/auth/signup', mode === 'login'
          ? { email: email.value, password: pw.value } : { email: email.value, password: pw.value, name: name.value, orgName: org.value });
        session.token = r.token;
        session.orgId = r.orgId || null;
        render();
      } catch (ex) {
        err.textContent = ex.message;
        submit.disabled = false;
      }
    });
    const switchBtn = h('button', { class: 'link', type: 'button', onclick: () => { mode = mode === 'login' ? 'signup' : 'login'; draw(); } },
      mode === 'login' ? 'New here? Create an account' : 'Already have an account? Sign in');
    clear(box).append(h('main', { class: 'card', id: 'main' }, h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, 'VS'), 'VulnSight AI'),
      h('h1', null, mode === 'login' ? 'Sign in' : 'Create your account'), form, h('p', null, switchBtn)));
    email.focus();
  };
  draw();
  return box;
}

// ---------------------------------------------------------------- shell
const NAV = [['overview', 'Overview'], ['repos', 'Repositories'], ['assistant', 'AI assistant'], ['reports', 'Reports'], ['settings', 'Settings']];

function shell(content, route) {
  const me = session.me;
  const orgSel = h('select', { 'aria-label': 'Organisation', onchange: (e) => { session.orgId = e.target.value; location.hash = '#/overview'; render(); } },
    me.orgs.map((o) => h('option', { value: o.id, selected: o.id === session.orgId }, `${o.name} (${o.role})`)));
  return h('div', { class: 'shell' },
    h('aside', { class: 'sidebar' },
      h('div', { class: 'brand' }, h('span', { class: 'brand-mark' }, 'VS'), 'VulnSight AI'),
      h('nav', { class: 'nav', 'aria-label': 'Main' }, NAV.map(([k, l]) => h('a', { href: `#/${k}`, 'aria-current': route[0] === k ? 'page' : null }, l))),
      h('div', { class: 'sidebar-foot' }, orgSel,
        h('div', { class: 'small muted' }, me.email),
        h('button', { type: 'button', onclick: async () => { await api.post('/auth/logout').catch(() => {}); session.token = null; session.me = null; render(); } }, 'Sign out'))),
    h('main', { class: 'content', id: 'main' }, content));
}

// ---------------------------------------------------------------- router
const ROUTES = {
  overview: (root) => main.overview(root),
  repos: (root, [id]) => (id ? main.repoDetail(root, id) : main.repos(root)),
  scans: (root, [id]) => main.scanView(root, id),
  assistant: (root, [repoId]) => more.assistant(root, repoId),
  reports: (root) => more.reports(root),
  settings: (root, [tab]) => more.settings(root, tab),
};

let renderToken = 0;
async function render() {
  const my = ++renderToken;
  if (!session.token) { clear(app).append(authScreen()); return; }
  if (!session.me) {
    try { session.me = await api.get('/me'); } catch { session.token = null; clear(app).append(authScreen()); return; }
  }
  if (!session.me.orgs.some((o) => o.id === session.orgId)) session.orgId = session.me.orgs[0] && session.me.orgs[0].id;
  if (!session.orgId) { clear(app).append(h('div', { class: 'auth' }, h('div', { class: 'card' }, 'You are not a member of any organisation.'))); return; }

  const [name = 'overview', ...rest] = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  const view = ROUTES[name] || ROUTES.overview;
  const content = h('div', null, h('p', { class: 'muted' }, 'Loading...'));
  clear(app).append(shell(content, [name]));
  document.title = `${(NAV.find(([k]) => k === name) || ['', 'VulnSight AI'])[1]} - VulnSight AI`;
  try {
    const fresh = h('div');
    await view(fresh, rest);
    if (my !== renderToken) return;
    clear(content).append(...fresh.childNodes);
    document.getElementById('main').focus({ preventScroll: true });
  } catch (err) {
    if (my !== renderToken) return;
    clear(content).append(h('div', { class: 'card' }, h('h2', null, 'Something went wrong'), h('p', null, err.message), h('a', { class: 'btn', href: '#/overview' }, 'Back to overview')));
    if (err.status !== 404) toast(err.message, 'error');
  }
}

window.addEventListener('hashchange', render);
render();
