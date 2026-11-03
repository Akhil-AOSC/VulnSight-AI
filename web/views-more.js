import {
  h, clear, api, session, toast, guard, fmtDate, ago, pad, sevBadge, statusBadge, field, table, pageHead, theme,
} from './lib.js';
import { can } from './views-main.js';

// ---------------------------------------------------------------- AI assistant
export async function assistant(root, repoId) {
  const [repos, settings] = await Promise.all([api.get(api.org('/repos')), api.get(api.org('/settings'))]);
  root.append(pageHead('AI security assistant', 'Ask about your findings. Scanner results always stay the source of truth.'));

  if (!settings.aiEnabled) {
    root.append(h('div', { class: 'card' }, h('h2', null, 'AI analysis is turned off'),
      h('p', null, 'Your organisation has not enabled AI analysis. When enabled, finding metadata (titles, identifiers, package versions and file names) is sent to the configured AI provider. Source code is never sent unless you separately allow it.'),
      can('org:settings') ? h('a', { class: 'btn primary', href: '#/settings/organisation' }, 'Open organisation settings') : h('p', { class: 'muted' }, 'Ask an organisation admin to enable it.')));
    return;
  }
  if (!repos.length) { root.append(h('div', { class: 'card empty' }, 'Add and scan a repository first.')); return; }

  const sel = h('select', { 'aria-label': 'Repository' }, repos.map((r) => h('option', { value: r.id, selected: r.id === repoId }, r.fullName)));
  const chat = h('div', { class: 'chat', 'aria-live': 'polite' });
  const history = [];
  const input = h('textarea', { 'aria-label': 'Your question', placeholder: 'For example: What should I fix first, and why?' });
  const send = h('button', { class: 'primary', type: 'submit' }, 'Ask');
  const summaryBtn = h('button', { type: 'button' }, 'Summarize security posture');

  const bubble = (role, text, extra) => { const m = h('div', { class: `msg ${role}` }, extra, text); chat.append(m); chat.scrollTop = chat.scrollHeight; return m; };
  const aiTag = (r) => h('div', { class: 'badge ai-label' }, `AI-generated - ${r.meta.provider}`);

  async function loadHistory() {
    clear(chat); history.length = 0;
    const rows = await api.get(api.org(`/repos/${sel.value}/ai/history`)).catch(() => []);
    for (const r of rows.filter((x) => x.kind === 'question').reverse().slice(-6)) {
      bubble('user', r.question); bubble('assistant', r.answer, h('div', { class: 'badge ai-label' }, 'AI-generated (earlier)'));
      history.push({ role: 'user', content: r.question }, { role: 'assistant', content: r.answer });
    }
    if (!rows.length) bubble('assistant', 'Ask me about this repository\'s findings: what is most urgent, how to fix something, or what an upgrade could break.');
  }

  summaryBtn.addEventListener('click', () => guard(async () => {
    bubble('user', 'Summarize this repository\'s security posture.');
    const r = await api.post(api.org(`/repos/${sel.value}/ai/summary`));
    bubble('assistant', r.text, aiTag(r));
  }, { busy: summaryBtn }));

  const form = h('form', { class: 'stack' }, input, h('div', { class: 'row' }, send, summaryBtn));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    guard(async () => {
      bubble('user', q); input.value = '';
      const r = await api.post(api.org(`/repos/${sel.value}/ai/ask`), { question: q, history });
      bubble('assistant', r.text, aiTag(r));
      if (r.warnings.length) toast(r.warnings.join(' '), 'error');
      history.push({ role: 'user', content: q }, { role: 'assistant', content: r.text });
    }, { busy: send });
  });
  sel.addEventListener('change', loadHistory);

  root.append(h('section', { class: 'card' }, h('div', { class: 'row' }, field('Repository', sel)),
    chat, form,
    h('p', { class: 'small muted' }, settings.aiSendCode ? 'Code snippets from scanners may be shared with the AI provider (enabled by your admin). Secrets are never shared.' : 'Only finding metadata is shared with the AI provider. Code snippets are not sent.')));
  loadHistory();
}

// ---------------------------------------------------------------- reports
export async function reports(root) {
  const [repos, scans] = await Promise.all([api.get(api.org('/repos')), api.get(api.org('/scans?limit=100'))]);
  root.append(pageHead('Reports and analytics', 'Export results and compare scans over time'));
  const name = (id) => (repos.find((r) => r.id === id) || {}).fullName || id;
  const done = scans.filter((s) => s.status === 'completed');

  if (!done.length) { root.append(h('div', { class: 'card empty' }, 'Complete a scan to see reports.')); return; }

  const exportBtns = (s) => h('div', { class: 'row' }, ...[['csv', 'CSV', 'csv'], ['markdown', 'Report', 'md'], ['cyclonedx', 'SBOM', 'cdx.json']].map(([fmt, label, ext]) =>
    h('button', { type: 'button', onclick: () => guard(() => api.download(api.org(`/scans/${s.id}/report?format=${fmt}`), `${name(s.repoId).replace('/', '-')}-${s.id.slice(0, 8)}.${ext}`)) }, label)));

  // history with deltas against the previous scan of the same repo+branch
  const prev = new Map();
  const rows = [...done].reverse().map((s) => {
    const key = `${s.repoId}|${s.branch}`;
    const before = prev.get(key);
    prev.set(key, s);
    const delta = before ? s.summary.total - before.summary.total : null;
    return { s, delta };
  }).reverse();

  root.append(h('section', { class: 'card' }, h('h2', null, 'Scan history and comparison'),
    table(['Repository', 'Branch', 'Date', 'Posture', 'Critical', 'High', 'Medium', 'Low', 'Change', 'Export'].map((x, i) => (i >= 4 && i <= 8 ? { label: x, num: true } : x)),
      rows.map(({ s, delta }) => ({ id: s.id, cells: [h('a', { href: `#/scans/${s.id}` }, name(s.repoId)), s.branch, fmtDate(s.finishedAt), `${s.summary.posture.grade} (${s.summary.posture.score})`,
        s.summary.bySeverity.critical, s.summary.bySeverity.high, s.summary.bySeverity.medium, s.summary.bySeverity.low,
        delta == null ? '-' : delta === 0 ? '0' : delta > 0 ? `+${delta}` : String(delta), exportBtns(s)] })))));

  const fixed = done.reduce((a, s) => a + s.summary.fixed, 0);
  const added = done.reduce((a, s) => a + s.summary.new, 0);
  const byRepo = repos.map((r) => ({ r, last: done.find((s) => s.repoId === r.id) })).filter((x) => x.last);
  root.append(h('div', { class: 'grid cols-2' },
    h('section', { class: 'card' }, h('h2', null, 'Remediation metrics'),
      h('dl', { class: 'kv' }, h('dt', null, 'Scans completed'), h('dd', null, done.length), h('dt', null, 'Findings introduced'), h('dd', null, added),
        h('dt', null, 'Findings fixed'), h('dd', null, fixed))),
    h('section', { class: 'card' }, h('h2', null, 'Compliance-oriented summary'),
      h('p', { class: 'muted small' }, 'Evidence for dependency and secret hygiene controls (for example SOC 2 CC7.1, ISO 27001 A.8.8, PCI DSS 6.3). This is supporting evidence, not a compliance certification.'),
      table(['Repository', 'Open critical/high', 'Secrets found'], byRepo.map(({ r, last }) => ({ cells: [r.fullName, last.summary.bySeverity.critical + last.summary.bySeverity.high, last.summary.byCategory.secret || 0] })), { empty: '-' }))));
}

// ---------------------------------------------------------------- settings
const TABS = [['profile', 'Profile'], ['organisation', 'Organisation'], ['members', 'Members'], ['teams', 'Teams'], ['providers', 'Git providers'], ['notifications', 'Notifications'], ['audit', 'Audit log']];

export async function settings(root, tab = 'profile') {
  root.append(pageHead('Settings'));
  root.append(h('nav', { class: 'tabs', 'aria-label': 'Settings sections' }, TABS.map(([k, l]) => h('a', { href: `#/settings/${k}`, 'aria-current': k === tab ? 'page' : null }, l))));
  const body = h('div', { class: 'grid' });
  root.append(body);
  await ({ profile, organisation, members, teams, providers, notifications, audit }[tab] || profile)(body);
}

function profile(body) {
  const me = session.me;
  const mode = h('select', { 'aria-label': 'Theme', onchange: (e) => theme.set(e.target.value) }, [['auto', 'Match system'], ['light', 'Light'], ['dark', 'Dark']].map(([v, l]) => h('option', { value: v, selected: theme.get() === v }, l)));
  body.append(h('section', { class: 'card' }, h('h2', null, 'Your profile'),
    h('dl', { class: 'kv' }, h('dt', null, 'Name'), h('dd', null, me.name), h('dt', null, 'Email'), h('dd', null, me.email), h('dt', null, 'Member since'), h('dd', null, fmtDate(me.created_at))),
    h('div', { class: 'row' }, field('Appearance', mode))));
}

async function organisation(body) {
  const s = await api.get(api.org('/settings'));
  const org = session.me.orgs.find((o) => o.id === session.orgId);
  const ro = !can('org:settings');
  const name = h('input', { value: org.name, disabled: ro });
  const aiOn = h('input', { type: 'checkbox', checked: s.aiEnabled, disabled: ro });
  const aiCode = h('input', { type: 'checkbox', checked: s.aiSendCode, disabled: ro });
  const days = h('input', { type: 'number', min: 1, max: 3650, value: s.retentionDays, disabled: ro });
  const save = h('button', { class: 'primary', type: 'submit', disabled: ro }, 'Save');
  body.append(h('section', { class: 'card' }, h('h2', null, 'Organisation'),
    h('form', {
      class: 'stack',
      onsubmit: (e) => {
        e.preventDefault();
        guard(async () => {
          if (name.value.trim() !== org.name) await api.patch(api.org(''), { name: name.value.trim() });
          await api.patch(api.org('/settings'), { aiEnabled: aiOn.checked, aiSendCode: aiCode.checked, retentionDays: Number(days.value) });
          toast('Settings saved');
          session.me = await api.get('/me');
        }, { busy: save });
      },
    },
    field('Organisation name', name),
    h('label', { class: 'inline' }, aiOn, 'Enable AI analysis (sends finding metadata to the AI provider)'),
    h('label', { class: 'inline' }, aiCode, 'Also allow code snippets from scanners to be sent to the AI provider (secrets are never sent)'),
    field('Keep scan data for (days)', days), save)));
  if (session.me.orgs.find((o) => o.id === session.orgId).role === 'owner') {
    const del = h('button', { class: 'danger', type: 'button' }, 'Delete organisation');
    del.addEventListener('click', () => {
      if (prompt(`Type the organisation name (${org.name}) to permanently delete it and all of its data:`) === org.name) {
        guard(async () => { await api.del(api.org('')); session.orgId = null; location.hash = '#/overview'; location.reload(); }, { busy: del });
      }
    });
    body.append(h('section', { class: 'card' }, h('h2', null, 'Danger zone'), del));
  }
}

async function members(body) {
  const list = await api.get(api.org('/members'));
  const manage = can('members:manage');
  const roles = ['viewer', 'developer', 'admin', 'owner'];
  body.append(h('section', { class: 'card' }, h('h2', null, 'Members'),
    table(['Name', 'Email', 'Role', ''], list.map((m) => ({
      cells: [m.name, m.email,
        manage ? (() => { const s = h('select', { 'aria-label': `Role for ${m.email}` }, roles.map((r) => h('option', { value: r, selected: r === m.role }, r)));
          s.addEventListener('change', () => guard(async () => { await api.patch(api.org(`/members/${m.id}`), { role: s.value }); toast('Role updated'); }).then(() => location.reload())); return s; })() : m.role,
        manage && m.id !== session.me.id ? h('button', { class: 'danger', type: 'button', onclick: () => { if (confirm(`Remove ${m.email}?`)) guard(async () => { await api.del(api.org(`/members/${m.id}`)); location.reload(); }); } }, 'Remove') : null],
    })))));
  if (manage) {
    const email = h('input', { type: 'email', required: true, placeholder: 'colleague@company.com' });
    const role = h('select', null, roles.map((r) => h('option', { value: r, selected: r === 'developer' }, r)));
    const add = h('button', { class: 'primary', type: 'submit' }, 'Add member');
    body.append(h('section', { class: 'card' }, h('h2', null, 'Add a member'),
      h('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); guard(async () => { await api.post(api.org('/members'), { email: email.value, role: role.value }); toast('Member added'); location.reload(); }, { busy: add }); } },
        field('Email (must already have an account)', email), field('Role', role), add),
      h('dl', { class: 'kv small' }, h('dt', null, 'Viewer'), h('dd', null, 'Read findings and reports'), h('dt', null, 'Developer'), h('dd', null, 'Run scans, triage findings, use the AI assistant'),
        h('dt', null, 'Admin'), h('dd', null, 'Manage repositories, members, Git providers and settings'), h('dt', null, 'Owner'), h('dd', null, 'Everything, including deleting the organisation'))));
  }
}

async function teams(body) {
  const [list, ms] = await Promise.all([api.get(api.org('/teams')), api.get(api.org('/members'))]);
  const manage = can('teams:manage');
  const nameOf = (id) => (ms.find((m) => m.id === id) || {}).email || id;
  body.append(h('section', { class: 'card' }, h('h2', null, 'Teams'),
    table(['Team', 'Members', ''], list.map((t) => {
      const pick = h('select', { 'aria-label': `Add member to ${t.name}` }, h('option', { value: '' }, 'Add member...'), ms.filter((m) => !t.members.includes(m.id)).map((m) => h('option', { value: m.id }, m.email)));
      pick.addEventListener('change', () => pick.value && guard(async () => { await api.post(api.org(`/teams/${t.id}/members/${pick.value}`)); location.reload(); }));
      return { cells: [t.name, t.members.map(nameOf).join(', ') || '-', manage ? h('div', { class: 'row' }, pick, h('button', { class: 'danger', type: 'button', onclick: () => { if (confirm(`Delete team ${t.name}?`)) guard(async () => { await api.del(api.org(`/teams/${t.id}`)); location.reload(); }); } }, 'Delete')) : null] };
    }), { empty: 'No teams yet.' })));
  if (manage) {
    const name = h('input', { required: true, placeholder: 'Team name' });
    const add = h('button', { class: 'primary', type: 'submit' }, 'Create team');
    body.append(h('section', { class: 'card' }, h('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); guard(async () => { await api.post(api.org('/teams'), { name: name.value }); location.reload(); }, { busy: add }); } }, field('New team', name), add)));
  }
}

async function providers(body) {
  const list = await api.get(api.org('/connections'));
  const manage = can('providers:manage');
  body.append(h('section', { class: 'card' }, h('h2', null, 'Connected Git providers'),
    table(['Provider', 'Account', 'Added', ''], list.map((c) => ({ cells: [c.provider, c.account || c.label, fmtDate(c.createdAt),
      manage ? h('button', { class: 'danger', type: 'button', onclick: () => { if (confirm('Disconnect this provider? Repositories using it can no longer be scanned.')) guard(async () => { await api.del(api.org(`/connections/${c.id}`)); location.reload(); }); } }, 'Disconnect') : null] })), { empty: 'No providers connected.' })));
  if (manage) {
    const provider = h('select', null, [['github', 'GitHub'], ['gitlab', 'GitLab'], ['bitbucket', 'Bitbucket']].map(([v, l]) => h('option', { value: v }, l)));
    const token = h('input', { type: 'password', required: true, autocomplete: 'off', size: 36, placeholder: 'Personal access token' });
    const add = h('button', { class: 'primary', type: 'submit' }, 'Connect');
    body.append(h('section', { class: 'card' }, h('h2', null, 'Connect a provider'),
      h('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); guard(async () => { const r = await api.post(api.org('/connections'), { provider: provider.value, token: token.value }); token.value = ''; toast(`Connected as ${r.account}`); location.reload(); }, { busy: add }); } },
        field('Provider', provider), field('Access token', token), add),
      h('p', { class: 'muted small' }, 'Use a token with read-only repository access. It is validated against the provider, encrypted at rest and never shown again. Scans use it only to clone the repository.')));
  }
}

async function notifications(body) {
  const list = await api.get(api.org('/notifications'));
  const mark = h('button', { type: 'button', onclick: () => guard(async () => { await api.post(api.org('/notifications/read'), {}); location.reload(); }) }, 'Mark all as read');
  body.append(h('section', { class: 'card' }, h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Notifications'), list.some((n) => !n.read) ? mark : null),
    table(['', 'Notification', 'When'], list.map((n) => ({ cells: [n.read ? '' : h('span', { class: 'badge st-open' }, 'new'), h('div', null, h('strong', null, n.title), n.body ? h('div', { class: 'muted small' }, n.body) : null), ago(n.createdAt)] })), { empty: 'No notifications.' })));
}

async function audit(body) {
  if (!can('audit:read')) { body.append(h('div', { class: 'card empty' }, 'Only admins can view the audit log.')); return; }
  const list = await api.get(api.org('/audit?limit=200'));
  body.append(h('section', { class: 'card' }, h('h2', null, 'Audit log'),
    table(['When', 'User', 'Action', 'Target', 'IP'], list.map((e) => ({ cells: [fmtDate(e.createdAt), e.user || '-', e.action, h('span', { class: 'mono' }, e.target || ''), e.ip || ''] })), { empty: 'No events.' })));
}
