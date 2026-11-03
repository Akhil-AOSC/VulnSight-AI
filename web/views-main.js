import {
  h, clear, api, session, toast, guard, fmtDate, ago, pad, sevBadge, statusBadge, field, table,
  severityBar, trendChart, pageHead,
} from './lib.js';

const SCANNERS = [
  ['sca', 'Dependencies (OSV)'], ['semgrep', 'Code (Semgrep)'], ['gitleaks', 'Secrets (Gitleaks)'],
  ['trivy', 'Dependencies + IaC (Trivy)'], ['checkov', 'Infrastructure (Checkov)'],
];

export const can = (perm) => {
  const org = session.me.orgs.find((o) => o.id === session.orgId);
  return !!org && org.permissions.includes(perm);
};

// ---------------------------------------------------------------- overview
export async function overview(root) {
  const d = await api.get(api.org('/overview'));
  const t = d.totals;
  const stat = (cls, num, label) => h('div', { class: `card stat ${cls}` }, h('div', { class: 'num' }, pad(num)), h('div', { class: 'label' }, label));

  root.append(pageHead('Security overview', 'Latest scan of each repository'));
  if (!d.repositories.length) {
    root.append(h('div', { class: 'card empty' }, h('p', null, 'No repositories yet.'),
      h('a', { class: 'btn primary', href: '#/repos' }, 'Add your first repository')));
    return;
  }

  root.append(h('div', { class: 'grid stats' },
    stat('', t.total, 'Open findings'), stat('critical', t.critical, 'Critical'), stat('high', t.high, 'High'),
    stat('medium', t.medium, 'Medium'), stat('low', t.low, 'Low'),
    h('div', { class: 'card stat' }, h('div', { class: 'num gauge' }, d.posture == null ? '-' : d.posture), h('div', { class: 'label' }, 'Posture score (100 = clean)'))));

  const trend = d.trend.length
    ? [trendChart(d.trend, [{ key: 'total', cls: 'l-total', label: 'total' }, { key: 'critical', cls: 'l-critical', label: 'critical' }, { key: 'high', cls: 'l-high', label: 'high' }]),
      h('div', { class: 'legend' }, h('span', null, 'Total'), h('span', null, 'Critical'), h('span', null, 'High'))]
    : [h('div', { class: 'empty' }, 'Run a scan to see trends.')];
  const rem = d.remediation;
  root.append(h('div', { class: 'grid cols-2', style: null },
    h('section', { class: 'card' }, h('h2', null, 'Vulnerability trend'), trend),
    h('section', { class: 'card' }, h('h2', null, 'Remediation progress'),
      h('p', { class: 'muted' }, rem.fixRate == null ? 'No tracked findings yet.' : `${rem.fixRate}% of tracked findings are fixed`),
      h('dl', { class: 'kv' }, h('dt', null, 'Open'), h('dd', null, rem.open), h('dt', null, 'Acknowledged'), h('dd', null, rem.acknowledged),
        h('dt', null, 'Fixed'), h('dd', null, rem.fixed), h('dt', null, 'Suppressed'), h('dd', null, rem.suppressed)))));

  root.append(h('section', { class: 'card' }, h('h2', null, 'Repositories'),
    table(['Repository', 'Status', 'Posture', 'Findings', 'Severity', 'Last scan'],
      d.repositories.map((r) => ({
        id: r.id,
        cells: [h('a', { href: `#/repos/${r.id}` }, r.fullName), r.lastStatus ? statusBadge(r.lastStatus) : h('span', { class: 'muted' }, 'never scanned'),
          r.posture ? `${r.posture.grade} (${r.posture.score})` : '-', pad(r.total), r.bySeverity ? severityBar(r.bySeverity) : '-', ago(r.lastScanAt)],
      })), { onRow: (r) => { location.hash = `#/repos/${r.id}`; } })));

  root.append(h('div', { class: 'grid cols-2' },
    h('section', { class: 'card' }, h('h2', null, 'Recent scans'), scanTable(d.recentScans, d.repositories)),
    h('section', { class: 'card' }, h('h2', null, 'Failed scans'),
      d.failedScans.length ? scanTable(d.failedScans, d.repositories, true) : h('div', { class: 'empty' }, 'No failed scans.'))));
}

function scanTable(scans, repos, showError) {
  const name = (id) => (repos.find((r) => r.id === id) || {}).fullName || id;
  return table(['Repository', 'Branch', 'Status', showError ? 'Error' : 'Found', 'When'],
    scans.map((s) => ({ id: s.id, cells: [name(s.repoId), s.branch, statusBadge(s.status), showError ? s.error : pad(s.summary && s.summary.total), ago(s.createdAt)] })),
    { onRow: (r) => { location.hash = `#/scans/${r.id}`; } });
}

// ---------------------------------------------------------------- repositories
export async function repos(root) {
  const [list, conns, teams] = await Promise.all([api.get(api.org('/repos')), api.get(api.org('/connections')), api.get(api.org('/teams'))]);
  root.append(pageHead('Repositories', 'Connect a repository and scan it'));

  if (can('repos:write')) {
    const url = h('input', { type: 'url', required: true, placeholder: 'https://github.com/owner/name', size: 38, autocomplete: 'off' });
    const branch = h('input', { placeholder: 'main', size: 12, value: 'main' });
    const conn = h('select', null, h('option', { value: '' }, 'Public repository (no connection)'), conns.map((c) => h('option', { value: c.id }, `${c.provider}: ${c.account || c.label}${c.isExpired ? ' (Expired)' : ''}`)));
    const team = h('select', null, h('option', { value: '' }, 'No team'), teams.map((t) => h('option', { value: t.id }, t.name)));
    const submit = h('button', { class: 'primary', type: 'submit' }, 'Add repository');

    const discoveryBox = h('div', { style: 'display: none; margin-top: 1rem; border-top: 1px solid var(--border); padding-top: 1rem;' });
    const browseBtn = conns.length ? h('button', {
      type: 'button',
      class: 'small',
      onclick: async () => {
        const connId = conn.value || (conns[0] && conns[0].id);
        if (!connId) {
          toast('Select a Git connection first', 'error');
          return;
        }
        conn.value = connId;
        clear(discoveryBox);
        discoveryBox.style.display = 'block';
        const loading = h('p', { class: 'muted' }, 'Fetching repositories from provider...');
        discoveryBox.append(loading);
        try {
          const remoteRepos = await api.get(api.org(`/connections/${connId}/repos`));
          loading.remove();
          if (!remoteRepos.length) {
            discoveryBox.append(h('p', { class: 'muted' }, 'No repositories found for this connection.'));
            return;
          }
          const existingUrls = new Set(list.map((r) => r.cloneUrl.toLowerCase()));
          const filterInput = h('input', { placeholder: 'Filter repositories...', style: 'margin-bottom: 0.75rem; width: 100%; max-width: 300px;' });
          const tableWrap = h('div');
          function updateRemoteTable(fText = '') {
            clear(tableWrap);
            const filtered = remoteRepos.filter((r) => r.fullName.toLowerCase().includes(fText.toLowerCase()));
            tableWrap.append(table(['Repository', 'Visibility', 'Default Branch', ''],
              filtered.map((r) => {
                const added = existingUrls.has(r.cloneUrl.toLowerCase());
                const addAction = added
                  ? h('span', { class: 'badge st-ok' }, 'Already added')
                  : h('button', {
                    class: 'primary small',
                    type: 'button',
                    onclick: () => guard(async () => {
                      addAction.disabled = true;
                      await api.post(api.org('/repos'), { url: r.cloneUrl, branch: r.defaultBranch || 'main', connectionId: connId, teamId: team.value || null });
                      existingUrls.add(r.cloneUrl.toLowerCase());
                      toast(`Repository ${r.fullName} added!`);
                      location.reload();
                    }, { busy: addAction }),
                  }, '+ Add');
                return {
                  cells: [
                    h('div', null, h('strong', null, r.fullName), r.description ? h('div', { class: 'muted small' }, r.description) : null),
                    r.private ? h('span', { class: 'badge st-open' }, 'Private') : h('span', { class: 'badge st-ok' }, 'Public'),
                    h('span', { class: 'mono small' }, r.defaultBranch || 'main'),
                    addAction,
                  ],
                };
              }),
              { empty: 'No matching repositories found.' }
            ));
          }
          filterInput.addEventListener('input', () => updateRemoteTable(filterInput.value.trim()));
          discoveryBox.append(
            h('div', { class: 'row', style: 'justify-content: space-between; align-items: center; margin-bottom: 0.5rem;' },
              h('h3', { style: 'margin: 0;' }, 'Accessible Repositories from Provider'),
              h('button', { type: 'button', class: 'small', onclick: () => { discoveryBox.style.display = 'none'; } }, 'Close')
            ),
            filterInput,
            tableWrap
          );
          updateRemoteTable('');
        } catch (err) {
          loading.remove();
          discoveryBox.append(h('p', { class: 'badge sev-critical' }, `Error fetching repositories: ${err.message}`));
        }
      },
    }, 'Browse Provider Repositories') : null;

    root.append(h('section', { class: 'card' },
      h('div', { class: 'row', style: 'justify-content: space-between; align-items: center; margin-bottom: 0.5rem;' },
        h('h2', { style: 'margin: 0;' }, 'Add a repository'),
        browseBtn
      ),
      h('form', {
        class: 'inline',
        onsubmit: (e) => {
          e.preventDefault();
          guard(async () => {
            await api.post(api.org('/repos'), { url: url.value.trim(), branch: branch.value.trim() || 'main', connectionId: conn.value || null, teamId: team.value || null });
            toast('Repository added');
            location.reload();
          }, { busy: submit });
        },
      }, field('Repository URL', url), field('Branch', branch), field('Git connection', conn), field('Team', team), submit),
      discoveryBox,
      h('p', { class: 'muted small', style: 'margin-top: 0.75rem;' }, 'Only https URLs on github.com, gitlab.com and bitbucket.org are accepted. Private repositories need a connection (Settings > Git providers).')));
  }

  root.append(h('section', { class: 'card' }, h('h2', null, 'Connected repositories'),
    table(['Repository', 'Provider', 'Branch', 'Status', 'Posture', 'Findings', 'Schedule', ''],
      list.map((r) => ({
        id: r.id,
        cells: [h('a', { href: `#/repos/${r.id}` }, r.fullName), r.provider, r.defaultBranch,
          r.lastScan ? statusBadge(r.lastScan.status) : h('span', { class: 'muted' }, 'never'),
          r.security ? `${r.security.posture.grade} (${r.security.posture.score})` : '-', pad(r.security && r.security.total), r.schedule || 'manual',
          can('scans:run') ? scanButton(r) : null],
      })), { empty: 'No repositories connected yet.', onRow: (r) => { location.hash = `#/repos/${r.id}`; } })));
}

function scanButton(repo, branch) {
  const b = h('button', {
    type: 'button',
    onclick: () => guard(async () => {
      const s = await api.post(api.org(`/repos/${repo.id}/scans`), branch ? { branch } : {});
      toast('Scan queued');
      location.hash = `#/scans/${s.id}`;
    }, { busy: b }),
  }, 'Scan now');
  return b;
}

export async function repoDetail(root, id) {
  const [repo, scans, branches] = await Promise.all([
    api.get(api.org(`/repos/${id}`)), api.get(api.org(`/scans?repoId=${id}&limit=30`)),
    api.get(api.org(`/repos/${id}/branches`)).catch(() => []),
  ]);
  const cfg = repo.config || {};
  const active = new Set(cfg.scanners || ['sca', 'semgrep', 'gitleaks']);

  const branchSel = h('select', { 'aria-label': 'Branch to scan' }, (branches.length ? branches : [repo.defaultBranch]).map((b) => h('option', { value: b, selected: b === repo.defaultBranch }, b)));
  const scanBtn = h('button', {
    class: 'primary', type: 'button',
    onclick: () => guard(async () => { const s = await api.post(api.org(`/repos/${id}/scans`), { branch: branchSel.value }); toast('Scan queued'); location.hash = `#/scans/${s.id}`; }, { busy: scanBtn }),
  }, 'Scan now');

  root.append(pageHead(repo.fullName, repo.cloneUrl, can('scans:run') ? [branchSel, scanBtn] : null));

  root.append(h('section', { class: 'card' }, h('h2', null, 'Scan history'),
    table(['Started', 'Branch', 'Commit', 'Trigger', 'Status', 'Findings', 'New', 'Fixed'],
      scans.map((s) => ({ id: s.id, cells: [fmtDate(s.createdAt), s.branch, s.commit ? s.commit.slice(0, 8) : '-', s.trigger, statusBadge(s.status),
        pad(s.summary && s.summary.total), pad(s.summary && s.summary.new), pad(s.summary && s.summary.fixed)] })),
      { empty: 'No scans yet. Press "Scan now".', onRow: (r) => { location.hash = `#/scans/${r.id}`; } })));

  if (!can('repos:write')) return;

  const boxes = SCANNERS.map(([key, label]) => ({ key, el: h('input', { type: 'checkbox', checked: active.has(key) }), label }));
  const threshold = h('select', null, ['low', 'medium', 'high', 'critical'].map((t) => h('option', { value: t, selected: (cfg.threshold || 'low') === t }, `Report ${t} and above`)));
  const schedule = h('select', null, [['', 'Manual only'], ['hourly', 'Every hour'], ['daily', 'Every day'], ['weekly', 'Every week']].map(([v, l]) => h('option', { value: v, selected: (repo.schedule || '') === v }, l)));
  const branchesInput = h('input', { value: (cfg.branches || []).join(', '), placeholder: repo.defaultBranch, size: 30 });
  const save = h('button', { class: 'primary', type: 'submit' }, 'Save settings');

  root.append(h('section', { class: 'card' }, h('h2', null, 'Scan configuration'),
    h('form', {
      class: 'stack',
      onsubmit: (e) => {
        e.preventDefault();
        guard(async () => {
          await api.patch(api.org(`/repos/${id}`), {
            config: { scanners: boxes.filter((b) => b.el.checked).map((b) => b.key), threshold: threshold.value, branches: branchesInput.value.split(',').map((x) => x.trim()).filter(Boolean) },
          });
          await api.put(api.org(`/repos/${id}/schedule`), { schedule: schedule.value || null });
          toast('Settings saved');
        }, { busy: save });
      },
    },
    h('div', { class: 'row' }, boxes.map((b) => h('label', { class: 'inline' }, b.el, b.label))),
    h('div', { class: 'row' }, field('Severity threshold', threshold), field('Scheduled scans', schedule), field('Branches monitored by webhooks (comma separated)', branchesInput)),
    h('div', { class: 'row' }, save))));

  const hook = h('div', { class: 'muted small' }, 'Loading webhook details...');
  root.append(h('section', { class: 'card' }, h('h2', null, 'Continuous monitoring (webhook)'), hook,
    h('p', { class: 'muted small' }, 'Add this webhook to your Git provider (push events, content type JSON) to scan on every push to a monitored branch. The secret signs each delivery.')));
  api.get(api.org(`/repos/${id}/webhook`)).then((w) => {
    clear(hook).append(h('dl', { class: 'kv' }, h('dt', null, 'Payload URL'), h('dd', null, h('code', null, `${location.origin}${w.url}`)),
      h('dt', null, 'Secret'), h('dd', null, h('code', null, w.secret))));
  }).catch(() => {});

  const del = h('button', {
    class: 'danger', type: 'button',
    onclick: () => { if (confirm(`Remove ${repo.fullName} and all of its scan data?`)) guard(async () => { await api.del(api.org(`/repos/${id}`)); location.hash = '#/repos'; }, { busy: del }); },
  }, 'Remove repository');
  root.append(h('section', { class: 'card' }, h('h2', null, 'Danger zone'), del));
}

// ---------------------------------------------------------------- scan results / findings
const FILTERS = { severity: '', category: '', status: '', q: '', page: 1 };

export async function scanView(root, id) {
  const scan = await api.get(api.org(`/scans/${id}`));
  const repo = await api.get(api.org(`/repos/${scan.repoId}`));
  const filters = { ...FILTERS };

  root.append(pageHead(`Scan of ${repo.fullName}`, `${scan.branch}${scan.commit ? ` @ ${scan.commit.slice(0, 8)}` : ''} - ${scan.trigger} - ${fmtDate(scan.createdAt)}`,
    h('a', { class: 'btn', href: `#/repos/${repo.id}` }, 'Repository'), statusBadge(scan.status)));

  if (scan.status === 'queued' || scan.status === 'running') {
    root.append(h('div', { class: 'card empty' }, `This scan is ${scan.status}. The page refreshes automatically.`,
      scan.status === 'queued' && can('scans:run') ? h('p', null, h('button', { type: 'button', onclick: () => guard(async () => { await api.post(api.org(`/scans/${id}/cancel`)); location.reload(); }) }, 'Cancel scan')) : null));
    const timer = setInterval(async () => {
      if (!document.body.contains(root) || location.hash !== `#/scans/${id}`) { clearInterval(timer); return; }
      const s = await api.get(api.org(`/scans/${id}`)).catch(() => null);
      if (s && s.status !== scan.status) { clearInterval(timer); location.reload(); }
    }, 2500);
    return;
  }
  if (scan.status === 'failed' || scan.status === 'cancelled') {
    root.append(h('div', { class: 'card' }, h('p', null, scan.error || `Scan ${scan.status}.`)));
    if (scan.status === 'cancelled') return;
  }

  const sum = scan.summary;
  if (sum) {
    root.append(h('div', { class: 'grid stats' },
      ...['critical', 'high', 'medium', 'low'].map((s) => h('div', { class: `card stat ${s}` }, h('div', { class: 'num' }, sum.bySeverity[s]), h('div', { class: 'label' }, s))),
      h('div', { class: 'card stat' }, h('div', { class: 'num' }, `${sum.posture.grade}`), h('div', { class: 'label' }, `Posture ${sum.posture.score}/100`)),
      h('div', { class: 'card stat' }, h('div', { class: 'num' }, `+${sum.new} / -${sum.fixed}`), h('div', { class: 'label' }, 'New / fixed since last scan'))));
  }
  if (scan.scanners.length) {
    root.append(h('section', { class: 'card' }, h('h2', null, 'Scanners'),
      table(['Scanner', 'Status', 'Version', 'Findings', 'Time', 'Message'],
        scan.scanners.map((s) => ({ cells: [s.scanner, statusBadge(s.status), s.version || '-', pad(s.findingCount), `${s.durationMs} ms`, s.error || ''] })))));
  }

  const exports = h('div', { class: 'row' }, ...[['csv', 'CSV', 'csv'], ['markdown', 'Markdown', 'md'], ['cyclonedx', 'SBOM (CycloneDX)', 'cdx.json'], ['json', 'JSON', 'json']].map(([fmt, label, ext]) =>
    h('button', { type: 'button', onclick: () => guard(() => api.download(api.org(`/scans/${id}/report?format=${fmt}`), `${repo.fullName.replace('/', '-')}-${id.slice(0, 8)}.${ext}`)) }, label)));

  const list = h('div');
  const q = h('input', { type: 'search', placeholder: 'Search title, CVE, package, file', size: 30, 'aria-label': 'Search findings' });
  const sev = h('select', { 'aria-label': 'Severity' }, [['', 'All severities'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']].map(([v, l]) => h('option', { value: v }, l)));
  const cat = h('select', { 'aria-label': 'Category' }, [['', 'All types'], ['sca', 'Dependencies'], ['sast', 'Code'], ['secret', 'Secrets'], ['container', 'Containers'], ['iac', 'Infrastructure']].map(([v, l]) => h('option', { value: v }, l)));
  const st = h('select', { 'aria-label': 'Status' }, [['', 'Any status'], ['open', 'Open'], ['acknowledged', 'Acknowledged'], ['suppressed', 'Suppressed'], ['fixed', 'Fixed']].map(([v, l]) => h('option', { value: v }, l)));

  async function load() {
    Object.assign(filters, { severity: sev.value, category: cat.value, status: st.value, q: q.value.trim() });
    const params = new URLSearchParams({ page: filters.page, pageSize: 25 });
    for (const k of ['severity', 'category', 'status', 'q']) if (filters[k]) params.set(k, filters[k]);
    const data = await guard(() => api.get(api.org(`/scans/${id}/findings?${params}`)));
    if (!data) return;
    clear(list);
    list.append(findingsTable(data.items, repo, id, load));
    const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
    list.append(h('div', { class: 'pager' }, h('span', { class: 'muted' }, `${data.total} finding(s) - page ${data.page} of ${pages}`),
      h('button', { type: 'button', disabled: data.page <= 1, onclick: () => { filters.page--; load(); } }, 'Previous'),
      h('button', { type: 'button', disabled: data.page >= pages, onclick: () => { filters.page++; load(); } }, 'Next')));
  }
  let debounce;
  q.addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(() => { filters.page = 1; load(); }, 250); });
  for (const s of [sev, cat, st]) s.addEventListener('change', () => { filters.page = 1; load(); });

  root.append(h('section', { class: 'card' },
    h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Findings'), exports),
    h('div', { class: 'row' }, q, sev, cat, st), list));
  load();
}

function findingsTable(items, repo, scanId, reload) {
  if (!items.length) return h('div', { class: 'empty' }, 'No findings match.');
  const body = h('tbody');
  for (const f of items) {
    const where = f.location.package ? `${f.location.package}@${f.location.version}` : `${f.location.file || ''}${f.location.line ? `:${f.location.line}` : ''}`;
    const detailRow = h('tr', { class: 'hidden' }, h('td', { colspan: 6, style: null }, findingDetail(f, repo, reload)));
    const toggle = h('button', { class: 'link', type: 'button', 'aria-expanded': 'false' }, f.title);
    toggle.addEventListener('click', () => {
      const open = detailRow.classList.toggle('hidden') === false;
      toggle.setAttribute('aria-expanded', String(open));
    });
    body.append(h('tr', null, h('td', null, sevBadge(f.severity)), h('td', null, toggle), h('td', null, f.category),
      h('td', { class: 'mono' }, where), h('td', null, f.remediation.fixedIn ? `Upgrade to ${f.remediation.fixedIn}` : f.remediation.advice ? 'See details' : '-'), h('td', null, statusBadge(f.status))), detailRow);
  }
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, ['Severity', 'Finding', 'Type', 'Location', 'Fix', 'Status'].map((x) => h('th', { scope: 'col' }, x)))), body));
}

function findingDetail(f, repo, reload) {
  const ids = [f.identifiers.primary, ...f.identifiers.aliases, ...f.identifiers.cwe].filter(Boolean);
  const kv = h('dl', { class: 'kv' },
    h('dt', null, 'Identifiers'), h('dd', null, ids.join(', ') || '-'),
    h('dt', null, 'Found by'), h('dd', null, (f.sources || [f.scanner]).map((s) => `${s.name}${s.version ? ` ${s.version}` : ''}`).join(', ')),
    f.cvssScore != null ? [h('dt', null, 'CVSS'), h('dd', null, f.cvssScore)] : null,
    f.location.file ? [h('dt', null, 'File'), h('dd', { class: 'mono' }, `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}`)] : null,
    f.location.package ? [h('dt', null, 'Package'), h('dd', null, `${f.location.package}@${f.location.version} (${f.location.ecosystem}, ${f.location.direct === true ? 'direct' : f.location.direct === false ? 'transitive' : 'unknown'})`)] : null,
    f.remediation.fixedIn ? [h('dt', null, 'Fixed in'), h('dd', null, f.remediation.fixedIn)] : null,
    f.remediation.advice ? [h('dt', null, 'Advice'), h('dd', null, f.remediation.advice)] : null,
    f.url && /^https:\/\//.test(f.url) ? [h('dt', null, 'Advisory'), h('dd', null, h('a', { href: f.url, target: '_blank', rel: 'noopener noreferrer' }, f.url))] : null);

  const left = h('div', null, h('h3', null, 'Details'), f.description ? h('p', null, f.description) : null, kv,
    f.evidence ? [h('h3', null, 'Evidence'), h('pre', { class: 'evidence' }, f.evidence)] : null,
    f.location.paths && f.location.paths.length ? [h('h3', null, 'Dependency path'),
      ...f.location.paths.slice(0, 3).map((p) => h('div', { class: 'mono small' }, p.join('  >  ')))] : null);

  // triage
  const status = h('select', { 'aria-label': 'Status' }, ['open', 'acknowledged', 'suppressed', 'fixed'].map((s) => h('option', { value: s, selected: s === f.status }, s)));
  const note = h('textarea', { 'aria-label': 'Note', placeholder: 'Note (required to suppress)' }, f.note || '');
  const save = h('button', { type: 'button', class: 'primary' }, 'Save');
  const history = h('div', { class: 'small muted' });
  save.addEventListener('click', () => guard(async () => {
    await api.patch(api.org(`/repos/${repo.id}/findings/${f.id}`), { status: status.value, note: note.value });
    toast('Finding updated');
    reload();
  }, { busy: save }));
  const showHistory = h('button', { class: 'link', type: 'button' }, 'Show review history');
  showHistory.addEventListener('click', () => guard(async () => {
    const rows = await api.get(api.org(`/repos/${repo.id}/findings/${f.id}/history`));
    clear(history).append(rows.length ? rows.map((r) => h('div', null, `${fmtDate(r.createdAt)} - ${r.user || 'system'}: ${r.action}${r.detail ? ` (${r.detail})` : ''}`)) : 'No changes yet.');
  }));

  const right = h('div', null, h('h3', null, 'Triage'), can('findings:write') ? [h('div', { class: 'row' }, status), note, h('div', { class: 'row' }, save)] : h('p', { class: 'muted' }, `Status: ${f.status}`), showHistory, history);

  const aiBox = h('div', { class: 'ai-box hidden' });
  const aiButtons = can('ai:use') ? h('div', { class: 'row' },
    aiButton('Explain with AI', `/findings/${f.rowId}/explain`, aiBox), aiButton('Suggest a fix', `/findings/${f.rowId}/fix`, aiBox)) : null;

  return [left, right, aiButtons ? h('div', { class: 'ai-box-wrap' }, aiButtons) : null, aiBox];
}

function aiButton(label, path, box) {
  const b = h('button', { type: 'button' }, label);
  b.addEventListener('click', () => guard(async () => {
    box.classList.remove('hidden');
    clear(box).append(h('span', { class: 'muted' }, 'Thinking...'));
    const r = await api.post(api.org(path)).catch((e) => { box.classList.add('hidden'); throw e; });
    clear(box).append(h('span', { class: 'badge ai-label' }, `AI-generated - ${r.meta.provider}`),
      h('p', null, r.text),
      r.upgradeImpact ? h('p', { class: 'small' }, `Upgrade impact (computed, not AI): ${r.upgradeImpact.kind} change ${r.upgradeImpact.from} to ${r.upgradeImpact.to}. ${r.upgradeImpact.note}`) : null,
      r.warnings && r.warnings.length ? h('p', { class: 'small' }, r.warnings.join(' ')) : null,
      h('p', { class: 'small muted' }, 'AI commentary can be wrong. The scanner finding above is the source of truth.'));
  }, { busy: b }));
  return b;
}
