'use strict';

(function () {
  const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];
  const LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown' };

  const $ = (id) => document.getElementById(id);

  // Builds DOM nodes. Text always goes through textContent, because advisory
  // titles come from an external database and must never be parsed as HTML.
  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : String(value));
    }
    for (const child of children.flat()) {
      if (child !== null && child !== undefined && child !== false) node.append(child);
    }
    return node;
  }

  const storage = {
    get(key) {
      try { return localStorage.getItem(key); } catch { return null; }
    },
    set(key, value) {
      try { localStorage.setItem(key, value); } catch { /* storage unavailable */ }
    },
  };

  const state = {
    history: [],
    scan: null,
    issues: [],
    filters: { search: '', severities: new Set(), project: '', fixable: false },
  };

  async function api(path, options) {
    const res = await fetch(path, options);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
    return body;
  }

  const basename = (p) => {
    const name = String(p).split(/[\\/]/).filter(Boolean).pop() || String(p);
    return name.endsWith('.git') ? name.slice(0, -4) : name;
  };
  const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
  const formatDate = (iso) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

  function sevLabel(level) {
    return el('span', { class: 'sev-label' }, el('i', { class: `dot sev-${level}`, 'aria-hidden': 'true' }), LABELS[level]);
  }

  // ---- Theme ----

  function effectiveTheme() {
    return document.documentElement.dataset.theme
      || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }

  function updateThemeButton() {
    $('theme-toggle').textContent = effectiveTheme() === 'dark' ? 'Light mode' : 'Dark mode';
  }

  function initTheme() {
    const saved = storage.get('vulnsight-theme');
    if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
    updateThemeButton();
    $('theme-toggle').addEventListener('click', () => {
      const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      storage.set('vulnsight-theme', next);
      updateThemeButton();
    });
  }

  // ---- History ----

  function renderHistory() {
    const list = $('history');
    list.replaceChildren();
    if (!state.history.length) {
      list.append(el('li', { class: 'history-empty', text: 'No scans yet.' }));
      return;
    }
    for (const item of state.history) {
      const worst = SEVERITIES.find((s) => item.summary[s] > 0);
      const isMongo = item.source === 'mongodb';
      list.append(el('li', {},
        el('button', {
          type: 'button',
          'aria-current': state.scan && state.scan.id === item.id ? 'true' : 'false',
          onclick: () => openScan(item.id),
        },
        el('span', { class: 'history-name', text: basename(item.target) }),
        el('span', { class: 'history-meta' },
          worst ? el('i', { class: `dot sev-${worst}`, 'aria-hidden': 'true' }) : null,
          `${plural(item.summary.issues, 'issue')} · ${formatDate(item.scannedAt)}`,
          isMongo ? el('span', { class: 'mongo-badge', title: 'Stored in MongoDB Atlas' }, '· Mongo') : null))));
    }
  }

  async function loadHistory() {
    state.history = await api('/api/scans');
    renderHistory();
  }

  async function openScan(id) {
    try {
      showScan(await api(`/api/scans/${encodeURIComponent(id)}`));
    } catch (err) {
      setStatus(err.message, true);
    }
  }

  // ---- Scan form ----

  function setStatus(message, isError = false, busy = false) {
    const status = $('scan-status');
    status.replaceChildren();
    status.classList.toggle('is-error', isError);
    if (busy) status.append(el('span', { class: 'spinner', 'aria-hidden': 'true' }));
    if (message) status.append(message);
  }

  async function runScan(event) {
    event.preventDefault();
    const targetVal = $('scan-path').value.trim();
    const isGit = /^(https?|git|ssh):\/\//i.test(targetVal)
      || /^(github|gitlab|bitbucket)\.[a-zA-Z0-9.-]+\//i.test(targetVal)
      || (targetVal.endsWith('.git') && !targetVal.includes('\\'));

    const button = $('scan-submit');
    button.disabled = true;
    button.textContent = 'Scanning...';
    setStatus(
      isGit
        ? 'Cloning remote repository and checking OSV.dev...'
        : 'Checking every package against OSV.dev. This can take a few seconds.',
      false,
      true
    );
    try {
      const record = await api('/api/scans', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          path: $('scan-path').value,
          threshold: $('scan-threshold').value,
          dev: $('scan-dev').checked,
        }),
      });
      setStatus('');
      await loadHistory();
      showScan(record);
    } catch (err) {
      setStatus(err.message, true);
    } finally {
      button.disabled = false;
      button.textContent = 'Run scan';
    }
  }

  function showNewScan() {
    state.scan = null;
    history.replaceState(null, '', location.pathname);
    $('page-title').textContent = 'New scan';
    $('page-meta').textContent = "Scan a project's dependencies for known vulnerabilities.";
    $('results').hidden = true;
    $('empty-state').hidden = false;
    setStatus('');
    renderHistory();
    $('scan-path').focus();
  }

  // ---- Results ----

  function showScan(scan) {
    state.scan = scan;
    state.issues = scan.projects.flatMap((project, projectIndex) =>
      project.vulnerabilities.map((v) => ({ ...v, project, projectIndex })));
    state.filters = { search: '', severities: new Set(), project: '', fixable: false };
    history.replaceState(null, '', `#scan=${scan.id}`);

    const options = scan.options || {};
    $('page-title').textContent = basename(scan.target);
    $('page-meta').textContent = `${scan.target} · scanned ${formatDate(scan.scannedAt)}`
      + (options.threshold && options.threshold !== 'low' ? ` · ${options.threshold} and above` : '')
      + (options.dev ? ' · including dev dependencies' : '');
    $('empty-state').hidden = true;
    $('results').hidden = false;

    renderSummary();
    renderAiCard();
    renderSeverityBar();
    renderWarnings();
    renderProjects();
    renderPlan();
    renderFilters();
    renderIssues();
    renderHistory();
  }

  function renderAiCard() {
    const ai = state.scan.ai;
    const card = $('ai-card');
    if (!card) return;
    if (!ai) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const tag = $('ai-risk-tag');
    tag.textContent = `Risk: ${ai.riskLevel || 'Analyzed'}`;
    tag.className = `ai-risk-tag ai-risk-${ai.riskLevel || 'Medium'}`;

    $('ai-summary').textContent = ai.executiveSummary || '';

    const impactBox = $('ai-impact-box');
    if (ai.impactAnalysis) {
      impactBox.hidden = false;
      $('ai-impact').textContent = ai.impactAnalysis;
    } else {
      impactBox.hidden = true;
    }

    const recBox = $('ai-rec-box');
    const recsList = $('ai-recs');
    recsList.replaceChildren();
    if (Array.isArray(ai.keyRecommendations) && ai.keyRecommendations.length > 0) {
      recBox.hidden = false;
      for (const rec of ai.keyRecommendations) {
        recsList.append(el('li', { text: rec }));
      }
    } else {
      recBox.hidden = true;
    }
  }

  function renderSummary() {
    const s = state.scan.summary;
    $('t-total').textContent = s.issues;
    $('t-deps').textContent = `${plural(s.dependencies, 'dependency', 'dependencies')} tested in ${plural(state.scan.projects.length, 'project')}`;
    for (const level of ['critical', 'high', 'medium', 'low']) $(`t-${level}`).textContent = s[level];
  }

  function renderSeverityBar() {
    const s = state.scan.summary;
    const bar = $('sevbar');
    const legend = $('legend');
    const tooltip = $('tooltip');
    const card = bar.closest('.card');
    bar.replaceChildren();
    legend.replaceChildren();

    const fixable = state.issues.filter((i) => i.fixedIn).length;
    $('fixable-note').textContent = s.issues ? `${fixable} of ${s.issues} have a fixed version` : '';

    if (!s.issues) {
      bar.setAttribute('aria-label', 'No issues found');
      legend.append(el('li', { text: 'No known vulnerabilities found.' }));
      return;
    }

    const levels = SEVERITIES.filter((l) => s[l] > 0);
    bar.setAttribute('aria-label', levels.map((l) => `${LABELS[l]}: ${s[l]}`).join(', '));

    for (const level of levels) {
      const pct = Math.round((s[level] / s.issues) * 100);
      const text = `${LABELS[level]}: ${plural(s[level], 'issue')} (${pct}%)`;
      const segment = el('span', { class: `sev-${level}` });
      segment.style.flex = `${s[level]} 1 0`;
      segment.addEventListener('mouseenter', () => {
        tooltip.textContent = text;
        tooltip.hidden = false;
      });
      segment.addEventListener('mousemove', (e) => {
        const box = card.getBoundingClientRect();
        let left = e.clientX - box.left + 12;
        if (left + tooltip.offsetWidth > box.width - 8) left = e.clientX - box.left - tooltip.offsetWidth - 12;
        tooltip.style.left = `${left}px`;
        tooltip.style.top = `${e.clientY - box.top - 40}px`;
      });
      segment.addEventListener('mouseleave', () => { tooltip.hidden = true; });
      bar.append(segment);

      legend.append(el('li', {},
        el('i', { class: `dot sev-${level}`, 'aria-hidden': 'true' }),
        `${LABELS[level]} `, el('strong', { text: String(s[level]) })));
    }
  }

  function renderWarnings() {
    const box = $('warnings');
    box.replaceChildren(...(state.scan.warnings || []).map((w) => el('div', { class: 'warning', text: w })));
  }

  function countsFor(summary) {
    const levels = ['critical', 'high', 'medium', 'low'].filter((l) => summary[l] > 0);
    if (!levels.length && !summary.unknown) return el('span', { class: 'counts' }, el('span', { class: 'plan-target', text: 'No issues' }));
    return el('span', { class: 'counts' },
      levels.map((l) => el('span', { title: LABELS[l] },
        el('i', { class: `dot sev-${l}`, 'aria-hidden': 'true' }), `${summary[l]} ${LABELS[l].toLowerCase()}`)));
  }

  function renderProjects() {
    $('projects').replaceChildren(...state.scan.projects.map((p) => {
      const meta = [p.packageManager, basename(p.file), plural(p.dependencyCount, 'dependency', 'dependencies')];
      if (p.skipped.length) meta.push(`${p.skipped.length} not pinned`);
      return el('li', {},
        el('div', {},
          el('div', { class: 'project-name', text: p.projectName }),
          el('div', { class: 'project-meta', text: meta.join(' · ') })),
        countsFor(p.summary));
    }));
  }

  function renderPlan() {
    const multi = state.scan.projects.length > 1;
    const items = state.scan.projects.flatMap((p) => p.upgradePlan.map((step) => ({ ...step, project: p })));
    if (!items.length) {
      $('plan').replaceChildren(el('li', { class: 'subtle', text: 'Nothing to upgrade.' }));
      return;
    }
    $('plan').replaceChildren(...items.map((step) => {
      const label = `${step.package}@${step.version}`;
      const where = multi ? ` · ${basename(step.project.file)}` : '';
      if (!step.target) {
        return el('li', {},
          el('span', { class: 'mono', text: label }),
          el('span', { class: 'plan-meta', text: `No fix yet for ${plural(step.unfixed, 'issue')}${where}` }));
      }
      const extra = step.unfixed ? `, ${step.unfixed} not fixable yet` : '';
      return el('li', {},
        el('span', { class: 'mono' }, `${label} → `, el('span', { class: 'plan-target', text: step.target })),
        el('span', { class: 'plan-meta', text: `Fixes ${plural(step.fixes, 'issue')}${extra}${where}` }));
    }));
  }

  // ---- Issues table ----

  function renderFilters() {
    const f = state.filters;
    $('f-search').value = '';
    $('f-fixable').checked = false;

    const chips = $('f-severity');
    chips.replaceChildren();
    for (const level of SEVERITIES.filter((l) => state.scan.summary[l] > 0)) {
      const chip = el('button', { type: 'button', class: 'chip', 'aria-pressed': 'false' },
        el('i', { class: `dot sev-${level}`, 'aria-hidden': 'true' }), `${LABELS[level]} ${state.scan.summary[level]}`);
      chip.addEventListener('click', () => {
        if (f.severities.has(level)) f.severities.delete(level);
        else f.severities.add(level);
        chip.setAttribute('aria-pressed', String(f.severities.has(level)));
        renderIssues();
      });
      chips.append(chip);
    }

    const select = $('f-project');
    select.replaceChildren(el('option', { value: '', text: 'All projects' }),
      ...state.scan.projects.map((p, i) => el('option', { value: String(i), text: `${p.projectName} (${basename(p.file)})` })));
    select.hidden = state.scan.projects.length < 2;
  }

  function filteredIssues() {
    const f = state.filters;
    const q = f.search.trim().toLowerCase();
    return state.issues.filter((i) =>
      (!f.severities.size || f.severities.has(i.severity))
      && (f.project === '' || String(i.projectIndex) === f.project)
      && (!f.fixable || i.fixedIn)
      && (!q || [i.title, i.id, i.package, ...i.aliases].some((s) => s.toLowerCase().includes(q))));
  }

  function detailsRow(issue) {
    const cves = issue.aliases.length ? issue.aliases.join(', ') : 'None';
    const items = [];
    if (issue.aiExplanation) {
      items.push(el('dt', { text: 'AI Explanation' }), el('dd', { class: 'ai-explanation', text: issue.aiExplanation }));
    }
    items.push(
      el('dt', { text: 'Remediation' }), el('dd', { text: issue.remediation }),
      el('dt', { text: 'Dependency paths' }),
      el('dd', {}, el('ul', {}, issue.paths.map((p) => el('li', { class: 'mono', text: p.join(' › ') })))),
      el('dt', { text: 'Other IDs' }), el('dd', { class: 'mono', text: cves }),
      el('dt', { text: 'CVSS score' }), el('dd', { text: issue.cvssScore === null ? 'Not provided' : issue.cvssScore.toFixed(1) }),
      el('dt', { text: 'Found in' }), el('dd', { class: 'mono', text: issue.project.file }),
      el('dt', { text: 'Advisory' }),
      el('dd', {}, el('a', { href: issue.url, target: '_blank', rel: 'noopener noreferrer', text: issue.url }))
    );
    return el('tr', { class: 'details' }, el('td', { colspan: 5 }, el('dl', {}, ...items)));
  }

  function issueRow(issue) {
    const cves = issue.aliases.filter((a) => a.startsWith('CVE-'));
    const firstPath = issue.paths[0] || [];
    const row = el('tr', { class: 'row', tabindex: 0, 'aria-expanded': 'false' },
      el('td', {}, sevLabel(issue.severity)),
      el('td', {},
        el('div', { class: 'issue-title', text: issue.title }),
        el('div', { class: 'issue-id', text: [issue.id, ...cves].join(' · ') })),
      el('td', { class: 'mono', text: `${issue.package}@${issue.version}` }),
      el('td', {},
        el('div', { class: 'path', text: firstPath.join(' › ') }),
        issue.paths.length > 1 ? el('div', { class: 'more', text: `+${plural(issue.paths.length - 1, 'more path')}` }) : null),
      el('td', {}, issue.fixedIn
        ? el('span', { class: 'fix', text: `Upgrade to ${issue.fixedIn}` })
        : el('span', { class: 'nofix', text: 'No fix yet' })));

    function toggle() {
      const open = row.getAttribute('aria-expanded') === 'true';
      row.setAttribute('aria-expanded', String(!open));
      if (open) row.nextElementSibling.remove();
      else row.after(detailsRow(issue));
    }
    row.addEventListener('click', (e) => {
      if (!e.target.closest('a')) toggle();
    });
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggle();
      }
    });
    return row;
  }

  function renderIssues() {
    const shown = filteredIssues();
    $('issues-body').replaceChildren(...shown.map(issueRow));
    $('issues-empty').hidden = shown.length > 0 || state.issues.length === 0;
    $('issue-count').textContent = state.issues.length
      ? `Showing ${shown.length} of ${state.issues.length} · click a row for details`
      : 'No known vulnerabilities';
  }

  // ---- Start ----

  async function init() {
    initTheme();
    $('scan-form').addEventListener('submit', runScan);
    $('new-scan').addEventListener('click', showNewScan);
    $('f-search').addEventListener('input', (e) => { state.filters.search = e.target.value; renderIssues(); });
    $('f-project').addEventListener('change', (e) => { state.filters.project = e.target.value; renderIssues(); });
    $('f-fixable').addEventListener('change', (e) => { state.filters.fixable = e.target.checked; renderIssues(); });

    try {
      const config = await api('/api/config');
      $('scan-path').value = config.defaultTarget;
      let tags = [`v${config.version}`];
      if (config.aiEnabled) tags.push('Groq AI');
      $('version').textContent = tags.join(' · ');

      const indicator = $('db-indicator');
      if (indicator && config.mongo) {
        indicator.hidden = false;
        if (config.mongo.connected) {
          indicator.textContent = 'MongoDB Atlas';
          indicator.className = 'db-indicator db-connected';
          indicator.title = 'History actively synced with MongoDB Atlas collection.';
        } else if (config.mongo.configured) {
          indicator.textContent = 'Local (Atlas Blocked)';
          indicator.className = 'db-indicator db-fallback';
          indicator.title = 'MongoDB Atlas connection blocked by IP Access List. Add your IP or 0.0.0.0/0 at cloud.mongodb.com -> Network Access to enable live sync.';
        }
      }

      await loadHistory();
    } catch (err) {
      setStatus(`Could not reach the VulnSight-AI server: ${err.message}`, true);
      return;
    }

    const fromHash = location.hash.match(/^#scan=([\w-]+)$/);
    const initial = fromHash ? fromHash[1] : state.history[0] && state.history[0].id;
    if (initial) await openScan(initial);
  }

  init();
})();
