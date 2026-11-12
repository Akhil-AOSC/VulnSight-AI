'use strict';

// HTML link/form extraction (used by every crawler) and a small sensitive-file probe that is the
// fallback for verified sites when Nuclei is not installed. The probe never stores file contents:
// evidence says what matched, with secrets redacted.

const { URL } = require('node:url');
const { createFinding } = require('../../findings');
const { guardedRequest, guardedLookup, detectBlock, redactEvidence } = require('./net-guard');

const SENSITIVE_PATHS = [
  {
    path: '/.env',
    title: 'Exposed Environment File (.env)',
    severity: 'critical',
    cwe: 'CWE-552',
    match: (body) => /^\s*(DB_|DATABASE_|SECRET|AWS_|API_KEY|APP_KEY|PASSWORD|MAIL_PASSWORD|[A-Z_]*TOKEN)[A-Z0-9_]*\s*=/m.test(body),
    describe: (body) => `${(body.match(/^\s*[A-Z][A-Z0-9_]*\s*=/gm) || []).length} KEY=value lines; names: ${(body.match(/^\s*([A-Z][A-Z0-9_]*)\s*=/gm) || []).slice(0, 6).map((l) => l.replace(/\s*=.*$/, '').trim()).join(', ')} (values not stored)`,
    advice: 'Remove .env from the public document root, rotate every credential it contains, and block dotfiles in the web server.',
  },
  {
    path: '/.git/HEAD',
    title: 'Exposed Git Repository Metadata (/.git/HEAD)',
    severity: 'high',
    cwe: 'CWE-538',
    match: (body) => /^ref: refs\/heads\/[\w./-]+\s*$/.test(body.trim()),
    describe: (body) => redactEvidence(body.trim(), 80),
    advice: 'Block public access to the .git directory; attackers can download the full source history from it.',
  },
  {
    path: '/.git/config',
    title: 'Exposed Git Repository Configuration (/.git/config)',
    severity: 'high',
    cwe: 'CWE-538',
    match: (body) => /^\[core\]/m.test(body) && /repositoryformatversion/.test(body),
    describe: () => '[core] section with repositoryformatversion (remote URLs not stored)',
    advice: 'Block public access to the .git directory and rotate any credentials embedded in remote URLs.',
  },
  {
    path: '/phpinfo.php',
    title: 'Exposed PHP Information Page (phpinfo.php)',
    severity: 'high',
    cwe: 'CWE-200',
    match: (body) => /<title>PHP \d[^<]*phpinfo\(\)<\/title>|<h1 class="p">PHP Version/i.test(body),
    describe: (body) => {
      const v = body.match(/PHP Version\s*([\d.]+)/i);
      return `phpinfo() output${v ? `, PHP ${v[1]}` : ''}`;
    },
    advice: 'Delete phpinfo.php; it reveals the full server configuration and environment.',
  },
  {
    path: '/server-status',
    title: 'Exposed Apache server-status Page',
    severity: 'medium',
    cwe: 'CWE-200',
    match: (body) => /<title>Apache Status<\/title>/i.test(body) && /Server Version:/i.test(body),
    describe: () => 'Apache mod_status page with live request list',
    advice: 'Restrict /server-status to localhost or an admin network.',
  },
  // Exposed debug, API-doc and config paths from the OWASP A05 list in the web-hacking skill
  // (mahmutka/cybersecurity-claude-skills). Matchers are anchored to each file's real format, so a
  // site that answers 200 with its home page for every path does not produce a finding.
  {
    path: '/actuator/env',
    title: 'Spring Boot Actuator Environment Exposed (/actuator/env)',
    severity: 'high',
    cwe: 'CWE-215',
    match: (body) => /"propertySources"\s*:/.test(body) && /"activeProfiles"\s*:/.test(body),
    describe: (body) => `actuator env JSON with ${(body.match(/"name"\s*:/g) || []).length} property sources (values not stored)`,
    advice: 'Do not expose Actuator endpoints publicly. Set management.endpoints.web.exposure.include=health and put the rest behind authentication.',
  },
  {
    path: '/actuator',
    title: 'Spring Boot Actuator Index Exposed (/actuator)',
    severity: 'medium',
    cwe: 'CWE-215',
    match: (body) => /"_links"\s*:\s*\{/.test(body) && /\/actuator\//.test(body),
    describe: (body) => `endpoints listed: ${[...new Set((body.match(/"([a-z-]+)"\s*:\s*\{\s*"href"/g) || []).map((s) => s.match(/"([a-z-]+)"/)[1]))].slice(0, 10).join(', ')}`,
    advice: 'Expose only /actuator/health publicly; require authentication for every other Actuator endpoint.',
  },
  {
    path: '/v3/api-docs',
    title: 'OpenAPI Specification Publicly Accessible (/v3/api-docs)',
    severity: 'low',
    cwe: 'CWE-200',
    match: (body) => /^\s*\{[\s\S]*"openapi"\s*:\s*"3\./.test(body),
    describe: (body) => `OpenAPI ${(body.match(/"openapi"\s*:\s*"([^"]+)"/) || [])[1] || '3.x'} with ${(body.match(/"\/[^"]*"\s*:\s*\{/g) || []).length} paths`,
    advice: 'If this API is not meant to be public, serve its specification only to authenticated users.',
  },
  {
    path: '/v2/api-docs',
    title: 'Swagger Specification Publicly Accessible (/v2/api-docs)',
    severity: 'low',
    cwe: 'CWE-200',
    match: (body) => /^\s*\{[\s\S]*"swagger"\s*:\s*"2\./.test(body),
    describe: (body) => `Swagger 2.0 with ${(body.match(/"\/[^"]*"\s*:\s*\{/g) || []).length} paths`,
    advice: 'If this API is not meant to be public, serve its specification only to authenticated users.',
  },
  {
    path: '/swagger-ui.html',
    title: 'Swagger UI Publicly Accessible',
    severity: 'low',
    cwe: 'CWE-200',
    match: (body) => /<title>\s*Swagger UI\s*<\/title>/i.test(body),
    describe: () => 'Swagger UI page served',
    advice: 'Disable Swagger UI in production or put it behind authentication.',
  },
  {
    path: '/web.config',
    title: 'IIS web.config Readable',
    severity: 'high',
    cwe: 'CWE-538',
    match: (body) => /<configuration[\s>]/.test(body) && /<system\.(web|webServer)[\s>]/.test(body),
    describe: (body) => `web.config XML${/connectionString/i.test(body) ? ' including connectionStrings' : ''} (contents not stored)`,
    advice: 'Block requests for web.config at the server; IIS normally refuses them, so check custom handlers and static-file rules.',
  },
  {
    path: '/wp-config.php.bak',
    title: 'WordPress Config Backup Readable (wp-config.php.bak)',
    severity: 'critical',
    cwe: 'CWE-530',
    match: (body) => /define\(\s*['"]DB_(NAME|USER|PASSWORD)['"]/.test(body),
    describe: () => 'wp-config backup with DB_* settings (values not stored)',
    advice: 'Delete the backup file, rotate the database password and WordPress salts, and block *.bak files at the server.',
  },
  {
    path: '/.env.bak',
    title: 'Environment File Backup Readable (.env.bak)',
    severity: 'critical',
    cwe: 'CWE-530',
    match: (body) => /^\s*(DB_|DATABASE_|SECRET|AWS_|API_KEY|APP_KEY|PASSWORD)[A-Z0-9_]*\s*=/m.test(body),
    describe: (body) => `${(body.match(/^\s*[A-Z][A-Z0-9_]*\s*=/gm) || []).length} KEY=value lines (values not stored)`,
    advice: 'Delete the backup, rotate every credential in it, and block dotfiles and *.bak files at the server.',
  },
  {
    path: '/.DS_Store',
    title: 'macOS .DS_Store File Exposed',
    severity: 'low',
    cwe: 'CWE-538',
    match: (body) => body.slice(0, 16).includes('Bud1'),
    describe: () => '.DS_Store index (lists file names in that folder)',
    advice: 'Delete .DS_Store files from the web root and block dotfiles at the server.',
  },
  {
    path: '/wp-content/uploads/',
    title: 'Directory Listing Enabled (/wp-content/uploads/)',
    severity: 'medium',
    cwe: 'CWE-548',
    match: (body) => /<title>\s*Index of \/wp-content\/uploads/i.test(body),
    describe: (body) => `directory index with ${(body.match(/<a href=/gi) || []).length} entries`,
    advice: 'Turn off directory listing (Apache: Options -Indexes; nginx: autoindex off).',
  },
  {
    path: '/uploads/',
    title: 'Directory Listing Enabled (/uploads/)',
    severity: 'medium',
    cwe: 'CWE-548',
    match: (body) => /<title>\s*Index of \/uploads/i.test(body),
    describe: (body) => `directory index with ${(body.match(/<a href=/gi) || []).length} entries`,
    advice: 'Turn off directory listing (Apache: Options -Indexes; nginx: autoindex off).',
  },
  {
    path: '/robots.txt',
    title: 'Robots.txt Lists Sensitive-Looking Paths',
    severity: 'low',
    cwe: 'CWE-200',
    match: (body) => /^\s*Disallow:\s*\/[^\s]*(admin|backup|private|internal|staging|config|secret|\.git|db|sql|dump)/im.test(body),
    describe: (body) => (body.match(/^\s*Disallow:\s*\/[^\s]*(admin|backup|private|internal|staging|config|secret|\.git|db|sql|dump)[^\s]*/gim) || []).slice(0, 5).map((l) => l.trim()).join('; '),
    advice: 'robots.txt is public. Protect sensitive areas with authentication instead of hiding them there.',
  },
];

function extractLinksAndForms(body, baseOrigin) {
  const links = new Set();
  const forms = [];

  const aRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["']/gi;
  let match;
  while ((match = aRegex.exec(body)) !== null) {
    const raw = match[1].trim();
    if (raw && !raw.startsWith('#') && !/^(javascript|mailto|tel|data):/i.test(raw)) {
      try {
        const u = new URL(raw, baseOrigin);
        if (u.origin === baseOrigin) links.add(u.pathname + u.search);
      } catch { /* ignore invalid url */ }
    }
  }

  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fMatch;
  while ((fMatch = formRegex.exec(body)) !== null) {
    const formAttrs = fMatch[1];
    const formInner = fMatch[2];
    const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i);
    const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i);
    const action = (actionMatch && actionMatch[1].trim()) || '';
    const method = ((methodMatch && methodMatch[1].trim()) || 'GET').toUpperCase();
    const params = [];
    const inputRegex = /<(?:input|select|textarea)\b([^>]*)>/gi;
    let iMatch;
    while ((iMatch = inputRegex.exec(formInner)) !== null) {
      const nameMatch = iMatch[1].match(/name=["']([^"']+)["']/i);
      if (nameMatch && !params.includes(nameMatch[1])) params.push(nameMatch[1]);
    }
    try {
      const u = new URL(action || '/', baseOrigin);
      if (u.origin === baseOrigin) forms.push({ url: u.href, path: u.pathname, method, parameters: params });
    } catch { /* ignore */ }
  }

  return { links: Array.from(links), forms };
}

/**
 * Requests a fixed list of well-known sensitive paths on a VERIFIED site. Content checks are
 * strict (a soft-404 page that returns 200 for everything does not match), and evidence never
 * contains the file's secret values.
 */
async function probeSensitivePaths(baseUrl, { lookup = guardedLookup, timeoutMs = 5000, minGapMs = 500, shouldStop = async () => false } = {}) {
  const base = new URL(baseUrl);
  const findings = [];
  let blocked = null;
  for (const s of SENSITIVE_PATHS) {
    if (await shouldStop()) break;
    const url = new URL(s.path, base.origin);
    let res;
    try {
      res = await guardedRequest(url, { timeoutMs, lookup, maxBytes: 100000, userAgent: 'VulnSight-Security-Crawler/1.0' });
    } catch {
      continue;
    }
    const block = detectBlock(res.statusCode, res.headers, res.body);
    if (block.blocked) {
      blocked = block;
      break;
    }
    // The matchers are anchored to the real file format, so a soft-404 page that answers 200 for
    // every path does not produce a finding.
    if (res.statusCode === 200 && s.match(res.body)) {
      findings.push(createFinding({
        category: 'dast',
        severity: s.severity,
        title: s.title,
        description: `The path "${s.path}" is publicly readable and its content matches a known sensitive file, not a generic error page.`,
        identifiers: { cwe: [s.cwe], primary: s.cwe },
        location: { url: url.href, path: s.path },
        scanner: { name: 'vulnsight-crawler', ruleId: `exposed-file-${s.path.replace(/[^a-z0-9]/gi, '_')}`, version: '1.1' },
        remediation: { advice: s.advice },
        evidence: redactEvidence(`HTTP 200 ${s.path}: ${s.describe(res.body)}`, 300),
      }));
    }
    await new Promise((r) => setTimeout(r, minGapMs));
  }
  return { findings, blocked };
}

module.exports = {
  extractLinksAndForms,
  probeSensitivePaths,
  SENSITIVE_PATHS,
};
