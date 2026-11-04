'use strict';

const BY_RULE = {
  'header-strict-transport-security':
    'The site is not telling browsers to always use HTTPS. Someone on the same Wi-Fi or network could try to push a visitor onto an unencrypted page.',
  '10035':
    'The site is not telling browsers to always use HTTPS. Someone on the same Wi-Fi or network could try to push a visitor onto an unencrypted page.',
  'header-content-security-policy':
    'The site does not set a Content-Security-Policy. That policy is an allow-list for scripts and other content. Without it, injected script is easier to run.',
  '10038':
    'The site does not set a Content-Security-Policy, or the policy is too weak. That policy is an allow-list for scripts and other content.',
  'header-x-frame-options':
    'The site does not block other websites from showing it inside a frame. That is a common trick for clickjacking: overlaying a fake button over a real one.',
  '10020':
    'The site does not block other websites from showing it inside a frame. That is a common trick for clickjacking.',
  'header-x-content-type-options':
    'The site does not tell the browser to trust the declared file type. The browser might guess, which can turn a harmless file into executable script.',
  '10021':
    'The site does not tell the browser to trust the declared file type. The browser might guess, which can turn a harmless file into executable script.',
  'header-referrer-policy':
    'When people click a link away from this site, the next site may receive the full URL they came from, including path details you might not want shared.',
  'header-permissions-policy':
    'The site does not restrict powerful browser features such as camera or location. A compromised page could try to use them.',
  '10063':
    'The site does not restrict powerful browser features such as camera or location.',
  'cors-arbitrary-credentials':
    'The server accepts any other website as a trusted origin while also allowing cookies. A hostile page could then call this API as if it were the logged-in user.',
  'cors-wildcard':
    'Any website is allowed to read this response. That is sometimes intentional for public data, but it is not safe if the response includes private information.',
  'tls-cert-expired':
    'The HTTPS certificate has expired. Browsers will warn visitors, and attackers can more easily impersonate the site.',
  'tls-cert-expiring-soon':
    'The HTTPS certificate will expire soon. When it does, visitors will see security warnings until it is renewed.',
  'tls-deprecated-version':
    'The site negotiated an old TLS version. Those older versions have known cryptographic weaknesses and should be turned off.',
  'plain-http':
    'The site is reachable over plain HTTP, so traffic is not encrypted. Passwords, cookies, and page content can be read or changed in transit.',
  '10015':
    'This page can be stored in a browser or proxy cache. If the page holds private data, a later visitor on the same computer might see it.',
  '10036':
    'The server advertises its product name or version. That helps an attacker pick known bugs for that software.',
  '10037':
    'The server advertises extra product information in a response header. That helps an attacker pick known bugs for that software.',
  '10010':
    'A cookie is missing the HttpOnly flag, so page scripts can read it. If a script-injection bug exists, the session cookie is easier to steal.',
  '10011':
    'A cookie is missing the Secure flag, so the browser may send it over plain HTTP.',
  '10054':
    'A cookie is missing SameSite, so other sites may include it on cross-site requests.',
};

function severityPhrase(severity) {
  if (severity === 'critical') return 'This is treated as urgent.';
  if (severity === 'high') return 'This is a serious issue and should be fixed soon.';
  if (severity === 'medium') return 'This is a moderate issue. It is worth fixing, but it is not the highest priority.';
  return 'This is a lower-priority hardening issue.';
}

function plainEnglishForFinding(finding, siteUrl) {
  const loc = (finding.location && (finding.location.url || finding.location.path || finding.location.parameter)) || siteUrl || 'this website';
  const rule = finding.scanner && finding.scanner.ruleId;
  const named = (rule && BY_RULE[rule]) || simplify(finding.description) || simplify(finding.title);
  const fix = (finding.remediation && finding.remediation.advice) || 'Ask the site owner to apply the recommended server or header change.';
  const scanner = finding.scanner && finding.scanner.name === 'owasp-zap-ascan'
    ? 'An active security probe (OWASP ZAP) reported this.'
    : 'A configuration check reported this.';
  return [
    `${scanner} It was found at ${loc}.`,
    named,
    severityPhrase(finding.severity),
    `What to do: ${fix}`,
  ].join(' ');
}

function simplify(text) {
  const raw = String(text || '').replace(/\s+/g, ' ').trim();
  if (!raw) return '';
  return raw.length > 400 ? `${raw.slice(0, 397)}...` : raw;
}

module.exports = { plainEnglishForFinding, BY_RULE };
