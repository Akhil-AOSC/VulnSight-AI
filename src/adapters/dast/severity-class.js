'use strict';

// Aligns Deep findings with pentest priority: injection / access-control / SSRF
// become high or critical. Header noise (CSP, HSTS, User-Agent fuzzer) stays medium/low.
const CRITICAL_CWE_IDS = new Set([
  22, // path traversal
  77, 78, // OS command injection
  89, // SQL injection
  90, // LDAP injection
  91, // XML injection
  94, 95, 96, 97, 98, // code / file inclusion
  284, 285, 639, 862, 863, // broken access control / IDOR
  287, 306, 384, // authentication bypass / session
  434, // unrestricted upload
  502, // unsafe deserialization
  611, // XXE
  917, // expression language injection
  918, // SSRF
]);

const DISCLOSURE_CWE_IDS = new Set([
  200, 209, 215, 259, 321, 522, 532, 798,
]);

const CRITICAL_TITLE = /sql\s*injection|remote\s+os\s+command|os\s+command\s+injection|remote\s+code\s+execution|\bcode\s+injection\b|ldap\s+injection|xpath\s+injection|expression\s+language|insecure\s+deserialization|xml\s+external\s+entity|server[\s-]*side\s+request\s+forgery|\bssrf\b|unrestricted\s+(file\s+)?upload|path\s+traversal|directory\s+traversal|file\s+inclusion|insecure\s+direct\s+object|broken\s+access\s+control|\bidor\b|authentication\s+bypass|auth(?:entication)?\s+bypass/i;
const CSRF_TITLE = /anti-?csrf|cross[\s-]?site request forgery|\bcsrf\b|\bxsrf\b/;
const CSRF_CWE_IDS = new Set([352]);
const STORED_XSS_TITLE = /stored\s+(cross[\s-]?site\s+scripting|xss)|(cross[\s-]?site\s+scripting|xss)\s*\(\s*stored/i;
const XSS_TITLE = /cross[\s-]?site\s+scripting|\bxss\b/i;
const DISCLOSURE_TITLE = /sensitive\s+information|source\s+code\s+disclosure|credentials?\s+disclosed|private\s+key|api[\s-]?key\s+disclosure/i;

function cweNumbers(cwes) {
  const out = [];
  for (const raw of [].concat(cwes || [])) {
    const m = String(raw).match(/(\d+)/);
    if (m) out.push(Number(m[1]));
  }
  return out;
}

function isCriticalAttackClass({ cwes, title } = {}) {
  if (cweNumbers(cwes).some((id) => CRITICAL_CWE_IDS.has(id))) return true;
  return CRITICAL_TITLE.test(String(title || ''));
}

function isSensitiveDisclosure({ cwes, title } = {}) {
  if (cweNumbers(cwes).some((id) => DISCLOSURE_CWE_IDS.has(id))) return true;
  return DISCLOSURE_TITLE.test(String(title || ''));
}

function classifyDastSeverity(baseSeverity, meta = {}) {
  const base = String(baseSeverity || 'low').toLowerCase();
  const title = String(meta.title || '');
  if (base === 'critical') return 'critical';
  if (isCriticalAttackClass(meta)) {
    if (base === 'high') return 'critical';
    if (base === 'medium') return 'high';
    return base;
  }
  if (cweNumbers(meta.cwes).some((id) => CSRF_CWE_IDS.has(id)) || CSRF_TITLE.test(title)) {
    if (base === 'high') return 'high';
    if (base === 'medium') return 'high';
    return base;
  }
  if (STORED_XSS_TITLE.test(title) && (base === 'medium' || base === 'high')) return 'high';
  if (XSS_TITLE.test(title) && base === 'high') return 'high';
  if (isSensitiveDisclosure(meta) && base === 'medium') return 'high';
  return base;
}

function elevateToCritical(baseSeverity, meta = {}) {
  return classifyDastSeverity(baseSeverity, meta);
}

module.exports = {
  CRITICAL_CWE_IDS,
  classifyDastSeverity,
  elevateToCritical,
  isCriticalAttackClass,
};
