'use strict';

const fs = require('fs');
const path = require('path');
const { createFinding } = require('../findings');

function mask(text, secret) {
  if (!text) return null;
  let out = String(text);
  if (secret && secret !== 'REDACTED') out = out.split(secret).join('[REDACTED]');
  return out.slice(0, 300);
}

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'vendor', 'coverage',
  '.vulnsight-data', '.vulnsight-tools', '.next', '__pycache__', 'out',
]);
const TEXT_EXTS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.go', '.env',
  '.json', '.yml', '.yaml', '.toml', '.ini', '.txt', '.md', '.cfg',
]);
const MAX_FILES = 400;
const MAX_FILE_BYTES = 200000;

const RULES = [
  {
    id: 'github-pat',
    title: 'GitHub personal access token',
    re: /\bghp_[A-Za-z0-9]{20,}/g,
  },
  {
    id: 'slack-webhook-url',
    title: 'Slack webhook URL',
    re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_+-]+/g,
  },
  {
    id: 'aws-access-token',
    title: 'AWS access key',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
  },
];

function walk(root, acc = [], state = { files: 0 }) {
  if (state.files >= MAX_FILES) return acc;
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const entry of entries) {
    if (state.files >= MAX_FILES) break;
    if (entry.name.startsWith('.') && entry.name !== '.' && entry.name !== '.env') continue;
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, acc, state);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (!TEXT_EXTS.has(ext) && entry.name !== '.env') continue;
      state.files += 1;
      acc.push(full);
    }
  }
  return acc;
}

function lineNumber(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text[i] === '\n') line += 1;
  }
  return line;
}

function scanBuiltinSecrets(root, { version = 'builtin-rules' } = {}) {
  const findings = [];
  for (const file of walk(root)) {
    let text;
    try {
      if (fs.statSync(file).size > MAX_FILE_BYTES) continue;
      text = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const rel = path.relative(root, file).split(path.sep).join('/');
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let match;
      while ((match = rule.re.exec(text))) {
        const secret = match[0];
        const line = lineNumber(text, match.index);
        findings.push(createFinding({
          category: 'secret',
          scanner: { name: 'gitleaks', version, ruleId: rule.id },
          title: rule.title,
          description: `A possible secret matching rule "${rule.id}" was found in the source.`,
          severity: 'high',
          identifiers: { primary: rule.id, aliases: [], cwe: ['CWE-798'] },
          location: { file: rel, line, endLine: line },
          remediation: {
            advice: 'Revoke and rotate this credential, then remove it from the code and Git history. Load secrets from the environment or a secret manager.',
          },
          evidence: mask(secret, secret),
        }));
      }
    }
  }
  return findings;
}

module.exports = { scanBuiltinSecrets, RULES, mask };
