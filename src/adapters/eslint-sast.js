'use strict';

const fs = require('fs');
const path = require('path');
const Module = require('module');
const { createFinding } = require('../findings');
const plugin = require('./sast-rules/eslint-plugin-vulnsight');

const IGNORE = ['**/node_modules/**', '**/dist/**', '**/build/**', '**/*.min.js', '**/.git/**'];
const FILES = ['**/*.js', '**/*.jsx', '**/*.mjs', '**/*.cjs'];
const SEVERITY = { 2: 'high', 1: 'medium', 0: 'low' };
const CWE = {
  'vulnsight/xss-res-send': ['CWE-79'],
  'vulnsight/detect-child-process': ['CWE-78'],
  'vulnsight/detect-eval-with-expression': ['CWE-95'],
};

function tryRequire(fromFile, id) {
  try {
    return Module.createRequire(fromFile)(id);
  } catch {
    return null;
  }
}

function loadEslintModule(bin, cwd) {
  const roots = [];
  if (cwd) roots.push(path.join(cwd, 'package.json'));
  if (bin) {
    const dir = path.dirname(bin);
    roots.push(path.join(dir, 'package.json'));
    roots.push(path.join(dir, 'node_modules', 'eslint', 'package.json'));
    roots.push(path.join(dir, '..', 'node_modules', 'eslint', 'package.json'));
  }
  roots.push(path.join(process.cwd(), 'package.json'));
  for (const root of roots) {
    if (!fs.existsSync(root)) continue;
    const insideEslint = path.basename(path.dirname(root)) === 'eslint';
    const mod = insideEslint ? tryRequire(root, '.') : tryRequire(root, 'eslint');
    if (mod && mod.ESLint) return mod;
  }
  try {
    const mod = require('eslint');
    if (mod && mod.ESLint) return mod;
  } catch { /* not a dependency of this package */ }
  return null;
}

function majorVersion(eslintMod) {
  const raw = (eslintMod.ESLint && eslintMod.ESLint.version) || '0';
  return Number(String(raw).split('.')[0]) || 0;
}

function toFinding(msg, file, root, version) {
  const ruleId = msg.ruleId || 'eslint';
  return createFinding({
    category: 'sast',
    scanner: { name: 'semgrep', version, ruleId },
    title: (msg.message || ruleId).split('\n')[0].slice(0, 200),
    description: msg.message || null,
    severity: SEVERITY[msg.severity] || 'medium',
    identifiers: { primary: ruleId, aliases: [], cwe: CWE[ruleId] || [] },
    location: {
      file: path.relative(root, file).split(path.sep).join('/'),
      line: msg.line || null,
      endLine: msg.endLine || msg.line || null,
    },
    remediation: { advice: msg.message || null },
    evidence: msg.source ? String(msg.source).trim().slice(0, 240) : null,
  });
}

async function lintWithApi(eslintMod, root) {
  const ESLint = eslintMod.ESLint;
  const rules = plugin.RULE_SETTINGS;
  const opts = majorVersion(eslintMod) >= 9
    ? {
      cwd: root,
      errorOnUnmatchedPattern: false,
      overrideConfigFile: true,
      overrideConfig: [{
        files: FILES,
        ignores: IGNORE,
        languageOptions: { ecmaVersion: 2022, sourceType: 'commonjs' },
        plugins: { vulnsight: plugin },
        rules,
      }],
    }
    : {
      cwd: root,
      useEslintrc: false,
      errorOnUnmatchedPattern: false,
      plugins: { vulnsight: plugin },
      extensions: ['.js', '.jsx', '.mjs', '.cjs'],
      overrideConfig: {
        plugins: ['vulnsight'],
        env: { node: true, es2022: true },
        parserOptions: { ecmaVersion: 2022 },
        rules,
        ignorePatterns: IGNORE,
      },
    };
  const engine = new ESLint(opts);
  return engine.lintFiles(FILES);
}

function parseEslintJson(stdout, root, version) {
  const data = JSON.parse(stdout || '[]');
  if (!Array.isArray(data)) return [];
  return data.flatMap((file) => (file.messages || [])
    .filter((msg) => msg.ruleId && msg.severity >= 1)
    .map((msg) => toFinding(msg, file.filePath, root, version)));
}

async function scanEslint(root, { bin, version, exec, signal, useApi = true } = {}) {
  const eslintMod = useApi ? loadEslintModule(bin, root) : null;
  if (eslintMod) {
    const results = await lintWithApi(eslintMod, root);
    const findings = results.flatMap((file) => (file.messages || [])
      .filter((msg) => msg.ruleId && msg.severity >= 1)
      .map((msg) => toFinding(msg, file.filePath, root, version)));
    return { findings, raw: { engine: 'eslint', api: true } };
  }
  if (!bin || !exec) throw new Error('eslint is not installed');
  const { stdout } = await exec(bin, ['--format', 'json', '--no-eslintrc', '--no-inline-config', '--rule', 'no-eval: error', '.'], {
    cwd: root,
    signal,
    okCodes: [0, 1],
  });
  return { findings: parseEslintJson(stdout, root, version), raw: { engine: 'eslint', api: false, note: 'CLI no-eval only' } };
}

module.exports = { scanEslint, parseEslintJson, loadEslintModule };
