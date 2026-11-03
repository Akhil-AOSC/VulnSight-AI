'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { which, defaultToolsDir } = require('./which');

const GITLEAKS_VERSION = '8.24.2';
const OPENGREP_VERSION = '1.33.1';

function gitleaksAsset() {
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  if (process.platform === 'win32') return { file: `gitleaks_${GITLEAKS_VERSION}_windows_${arch}.zip`, binary: 'gitleaks.exe' };
  if (process.platform === 'darwin') return { file: `gitleaks_${GITLEAKS_VERSION}_darwin_${arch}.tar.gz`, binary: 'gitleaks' };
  return { file: `gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz`, binary: 'gitleaks' };
}

function run(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (c) => { stderr = (stderr + c).slice(-2000); });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`${command} ${args.join(' ')} failed: ${stderr.trim()}`))));
  });
}

async function download(url, dest) {
  const res = await fetch(url, { signal: AbortSignal.timeout(180000) });
  if (!res.ok) throw new Error(`Download failed HTTP ${res.status} for ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(dest, buf);
}

async function extractArchive(archive, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  if (process.platform === 'win32' || archive.endsWith('.zip')) {
    await run('tar', ['-xf', archive, '-C', destDir]);
    return;
  }
  await run('tar', ['-xzf', archive, '-C', destDir]);
}

async function ensureGitleaks(preferred = 'gitleaks') {
  const existing = which(preferred) || which('gitleaks');
  if (existing) return existing;
  if (preferred !== 'gitleaks') return preferred;

  const dir = defaultToolsDir();
  fs.mkdirSync(dir, { recursive: true });
  const { file, binary } = gitleaksAsset();
  const dest = path.join(dir, binary);
  if (fs.existsSync(dest)) return dest;

  const url = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${file}`;
  const archive = path.join(dir, file);
  await download(url, archive);
  await extractArchive(archive, dir);
  try { fs.unlinkSync(archive); } catch { /* ignore */ }
  if (!fs.existsSync(dest)) throw new Error(`gitleaks download succeeded but ${binary} was not found`);
  try { fs.chmodSync(dest, 0o755); } catch { /* windows */ }
  return dest;
}

function opengrepAsset() {
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  if (process.platform === 'win32') return { file: 'opengrep_windows_x86.exe', binary: 'opengrep.exe' };
  if (process.platform === 'darwin') {
    return { file: arch === 'arm64' ? 'opengrep_osx_arm64' : 'opengrep_osx_x86', binary: 'opengrep' };
  }
  return { file: arch === 'arm64' ? 'opengrep_manylinux_aarch64' : 'opengrep_manylinux_x86', binary: 'opengrep' };
}

async function ensureOpengrep(preferred = 'opengrep') {
  const existing = which(preferred) || which('opengrep') || which('opengrep.exe');
  if (existing) return existing;
  if (preferred !== 'opengrep' && preferred !== 'semgrep') return preferred;

  const dir = defaultToolsDir();
  fs.mkdirSync(dir, { recursive: true });
  const { file, binary } = opengrepAsset();
  const dest = path.join(dir, binary);
  if (fs.existsSync(dest)) return dest;

  const url = `https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${file}`;
  if (file.endsWith('.zip')) {
    const archive = path.join(dir, file);
    await download(url, archive);
    await extractArchive(archive, dir);
    try { fs.unlinkSync(archive); } catch { /* ignore */ }
  } else {
    await download(url, dest);
  }
  if (!fs.existsSync(dest)) throw new Error(`opengrep download succeeded but ${binary} was not found`);
  try { fs.chmodSync(dest, 0o755); } catch { /* windows */ }
  return dest;
}

function resolveSemgrep(preferred = 'semgrep') {
  return which(preferred) || which('semgrep') || which('semgrep.exe');
}

function resolveOpengrep() {
  return which('opengrep') || which('opengrep.exe');
}

function resolveEslint(cwd) {
  const local = cwd
    ? which(path.join(cwd, 'node_modules', '.bin', process.platform === 'win32' ? 'eslint.cmd' : 'eslint'))
      || which(path.join(cwd, 'node_modules', '.bin', 'eslint'))
    : null;
  return local || which('eslint') || which('eslint.cmd') || which('eslint.exe');
}

// Local SAST engines, strongest first. None of these are downloaded; missing tools fall through.
function resolveSastEngine({ lookup, cwd } = {}) {
  const find = lookup || which;
  const opengrep = find('opengrep') || find('opengrep.exe');
  if (opengrep) return { kind: 'opengrep', bin: opengrep };
  const semgrep = find('semgrep') || find('semgrep.exe');
  if (semgrep) return { kind: 'semgrep', bin: semgrep };
  const eslintName = process.platform === 'win32' ? 'eslint.cmd' : 'eslint';
  const eslintLocal = cwd ? find(path.join(cwd, 'node_modules', '.bin', eslintName)) || find(path.join(cwd, 'node_modules', '.bin', 'eslint')) : null;
  const eslint = eslintLocal || find('eslint') || find('eslint.cmd') || find('eslint.exe');
  if (eslint) return { kind: 'eslint', bin: eslint };
  return { kind: 'builtin', bin: null };
}

module.exports = {
  ensureGitleaks, ensureOpengrep, resolveSemgrep, resolveOpengrep, resolveEslint, resolveSastEngine,
  GITLEAKS_VERSION, OPENGREP_VERSION,
};
