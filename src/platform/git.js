'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const { execTool } = require('../adapters/runner');
const { ValidationError } = require('./rbac');
const { isPublicAddress } = require('../adapters/dast/net-guard');

// ---- SSRF protection ---------------------------------------------------------------------
// A user-supplied repository URL makes our server open network connections. Without checks it
// could be pointed at cloud metadata (169.254.169.254), localhost services or the private
// network. We allow only https, no credentials, standard port, and only hostnames whose every
// DNS answer is a public address. The validated address is then pinned for the clone so DNS
// can't change between the check and the connection (DNS rebinding).

// Address classification lives in one place so the repository cloner, the egress proxy and the
// website scanner agree (it also covers IPv4-mapped hex forms, 6to4, Teredo and NAT64).
function isPrivateIp(ip) {
  return !isPublicAddress(ip); // non-IPs are refused too
}

const SEGMENT = /^[A-Za-z0-9._~-]+$/;

async function validateRepoUrl(input, { lookup = (h) => dns.lookup(h, { all: true }), allowHosts = null } = {}) {
  let url;
  try {
    url = new URL(String(input).trim());
  } catch {
    throw new ValidationError('Invalid repository URL');
  }
  if (String(input).length > 300) throw new ValidationError('Repository URL is too long');
  if (url.protocol !== 'https:') throw new ValidationError('Only https:// repository URLs are allowed');
  if (url.username || url.password) throw new ValidationError('Repository URLs must not contain credentials');
  if (url.port && url.port !== '443') throw new ValidationError('Only the default https port is allowed');
  if (url.search || url.hash) throw new ValidationError('Repository URLs must not contain a query or fragment');

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (net.isIP(host) || host.startsWith('[')) throw new ValidationError('IP addresses are not allowed; use a hostname');
  if (host === 'localhost' || !host.includes('.') || /\.(local|internal|localdomain|lan|home|corp)$/.test(host)) {
    throw new ValidationError('That host is not allowed');
  }
  if (allowHosts && !allowHosts.includes(host)) throw new ValidationError(`Host not allowed. Allowed hosts: ${allowHosts.join(', ')}`);

  const segments = url.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
  if (segments.length < 2 || segments.length > 6 || !segments.every((s) => SEGMENT.test(s) && s !== '.' && s !== '..')) {
    throw new ValidationError('Repository path must look like /owner/name');
  }

  let answers;
  try {
    answers = await lookup(host);
  } catch {
    throw new ValidationError('Could not resolve the repository host');
  }
  const addresses = answers.map((a) => (typeof a === 'string' ? a : a.address));
  if (!addresses.length || addresses.some(isPrivateIp)) throw new ValidationError('That host resolves to a non-public address');

  return { url: `https://${host}/${segments.join('/')}.git`, host, fullName: segments.join('/'), address: addresses[0] };
}

const BRANCH = /^[A-Za-z0-9][\w./-]{0,199}$/;
function validateBranch(branch) {
  if (typeof branch !== 'string' || !BRANCH.test(branch) || branch.includes('..') || branch.endsWith('.lock') || branch.includes('//')) {
    throw new ValidationError('Invalid branch name');
  }
  return branch;
}

// ---- Workspace hygiene --------------------------------------------------------------------
const LIMITS = { maxBytes: 500 * 1024 * 1024, maxFiles: 100000 };

// A hostile repository can contain symlinks to files outside the checkout (for example
// /etc/passwd or our own secrets). Scanners that follow them would read and report host
// files, so every symlink is removed. Also enforces size and file-count limits.
function sanitizeWorkspace(root, limits = LIMITS) {
  let bytes = 0;
  let files = 0;
  let removedLinks = 0;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) {
        fs.rmSync(full, { force: true });
        removedLinks++;
      } else if (st.isDirectory()) {
        stack.push(full);
      } else if (st.isFile()) {
        files++;
        bytes += st.size;
        if (files > limits.maxFiles) throw new Error(`Repository has too many files (limit ${limits.maxFiles})`);
        if (bytes > limits.maxBytes) throw new Error(`Repository is too large (limit ${Math.round(limits.maxBytes / 1048576)} MB)`);
      } else {
        fs.rmSync(full, { force: true });
      }
    }
  }
  return { bytes, files, removedLinks };
}

// Environment for git: nothing from the host except what git needs to run.
function gitEnv(workdir, auth) {
  // An empty config file stands in for the user's global config. (os.devNull is not usable
  // for this on Windows, where git can't open the NUL device as a config file.)
  const emptyConfig = path.join(workdir, '.empty-gitconfig');
  try {
    if (!fs.existsSync(emptyConfig)) fs.writeFileSync(emptyConfig, '');
  } catch { /* workdir may not exist yet in unit tests */ }
  const env = {
    PATH: process.env.PATH || '',
    HOME: workdir,
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: emptyConfig,
    GIT_ASKPASS: 'echo',
    GCM_INTERACTIVE: 'never',
  };
  if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
  // Egress goes through the allowlist proxy when one is configured.
  for (const k of ['HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy']) if (process.env[k]) env[k] = process.env[k];
  if (auth) {
    // The token is passed through the environment, never on the command line (visible in
    // process listings) and never embedded in the URL.
    const basic = Buffer.from(`${auth.username}:${auth.token}`).toString('base64');
    env.GIT_CONFIG_COUNT = '1';
    env.GIT_CONFIG_KEY_0 = 'http.extraHeader';
    env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${basic}`;
  }
  return env;
}

// Shallow-clones one branch into a fresh temp directory and returns { dir, commit, cleanup }.
// `validated` is the result of validateRepoUrl (its address is pinned for the connection).
async function cloneRepo(validated, { branch, auth = null, timeoutMs = 120000, exec = execExec, limits = LIMITS } = {}) {
  validateBranch(branch);
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-'));
  const dir = path.join(base, 'src');
  const cleanup = () => fs.rmSync(base, { recursive: true, force: true });
  try {
    const args = [
      '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
      '-c', 'core.symlinks=false', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=' + path.join(base, 'no-hooks'),
      '-c', `http.curloptResolve=${validated.host}:443:${validated.address}`,
      '-c', 'http.followRedirects=false',
      'clone', '--depth', '1', '--single-branch', '--no-tags', '--no-recurse-submodules', '--template=',
      '--branch', branch, '--', validated.url, dir,
    ];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      await exec('git', args, { cwd: base, env: gitEnv(base, auth), signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
    const { stdout } = await exec('git', ['rev-parse', 'HEAD'], { cwd: dir, env: gitEnv(base, null) });
    const commit = stdout.trim();
    fs.rmSync(path.join(dir, '.git'), { recursive: true, force: true });
    const stats = sanitizeWorkspace(dir, limits);
    return { dir, commit, stats, cleanup };
  } catch (err) {
    cleanup();
    throw new Error(describeGitError(err));
  }
}

// Messages are mapped to stable, user-safe text. Raw git output can include URLs or headers.
function describeGitError(err) {
  const m = String(err.message || err);
  if (/Remote branch .* not found/i.test(m)) return 'Branch not found. It may have been deleted or renamed';
  if (/Authentication failed|could not read Username|403|401/i.test(m)) return 'Repository access denied. Check the provider connection and its permissions';
  if (/not found|does not exist|404/i.test(m)) return 'Repository not found';
  if (/rate limit|429/i.test(m)) return 'The Git provider rate-limited the request. Try again later';
  if (/abort/i.test(m)) return 'Cloning timed out';
  if (/too (large|many)/i.test(m)) return m;
  if (/not installed/i.test(m)) return 'git is not installed on the worker';
  return 'Could not clone the repository';
}

function execExec(command, args, opts) {
  const { spawn } = require('child_process');
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: opts.cwd, env: opts.env, signal: opts.signal, shell: false, windowsHide: true });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; if (out.length > 1e6) child.kill(); });
    child.stderr.on('data', (d) => { err = (err + d).slice(-2000); });
    child.on('error', (e) => reject(e.code === 'ENOENT' ? new Error('git is not installed') : e));
    child.on('close', (code) => (code === 0 ? resolve({ stdout: out }) : reject(new Error(err.trim() || `git exited with ${code}`))));
  });
}

module.exports = { validateRepoUrl, validateBranch, isPrivateIp, sanitizeWorkspace, cloneRepo, gitEnv, describeGitError, LIMITS };
