'use strict';

const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

function isGitUrl(str) {
  if (typeof str !== 'string') return false;
  const trimmed = str.trim();
  if (!trimmed) return false;
  if (/^(https?|git|ssh|git\+(https?|ssh)):\/\//i.test(trimmed)) return true;
  if (/^git@[a-zA-Z0-9._-]+:/i.test(trimmed)) return true;
  if (/^(github|gitlab|bitbucket)\.[a-zA-Z0-9.-]+\//i.test(trimmed)) return true;
  if (/\.git$/i.test(trimmed) && !fs.existsSync(trimmed)) return true;
  return false;
}

function parseGitUrl(raw) {
  let trimmed = raw.trim();
  if (/^(github|gitlab|bitbucket)\.[a-zA-Z0-9.-]+\//i.test(trimmed)) {
    trimmed = `https://${trimmed}`;
  }

  let subpath = null;
  let branch = null;

  // Handle GitHub / GitLab tree/blob URLs:
  // e.g. https://github.com/owner/repo/tree/main/path/to/app
  const treeMatch = trimmed.match(/^(https?:\/\/[^/]+\/[^/]+\/[^/]+?)(?:\.git)?\/(?:tree|blob)\/([^/]+)(?:\/(.*))?$/i);
  if (treeMatch) {
    trimmed = treeMatch[1].endsWith('.git') ? treeMatch[1] : `${treeMatch[1]}.git`;
    branch = treeMatch[2];
    subpath = treeMatch[3] ? decodeURIComponent(treeMatch[3]) : null;
  }

  return {
    cloneUrl: trimmed,
    branch,
    subpath,
  };
}

function injectAuthToken(url, token = process.env.GITHUB_TOKEN) {
  if (!token) return url;
  try {
    const parsed = new URL(url);
    if ((parsed.hostname.toLowerCase() === 'github.com' || parsed.hostname.toLowerCase() === 'gitlab.com') && !parsed.username) {
      parsed.username = 'x-access-token';
      parsed.password = token;
      return parsed.toString();
    }
  } catch {
    /* fallback to url */
  }
  return url;
}

function sanitizeError(msg) {
  return String(msg).replace(/x-access-token:[^@]+@/gi, 'x-access-token:***@');
}

function makeWritable(dir) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      try {
        fs.chmodSync(full, 0o666);
      } catch {
        /* best effort */
      }
      if (entry.isDirectory()) {
        makeWritable(full);
      }
    }
  } catch {
    /* best effort */
  }
}

function safeRmDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  } catch {
    try {
      makeWritable(dir);
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

function cloneRepository(url, { depth = 1, timeout = 120000, token = process.env.GITHUB_TOKEN } = {}) {
  const { cloneUrl, branch, subpath } = parseGitUrl(url);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnsight-repo-'));

  const args = ['clone', '--depth', String(depth)];
  if (branch) {
    args.push('--branch', branch);
  }
  const authUrl = injectAuthToken(cloneUrl, token);
  args.push(authUrl, tempDir);

  return new Promise((resolve, reject) => {
    execFile('git', args, { timeout }, (err, stdout, stderr) => {
      if (err) {
        safeRmDir(tempDir);
        if (err.code === 'ENOENT') {
          reject(new Error('Git is not installed or not found in PATH. Please install Git to scan remote repositories.'));
          return;
        }
        const msg = sanitizeError((stderr || err.message || '').trim());
        reject(new Error(`Failed to clone git repository: ${msg || err.code}`));
        return;
      }

      const targetDir = subpath ? path.join(tempDir, subpath) : tempDir;
      if (subpath && !fs.existsSync(targetDir)) {
        safeRmDir(tempDir);
        reject(new Error(`Subdirectory "${subpath}" does not exist in repository ${cloneUrl}`));
        return;
      }

      resolve({
        root: tempDir,
        dir: targetDir,
        cleanup: () => safeRmDir(tempDir),
        cloneUrl,
      });
    });
  });
}

module.exports = {
  isGitUrl,
  parseGitUrl,
  cloneRepository,
  safeRmDir,
  injectAuthToken,
  sanitizeError,
};
