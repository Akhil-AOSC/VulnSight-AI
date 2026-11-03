'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

function toolsDirs() {
  const dirs = [];
  if (process.env.VULNSIGHT_TOOLS_DIR) dirs.push(process.env.VULNSIGHT_TOOLS_DIR);
  dirs.push(path.join(os.homedir(), '.vulnsight-tools'));
  dirs.push(path.join(os.homedir(), '.vulnsight-tools', 'venv', process.platform === 'win32' ? 'Scripts' : 'bin'));
  return dirs;
}

function extensions() {
  if (process.platform !== 'win32') return [''];
  return (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean);
}

function candidates(command) {
  if (process.platform === 'win32' && !path.extname(command)) {
    return extensions().map((ext) => command + ext);
  }
  return [command];
}

function isFile(file) {
  try {
    return fs.existsSync(file) && fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

// Resolves a CLI name to an executable path. On Windows this honours PATHEXT so
// `semgrep.cmd` / `gitleaks.exe` work with spawn({ shell: false }).
function which(command) {
  if (!command) return null;
  if (path.isAbsolute(command) || command.includes('/') || command.includes('\\')) {
    return isFile(command) ? command : null;
  }
  const names = candidates(command);
  const search = [...toolsDirs(), ...(process.env.PATH || '').split(path.delimiter)];
  for (const dir of search) {
    if (!dir) continue;
    for (const name of names) {
      const full = path.join(dir, name);
      if (isFile(full)) return full;
    }
  }
  return null;
}

function defaultToolsDir() {
  return process.env.VULNSIGHT_TOOLS_DIR || path.join(os.homedir(), '.vulnsight-tools');
}

module.exports = { which, toolsDirs, defaultToolsDir };
