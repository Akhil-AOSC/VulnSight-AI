#!/usr/bin/env node
'use strict';

// Starts the VulnSight server as a fully detached background process (its own process group, no
// console), logging to .vulnsight-data/server.log. Use this for long website scans: a server
// started from an editor, terminal tab or app pane is stopped when that host closes or restarts,
// which abandons any scan that is running.
//
//   node scripts/serve-detached.js [--port=4400]
//
// Stop it with the PID it prints (Windows: taskkill /PID <pid>; macOS/Linux: kill <pid>).

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const dataDir = path.join(root, '.vulnsight-data');
fs.mkdirSync(dataDir, { recursive: true });
const logFile = path.join(dataDir, 'server.log');
const out = fs.openSync(logFile, 'a');
fs.writeSync(out, `\n--- ${new Date().toISOString()} starting detached server ---\n`);

const portArg = process.argv.find((a) => a.startsWith('--port=')) || '--port=4400';
const child = spawn(process.execPath, [path.join(root, 'bin', 'vulnsight.js'), 'serve', portArg], {
  cwd: root,
  detached: true,
  windowsHide: true,
  stdio: ['ignore', out, out],
});
child.unref();
console.log(`VulnSight server started in the background. PID ${child.pid}. Log: ${logFile}`);
