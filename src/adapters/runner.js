'use strict';

const { spawn } = require('child_process');

// Scanner adapter contract
//
//   {
//     name:     'osv'                  unique id
//     category: 'sca'                  finding category it produces
//     async version()                  scanner/tool version string (provenance)
//     async supports(target)           true if this adapter can scan the target
//     async run(target, ctx)           returns { findings: Finding[], raw?: any }
//   }
//
// target = { path }.  ctx = { timeoutMs, signal }.
// Adapters throw on failure; runAdapter turns that into a status so one broken
// scanner never takes down the others.
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

async function runAdapter(adapter, target, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const started = Date.now();
  const result = {
    scanner: adapter.name, category: adapter.category, version: null,
    status: 'ok', findings: [], raw: null, error: null, durationMs: 0,
  };

  try {
    result.version = (await adapter.version()) || null;
    if (!(await adapter.supports(target))) {
      result.status = 'skipped';
    } else {
      const controller = new AbortController();
      let timer;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          const err = new Error(`${adapter.name} timed out after ${timeoutMs}ms`);
          err.code = 'ADAPTER_TIMEOUT';
          reject(err);
        }, timeoutMs);
      });
      try {
        const out = await Promise.race([adapter.run(target, { timeoutMs, signal: controller.signal }), timeout]);
        result.findings = out.findings || [];
        result.raw = out.raw === undefined ? null : out.raw;
      } finally {
        clearTimeout(timer);
      }
    }
  } catch (err) {
    result.status = err.code === 'ADAPTER_TIMEOUT' ? 'timeout' : 'error';
    result.error = err.message;
  }
  result.durationMs = Date.now() - started;
  return result;
}

// Runs every adapter concurrently; results keep adapter order.
function runAdapters(adapters, target, opts) {
  return Promise.all(adapters.map((a) => runAdapter(a, target, opts)));
}

// Helper for CLI-based scanners (Semgrep, Gitleaks, Trivy...). No shell, an output cap and a
// kill on abort, so a hostile or runaway scan can't hang or exhaust the host.
const MAX_OUTPUT_BYTES = 50 * 1024 * 1024;

function execTool(command, args, { cwd, env, signal, maxBytes = MAX_OUTPUT_BYTES, okCodes = [0] } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, shell: false, signal, windowsHide: true });
    const out = [];
    let size = 0;
    let stderr = '';
    let done = false;
    const finish = (fn, value) => { if (!done) { done = true; fn(value); } };

    child.stdout.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        child.kill();
        finish(reject, new Error(`${command} output exceeded ${maxBytes} bytes`));
        return;
      }
      out.push(chunk);
    });
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4000); });
    child.on('error', (err) => finish(reject, err.code === 'ENOENT' ? new Error(`${command} is not installed`) : err));
    child.on('close', (code) => {
      if (okCodes.includes(code)) finish(resolve, { stdout: Buffer.concat(out).toString('utf8'), stderr, code });
      else finish(reject, new Error(`${command} exited with code ${code}: ${stderr.trim()}`));
    });
  });
}

module.exports = { runAdapter, runAdapters, execTool, DEFAULT_TIMEOUT_MS };
