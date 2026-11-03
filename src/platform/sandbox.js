'use strict';

const path = require('path');
const { execTool } = require('../adapters/runner');

// Worker isolation. Repository content is untrusted, so scanners never run inside the API
// process.
//
//  mode 'docker'  (hosted / production): a short-lived container per scan with no
//                 application credentials, a read-only root filesystem, dropped
//                 capabilities, non-root user, CPU/memory/PID limits and a hard timeout.
//  mode 'process' (development / tests): a child process with a scrubbed environment and a
//                 memory cap. It does NOT isolate the filesystem, so it is not a security
//                 boundary: use docker for anything exposed to other people's code.

const IMAGE = process.env.VULNSIGHT_WORKER_IMAGE || 'vulnsight-worker:latest';

// `command` is only overridden by the isolation tests, which run probe commands in the same sandbox.
function dockerArgs({ workspace, request, image = IMAGE, memory = '1g', cpus = '1', pids = 256, network = 'vulnsight-scan', proxy = process.env.VULNSIGHT_EGRESS_PROXY, command }) {
  return [
    'run', '--rm', '--pull=never',
    '--user', '10001:10001',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', String(pids),
    '--memory', memory, '--memory-swap', memory,
    '--cpus', cpus,
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m',
    // 'vulnsight-scan' must be created with --internal (no route out). The only way out is the allowlist
    // proxy on that network; see deploy/docker/setup-egress.sh.
    '--network', network,
    '--mount', `type=bind,source=${workspace},target=/work,readonly`,
    '--workdir', '/work',
    '--env', 'HOME=/tmp',
    ...(proxy ? ['--env', `HTTPS_PROXY=${proxy}`, '--env', 'NODE_USE_ENV_PROXY=1'] : []),
    image, ...(command || ['node', '/app/src/platform/scan-child.js', JSON.stringify({ ...request, path: '/work' })]),
  ];
}

// Environment for the child: only what the scanners need to run. No DB path, master key,
// session secrets, AI keys or provider tokens.
function scrubbedEnv() {
  const keep = ['PATH', 'SystemRoot', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LANG', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'NODE_USE_ENV_PROXY'];
  const env = {};
  for (const k of keep) if (process.env[k]) env[k] = process.env[k];
  return env;
}

async function runSandboxed(workspace, { scanners, threshold = 'low', timeoutMs = 10 * 60 * 1000, mode = 'process', exec = execTool, image } = {}) {
  const request = { scanners, threshold, timeoutMs: Math.max(1000, timeoutMs - 5000) };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let result;
    if (mode === 'docker') {
      // Fail closed: without the allowlist proxy a docker worker would have no network at all (or, on a
      // misconfigured host, unrestricted network). Refuse rather than guess.
      if (!process.env.VULNSIGHT_EGRESS_PROXY && !process.env.VULNSIGHT_ALLOW_NO_PROXY) throw new Error('Docker mode needs VULNSIGHT_EGRESS_PROXY (worker egress must go through the allowlist proxy)');
      result = await exec('docker', dockerArgs({ workspace: path.resolve(workspace), request, image }), { signal: controller.signal });
    } else {
      const child = path.join(__dirname, 'scan-child.js');
      result = await exec(process.execPath, ['--max-old-space-size=768', child, JSON.stringify({ ...request, path: path.resolve(workspace) })], {
        signal: controller.signal, env: scrubbedEnv(),
      });
    }
    return JSON.parse(result.stdout);
  } catch (err) {
    if (controller.signal.aborted) throw new Error('The scan timed out');
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { runSandboxed, dockerArgs, scrubbedEnv };
