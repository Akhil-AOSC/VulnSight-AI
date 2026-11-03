'use strict';

const { DEFAULT_SCANNERS } = require('../pipeline');

// An executor turns one validated repository into a scan report:
//
//   async execute({ validated, branch, auth, config, scanId })
//     -> { report, commit, scrub: [strings to remove from messages, e.g. temp paths] }
//
// Local executor: the worker clones into a temp directory and runs the scanners in a sandbox
// (docker container, or a plain child process for development). Cloud executors (see aca.js)
// hand the whole job to an isolated, short-lived container that clones and scans by itself.
function createLocalExecutor({ clone, runScan, mode = 'process' }) {
  return async function execute({ validated, branch, auth, config = {} }) {
    const workspace = await clone(validated, { branch, auth });
    try {
      const report = await runScan(workspace.dir, {
        scanners: config.scanners || DEFAULT_SCANNERS, threshold: config.threshold || 'low', mode,
      });
      return { report, commit: workspace.commit, scrub: [workspace.dir] };
    } finally {
      workspace.cleanup(); // source code is never retained, even when the scan fails
    }
  };
}

module.exports = { createLocalExecutor };
