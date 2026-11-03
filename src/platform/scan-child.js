'use strict';

// Runs inside the isolated scan process/container. Input: one JSON argument
// { path, scanners, threshold }. Output: the scan report as JSON on stdout. It receives no
// application secrets (the parent starts it with a scrubbed environment).

const { runPipeline } = require('../pipeline');

(async () => {
  try {
    const req = JSON.parse(process.argv[2] || '{}');
    const report = await runPipeline({ path: req.path }, {
      scanners: req.scanners, threshold: req.threshold || 'low', timeoutMs: req.timeoutMs,
    });
    process.stdout.write(JSON.stringify(report));
  } catch (err) {
    process.stderr.write(String(err && err.message ? err.message : err));
    process.exit(1);
  }
})();
