'use strict';

const { uuid, now, transaction } = require('./db');

// Durable job queue. This is the small interface (enqueue / claim / complete / fail / cancel)
// that Celery + Redis would implement in the hosted deployment; here it is backed by the same
// database so a restart never loses queued scans.
const VISIBILITY_TIMEOUT_MS = 15 * 60 * 1000;
const DAST_VISIBILITY_TIMEOUT_MS = 6 * 60 * 60 * 1000;
const BACKOFF_MS = [30 * 1000, 2 * 60 * 1000, 10 * 60 * 1000];

function createQueue(db, { clock = () => Date.now() } = {}) {
  const iso = (ms) => new Date(ms).toISOString();

  return {
    enqueue(type, payload, { orgId = null, delayMs = 0, maxAttempts = 3 } = {}) {
      const id = uuid();
      db.prepare('INSERT INTO jobs (id, type, payload, org_id, status, max_attempts, run_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(id, type, JSON.stringify(payload), orgId, 'queued', maxAttempts, iso(clock() + delayMs), now());
      return id;
    },

    // Takes the next ready job. Jobs whose worker died (locked longer than the visibility
    // timeout) become claimable again, so a crashed worker doesn't strand a scan.
    claim() {
      return transaction(db, () => {
        const t = iso(clock());
        const stale = iso(clock() - VISIBILITY_TIMEOUT_MS);
        const staleDast = iso(clock() - DAST_VISIBILITY_TIMEOUT_MS);
        const row = db.prepare(`SELECT * FROM jobs WHERE (status = 'queued' AND run_at <= ?)
                                OR (status = 'running' AND type = 'website_scan' AND locked_at <= ?)
                                OR (status = 'running' AND type != 'website_scan' AND locked_at <= ?)
                                ORDER BY run_at LIMIT 1`).get(t, staleDast, stale);
        if (!row) return null;
        db.prepare("UPDATE jobs SET status = 'running', attempts = attempts + 1, locked_at = ? WHERE id = ?").run(t, row.id);
        return { ...row, attempts: row.attempts + 1, payload: JSON.parse(row.payload) };
      });
    },

    heartbeat(id) {
      if (!id) return;
      db.prepare("UPDATE jobs SET locked_at = ? WHERE id = ? AND status = 'running'").run(iso(clock()), id);
    },

    complete(id) {
      db.prepare("UPDATE jobs SET status = 'done', locked_at = NULL WHERE id = ?").run(id);
    },

    // retryable=false (e.g. access denied) fails immediately instead of burning retries.
    fail(job, error, { retryable = true } = {}) {
      const msg = String(error && error.message ? error.message : error).slice(0, 500);
      if (retryable && job.attempts < job.max_attempts) {
        const delay = BACKOFF_MS[Math.min(job.attempts - 1, BACKOFF_MS.length - 1)];
        db.prepare("UPDATE jobs SET status = 'queued', run_at = ?, locked_at = NULL, error = ? WHERE id = ?").run(iso(clock() + delay), msg, job.id);
        return 'retry';
      }
      db.prepare("UPDATE jobs SET status = 'failed', locked_at = NULL, error = ? WHERE id = ?").run(msg, job.id);
      return 'failed';
    },

    cancelWhere(type, matcher) {
      let n = 0;
      for (const row of db.prepare("SELECT id, payload FROM jobs WHERE type = ? AND status IN ('queued')").all(type)) {
        if (matcher(JSON.parse(row.payload))) {
          db.prepare("UPDATE jobs SET status = 'cancelled' WHERE id = ?").run(row.id);
          n++;
        }
      }
      return n;
    },

    counts() {
      return Object.fromEntries(db.prepare('SELECT status, COUNT(*) AS n FROM jobs GROUP BY status').all().map((r) => [r.status, r.n]));
    },
  };
}

class NonRetryableError extends Error {}

// Runs jobs with the given handlers. `runOnce` processes at most one job (used by tests and
// by schedulers); `start` polls until `stop`.
function createWorker({ queue, handlers, pollMs = 1000, onError = () => {} }) {
  let timer = null;
  let running = false;

  async function runOnce() {
    const job = queue.claim();
    if (!job) return false;
    const handler = handlers[job.type];
    try {
      if (!handler) throw new NonRetryableError(`No handler for job type "${job.type}"`);
      await handler(job.payload, job);
      queue.complete(job.id);
    } catch (err) {
      const outcome = queue.fail(job, err, { retryable: !(err instanceof NonRetryableError) });
      onError(err, job, outcome);
    }
    return true;
  }

  async function loop() {
    if (running) return;
    running = true;
    try {
      while (timer && (await runOnce())) { /* drain */ }
    } finally {
      running = false;
    }
  }

  return {
    runOnce,
    start() { if (!timer) { timer = setInterval(loop, pollMs); loop(); } },
    stop() { clearInterval(timer); timer = null; },
  };
}

module.exports = { createQueue, createWorker, NonRetryableError, VISIBILITY_TIMEOUT_MS, DAST_VISIBILITY_TIMEOUT_MS };
