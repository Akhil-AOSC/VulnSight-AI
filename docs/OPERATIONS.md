# Operating VulnSight AI

## Configuration

| Variable | Purpose |
|---|---|
| `VULNSIGHT_MASTER_KEY` | **Required in production.** 32 random bytes, base64. Encrypts stored Git tokens and webhook secrets. Keep it in Key Vault. Losing it makes stored tokens unrecoverable (users reconnect providers). |
| `VULNSIGHT_DB` / `VULNSIGHT_DATA` | Database file and data directory (default `/data`). |
| `VULNSIGHT_SANDBOX` | `aca` (Azure Container Apps jobs), `docker` (a Docker host), or `process` (development only; not isolated). |
| `VULNSIGHT_ACA_SUBSCRIPTION`, `_RESOURCE_GROUP`, `_JOB`, `_IMAGE`, `_STORAGE_ACCOUNT`, `_CONTAINER`, `_JOB_CLIENT_ID`, `_API_CLIENT_ID` | Settings for `aca` mode (set by the Bicep template). |
| `VULNSIGHT_WORKER_IMAGE` | Scan worker image (default `vulnsight-worker:latest`). |
| `VULNSIGHT_TRUST_PROXY=1` | Use `X-Forwarded-For` for client IPs. Only behind a trusted proxy. |
| `VULNSIGHT_HSTS=1` | Send HSTS. Enable when served over HTTPS. |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`, `VULNSIGHT_AI_PROVIDER`, `VULNSIGHT_AI_MODEL` | AI provider. AI also needs to be enabled per organisation. |

Generate a key: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`

## Deploy

Nothing below has been run against a real Azure subscription yet (see STATUS.md). **Review before you
deploy: this template creates billable resources** (Container Registry Premium, three Container Apps
environments, private endpoints, Log Analytics, Key Vault, storage).

1. Build and push `deploy/Dockerfile.api` and `deploy/Dockerfile.worker` to your registry.
2. **Preview, change nothing:** `az login`, `az account set --subscription <id>`, then
   `deploy/azure/whatif.sh <region>`. It runs `az deployment sub what-if` against
   `deploy/azure/subscription.bicep`, so it works without the resource group existing. Read the whole
   output: resources to create, role assignments, network rules.
3. **Only after review and explicit approval**, deploy with
   `az deployment sub create --location <region> --template-file deploy/azure/subscription.bicep --parameters location=<region> apiImage=<img> workerImage=<img> masterKey=<generated key>`.
   Prefer a scratch resource group first (`resourceGroupName=rg-vulnsight-scratch`).
4. **Test the egress controls from inside a job before accepting any repository**: a direct connection
   to the internet, to `169.254.169.254`, and to another storage account must all fail, while a scan
   through the proxy succeeds. If Container Apps cannot start under the network rules, the platform's
   required outbound rules need adjusting; do not "fix" it by opening outbound to the internet.
5. For a non-Azure host: `VULNSIGHT_SANDBOX=docker` on a machine with Docker, the pre-pulled worker image,
   and `deploy/docker/setup-egress.sh` (creates the internal network and the allowlist proxy; docker mode
   refuses to run without `VULNSIGHT_EGRESS_PROXY`).

## Egress proxy

Scan workers can only reach the internet through `src/platform/egress-proxy.js`. It allows a fixed
list of hostnames on port 443 (git hosts, OSV, Semgrep, Trivy databases, and this API for credential
grants), refuses IP literals and anything resolving to a private or metadata address, and logs each
denial as JSON (`{"event":"egress.denied","host":...,"reason":...}`).

- **Add a host** with `VULNSIGHT_EGRESS_ALLOW=host,*.example.net` (or `extraEgressHosts` in the template).
  A tool that stops working after an upgrade usually shows up as a denial in this log: check there first.
- **Alert on** denials for unexpected hosts: a hostile repository trying to exfiltrate data looks exactly
  like this. `check.trivy.dev` (Trivy's version/telemetry check) is denied on purpose and is harmless.
- Node clients only use the proxy when `NODE_USE_ENV_PROXY=1` is set when the process starts; the
  executors set it. The network rule, not the proxy, is what stops a client that ignores it.

## Data retention and deletion

- Scan data is deleted automatically after each organisation's retention period (default 90 days,
  configurable 1-3650 days in Settings). The purge runs daily and also removes expired sessions, old
  jobs, notifications and AI history.
- Source code is **never retained**: each repository is cloned into a temporary directory, scanned,
  and deleted in a `finally` block, even when the scan fails. Only findings, metadata and the
  dependency inventory are stored.
- Removing a repository deletes its scans, findings, triage state, review history and AI history.
  Deleting an organisation deletes everything it owns. Both are written to the audit log.

## Backup, restore and incident tooling

All of these work on the database file directly (no API needed): `node scripts/ops.js <command>`.

| Command | Purpose |
|---|---|
| `backup <db> <file>` | Consistent online backup (`VACUUM INTO`), integrity-checked; refuses to overwrite |
| `verify <file>` | Integrity and foreign-key check, plus a count of what the file holds |
| `restore <file> <db>` | Verifies the backup, **keeps the current database aside (never deletes it)**, restores, applies newer migrations |
| `rotate-key <db>` | Re-encrypts every stored secret under a new master key in one transaction (`OLD_KEY`, `NEW_KEY` in the environment). Use after a suspected key exposure; rotate before destroying the old key |
| `disable-user <db> <email>` | Disables the account and ends its sessions immediately |
| `revoke-sessions <db>` | Ends every session |
| `new-key` | Prints a fresh master key |

- **What to back up:** the database file and the master key, **stored separately**. A backup without the
  key restores, but the stored Git tokens cannot be decrypted (verified by test).
- **Schedule (proposed):** daily backup, copied off-host to geo-redundant storage, 30 days kept.
- **Targets (proposed, unmeasured in production):** RPO 24 h, RTO 4 h. Tighten after the PostgreSQL migration.

### Drills

| Drill | What was actually run | Result |
|---|---|---|
| Backup, destroy, restore | `test/ops.test.js` on a populated database file on a laptop | Passed: login, org data and provider-token decryption work after restore; the backup alone reveals no tokens |
| Master-key rotation | Same file | Passed: all secrets (provider token, webhook secret, pending grant) moved atomically; the old key opens nothing; a wrong old key changes nothing |
| Compromised account | Same file | Passed: existing session dead and login refused immediately |
| **Not yet run** | A restore on a deployed environment by an operator following this document; a tabletop of the incident steps below with the people who would be on call | Do these before go-live, and record the timings |

## Monitoring and alerting

Structured JSON logs go to stdout (Log Analytics / Application Insights). Alert on:

- repeated `user.login_failed` audit events from one IP or for one email;
- scans stuck in `running` for more than 15 minutes (the queue re-delivers them, but investigate);
- a rise in failed scans, and any scanner reporting `error: ... is not installed` (broken worker image);
- HTTP 5xx rate, and `429` spikes (possible abuse);
- sandbox failures (`docker run` errors) and workers exceeding memory/time limits.

## Incident response (summary)

1. **Contain:** `node scripts/ops.js disable-user <db> <email>` for a compromised account;
   `revoke-sessions` if tokens may have leaked; `rotate-key` if the master key may have leaked (then
   rotate the Git tokens customers connected, since a leaked key plus a leaked database exposes them);
   stop the worker if a scan escape is suspected. Review egress-proxy denial logs for exfiltration attempts.
2. **Assess:** use the audit log (`audit_logs`) to see who did what and from which IP.
3. **Eradicate and recover:** patch, rebuild images, redeploy; restore from backup if data was altered.
4. **Notify:** affected customers and, where required, regulators, within legal deadlines.
5. **Review:** write a post-incident report and add a regression test for the cause.

## Cost and capacity notes

The API is light (single 0.5 vCPU / 1 GiB container). Cost is dominated by scans: each scan needs a
worker container with up to 1 CPU / 1 GiB for its duration and egress to OSV and rule registries.
Measure real scan durations on representative repositories before sizing; the figures here are
placeholders, not benchmarks.
