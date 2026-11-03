# Implementation status against the upgrade specification

**This platform is not production-ready, and nothing here should be read as saying it is.** Passing
tests are necessary, not sufficient. The most important controls (network-enforced egress
restriction, the Docker sandbox, the Azure deployment) have never run in a real environment, and no
independent security assessment has been done.

How to read the tiers:

- **Verified**: exercised against the real thing (real tool, real network, real browser, real
  database file) and covered by an automated check that still passes.
- **Partially verified**: implemented and tested against fakes or samples; the real-world run has not
  happened, or only part of it has.
- **Unverified / not done**: written but never executed in a real environment, or not implemented.

Test counts at the time of writing: **134 tests, 0 failing.** 123 run everywhere; 5 more need the real
scanners installed (`VULNSIGHT_TOOLS_DIR`, `VULNSIGHT_CHECKOV_PYTHON`), giving 128; the last 6 need a
machine with Docker (`VULNSIGHT_DOCKER_TEST=1`) and have only ever been skipped. Scripts (not part of
`npm test`): `npm run probe`, `npm run probe:xss`, `npm run loadtest`, `npm run ops`.

## Verified

| Area | Evidence |
|---|---|
| Dependency scanning (npm, PyPI, yarn, pnpm, Go) against live OSV.dev | Real scans, including OWASP NodeGoat (91 findings) |
| **Semgrep 1.183.0, Gitleaks 8.21.2, Trivy 0.76.1 (filesystem), Checkov 3.4.3** adapters | `test/real-tools.test.js` against the insecure example app. The Gitleaks run exposed a real bug (a scan that looked clean) which is fixed and tested |
| **Egress proxy** (`egress-proxy.js`): hostname allowlist, port 443 only, refuses IP literals and any hostname resolving to a private/metadata address, tunnel and upload caps, denial logging | 9 unit tests with real sockets, plus a run of **real git, Semgrep, Trivy and the OSV client through it** over the real internet. Blocked correctly: an unlisted host, `169.254.169.254`, port 80, an arbitrary storage account. The run also found that a Node client ignores the proxy unless `NODE_USE_ENV_PROXY=1` is set at process start, which is why the proxy alone is not enforcement (see below) |
| **Single-use credential grants**: the job-start request carries no Git token; the job redeems a one-time secret over HTTP for the credential | `test/grants.test.js` (6 tests) plus the job and executor tests in `test/aca.test.js`: single use, replay detection and audit, expiry, only while the scan runs, wrong scan, encrypted at rest, rate limited, identical error for every failure, and a private-repo round trip showing the start request contains no token and the spent secret is useless |
| **Async password hashing with a concurrency cap** | A load test showed `scryptSync` freezing the whole server (10 concurrent logins = 340 ms stall). Fixed; regression tests assert the event loop is not blocked and that a flood is shed with 503. Re-measured: 773 -> 1,017 req/s, read p95 ~50 -> ~35 ms |
| **Backup and restore drill** | Test: back up a populated database, destroy it, restore, then prove login, data and provider-token decryption work again (same key), and that the backup alone cannot reveal tokens without the key |
| **Incident tooling drills** | Test: master-key rotation re-encrypts every secret atomically and the old key stops working; disabling an account kills existing sessions and blocks login |
| **Security self-assessment** (`scripts/security-probe.js`, 26 checks) | SQL injection payloads, cross-tenant access with valid ids, mass assignment and prototype pollution, hostile input, CORS/CSRF behaviour, static file exposure, login timing, brute-force throttling, headers, secrets at rest |
| **Stored XSS** (`scripts/xss-probe.js`) | Hostile payloads stored in user, org, team, repo, branch, finding, scanner, notification and audit fields; all 13 screens loaded in a real browser: nothing executed, everything rendered as text |
| Git cloning with SSRF defences, scan pipeline, auth, organisations, roles, tenant isolation, audit log, encryption, webhooks, rate limiting, retention, exports, finding lifecycle | Automated tests plus real clones and end-to-end scans |
| Web app, 13 screens with real data, zero JavaScript errors, mobile layout | Driven in headless Edge |
| Bicep templates compile | Bicep CLI 0.48.1, no errors or warnings (this checks syntax and types only, not what Azure accepts) |

Load test (`scripts/loadtest.js`, 25 virtual users, 20 s, 200 findings per scan): ~1,017 requests/s, 0
errors, p95 33-39 ms. **This is one Node process and SQLite on one laptop (8 vCPU, 16 GB,
Windows).** It says nothing about Azure capacity.

## Partially verified

| Area | What was tested | What was not |
|---|---|---|
| **Network egress enforcement** | The proxy (above) works with real tools; the Bicep NSG, private endpoints and subnet layout compile | **The part that makes it a control is untested**: that the NSG really blocks direct outbound, that Container Apps still starts under it (the platform's own required outbound rules were written from memory of the docs), that private endpoints resolve, and that the proxy is reachable at its static IP over internal TCP ingress. Without the network rules the proxy is advisory: a client that ignores it can connect directly |
| **Azure Container Apps scan launcher** | Executor and job entry tested together against a fake Azure (ARM and Blob) | Never run against real Azure; request shapes, API versions and status values come from documentation |
| **Least-privilege API role** | Replaced Contributor with the built-in *Container Apps Jobs Operator* role (read, start, stop jobs), scoped to the one job. Role id and actions taken from Microsoft's documentation | Not exercised in Azure: whether starting an execution with a template override needs only this role is unconfirmed |
| **Docker sandbox** | The exact `docker run` flags are unit-tested; fail-closed without a proxy; `deploy/docker/setup-egress.sh` written | **Never executed.** There is no container runtime on the development machine, so `test/docker-sandbox.test.js` has only ever been skipped |
| Trivy image scanning | Image-name validation and output mapping | Needs Docker/registry access |
| GitHub / GitLab / Bitbucket connections | Request construction and token handling with fakes | Never called against the live provider APIs |
| AI assistant (Claude, OpenAI) | Request shapes, consent gating, injection screening, citations, with fakes | Never called against the live APIs; answer quality unevaluated |
| Scanner coverage and deduplication | OSV/Trivy merge on one fixture | No coverage or false-positive measurement. Trivy/Checkov rule ids differ for the same IaC issue, and Semgrep/Gitleaks report the same secret under different categories; these are not merged |

## Unverified or not done

| Area | Status |
|---|---|
| **`az deployment sub what-if`** | **Not run.** The Azure CLI login has expired (refresh token inactive), and I will not log in interactively on your behalf. `deploy/azure/whatif.sh` previews everything without creating anything, including the resource group |
| Deployment to Azure | **Not done, by instruction.** No Azure resources have been created or changed |
| Independent penetration test | **Not done.** The probes above are self-assessments; they cannot replace human testers |
| Load test on production-like infrastructure | Not done; the figures above are from a laptop |
| Production backup/restore and incident drills | The logic is tested locally; no drill has been run on a deployed environment with a real operator |
| Residual risks in the egress design | The scan environment's required outbound is allowed by service tag (Microsoft Container Registry, Front Door first-party), which is Microsoft-operated; reachable hosts via the proxy are only as safe as the allowlist |
| Credential handoff residual | The grant secret is in the start request until redeemed (seconds). Anyone able to read executions in that window could redeem it first; the job would then fail loudly and the replay is audited, but the credential would have been taken. Narrowing the window needs a network-restricted or authenticated callback |
| Account-lockout tradeoff | Login throttling is per email as well as per address, so an attacker can lock a known user out of login for 15 minutes by sending bad passwords. This favours safety over availability |
| PostgreSQL, Redis/Celery | Not implemented. SQLite and a database-backed queue; **one API replica only** |
| SSO, MFA | Not implemented |
| API security analysis, DAST, SPDX, PDF reports, email/Slack notifications, billing | Not implemented (billing is out of scope by decision) |
| Accuracy and performance benchmarks of the scanners | None; no accuracy claims are made |
| Next.js/TypeScript, FastAPI | Not used (see deviations) |

## Deviations from the specification

- Node.js with zero runtime dependencies instead of FastAPI + Next.js: the existing, tested code was
  Node, and the development machine has no Postgres, Redis or container runtime to verify against.
- SQLite plus a database-backed queue instead of PostgreSQL, Redis and Celery. Storage, queue and
  secrets sit behind small interfaces (`db.js`, `queue.js`, `crypto.js`) so they can be swapped.
- Scan execution is pluggable: `process` (development only, not a security boundary), `docker`, or
  `aca` (Azure Container Apps Jobs).

## What still blocks calling this production-ready

1. **You run `az login`, then `deploy/azure/whatif.sh <region>`** and review the output with me. I will
   not deploy until you approve it.
2. Deploy to a scratch resource group, run a real scan through the job, and **test the egress
   controls from inside a job**: direct connections to the internet, to `169.254.169.254` and to
   another storage account must fail; the proxy path must work. Fix whatever differs from the
   documentation (the NSG rules for the managed environment are the likeliest to need changes).
3. Run `test/docker-sandbox.test.js` and `deploy/docker/setup-egress.sh` on a Docker host.
4. Independent penetration test, including attempts to escape the scan container and to reach internal
   services from a scan.
5. Load-test on the real deployment, then run the backup/restore and incident drills there with a real
   operator following `docs/OPERATIONS.md`.
6. Migrate to PostgreSQL before running more than one API replica.
