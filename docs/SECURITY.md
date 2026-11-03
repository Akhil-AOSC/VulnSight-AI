# Securing VulnSight AI itself

VulnSight AI clones and analyses other people's code, so the platform is a target. This document
lists the threats, the control that answers each one, and where it is implemented and tested.

| Threat | Control | Code | Test |
|---|---|---|---|
| SSRF through a repository URL (cloud metadata, localhost, private network) | https only; no credentials, port, query; hostname only (no IPs); host allowlist (github.com, gitlab.com, bitbucket.org); every DNS answer must be public; the validated address is pinned for the clone (`http.curloptResolve`) so DNS cannot change in between; redirects disabled | `src/platform/git.js` `validateRepoUrl`, `cloneRepo` | `SSRF protection rejects dangerous repository URLs`, `SSRF attempts through the API are rejected` |
| Git option / command injection | Branch names validated against a strict pattern; `--` before the URL; no shell anywhere (`spawn` with `shell: false`) | `validateBranch`, `execTool` | `branch names are validated` |
| Malicious repository content (symlinks to host files, huge repos, hooks) | `.git` removed after the commit is read; every symlink deleted; size and file-count limits; `core.hooksPath`, `fsmonitor`, submodules and templates disabled; install scripts are never run | `sanitizeWorkspace`, `cloneRepo` | `sanitizeWorkspace removes symlinks and enforces limits` |
| Credential leakage | Provider tokens encrypted with AES-256-GCM (key from Key Vault); passed to git through the environment, never the command line or URL; never returned by the API; secrets found by Gitleaks are redacted before they are stored, logged, exported or sent to AI | `crypto.js`, `gitEnv`, `gitleaks.js` | `provider tokens are validated, stored encrypted...`, `parseGitleaks never lets the raw secret into a finding` |
| Worker escape / resource exhaustion | Hosted scans run in a short-lived container: non-root, read-only root, all capabilities dropped, `no-new-privileges`, CPU/memory/PID limits, no application secrets, egress-restricted network, hard timeout, output size cap. The `process` mode is for development only and is **not** a security boundary | `sandbox.js` | `docker worker arguments are locked down` |
| Cross-tenant access | Every row carries `org_id`; every service call authorizes the caller's membership first and filters by `org_id`; non-members get "not found" so ids cannot be probed | `service.js` `authorize` | `tenant isolation...` (service and HTTP) |
| Broken access control | Role to permission table checked in the service layer on every call (not only in HTTP routes); last owner cannot be removed; only owners can change owners | `rbac.js` | `RBAC...`, `member management...`, `every non-public API route rejects unauthenticated requests` |
| Credential stuffing / brute force | scrypt password hashing; password policy; per-IP and per-email rate limits; constant-time login path for unknown emails; generic error messages; 12 h sessions stored only as SHA-256 | `crypto.js`, `api.js` | `login and signup are rate limited`, `sessions expire` |
| Web attacks (XSS, clickjacking, CSRF) | Strict CSP (`script-src 'self'`, no inline script or style), `X-Frame-Options: DENY`, `nosniff`, no CORS; the UI builds the DOM with `textContent` only; bearer-token auth (no cookies, so no CSRF) | `api.js`, `web/lib.js` | `security headers` test |
| Prompt injection via repository content | Repository text is delimited as untrusted and stripped of delimiter look-alikes; injection phrases cause the content to be withheld from the model; AI output is labelled, stored separately, and can never change severity or status | `ai/assistant.js` | `prompt injection...`, `AI output is labelled...` |
| Code sent to an AI provider without consent | AI is off by default per organisation; code evidence needs a second explicit setting; secrets are never sent; Q&A never includes code | `ai/assistant.js`, `service.js` | `code evidence is only sent with sendCode consent...` |
| CSV / spreadsheet formula injection in exports | Cells starting with `= + - @` are neutralised | `reports/export.js` | `CSV neutralises spreadsheet formulas` |
| Forged webhooks | HMAC-SHA256 signature (GitHub) or shared token (GitLab/Bitbucket), constant-time compare | `service.js` `handleWebhook` | `webhooks need a valid signature...` |
| Scan workers reaching the internet or internal services (exfiltration, metadata, lateral movement) | Two layers. (1) **Network**: scan jobs run in their own subnet whose NSG denies all outbound except the egress proxy, private endpoints for our own storage and registry, Azure DNS and the platform's required services; (2) **Proxy**: CONNECT-only, hostname allowlist, port 443 only, refuses IP literals and any name that resolves to a private or metadata address, caps tunnels and upload bytes, logs every denial. Docker mode: an `--internal` network whose only exit is the same proxy; it **fails closed** if no proxy is configured | `egress-proxy.js`, `sandbox.js`, `deploy/azure/main.bicep`, `deploy/docker/setup-egress.sh` | `egress-proxy.test.js`, `egress-wiring.test.js`; real tools run through the proxy. **The network layer is untested** (see below) |
| Repository credential exposed through the job definition | The job-start request carries no Git token. It carries a one-time secret bound to the scan; the job redeems it once (within 10 minutes, only while the scan runs) over HTTPS for the credential, which is encrypted at rest and deleted when the scan ends. Replays are refused and audited; every failure looks identical | `service.js` `grants`, `aca.js`, `scan-job.js` | `grants.test.js` |
| Over-privileged API identity | The API can only read, start and stop the one scan job (built-in *Container Apps Jobs Operator*), read/write scan results, read the master key and pull images. The scan job has a different identity that can only pull its image and write results. The proxy has a third that can only pull its image | `deploy/azure/main.bicep` | compiles; not exercised in Azure |
| Login flood freezing the server | Password hashing runs on the thread pool, at most 2 at a time, with a bounded queue (excess gets a 503), so hashing cannot block the event loop or starve DNS lookups | `crypto.js` | `hashing.test.js` |
| Stored XSS | All screens build the DOM with `textContent`; strict CSP; only `https://` links are rendered | `web/lib.js`, `api.js` | `scripts/xss-probe.js` (real browser, 13 screens) |
| Supply chain | No runtime npm dependencies; CI scans our dependencies, source, secrets, IaC and images and fails on findings | `.github/workflows/ci.yml` | CI |

## Known limits (be honest about these)

- **Worker isolation is only as good as the container runtime.** `process` mode shares the host
  filesystem and must not be used for untrusted repositories.
- **Docker mode has never been run.** `sandbox.js` starts workers with `docker run`; the flags are
  unit-tested and `test/docker-sandbox.test.js` verifies the isolation inside a real container, but
  there was no container runtime on the development machine, so that test has only ever been skipped.
  It also needs a Docker host: never give the API container the host Docker socket (equivalent to
  root on the host).
- **The egress restriction is only half-verified, and the verified half is not the enforcing one.**
  The proxy is tested, including with real git, Semgrep and Trivy. But a client that ignores the proxy
  settings connects directly (the OSV client did exactly that until `NODE_USE_ENV_PROXY=1` was set at
  process start), so the control that actually prevents exfiltration is the network rule that denies
  direct outbound. That rule, the private endpoints, and Container Apps' own required outbound
  traffic under it have **never been run**; the NSG's platform allowances were written from memory of
  Microsoft's documentation and are the likeliest thing to need correction. Until they have been tested
  from inside a job (direct internet, `169.254.169.254` and another storage account must all fail), do
  not treat workers as egress-restricted.
- **Azure Container Apps mode (`VULNSIGHT_SANDBOX=aca`) is implemented but untested against Azure.**
  Each scan runs as a job execution that clones and scans by itself and writes its result to Blob
  Storage with its own managed identity. Tested against a fake Azure only. Residual weakness in the
  credential handoff: the one-time secret is in the start request until it is redeemed (seconds).
  Someone who can read job executions in that window could redeem it first; the job would then fail
  loudly and the replay is audited, but that credential would have been taken. Use read-only tokens.
- **Login throttling is also a lockout lever.** Limits apply per email as well as per address, so an
  attacker can block a known user's logins for 15 minutes by sending bad passwords.
- **The embedded database is single-node.** Run one API replica until the PostgreSQL migration.
- **No SSO/MFA yet.** Authentication is email and password with server-side sessions.
- **Penetration testing has not been performed.** The tests here are automated unit and integration
  tests, not a substitute for an independent assessment.
