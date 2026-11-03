# Product Requirements Document (PRD)

> **Document ID:** VS-DOC-03  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Engineering, Product Management, Security Operations, QA  

---

## 1. Product Overview

VulnSight AI is a cloud-based, multi-tenant vulnerability management and security orchestration platform. It provides end-to-end vulnerability scanning (SCA, SAST, Secrets, Container, IaC), automated finding triaging, compliance export (CycloneDX SBOM), and AI-driven remediation analysis within an isolated zero-trust architecture.

---

## 2. Target Personas

| Persona | Role | Key Needs | Primary Platform Touchpoints |
| :--- | :--- | :--- | :--- |
| **Alex (DevSecOps Lead)** | Security Engineer | Configure security baselines, monitor posture across all repositories, enforce compliance, audit user actions. | Overview Dashboard, Audit Logs, Settings, Egress Policy, Policy Gates. |
| **Priya (Senior Developer)** | Software Engineer | Quickly understand why a finding occurred, assess if it affects production, obtain safe version upgrade guidance without breaking dependencies. | Scan Detail, Finding Drawer, AI Explain & Fix, Triage Notes. |
| **Marcus (Engineering Manager)** | Team Lead | Monitor team vulnerability backlog, track SLA progress, review Security Posture Scores, assign issues. | Team Management, Trend Reports, Posture Scoring, Repository Schedules. |
| **Elena (Compliance Officer)** | Auditor | Generate verifiable Software Bill of Materials (SBOM) for external compliance audits, verify zero secret leaks. | Reports View (CycloneDX, CSV, Markdown, JSON), Audit Logs. |

---

## 3. Functional Requirements

### 3.1 Authentication, Organizations & RBAC
- **FR-AUTH-01:** System must support email/password registration with strict complexity validation (minimum 12 characters, uppercase, lowercase, numeric).
- **FR-AUTH-02:** Passwords must be hashed using `scrypt` with per-user unique cryptographic salts.
- **FR-AUTH-03:** Authentication sessions must utilize cryptographically secure 256-bit random tokens, stored strictly as SHA-256 hashes with an automatic 12-hour expiration.
- **FR-AUTH-04:** Multi-tenant organization support: users can create, join, and switch between multiple organizations.
- **FR-AUTH-05:** Granular Role-Based Access Control (RBAC) supporting four distinct roles:
  - **Owner:** Full organization control, billing, member deletion, and organization deletion (`org:delete`).
  - **Admin:** Team management, member invites/role changes, Git provider connections, repository configuration, audit log inspection.
  - **Developer:** Read repositories/scans, trigger on-demand scans (`scans:run`), update finding triage states (`findings:write`), interact with AI assistant (`ai:use`).
  - **Viewer:** Read-only access to repositories, scans, findings, and reports.
- **FR-AUTH-06:** The system must strictly enforce that the last remaining Owner of an organization cannot be removed or downgraded.

### 3.2 Git Provider Integrations & Repository Management
- **FR-REPO-01:** Support public and private repository connections for GitHub, GitLab, and Bitbucket.
- **FR-REPO-02:** Provider access tokens must be encrypted at rest using AES-256-GCM under a master key sourced from environment/Key Vault.
- **FR-REPO-03:** Pre-clone validation must enforce strict SSRF protections: require `https://`, prohibit IP literals, validate host against allowlist, resolve DNS and reject any private/loopback/link-local/metadata IP addresses.
- **FR-REPO-04:** Git clone operations must pin the validated IP address using `--config http.curloptResolve` to prevent DNS rebinding attacks.
- **FR-REPO-05:** Support automated scans via webhooks with HMAC-SHA256 signature verification (GitHub) or shared secret verification (GitLab, Bitbucket).
- **FR-REPO-06:** Support configurable branch scan scheduling (Daily, Weekly, Monthly) with automated queue dispatching.

### 3.3 Multi-Scanner Orchestration & Execution
- **FR-SCAN-01:** Orchestration layer must execute five security scanning categories:
  - Software Composition Analysis (SCA) querying live OSV.dev REST API.
  - Static Application Security Testing (SAST) via Semgrep.
  - Secret Detection via Gitleaks with automated in-memory secret value redaction.
  - Container image and filesystem scanning via Trivy.
  - Infrastructure-as-Code (IaC) configuration analysis via Checkov.
- **FR-SCAN-02:** Scanner execution must support three pluggable isolation backends:
  - `aca`: Azure Container Apps Job execution.
  - `docker`: Hardened, capability-dropped Docker container.
  - `process`: Local child process (strictly restricted to development and testing).
- **FR-SCAN-03:** Credential delivery to scan workers must use single-use grant secrets (`scan_grants`) exchanged over a one-time API redemption endpoint, eliminating persistent credentials from worker execution payloads.
- **FR-SCAN-04:** Workspaces must be sanitized prior to scanning: purge `.git` folder, delete all symbolic links, enforce 500 MB max size and 100,000 max file limits.
- **FR-SCAN-05:** Fault isolation: Failure or absence of an optional scanner binary must produce an informational error status rather than aborting the remaining scanners.

### 3.4 Finding Lifecycle, Normalization & Triage
- **FR-FIND-01:** Disparate scanner outputs must be normalized into a canonical Finding schema.
- **FR-FIND-02:** Findings must generate a stable, deterministic cryptographic fingerprint based on vulnerability identity, location, and package/rule to support tracking across multiple scans.
- **FR-FIND-03:** Automatic deduplication: Findings reporting the same underlying vulnerability across multiple scanners (e.g., OSV and Trivy) must be merged, retaining the highest severity rating and union of identifiers.
- **FR-FIND-04:** Finding triage management: Support status transitions (`open`, `in_review`, `confirmed`, `false_positive`, `mitigated`, `accepted`), assignment to team members, triage notes, and immutable review audit entries.
- **FR-FIND-05:** Real-time Security Posture Scoring (0 to 100, graded A to F) calculated based on open findings weighted by severity, ignoring suppressed/mitigated issues.

### 3.5 AI-Assisted Security Guidance
- **FR-AI-01:** Governed AI assistance supporting Anthropic Claude (claude-3-5-sonnet) and OpenAI (gpt-4o).
- **FR-AI-02:** Two-level consent verification: `aiEnabled` flag at organization settings, and `sendCode` flag for providing source code context.
- **FR-AI-03:** Zero-Secret Exposure: Source code evidence for findings categorized as `secret` must never be sent to any AI model, regardless of consent settings.
- **FR-AI-04:** System-prompt override defense: Repository text must be delimited within `<untrusted>` tags, stripped of delimiter look-alikes, and pre-screened against prompt injection regex patterns.
- **FR-AI-05:** Output labeling: All AI responses must be stamped with `aiGenerated: true`, model metadata, timestamp, and stored in a dedicated `ai_history` table without modifying scanner findings.

### 3.6 Compliance, Export & Reporting
- **FR-REP-01:** On-demand export of scan results in four formats:
  - **JSON:** Comprehensive canonical vulnerability payload.
  - **CycloneDX v1.5 JSON:** Software Bill of Materials (SBOM) with standard Package URLs (`purl`) and dependency vulnerability links.
  - **CSV:** Formatted table with CSV injection protection (sanitizing cells starting with `=`, `+`, `-`, `@`).
  - **Markdown:** Formatted summary suitable for pull request or audit comments.
- **FR-REP-02:** Configurable data retention policy (default 90 days, configurable 1–3650 days) with automated background purge of expired scans, raw data, and findings.

---

## 4. Non-Functional Requirements (NFR)

### 4.1 Performance & Scalability
- **NFR-PERF-01:** API response latency for cached read operations (Overview, Repositories, Scan lists) must maintain $p_{95} < 50\text{ ms}$ under standard loads.
- **NFR-PERF-02:** Platform must sustain $\ge 1,000\text{ req/s}$ on a standard 8-core host without HTTP 5xx errors or dropped connections.
- **NFR-PERF-03:** Password hashing concurrency must be hard-capped (maximum 2 concurrent operations) with a bounded queue (maximum 50 pending requests) to guarantee the event loop and DNS resolution are never starved.
- **NFR-PERF-04:** Memory footprint: Background worker and API server must run with bounded heap limits (`--max-old-space-size=768MB`).

### 4.2 Security & Isolation
- **NFR-SEC-01:** Zero Source Retention: Cloned repository source code must be purged in a guaranteed `finally` execution block upon scan completion or failure.
- **NFR-SEC-02:** Egress Filtering: All worker outbound internet traffic must route through a CONNECT-only proxy enforcing a strict hostname allowlist on port 443. All direct outbound traffic must be denied by NSG.
- **NFR-SEC-03:** Container Hardening: Worker containers must run with dropped Linux capabilities (`--cap-drop ALL`), `no-new-privileges`, read-only root filesystems, and unprivileged UIDs (`10001:10001`).
- **NFR-SEC-04:** Web Application Defenses: HTTP responses must enforce strict Content Security Policy (`script-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and prohibit third-party cookies.

### 4.3 Reliability & Disaster Recovery
- **NFR-REL-01:** Database transactions must run in Write-Ahead Logging (WAL) mode with strict foreign key constraints enabled.
- **NFR-REL-02:** Online non-blocking database backups using `VACUUM INTO` ensuring zero service interruption.
- **NFR-REL-03:** Recovery Point Objective (RPO) $\le 24\text{ hours}$; Recovery Time Objective (RTO) $\le 4\text{ hours}$.

---

## 5. Requirements Traceability Matrix

| Requirement | Implementation Module | Verification Test Suite |
| :--- | :--- | :--- |
| FR-AUTH-01 / 02 | `src/platform/crypto.js` | `test/platform.test.js`, `test/hashing.test.js` |
| FR-AUTH-03 / 05 | `src/platform/rbac.js`, `service.js` | `test/platform.test.js`, `test/api.test.js` |
| FR-REPO-02 | `src/platform/crypto.js` | `test/platform.test.js`, `test/ops.test.js` |
| FR-REPO-03 / 04 | `src/platform/git.js` | `test/git.test.js`, `test/api.test.js` |
| FR-SCAN-01 / 05 | `src/adapters/index.js`, `runner.js` | `test/scanners.test.js`, `test/real-tools.test.js` |
| FR-SCAN-02 / 04 | `src/platform/sandbox.js`, `aca.js` | `test/aca.test.js`, `test/docker-sandbox.test.js` |
| FR-SCAN-03 | `src/platform/service.js` | `test/grants.test.js` |
| FR-FIND-01 / 02 / 03 | `src/findings.js`, `risk.js` | `test/findings.test.js`, `test/scoring.test.js` |
| FR-AI-01 / 02 / 03 / 04 | `src/ai/assistant.js` | `test/ai.test.js` |
| FR-REP-01 / 02 | `src/reports/export.js`, `service.js` | `test/platform.test.js` |
| NFR-SEC-02 | `src/platform/egress-proxy.js` | `test/egress-proxy.test.js`, `test/egress-wiring.test.js` |
| NFR-PERF-02 / 03 | `src/platform/crypto.js`, `api.js` | `scripts/loadtest.js`, `test/hashing.test.js` |
