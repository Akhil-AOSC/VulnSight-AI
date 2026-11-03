# Known Issues & Limitations

> **Document ID:** VS-DOC-33  
> **Status:** Active Reference (Strict Disclosure Policy)  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Engineering Leads, SREs, Security Officers, Operators  

---

## 1. Transparency & Disclosure Philosophy

In accordance with enterprise security engineering ethics and `docs/STATUS.md`, VulnSight AI maintains an explicit, transparent inventory of current architectural limitations, verified vs unverified controls, and operational tradeoffs. 

> [!IMPORTANT]
> **Passing tests are necessary, but not sufficient.**  
> Several core controls (such as network-enforced NSG egress blocking and live Azure Container Apps job executions) have been validated against fakes and compilers, but have not yet been executed in a live Azure subscription. Operators must review these limitations before declaring production readiness.

---

## 2. Technical Limitations & Architectural Constraints

### 2.1 Single-Node Database Constraint (SQLite WAL)
- **Current Limitation:** The platform currently runs on an embedded SQLite database (`db.js`) in Write-Ahead Logging mode.
- **Operational Impact:** **Only one API server replica can run at a time.** Running multiple API container instances against a shared SQLite database over network storage (like Azure Files or NFS) risks database corruption and lock timeouts.
- **Resolution Path:** The storage layer is strictly partitioned behind an abstraction interface. Migrating to managed Azure Database for PostgreSQL is required before horizontal API autoscaling is enabled.

### 2.2 Network-Layer Egress Enforcement Is Partially Verified
- **Current Limitation:** The egress proxy (`egress-proxy.js`) is verified and tested with real sockets, real tools, and real external networks. However, **the Network Security Group rule that physically enforces traffic through the proxy is untested in a live Azure subscription.**
- **Operational Impact:** If a malicious tool or worker process intentionally bypasses proxy environment variables (`HTTPS_PROXY`), the proxy cannot stop it on its own. The NSG is what makes the proxy an enforceable security control.
- **Resolution Path:** Prior to running production workloads, an operator must deploy to a scratch Azure resource group and execute `curl` tests from inside a running job pod to verify that direct outbound internet and `169.254.169.254` are physically dropped by the Azure virtual network.

### 2.3 Single-Use Grant Secret Interception Window
- **Current Limitation:** The API orchestrator passes a single-use grant secret (`VS_GRANT_SECRET`) in the Azure ARM job start request. The secret exists until redeemed by the worker (typically 1–3 seconds).
- **Operational Impact:** An adversary possessing broad read permissions to Azure Container Apps execution templates could theoretically read the grant secret during that brief multi-second window and attempt to redeem it before the worker.
- **Mitigating Factor:** Redeeming the secret immediately marks it as spent (`used_at`). When the real worker attempts redemption, the replay is detected, the scan is aborted, an audit alert is triggered, and the token is revoked.
- **Resolution Path:** Implement mutual TLS (mTLS) or an authenticated internal callback between the worker and API.

### 2.4 Account Lockout Brute-Force Lever
- **Current Limitation:** To defend against distributed brute-force attacks, the rate limiter throttles authentication by both IP address and normalized email address (10 failed attempts per 15 minutes).
- **Operational Impact:** An attacker who knows an employee's email address can intentionally send 10 incorrect passwords from an arbitrary IP, locking the legitimate user out of the platform for 15 minutes.
- **Design Tradeoff:** This design deliberately favors **confidentiality and defense against credential stuffing over availability**.
- **Resolution Path:** Implement CAPTCHA challenges or email-based magic-link fallback when email-level rate limits are tripped.

### 2.5 Container Mode Local Host Prerequisites
- **Current Limitation:** In `VULNSIGHT_SANDBOX=docker` mode, tests require an active Docker daemon on the host. In environments lacking Docker (such as standard CI runners or Windows without Docker Desktop), unit tests in `test/docker-sandbox.test.js` are skipped.
- **Operational Warning:** Never mount `/var/run/docker.sock` into the API container. Use Azure Container Apps Jobs mode (`aca`) for hosted enterprise environments.

### 2.6 Scanner Output Deduplication Nuances
- **Current Limitation:** While the deduplication engine merges overlapping CVE and GHSA findings between OSV and Trivy, rule IDs between Trivy and Checkov for Infrastructure-as-Code issues currently differ and may produce separate finding records.
- **Operational Impact:** An insecure Dockerfile directive may be reported separately by Trivy and Checkov under their respective proprietary rule IDs.

---

## 3. Deployment Pre-Requisites Checklist

Before removing the "pre-production" designation, the engineering team must satisfy the following criteria:

- [ ] Execute `deploy/azure/whatif.sh` against an active Azure subscription and review the planned billable resources.
- [ ] Deploy to a scratch Azure resource group (`rg-vulnsight-scratch`).
- [ ] Run an end-to-end scan through an Azure Container Apps Job execution.
- [ ] Verify that direct connections from the scan container to `169.254.169.254` and `google.com` are dropped by NSGs.
- [ ] Execute an independent third-party penetration test against the deployed environment.
- [ ] Complete the PostgreSQL storage driver migration for multi-replica clustering.
