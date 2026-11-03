# VulnSight AI — Project Overview

> **Document ID:** VS-DOC-01  
> **Status:** Active Reference  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Engineering Leadership, Security Architects, DevOps Engineers, Product Managers  

---

## 1. Executive Summary

**VulnSight AI** is an enterprise-grade, multi-tenant software security platform engineered to discover, evaluate, and remediate vulnerabilities across modern application ecosystems. Evolving from a specialized open-source Software Composition Analysis (SCA) CLI tool, VulnSight AI delivers a comprehensive, cloud-native security orchestration platform. 

The platform seamlessly connects to distributed Git source code management systems (GitHub, GitLab, Bitbucket), executes isolated multi-scanner security analysis in hardened sandbox environments, normalizes disparate security findings into a unified data model, and empowers developers through contextual, security-governed AI remediation guidance.

```
+-----------------------------------------------------------------------------------+
|                                  VulnSight AI                                     |
|  Unified Multi-Tenant Security Orchestration & AI-Assisted Remediation Platform   |
+-----------------------------------------------------------------------------------+
        |                         |                         |
        v                         v                         v
 [ Multi-Source Scan ]   [ Sandboxed Execution ]   [ Governed AI Guidance ]
  - SCA (OSV.dev)         - Azure Container Apps    - Claude 3.5 Sonnet
  - SAST (Semgrep)        - Docker Hardened         - OpenAI GPT-4o
  - Secrets (Gitleaks)    - Process (Dev/Test)      - Deterministic Risk Calc
  - Container (Trivy)     - Strict Egress Proxy     - Strict Prompt Isolation
  - IaC (Checkov)         - Ephemeral Workspaces    - Zero-Code Consent Gate
```

---

## 2. Core Value Proposition

Modern development teams struggle with tool fragmentation, overwhelming alert volume, slow remediation lifecycles, and security risks inherent in analyzing untrusted third-party code. VulnSight AI resolves these core pain points through five foundational pillars:

| Pillar | Industry Pain Point | VulnSight AI Solution |
| :--- | :--- | :--- |
| **Unified Vulnerability Model** | Siloed tools produce incompatible reports (SCA, SAST, Secrets, IaC). | A single, canonical JSON finding schema with deterministic fingerprinting and cross-scanner deduplication. |
| **Secure Worker Isolation** | Scanning untrusted customer repositories can compromise build infrastructure. | Ephemeral worker sandboxes (Docker / Azure Container Apps Jobs) governed by CONNECT-only egress filtering and single-use credential grants. |
| **Zero-Source Retention** | Enterprise risk of code leakage or exfiltration to SaaS vendors. | Repositories are cloned to ephemeral storage, scanned, and permanently destroyed in a `finally` block; only metadata and findings persist. |
| **Governed AI Remediation** | Generic LLMs hallucinate, leak proprietary source code, or fall victim to prompt injection. | Strict consent gating, delimiter look-alike stripping, prompt injection pattern matching, and an architectural guarantee that AI cannot alter scanner severity. |
| **Enterprise Readiness** | Fragmented command-line utilities lack multi-tenancy, RBAC, and auditability. | Native organization workspaces, fine-grained RBAC (Owner, Admin, Developer, Viewer), audit logging, and automated compliance reporting. |

---

## 3. Evolutionary Journey: From CLI to Cloud SaaS

VulnSight AI originated as a zero-dependency, local-first SCA tool designed to parse lockfiles (`package-lock.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`) and query the open OSV.dev vulnerability database.

### Transformation Milestones

```mermaid
timeline
    title VulnSight AI Evolution Roadmap
    section Phase 1 : CLI & Local Scanner
        Local Lockfile Parsing : npm, PyPI, Yarn, Pnpm, Go
        OSV.dev Integration : Direct & Transitive Vulnerability Mapping
        Local Web UI : Single-user localhost dashboard (port 4321)
    section Phase 2 : Platform Architecture
        Multi-Tenancy & RBAC : Organizations, Teams, Memberships
        Hardened Sandbox : Azure Container Apps Jobs & Docker Isolation
        Egress Allowlist Proxy : Port 443 CONNECT-only DNS Pinning
    section Phase 3 : Scanner Orchestration
        Adapter Ecosystem : Semgrep, Gitleaks, Trivy, Checkov
        Single-Use Grants : Zero-credential worker dispatch
        Compliance Reports : CycloneDX SBOM, CSV, Markdown, JSON
    section Phase 4 : AI & Production Hardening
        Governed AI Assistant : Explanations, Fix Plans, Posture Scoring
        Operations & Tooling : Online Backup, Master Key Rotation, Audit Trail
        Zero Runtime Dependencies : Pure Node.js Standard Library Core
```

---

## 4. Key Platform Capabilities

### 4.1 Multi-Ecosystem Security Scanning
The platform orchestrates five specialized security analyzers:
1. **Software Composition Analysis (SCA):** Direct and transitive dependency inspection querying the live OSV.dev database with alias aggregation (CVE, GHSA, PYSEC).
2. **Static Application Security Testing (SAST):** AST-based code analysis using Semgrep to detect application logic vulnerabilities, injection flaws, and insecure patterns.
3. **Secret Detection:** High-speed entropy and pattern-based secret scanning powered by Gitleaks, with automated in-memory redaction before storage.
4. **Container Image & Filesystem Security:** Trivy adapter identifying base image CVEs and misconfigured container definitions.
5. **Infrastructure-as-Code (IaC) Scanning:** Checkov adapter scanning Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles against CIS benchmarks.

### 4.2 Ephemeral Sandboxing & Egress Defense
- **Single-Use Credential Grants:** The API orchestrator never exposes persistent Git access tokens to worker nodes. Workers receive an ephemeral grant secret, which is exchanged over a mutually authenticated internal channel for temporary clone credentials.
- **CONNECT-Only Egress Proxy:** Scan workers operate inside private network subnets. Outbound access is restricted to an allowlist proxy that denies IP literals, non-standard ports, and any domain resolving to private or metadata network addresses (`169.254.169.254`).
- **Workspace Sanitization:** Untrusted repositories are sanitized by stripping all symlinks, disallowing `.git` hooks, and enforcing strict byte (500 MB) and file (100,000) limits before analysis.

### 4.3 AI Security Assistant with Architectural Guardrails
- **Ground Truth Invariance:** AI output is stored in separate data records (`ai_history`) and explicitly marked as `aiGenerated: true`. The AI model is strictly prohibited from altering scanner-assigned severity ratings or triaged finding states.
- **Two-Tier Consent Gating:** AI analysis requires affirmative organization consent (`aiEnabled: true`). Transmission of code snippets requires an additional granular flag (`sendCode: true`), which is permanently blocked for secret findings.
- **Active Injection Screening:** Untrusted repository text is sanitized, bounded, and screened for system-prompt overrides before dispatching requests to Anthropic Claude or OpenAI APIs.

---

## 5. Architectural Principles

1. **Zero External Runtime Dependencies:** The entire backend engine, rate limiters, crypto subsystems, API router, and HTTP server are constructed using the pure Node.js standard library (`node:http`, `node:crypto`, `node:sqlite`, `node:net`, `node:dns`), drastically reducing supply chain attack surface.
2. **Tenant Isolation by Construction:** Every database record carries an `org_id`. The platform service layer enforces cryptographic and relational organization scoping before servicing any read, write, or scan action.
3. **Least Privilege Infrastructure:** Designed to deploy on Azure with discrete User-Assigned Managed Identities for the API Server, Scan Worker Jobs, and Egress Proxy.
4. **Defensive Resource Management:** High-overhead operations (such as `scrypt` password hashing) run off the main event loop inside bounded thread pool queues, preventing denial-of-service starvation.

---

## 6. Document Suite Organization

This documentation suite provides a complete, 360-degree technical and operational blueprint for VulnSight AI:

- **System & Architecture:** HLD, LLD, Solution Architecture, Component, Data Flow, Sequence, and Technology Stack.
- **Cloud & Network:** Azure Cloud Architecture, Infrastructure Bicep, Network Segmentation, and Docker Sandbox.
- **Security & Hardening:** Security Architecture, Threat Model (STRIDE), VAPT Assessment, and Security Hardening Report.
- **Testing & Verification:** Test Strategy, Execution Reports, Scanner Validation, and Performance Benchmarks.
- **Operations & Governance:** Deployment Guide, Operations Manual, Disaster Recovery, Feature Gap Analysis, and Roadmap.
- **User & Administrative Guides:** User Manual, Admin Guide, Live Demo Script, and Production Readiness Assessment.
