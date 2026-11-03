# VulnSight AI -- Platform Upgrade Specification

**Document type:** POC-to-product upgrade plan\
**Purpose:** Define what must be retained, improved, added, and
redesigned to evolve the existing VulnSight AI proof of concept into a
cloud-based, multi-user security scanning platform.

------------------------------------------------------------------------

## 1. Executive Summary

The recommended approach is **not to rebuild the existing POC from
scratch**. The existing POC provides a useful scanning foundation,
including dependency analysis, transitive dependency detection, OSV.dev
integration, Semgrep, Gitleaks, and Claude-based explanations.

The target is to evolve the local-first scanning application into a
complete SaaS security platform that can:

-   Connect to public and private Git repositories.
-   Scan repositories through isolated, short-lived workers.
-   Detect dependency, source-code, secret, container, and
    infrastructure-as-code risks.
-   Consolidate findings into a consistent vulnerability model.
-   Provide AI-assisted explanations and remediation guidance.
-   Offer dashboards, reports, scan history, team management, and access
    control.
-   Continuously monitor connected repositories.
-   Secure the VulnSight AI platform and its infrastructure using its
    own security controls.

**Important implementation caveat:** The POC architecture document
describes intended capabilities and success criteria. It does not, by
itself, prove that every feature is implemented, tested, or
production-ready. An audit of the actual source code is required before
deciding which components can be reused.

------------------------------------------------------------------------

## 2. Overall Transformation

### 2.1 Existing POC

The existing POC is primarily a local security scanning application:

-   Scans local project folders.
-   Analyses package manifests and lockfiles.
-   Detects direct and transitive dependency vulnerabilities.
-   Uses OSV.dev for vulnerability information.
-   Uses Semgrep for static application security testing (SAST).
-   Uses Gitleaks for secret detection.
-   Uses Claude for explanations and developer Q&A.
-   Provides scan results and remediation guidance.

### 2.2 Target Platform

The target is a cloud-based, multi-user SaaS platform:

-   Connect GitHub, GitLab, and Bitbucket.
-   Support public and private repositories.
-   Scan selected repositories and branches.
-   Run multiple scanners through an orchestration service.
-   Support dependency, SAST, secret, container, and IaC scanning.
-   Normalize and deduplicate findings.
-   Provide AI-assisted vulnerability analysis and remediation.
-   Provide dashboards, reports, scan history, and trend analysis.
-   Support organisations, teams, roles, and permissions.
-   Schedule scans and monitor repositories continuously.
-   Secure the application, APIs, workers, infrastructure, and AI
    workflows.

------------------------------------------------------------------------

## 3. Detailed Upgrade Requirements

## 3.1 Repository Integration and Scanning

**Status: Major update required**

  -----------------------------------------------------------------------
  Existing POC capability             Required target capability
  ----------------------------------- -----------------------------------
  Local project-folder scanning       Retain as an option

  Local manifest and lockfile         Retain
  scanning                            

  No complete remote Git workflow     Add Git repository URL submission

  No complete private Git integration Add GitHub, GitLab, and Bitbucket
                                      authentication

  Primarily manual scanning           Add scheduled and automatic scans

  Limited repository management       Add repository connection,
                                      selection, branch selection, and
                                      scan configuration
  -----------------------------------------------------------------------

### Expected user workflow

1.  User signs in to VulnSight AI.
2.  User connects a Git provider or submits a repository URL.
3.  User selects a repository and branch.
4.  User configures and starts a scan.
5.  The platform creates an isolated scanning job.
6.  Scanner workers analyse the repository.
7.  Results are normalized, deduplicated, and stored.
8.  The dashboard displays findings and remediation guidance.

### Requirements

-   Support public Git repositories.
-   Support private repositories through secure provider authorization.
-   Validate repository URLs and provider credentials.
-   Support branch selection and commit identification.
-   Preserve local-folder scanning where it remains useful.
-   Store scan metadata and results without unnecessarily retaining
    source code.
-   Support manual, scheduled, and event-triggered scans.
-   Handle repository access failures, deleted branches, rate limits,
    and interrupted scans.

------------------------------------------------------------------------

## 3.2 Security Scanning Engine

**Status: Expand existing scanners and add new scanner categories**

The POC already establishes a useful foundation in software composition
analysis, SAST, and secret scanning. The target platform should expand
scanning coverage.

  -----------------------------------------------------------------------
  Scanner / capability    POC position            Required update
  ----------------------- ----------------------- -----------------------
  Dependency scanning     Included                Retain and improve
  (SCA)                                           

  Direct dependencies     Included                Retain

  Transitive dependencies Included                Retain and improve
                                                  dependency graph

  OSV vulnerability       Included                Retain
  database                                        

  SAST -- Semgrep         Included                Expand rules and
                                                  language coverage

  Secret scanning --      Included                Expand secret types and
  Gitleaks                                        validation

  Container scanning      Not included in POC     Add Trivy
                          scope                   

  Infrastructure as Code  Not included in POC     Add Checkov and/or
  scanning                scope                   Trivy

  API security            Limited                 Add API security
                                                  analysis and testing

  SBOM generation         Not established         Add CycloneDX or SPDX
                                                  support

  DAST                    Not included            Consider for a later
                                                  phase
  -----------------------------------------------------------------------

### Recommended scanning architecture

``` text
Repository / Project
        |
        v
Scan Orchestrator
        |
        +------------------+------------------+
        |                  |                  |
        v                  v                  v
       SCA                SAST              Secrets
   Trivy + OSV           Semgrep           Gitleaks
        |                  |                  |
        +------------------+------------------+
                           |
                           v
                  IaC / Container Scanning
                      Checkov + Trivy
                           |
                           v
                 Unified Finding Engine
           Normalization, deduplication, severity,
                risk scoring and correlation
                           |
                           v
                  AI Analysis and Remediation
                           |
                           v
                 Dashboard, Reports and APIs
```

### Scanner adapter design

Each scanner should be integrated through an independent adapter with a
consistent interface. This will allow the platform to add, remove, or
replace scanners without rewriting the entire application.

Each adapter should define:

-   Input requirements.
-   Execution configuration.
-   Resource limits.
-   Scanner version.
-   Output parsing.
-   Error handling.
-   Normalized finding conversion.
-   Execution status and timing.

### Finding engine requirements

The unified finding engine should:

-   Normalize output from all scanners.
-   Deduplicate findings across scanners.
-   Preserve original scanner identifiers and evidence.
-   Map CVE, GHSA, OSV, CWE, and other identifiers where available.
-   Record affected package, file, line, dependency path, and version.
-   Store fixed-version guidance where available.
-   Distinguish confirmed findings from AI-generated commentary.
-   Support finding status, assignment, suppression, and review history.

------------------------------------------------------------------------

## 3.3 AI Capabilities

**Status: Improve existing Claude integration**

The POC includes AI-based explanations and developer interaction. The
target should provide a more complete AI security assistant.

  -----------------------------------------------------------------------
  Existing capability                 Required update
  ----------------------------------- -----------------------------------
  Vulnerability explanations          Add contextual risk analysis

  Fixed-version recommendations       Add upgrade impact analysis

  Interactive AI Q&A                  Add repository-aware security
                                      assistant

  AI remediation suggestions          Generate code-level remediation
                                      examples

  Developer challenges                Allow developers to question and
                                      review findings

  Claude integration                  Add a provider abstraction for
                                      Claude and GPT
  -----------------------------------------------------------------------

### Target AI capabilities

The AI assistant should be able to:

-   Explain why a vulnerability exists.
-   Explain potential impact on the application.
-   Recommend a safe fix.
-   Identify the affected file and dependency.
-   Explain whether an upgrade could introduce breaking changes.
-   Suggest code changes and remediation steps.
-   Help developers investigate and understand findings.
-   Summarize security posture for a repository or organisation.

### AI safety and trust requirements

-   Scanner findings remain the source of truth.
-   AI must not invent vulnerabilities or silently change scanner
    severity.
-   AI-generated conclusions must be clearly labelled.
-   AI should cite the relevant finding, file, package, or evidence
    used.
-   Repository content must be treated as untrusted input.
-   Protect against prompt injection in source files, README files,
    comments, and other repository content.
-   Do not send repository source code to an AI provider unless the user
    has explicitly enabled and consented to that processing.
-   Define retention, provider usage, and data-sharing policies.

------------------------------------------------------------------------

## 3.4 Dashboard and Frontend

**Status: Significant UI expansion**

The existing POC dashboard should evolve into a complete enterprise SaaS
interface.

### Required screens

#### 1. Security overview dashboard

-   Total vulnerabilities.
-   Critical, high, medium, and low findings.
-   Repository security status.
-   Overall risk score.
-   Vulnerability trends.
-   Recent scans and failed scans.
-   Remediation progress.

#### 2. Repository management

-   Connected Git providers.
-   Repository list.
-   Branch selection.
-   Repository security status.
-   Scan history.
-   Scan configuration.
-   Scheduled scan settings.

#### 3. Vulnerability management

-   Finding details.
-   Severity filters.
-   Affected files and packages.
-   Dependency paths.
-   Fix recommendations.
-   Finding assignment and status.
-   Suppression and review history.
-   Links to source advisories where available.

#### 4. AI security assistant

-   Ask questions about findings.
-   Explain vulnerabilities.
-   Generate remediation guidance.
-   Review proposed fixes.
-   Summarize repository security posture.

#### 5. Reporting and analytics

-   PDF and CSV reports.
-   Security summaries.
-   Historical comparisons.
-   Remediation metrics.
-   Compliance-oriented reporting where supported.

#### 6. Administration and settings

-   User profile and authentication settings.
-   Organisation settings.
-   Team management.
-   Roles and permissions.
-   Git provider connections.
-   Notifications.
-   Audit logs.
-   Billing and plan management, if commercial billing is in scope.

### UX requirements

-   Professional enterprise SaaS design.
-   Responsive desktop and mobile layouts.
-   Consistent design system and reusable components.
-   Clear severity and status indicators.
-   Search, sorting, filtering, and pagination for large finding lists.
-   Accessible interaction patterns.
-   Light and dark themes if required by the product design.

------------------------------------------------------------------------

## 3.5 Backend and Technology Architecture

**Status: Architecture recommendation**

The POC technology stack is described as React/Vite,
JavaScript/Node/Express, MongoDB, OSV, Semgrep, Gitleaks, Claude,
node-cron, Docker, and Render/Railway deployment.

For the target product, the recommended stack is:

  Layer                 POC technology      Recommended target
  --------------------- ------------------- ---------------------------------
  Frontend              React + Vite        Next.js + TypeScript
  Backend               Node.js + Express   Python + FastAPI
  Database              MongoDB             PostgreSQL
  Job processing        node-cron           Celery + Redis
  Scanner execution     Docker              Isolated Docker workers
  Dependency scanning   OSV                 Trivy + OSV
  SAST                  Semgrep             Semgrep
  Secrets               Gitleaks            Gitleaks
  IaC                   Not included        Checkov
  AI                    Claude              Claude/GPT provider abstraction
  Hosting               Render/Railway      Microsoft Azure

These are recommended changes, not a requirement to rewrite every
working component. Existing scanner integrations can be retained behind
adapters even if the backend is migrated.

### Suggested backend modules

-   Authentication and authorization.
-   Organisation and team management.
-   Git provider integration.
-   Repository management.
-   Scan orchestration.
-   Scanner adapters.
-   Finding normalization and deduplication.
-   AI analysis and remediation.
-   Reporting.
-   Notifications.
-   Audit logging.
-   Billing and plan management, if required.

------------------------------------------------------------------------

## 3.6 Database and Data Management

**Status: New architecture required**

The target product needs a structured data model that supports multiple
organisations and repositories.

### Recommended core entities

-   Users.
-   Organisations.
-   Teams.
-   Roles and permissions.
-   Git provider connections.
-   Repositories.
-   Repository branches.
-   Scan jobs.
-   Scan results.
-   Vulnerability findings.
-   Dependency packages.
-   Remediation recommendations.
-   AI analysis history.
-   Reports.
-   Audit logs.
-   Notifications.

### Data requirements

-   Every organisation's data must be isolated from other organisations.
-   Enforce authorization at the API and database-access layers.
-   Store repository credentials securely; do not store plaintext
    tokens.
-   Define data retention and deletion policies.
-   Track scan status, scanner versions, repository commit, and
    timestamps.
-   Keep source-code retention to the minimum necessary.
-   Separate raw scanner output from normalized findings and AI
    commentary.

------------------------------------------------------------------------

## 3.7 Security of VulnSight AI Itself

**Status: Mandatory -- do not postpone**

The platform will process untrusted source code, repositories, files,
and dependencies. The platform itself must therefore be secured as a
first-class product requirement.

  Security area          Required implementation
  ---------------------- ------------------------------------------------
  Application security   SAST and secure code review
  Dependency security    Scan our own dependencies
  Secret security        Gitleaks in CI/CD
  Container security     Scan Docker images
  IaC security           Scan Azure infrastructure configuration
  API security           Authentication, authorization, and API testing
  Repository security    SSRF protection and safe Git URL validation
  Worker security        Isolated, short-lived scanning environments
  Tenant security        Organisation-level data isolation
  AI security            Prompt-injection protection
  Credential security    Azure Key Vault and managed identities
  Deployment security    CI/CD security gates
  Monitoring             Security logs and alerts

### Threats to address

-   Malicious repositories and source files.
-   Server-side request forgery (SSRF).
-   Attempts to access cloud metadata endpoints or private network
    services.
-   Malicious package scripts and build steps.
-   Archive extraction path traversal.
-   Scanner or worker container escape.
-   Resource exhaustion and denial of service.
-   Credential leakage.
-   Cross-tenant data access.
-   Prompt injection through repository content.
-   Compromised dependencies and software supply-chain risks.

### Worker isolation requirements

-   Use short-lived scanning workers.
-   Restrict CPU, memory, disk, and execution time.
-   Restrict network access to only what is required.
-   Avoid running repository build or package scripts by default.
-   Use non-root execution and restricted container capabilities.
-   Use temporary workspaces and clean them after scans.
-   Do not expose application credentials to scanning jobs.
-   Validate and sanitize repository URLs and archive paths.

------------------------------------------------------------------------

## 4. Recommended Azure Deployment Architecture

**Status: Target deployment recommendation**

Azure Container Apps is a suitable initial deployment option. Consider
AKS later if workload scale, isolation requirements, or orchestration
complexity justify it.

``` text
                       Users / Developers
                               |
                               v
                     Frontend – Next.js
                     Azure Container Apps
                               |
                               v
                      Backend – FastAPI
                     Azure Container Apps
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
             Redis Queue                PostgreSQL
          Celery job broker          Application data
                 |
                 v
        Isolated Scanner Workers
       Trivy / Semgrep / Gitleaks
             / Checkov
                 |
        +--------+---------+
        |                  |
        v                  v
   Blob Storage        Key Vault
 Reports/artifacts   Secrets/credentials

 Supporting services:
 - Azure Container Registry
 - Managed identities
 - Azure Monitor
 - Application Insights
 - Private networking and controlled egress
```

### Azure components

  Component                       Purpose
  ------------------------------- -------------------------------------------
  Azure Container Apps            Host frontend, API, and worker services
  Azure Container Registry        Store application and scanner images
  Azure Database for PostgreSQL   Store application data
  Redis-compatible service        Queue and background job coordination
  Azure Blob Storage              Store reports and approved scan artifacts
  Azure Key Vault                 Protect secrets and credentials
  Managed identities              Secure service-to-service access
  Azure Monitor                   Infrastructure and application monitoring
  Application Insights            Application telemetry and diagnostics

The final design should account for network segmentation, controlled
outbound traffic, private endpoints where appropriate, backups,
recovery, and operational cost.

------------------------------------------------------------------------

## 5. Implementation Roadmap

Do not implement every capability in one release. Use phased delivery
and validate each phase.

### Phase 1 -- Strengthen the Existing POC

**Objective:** Establish a reliable scanning core.

-   [ ] Audit the existing source code and verify implemented features.
-   [ ] Improve dependency and transitive dependency detection.
-   [ ] Standardize vulnerability findings.
-   [ ] Improve Semgrep integration and rule coverage.
-   [ ] Improve Gitleaks integration and secret handling.
-   [ ] Improve AI explanations and remediation.
-   [ ] Add reliable scan history and reports.
-   [ ] Validate existing performance and accuracy claims with
    repeatable tests.

### Phase 2 -- Build the SaaS Foundation

**Objective:** Support hosted repository scanning and multiple users.

-   [ ] GitHub integration.
-   [ ] GitLab integration.
-   [ ] Bitbucket integration.
-   [ ] Public and private repository scanning.
-   [ ] User authentication.
-   [ ] Organisation and team management.
-   [ ] PostgreSQL data model.
-   [ ] API architecture.
-   [ ] Redis-based background scan orchestration.
-   [ ] Isolated scanner workers.
-   [ ] Secure Git credentials and repository access.

### Phase 3 -- Expand Security Scanning

**Objective:** Increase security coverage.

-   [ ] Trivy integration.
-   [ ] Container scanning.
-   [ ] IaC scanning with Checkov.
-   [ ] SBOM generation.
-   [ ] API security analysis.
-   [ ] Unified finding and risk engine.
-   [ ] Scanner version and provenance tracking.
-   [ ] Finding deduplication and correlation.

### Phase 4 -- Complete the Product Experience

**Objective:** Deliver a complete SaaS user experience.

-   [ ] Enterprise dashboard.
-   [ ] Repository management interface.
-   [ ] Vulnerability management interface.
-   [ ] AI security assistant.
-   [ ] Reports and analytics.
-   [ ] Team roles and permissions.
-   [ ] Notifications.
-   [ ] Audit logs.
-   [ ] Scheduled scans.
-   [ ] Continuous repository monitoring.

### Phase 5 -- Production Readiness

**Objective:** Secure, test, and operate the platform reliably.

-   [ ] Secure our own source code and infrastructure.
-   [ ] Add CI/CD security gates.
-   [ ] Test tenant isolation.
-   [ ] Test worker isolation.
-   [ ] Perform penetration testing.
-   [ ] Conduct performance and scalability testing.
-   [ ] Establish backup and recovery procedures.
-   [ ] Establish incident response and security monitoring.
-   [ ] Define data retention and deletion procedures.
-   [ ] Validate operational cost and capacity.

------------------------------------------------------------------------

## 6. Final Gap Analysis

  Component                        Required action
  -------------------------------- ------------------------------------------
  Dependency scanning              Improve
  Transitive dependency analysis   Retain and improve
  OSV integration                  Retain
  Semgrep                          Retain and expand
  Gitleaks                         Retain and expand
  Claude AI                        Upgrade to multi-provider AI abstraction
  Local scanning                   Retain as an option
  Git repository scanning          Build
  Private Git authentication       Build
  Trivy                            Add
  Checkov                          Add
  Unified vulnerability engine     Build
  SaaS dashboard                   Redesign and expand
  User authentication              Build or verify and strengthen
  Multi-tenancy and RBAC           Build
  Scan orchestration               Build
  Isolated scanning workers        Build
  Reporting                        Expand
  Continuous monitoring            Build
  Internal platform security       Build
  Azure deployment                 Build

------------------------------------------------------------------------

## 7. Recommended Product Architecture

Organize the target platform into four major modules.

### 1. Scanning Engine

Responsibilities:

-   Dependency scanning.
-   SAST.
-   Secret scanning.
-   Container scanning.
-   IaC scanning.
-   SBOM generation.
-   Scanner adapters.
-   Finding normalization.

### 2. Platform Backend

Responsibilities:

-   Git integrations.
-   Authentication and authorization.
-   Organisation and team management.
-   Repository management.
-   Scan orchestration.
-   Database and artifact management.
-   Notifications and audit logs.

### 3. AI Intelligence

Responsibilities:

-   Vulnerability explanations.
-   Contextual risk analysis.
-   Remediation recommendations.
-   Upgrade impact analysis.
-   Repository-aware security Q&A.
-   AI provider abstraction and safety controls.

### 4. Frontend

Responsibilities:

-   Security overview dashboard.
-   Repository management.
-   Scan configuration and progress.
-   Vulnerability findings.
-   AI assistant.
-   Reports and analytics.
-   Administration and settings.

------------------------------------------------------------------------

## 8. Recommended Decisions Before Development

The following decisions should be confirmed during technical discovery:

1.  **Source-code handling:** Will the hosted service retain repository
    source code temporarily, or should it delete the working copy
    immediately after each scan?
2.  **Git authentication:** Which Git providers are required for the
    first release?
3.  **Deployment model:** Is the first release multi-tenant SaaS only,
    or must it also support customer-hosted/self-hosted deployments?
4.  **AI data policy:** Can repository code be sent to an AI provider,
    and under what explicit user consent and retention settings?
5.  **Scan execution:** Which scanner types are required in the first
    production release?
6.  **Continuous monitoring:** Should scans be triggered by pull
    requests, pushes, schedules, or all three?
7.  **Commercial model:** Are billing, subscriptions, usage limits, and
    plan management required in the first release?

------------------------------------------------------------------------

## 9. Final Recommendation

The existing POC should become the **scanning-engine foundation** of
VulnSight AI. Build the SaaS platform around it rather than replacing
working components unnecessarily.

The recommended approach is:

1.  Audit the actual POC source code.
2.  Classify every feature as implemented, partially implemented,
    documented only, or missing.
3.  Preserve and improve the working scanner capabilities.
4.  Build the Git integration, SaaS backend, organisation model, and
    isolated worker architecture.
5.  Add container and IaC scanning.
6.  Build the enterprise frontend and AI security assistant.
7.  Secure VulnSight AI itself throughout development.
8.  Deploy and validate the platform in Azure.

**The next engineering deliverable should be a module-by-module V2
upgrade specification** mapping each existing POC component to its
target module, code changes, APIs, database changes, security controls,
tests, and implementation tasks. This will give the development team a
concrete execution blueprint while minimizing unnecessary rewrites.

------------------------------------------------------------------------

## 10. Source and Scope Note

This document consolidates the platform upgrade recommendations
discussed for VulnSight AI and the POC architecture/requirements
document supplied for review.

-   POC capabilities and stated scope should be verified against the
    actual implementation.
-   The target architecture, additional scanners, SaaS capabilities, and
    Azure deployment recommendations are proposed product upgrades.
-   Performance and accuracy targets should be validated through
    reproducible benchmarks; they should not be treated as achieved
    results without test evidence.
