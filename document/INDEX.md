# VulnSight AI — Master Documentation Index

> **Platform Version:** 1.0.0  
> **Documentation Release:** Enterprise Baseline  
> **Total Documents:** 39 Technical Specifications & Architectural Guides  
> **Storage Directory:** `document/`  

---

## Welcome to the VulnSight AI Documentation Suite

This folder contains the complete, authoritative documentation suite for **VulnSight AI**, generated from the codebase, test suites, infrastructure Bicep files, security probes, and architectural specifications.

Every document is cross-referenced, fully formatted with GitHub-style markdown, structured tables, KaTeX formulas, and Mermaid diagrams.

---

## Documentation Navigation Catalog

### Section 1: Executive, Strategy & Requirements
- **[01. Project Overview](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/01_PROJECT_OVERVIEW.md):** Executive summary, core value propositions, evolutionary milestones (CLI to SaaS), architectural principles, and document directory roadmap.
- **[02. Problem Statement & Business Objectives](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/02_PROBLEM_STATEMENT_AND_BUSINESS_OBJECTIVES.md):** Developer security fatigue, supply chain risks, business OKRs, MTTR metrics, and stakeholder value analysis.
- **[03. Product Requirements Document (PRD)](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/03_PRODUCT_REQUIREMENTS_DOCUMENT.md):** Personas, functional requirements (Auth, Scans, Triage, AI, Reporting), non-functional requirements (Performance, Security, BCDR), and traceability matrix.

### Section 2: Architecture & System Design
- **[04. High-Level Architecture (HLD)](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/04_HIGH_LEVEL_ARCHITECTURE.md):** Tiered system topology, trust boundaries, multi-tenancy model, and cloud service perimeter.
- **[05. Low-Level Architecture (LLD)](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/05_LOW_LEVEL_ARCHITECTURE.md):** Modular codebase breakdown, async `scrypt` thread pool queue, SSRF DNS pinning, single-use grants authority, and finding fingerprinting formulas.
- **[06. Solution Architecture Diagram](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/06_SOLUTION_ARCHITECTURE_DIAGRAM.md):** High-level solution topology, end-to-end communication links, structural class diagrams, and operational characteristics.
- **[07. System Component Diagram](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/07_SYSTEM_COMPONENT_DIAGRAM.md):** Component boundaries across Web Frontend, API Server, Domain Services, Scanner Adapters, AI Gateway, and Storage.
- **[08. End-to-End Data Flow Diagram](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/08_END_TO_END_DATA_FLOW_DIAGRAM.md):** Data lifecycle across in-transit, ephemeral workspace, and encrypted-at-rest states; zero-source retention policy.
- **[09. Repository Scanning Workflow](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/09_REPOSITORY_SCANNING_WORKFLOW.md):** Ten-stage scanning pipeline from trigger, SSRF check, grant issuance, clone, symlink purge, to deduplication and scoring.
- **[10. Sequence Diagrams](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/10_SEQUENCE_DIAGRAMS.md):** Mermaid sequence diagrams for user scans, webhooks, single-use grant redemption, AI analysis, and finding triage.

### Section 3: Technology, Schema & APIs
- **[11. Technology Stack](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/11_TECHNOLOGY_STACK.md):** Pure Node.js runtime, zero-dependency core, scanner ecosystem, cloud PaaS services, and dependency audit.
- **[12. Database Schema & ER Diagram](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/12_DATABASE_SCHEMA_AND_ER_DIAGRAM.md):** Relational ER diagram, 18 table specifications, indexes, foreign key actions, and PostgreSQL migration path.
- **[13. API Documentation](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/13_API_DOCUMENTATION.md):** Complete REST API reference covering Auth, Orgs, Teams, Git Connections, Repositories, Scans, Triage, AI, and Webhooks.

### Section 4: Cloud, Infrastructure & Network Architecture
- **[14. Azure Cloud Architecture](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/14_AZURE_CLOUD_ARCHITECTURE.md):** Azure Container Apps, Container Apps Jobs, Key Vault, ACR Premium, Private Endpoints, and Managed Identities.
- **[15. Infrastructure Architecture](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/15_INFRASTRUCTURE_ARCHITECTURE.md):** Bicep IaC modules (`main.bicep`, `subscription.bicep`), compute sizing, autoscaling, and cost optimization.
- **[16. Network Architecture](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/16_NETWORK_ARCHITECTURE.md):** Virtual Network topology (`10.40.0.0/16`), 4 subnets, NSG default-deny outbound rules, and CONNECT-only forward proxy.
- **[17. Security Architecture](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/17_SECURITY_ARCHITECTURE.md):** 5-layer defense-in-depth model, cryptographic subsystems (AES-256-GCM, scrypt), CSP headers, and controls matrix.
- **[18. Threat Model (STRIDE)](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/18_THREAT_MODEL.md):** STRIDE threat vectors, attack scenarios, security mitigations, and residual risk assessment.

### Section 5: Security Assessments & Scanner Integration
- **[19. Vulnerability Assessment Report (VAPT)](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/19_VULNERABILITY_ASSESSMENT_REPORT_VAPT.md):** Automated security probe results (26/26 checks passed) and headless Edge stored XSS probe (13/13 views passed).
- **[20. Security Hardening Report](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/20_SECURITY_HARDENING_REPORT.md):** Linux container hardening (`--cap-drop ALL`, read-only root, UID 10001), process limits, and database hardening.
- **[21. AI Architecture & Workflow](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/21_AI_ARCHITECTURE_AND_WORKFLOW.md):** Ground truth invariance, prompt injection regex screening (`INJECTION_PATTERNS`), consent gating, and upgrade risk calculator.
- **[22. Scanner Integration Architecture](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/22_SCANNER_INTEGRATION_ARCHITECTURE.md):** Adapter contracts for OSV.dev, Semgrep, Gitleaks, Trivy, Checkov, fault isolation, and deduplication logic.
- **[23. Docker Sandbox Architecture](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/23_DOCKER_SANDBOX_ARCHITECTURE.md):** Self-hosted Docker sandbox, `setup-egress.sh`, internal bridge network, and fail-closed egress requirements.

### Section 6: CI/CD, Testing & Performance Reports
- **[24. CI/CD Pipeline](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/24_CICD_PIPELINE.md):** GitHub Actions workflows, multi-version Node.js matrix, self-scanning, Bicep compilation, and image building.
- **[25. Test Strategy & Test Cases](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/25_TEST_STRATEGY_AND_TEST_CASES.md):** Verification tiers (Verified, Partially Verified, Unverified), test suites breakdown, and high-priority test cases.
- **[26. Test Execution Report](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/26_TEST_EXECUTION_REPORT.md):** Official test execution report: 142 total tests, 131 passed, 11 skipped, 0 failed, 3.33s duration.
- **[27. Scanner Validation Report](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/27_SCANNER_VALIDATION_REPORT.md):** Validation against OWASP NodeGoat (91 real findings), Semgrep fixtures, Gitleaks redaction, and Trivy/Checkov IaC rules.
- **[28. Performance & Load Testing Report](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/28_PERFORMANCE_AND_LOAD_TESTING_REPORT.md):** Benchmark results: 1,050 req/s, 0 errors, median read latency 7.6 ms, $p_{95}$ latency 18.9 ms.

### Section 7: Deployment, Operations & Disaster Recovery
- **[29. Deployment Architecture & Guide](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/29_DEPLOYMENT_ARCHITECTURE_AND_GUIDE.md):** Step-by-step deployment guide for Azure Bicep, on-premise Docker, and developer environments.
- **[30. Monitoring & Logging Architecture](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/30_MONITORING_AND_LOGGING_ARCHITECTURE.md):** Structured JSON logging schemas, Log Analytics integration, alert rules (proxy denials, brute force), and health probes.
- **[31. Backup & Disaster Recovery Plan](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/31_BACKUP_AND_DISASTER_RECOVERY_PLAN.md):** BCDR SLAs (RPO $\le 24\text{h}$, RTO $\le 4\text{h}$), online non-blocking `VACUUM INTO` backups, and emergency incident tooling.
- **[32. Feature Completion & Gap Analysis](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/32_FEATURE_COMPLETION_AND_GAP_ANALYSIS.md):** Comparison between Platform Upgrade Specification and implemented codebase; architectural deviation analysis.
- **[33. Known Issues & Limitations](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/33_KNOWN_ISSUES_AND_LIMITATIONS.md):** Transparent disclosure of single-node SQLite constraint, untested live Azure NSG rules, and brute-force lockout tradeoffs.

### Section 8: Roadmap, Governance & Manuals
- **[34. Project Roadmap](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/34_PROJECT_ROADMAP.md):** Multi-year roadmap across Phase 1 (Core), Phase 2 (Azure & Postgres), Phase 3 (PR Autofix & SSO), and Phase 4 (DAST & IDE).
- **[35. Future Enhancements](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/35_FUTURE_ENHANCEMENTS.md):** Detailed technical specifications for PR Autofix Bot, Continuous SBOM Diffing, and ML False Positive Suppression.
- **[36. Live Product Demonstration](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/36_LIVE_PRODUCT_DEMONSTRATION.md):** End-to-end demonstration script and scenario for executive and customer presentations.
- **[37. User Guide](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/37_USER_GUIDE.md):** Comprehensive developer manual for navigating dashboards, managing repos, triaging findings, and querying the AI Assistant.
- **[38. Administrator Guide](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/38_ADMINISTRATOR_GUIDE.md):** Platform operations manual for managing organization policies, RBAC roles, Git integrations, and CLI drills.
- **[39. Production Readiness Assessment](file:///c:/Users/DELL/Desktop/VulnSight%20AI/document/39_PRODUCTION_READINESS_ASSESSMENT.md):** Dimensional evaluation scorecard (Conditional Go), pre-production blockers checklist, and sign-off criteria.
