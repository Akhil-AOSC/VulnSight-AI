# Solution Architecture Diagram

> **Document ID:** VS-DOC-06  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Solution Architects, Technical Leads, DevOps Specialists, Security Auditors  

---

## 1. High-Level Solution Topology

VulnSight AI operates as an integrated software security solution connecting web users, automated CI/CD webhooks, isolated cloud compute, and external vulnerability intelligence services.

```mermaid
graph TB
    subgraph UserTier ["Presentation & User Ingress Tier"]
        UI["Web SPA Dashboard<br/>(Vanilla JS / Responsive CSS)"]
        CLI["VulnSight CLI / CI Workflows"]
        GitWebhook["Git Provider Webhooks<br/>(GitHub / GitLab / Bitbucket)"]
    end

    subgraph SecurityBoundary ["Security Gateway & Ingress"]
        WAF["Web Application Firewall / Load Balancer"]
        TLS["TLS 1.3 Termination<br/>(HSTS / Strict CSP / No Cookies)"]
    end

    subgraph ControlPlane ["Platform Control Plane (Azure Container App)"]
        Router["HTTP Router & Rate Limiter<br/>(src/platform/api.js)"]
        AuthModule["Auth & scrypt Hash Queue<br/>(src/platform/crypto.js)"]
        RBAC["RBAC & Tenant Scoping<br/>(src/platform/rbac.js)"]
        ServiceLayer["Domain Services Orchestrator<br/>(src/platform/service.js)"]
        Queue["Background Task Queue<br/>(src/platform/queue.js)"]
        GrantManager["Single-Use Credential Authority<br/>(scan_grants engine)"]
        AIGateway["Governed AI Gateway<br/>(src/ai/assistant.js)"]
        ExportEngine["Compliance & SBOM Export<br/>(src/reports/export.js)"]
    end

    subgraph PersistenceTier ["Persistence & Secrets Management"]
        DB[(Platform Database<br/>SQLite WAL / PostgreSQL)]
        KeyVault["Azure Key Vault<br/>(Master Key / SecretBox)"]
        BlobStorage["Azure Blob Storage<br/>(Temporary Scan Results Container)"]
    end

    subgraph IsolationZone ["Sandboxed Execution Plane (Azure Container Apps Jobs)"]
        JobOrchestrator["ACA Job Executor<br/>(src/platform/aca.js)"]
        WorkerPod["Hardened Worker Container<br/>(Unprivileged UID 10001, Read-Only Root)"]
        Workspace["Ephemeral RAM/Disk Workspace<br/>(Symlinks Stripped, Size Capped)"]
        ScannerSuite["Scanner Adapters:<br/>SCA (OSV) | Semgrep | Gitleaks | Trivy | Checkov"]
        EgressProxy["CONNECT-only Egress Proxy<br/>(Port 443 Only, DNS Pinning)"]
    end

    subgraph ExternalEcosystem ["External Services & APIs"]
        GitHosts["Git Remotes<br/>(github.com, gitlab.com, bitbucket.org)"]
        OSV["Google OSV.dev REST API"]
        LLMs["Anthropic Claude / OpenAI GPT-4o"]
    end

    UI -->|HTTPS / Bearer Auth| WAF
    CLI -->|REST API Calls| WAF
    GitWebhook -->|HMAC Verified POST| WAF
    WAF --> TLS
    TLS --> Router

    Router --> AuthModule
    Router --> RBAC
    RBAC --> ServiceLayer
    ServiceLayer --> Queue
    ServiceLayer --> DB
    ServiceLayer --> KeyVault
    ServiceLayer --> GrantManager
    ServiceLayer --> AIGateway
    ServiceLayer --> ExportEngine

    Queue -->|Dispatch Job Execution| JobOrchestrator
    JobOrchestrator -->|Trigger Job with Env & Grant Secret| WorkerPod
    WorkerPod -->|Redeem Secret for Temporary Token| GrantManager
    WorkerPod -->|Clone Repository over HTTPS| GitHosts
    WorkerPod -->|Mount and Sanitize Workspace| Workspace
    WorkerPod -->|Execute Scanners in Parallel| ScannerSuite
    ScannerSuite -->|Query Batch Vulnerabilities via Proxy| EgressProxy
    EgressProxy -->|Allowlisted Hostnames Only| OSV
    ScannerSuite -->|Write Unified Output| BlobStorage
    JobOrchestrator -->|Read Staged Result & Purge Blob| BlobStorage
    JobOrchestrator -->|Normalize & Ingest Findings| ServiceLayer

    AIGateway -->|Sanitized Prompt & Injection Check| LLMs
```

---

## 2. Communication Protocols & Boundaries

| Communication Link | Source Component | Destination Component | Protocol / Port | Security Mechanisms |
| :--- | :--- | :--- | :--- | :--- |
| **User Ingress** | Browser / Client | Ingress Gateway | HTTPS / 443 | TLS 1.3, Strict CSP, No-Cookie Bearer Tokens. |
| **API to DB** | Service Layer | Relational DB | Native IPC / TCP (5432) | WAL Mode, Parameterized Prepared Statements. |
| **API to Key Vault** | Service Layer | Azure Key Vault | HTTPS / 443 | User-Assigned Managed Identity, RBAC. |
| **Worker Dispatch** | Job Orchestrator | Azure ARM API | HTTPS / 443 | `Container Apps Jobs Operator` role identity. |
| **Grant Redemption** | Worker Pod | API Control Plane | HTTPS / 443 | One-time secret, SHA-256 match, 10-min TTL. |
| **Worker Egress** | Worker Container | Egress Proxy | HTTP CONNECT / 3128 | Internal VNet route, Hostname Allowlist, DNS Pinning. |
| **Proxy Outbound** | Egress Proxy | External APIs | TLS / 443 | Strict FQDN checking, private IP refusal. |
| **AI Query** | AI Gateway | Anthropic / OpenAI | HTTPS / 443 | Zero secret transmission, `<untrusted>` tagging. |

---

## 3. Structural Decomposition

```mermaid
classDiagram
    class VulnSightPlatform {
        +startPlatform(config)
        +handleRequest(req, res)
    }

    class ServiceLayer {
        +authService
        +orgService
        +repoService
        +scanService
        +findingService
        +aiService
        +exportService
    }

    class ExecutionEngine {
        <<interface>>
        +executeScan(scanParams)
    }

    class AcaExecutor {
        +createAzureIdentity()
        +execute()
        +pollJobStatus()
    }

    class DockerExecutor {
        +dockerArgs()
        +runSandboxed()
    }

    class ScannerSuite {
        +scanTarget()
        +runAdapters()
    }

    class StorageEngine {
        +openDatabase()
        +executeMigrations()
        +prepareStatements()
    }

    VulnSightPlatform --> ServiceLayer
    VulnSightPlatform --> StorageEngine
    ServiceLayer --> ExecutionEngine
    ExecutionEngine <|.. AcaExecutor
    ExecutionEngine <|.. DockerExecutor
    AcaExecutor --> ScannerSuite
    DockerExecutor --> ScannerSuite
```

---

## 4. Key Operational Characteristics

1. **Decoupled Job Lifecycle:** The API Control Plane never executes scanners inside its own Node.js runtime process. Scans are dispatched asynchronously to dedicated worker containers, ensuring that memory leaks, native crashes, or infinite loops caused by malicious codebases cannot destabilize the management server.
2. **Deterministic Data Flow:** Every scan produces an immutable, point-in-time snapshot of findings stored in `scans` and `findings` tables. Finding triage modifications are tracked separately in `finding_states` and `finding_reviews`, preserving historical integrity across subsequent scans.
3. **Resilient Network Confinement:** Workers operate inside a closed loop. If an adversary attempts to connect back to their command-and-control server or pivot laterally to instance metadata (`169.254.169.254`), the Network Security Group drops direct packets, and the egress proxy terminates unauthorized CONNECT tunnels immediately.
