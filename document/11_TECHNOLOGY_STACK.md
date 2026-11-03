# Technology Stack

> **Document ID:** VS-DOC-11  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Engineering Leadership, Full-Stack Developers, Cloud Architects  

---

## 1. Executive Summary & Design Philosophy

The VulnSight AI platform is built on a deliberate architectural philosophy: **Zero External Runtime Dependencies for the Core Control Plane.**

By intentionally relying exclusively on standard runtime capabilities provided by modern Node.js, the platform virtually eliminates third-party supply chain risks, dependency rot, licensing incompatibilities, and high runtime overhead.

```
+-----------------------------------------------------------------------------------+
|                        VulnSight AI Technology Stack                              |
+-----------------------------------------------------------------------------------+
|  Runtime Environment   | Node.js 18.x LTS / 20.x LTS / 22.x+ (Tested on v24.19)   |
|  Language Core         | Modern Vanilla ECMAScript (ES2022+ / CommonJS + ESM)     |
|  Database Engine       | Native node:sqlite (SQLiteSync WAL) -> PostgreSQL Ready   |
|  Network & Ingress     | node:http, node:net, node:dns (Zero HTTP frameworks)      |
|  Cryptography & Auth   | node:crypto (AES-256-GCM, async scrypt, SHA-256)         |
|  Security Scanners     | OSV.dev, Semgrep 1.183+, Gitleaks 8.21+, Trivy, Checkov  |
|  AI Providers          | Anthropic Claude 3.5 Sonnet & OpenAI GPT-4o REST APIs    |
|  Cloud Infrastructure  | Azure Container Apps, ACA Jobs, Bicep, Key Vault, ACR    |
|  Frontend Client       | Vanilla JS (ES Modules), Custom CSS Design System        |
+-----------------------------------------------------------------------------------+
```

---

## 2. Comprehensive Layer Breakdown

### 2.1 Backend Runtime & Core Services

| Component | Technology Selected | Version / Specification | Rationale & Advantage |
| :--- | :--- | :--- | :--- |
| **Execution Runtime** | **Node.js** | `>= 18.0.0` (22.5+ for native SQLite) | Event-driven, non-blocking I/O ideal for API gateways and high-concurrency request routing. |
| **Storage Engine** | **SQLite via `node:sqlite`** | Native `DatabaseSync` in Node.js | Zero database daemon overhead, file-based portability, WAL mode support, seamless migration path to PostgreSQL. |
| **HTTP Gateway** | **`node:http`** | Standard Library | Zero dependency vulnerability footprint; custom lightweight router with path regex caching. |
| **Network & DNS** | **`node:net`, `node:dns`** | Standard Library | Direct socket-level CONNECT proxy implementation; authoritative DNS resolution for SSRF defense. |
| **Cryptography Subsystem**| **`node:crypto`** | Standard Library | Hardware-accelerated AES-256-GCM, scrypt password hashing on worker threads, constant-time comparisons. |
| **Process Orchestration**| **`node:child_process`** | Standard Library | Safe process spawning (`shell: false`) eliminating command-injection surfaces. |

### 2.2 Security Scanner Suite

| Scanner Engine | Version Verified | Scanner Category | Role & Detection Focus |
| :--- | :--- | :--- | :--- |
| **OSV.dev API** | Live REST v1 | Software Composition Analysis (SCA) | Direct and transitive vulnerabilities in npm, PyPI, Yarn, Pnpm, and Go modules. |
| **Semgrep OSS** | `1.183.0` | Static Application Security Testing (SAST) | AST-based code analysis detecting injection flaws, XSS, insecure cryptography, and OWASP Top 10 risks. |
| **Gitleaks** | `8.21.2` | Secret & Credential Detection | High-speed regex and entropy scanning targeting hardcoded API keys, tokens, and private certificates. |
| **Trivy** | `0.76.1` | Container & Filesystem Scanning | Base OS package vulnerabilities and container image misconfigurations. |
| **Checkov** | `3.4.3` | Infrastructure-as-Code (IaC) | Static analysis for Terraform, CloudFormation, Kubernetes, and Dockerfile misconfigurations. |

### 2.3 Artificial Intelligence Gateway

| Provider / Model | Integration Method | Security Boundary & Controls |
| :--- | :--- | :--- |
| **Anthropic Claude 3.5 Sonnet** | HTTPS REST API (`/v1/messages`) | System prompt enforcement, injection regex screening, `<untrusted>` tagging, code evidence consent gate. |
| **OpenAI GPT-4o** | HTTPS REST API (`/v1/chat/completions`) | Parameterized context injection, zero secret transmission, deterministic upgrade impact calculation fallback. |
| **Mock Provider** | In-Memory Deterministic Stub | Used for automated integration test suites and offline environments. |

### 2.4 Cloud Infrastructure & Azure Architecture

| Cloud Resource | Azure Service Name | Configuration / SKU |
| :--- | :--- | :--- |
| **Control Plane API** | **Azure Container Apps** | Consumption / Dedicated, User-Assigned Managed Identity, HTTPS Ingress. |
| **Scan Execution** | **Azure Container Apps Jobs** | Consumption Job, triggered per scan execution with custom environment overrides. |
| **Secret Management** | **Azure Key Vault** | Standard SKU, RBAC Authorization, Soft Delete & Purge Protection enabled. |
| **Image Registry** | **Azure Container Registry** | Premium SKU (enabling Private Endpoints for isolated subnets). |
| **Result Staging** | **Azure Blob Storage** | Standard LRS, TLS 1.3 enforced, private container access via Managed Identity. |
| **Infrastructure as Code**| **Azure Bicep** | Modular Bicep (`main.bicep`, `subscription.bicep`) compiling with Bicep CLI 0.48+. |
| **Telemetry & Logs** | **Azure Monitor & Log Analytics** | PerGB2018 SKU, structured JSON log ingestion, Application Insights integration. |

### 2.5 Frontend Web Architecture

| Category | Technology | Characteristics & Details |
| :--- | :--- | :--- |
| **Architecture** | **Single Page Application (SPA)** | Client-side routing via hash navigation (`#/overview`, `#/repos`, etc.). |
| **Rendering Model** | **Pure DOM Building** | Custom `h(tag, props, children)` helper; 100% `textContent` rendering; zero `innerHTML`. |
| **Styling & Design System**| **Custom CSS3** | CSS Custom Properties (Variables), Responsive CSS Grid & Flexbox, Light and Dark themes. |
| **Build Pipeline** | **Zero Build Step** | Native ECMAScript Modules (`import` / `export`); no Webpack, Vite, Babel, or transpilations. |

---

## 3. Dependency Footprint Audit

A comprehensive review of `package.json` reveals the minimal footprint:

```json
{
  "name": "vulnsight-ai",
  "version": "0.1.0",
  "description": "Open-source dependency vulnerability scanner for npm and Python projects, powered by OSV.dev",
  "license": "MIT",
  "bin": {
    "vulnsight": "bin/vulnsight.js"
  },
  "engines": {
    "node": ">=18"
  },
  "dependencies": {
    "mongodb": "^7.8.0"
  }
}
```

> [!NOTE]
> `mongodb` is defined as an optional driver for teams migrating to document storage; the core platform runs completely dependency-free using the native Node.js runtime and `node:sqlite`.
