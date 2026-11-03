# Executive Research Summary: Dependency Vulnerability Scanner (SCA POC)

**Date**: November 2, 2026  
**Author**: Engineering Team  
**Scope**: Software Composition Analysis (SCA) Proof-of-Concept for npm Projects  
**Target Category**: Open-source dependency security auditor (Snyk / Dependabot / Trivy equivalent)

---

## 1. Executive Summary

Modern software applications rely heavily on open-source packages—often consisting of 80% to 90% third-party code. While open source accelerates development, unpatched dependencies expose organizations to critical vulnerabilities including Remote Code Execution (RCE), Prototype Pollution, and Denial of Service (DoS).

To address this risk in-house, we designed and implemented **`vuln-scanner`**: a fast, zero-credential Software Composition Analysis (SCA) CLI tool. It inspects project dependency manifests (`package.json` and `package-lock.json`), queries Google’s public **OSV.dev** (Open Source Vulnerabilities) database in high-efficiency batches, matches installed versions against known vulnerable ranges, and provides actionable remediation guidance.

```
┌─────────────────┐     ┌───────────────────────┐     ┌────────────────────────┐
│  package.json   │ ──> │   Manifest Parser     │ ──> │  OSV.dev Batch Client  │
│package-lock.json│     │ (Direct + Transitive) │     │   (/v1/querybatch)     │
└─────────────────┘     └───────────────────────┘     └───────────┬────────────┘
                                                                  │
┌─────────────────┐     ┌───────────────────────┐                 │
│   Exit Codes    │ <── │ Severity & Reporting  │ <───────────────┘
│  (0=Pass, 1=Fail)     │ (Console/JSON/MD)     │
└─────────────────┘     └───────────────────────┘
```

---

## 2. Market Context: Snyk vs. Open-Source OSV Architecture

| Capability | Commercial SCA (e.g., Snyk) | Our POC (`vuln-scanner` + OSV.dev) |
|---|---|---|
| **Data Source** | Proprietary Intel + NVD + GitHub Advisories | OSV.dev (Google, OpenSSF, GitHub Advisories, NVD, RustSec, PyPA) |
| **API Authentication** | API Token Required (per seat / rate limited) | Open Access (No API key, no per-seat licensing fees) |
| **Lockfile Support** | npm, yarn, pnpm, pip, maven, etc. | npm (v1, v2, v3 lockfiles supported in POC; modular for PyPI/Go) |
| **Transitive Resolution** | Full lockfile graph | Full lockfile graph with dependency path attribution |
| **Query Performance** | Single or proprietary batch API | HTTP batching (`/v1/querybatch`) up to 500 dependencies/call |
| **CI Integration** | Native CLI + webhook integrations | Native CLI with exit codes (0/1), `--fail-on`, and JSON/Markdown outputs |
| **Remediation Advice** | Automated PRs / suggested upgrade version | Calculated minimum safe version (`fixedVersion`) per advisory |

---

## 3. Key Findings on Test Fixtures

We evaluated the scanner against both vulnerable and clean npm test fixtures:

### A. Vulnerable Test Fixture (`test-fixtures/vulnerable-npm-project`)
- **Direct Dependencies**: `lodash@4.17.15`, `minimist@1.2.0`, `express@4.16.4`
- **Transitive Dependencies**: `qs@6.5.2` (introduced via `express`)
- **Scan Result**: **13 vulnerabilities detected**
  - **1 Critical**: `minimist@1.2.0` (CVSS 9.8, Prototype Pollution CVE-2021-44906)
  - **4 High**: `lodash@4.17.15` (Command Injection CVE-2021-23337, Prototype Pollution CVE-2020-8203) & `qs@6.5.2` (Prototype Pollution CVE-2022-24999)
  - **7 Medium**: ReDoS, Open Redirect, and memory exhaustion DoS
  - **1 Low**: Express redirect XSS
- **Remediation**: Correctly identified minimum safe upgrade targets (e.g. `minimist >= 1.2.6`, `lodash >= 4.17.21`, `qs >= 6.5.3`).
- **Pipeline Decision**: Triggered exit code `1` under default `--fail-on low` threshold.

### B. Clean Test Fixture (`test-fixtures/clean-npm-project`)
- **Dependencies**: Modern pinned packages (`semver@7.7.1`, `picocolors@1.1.1`)
- **Scan Result**: **0 vulnerabilities**
- **Scan Duration**: **~0.5 seconds**
- **Pipeline Decision**: Clean exit code `0`.

---

## 4. Definition of Done Checklist

| Requirement | Status | Verification Method |
|---|---|---|
| CLI scans an npm project given its path | **Complete** | `node bin/scanner.js <path>` |
| Transitive dependencies included in scan | **Complete** | Tested on `qs@6.5.2` via `express` |
| Known CVE correctly detected on sample project | **Complete** | Verified detection of CVE-2021-44906, CVE-2021-23337 |
| Report includes severity, affected package, and fixed version | **Complete** | Formatted in Console, JSON, and Markdown |
| Clean exit code (0) vs failure exit code (1) | **Complete** | Automated in test suite & CLI flags |
| Automated test suite passing | **Complete** | `npm test` runs 11/11 passing tests |
| Research summary and technical report delivered | **Complete** | Documented in `docs/` and brain artifacts |

---

## 5. Strategic Recommendations & Roadmap

1. **Phase 2 — Multi-Ecosystem Support**: Extend `src/manifest/parser.js` to support Python (`requirements.txt`, `Pipfile.lock`, `poetry.lock`) and Go (`go.mod`, `go.sum`).
2. **Phase 3 — Local Caching & Offline DB**: Download OSV zip dumps for offline or air-gapped CI/CD environments.
3. **Phase 4 — Automated Remediation**: Add a `--fix` flag that runs `npm install <package>@<fixedVersion>` automatically.
