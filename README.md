# 🛡️ VulnSight-AI

> A high-performance, open-source Software Composition Analysis (SCA) dependency vulnerability scanner for npm projects using Google's **OSV.dev** database.

[![Tests](https://img.shields.io/badge/tests-11%20passed-brightgreen.svg)]()
[![Node](https://img.shields.io/badge/node-%3E%3D20.0.0-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

---

## 🚀 Overview

**VulnSight-AI** (`vulnsight`) inspects an npm project's dependency manifest (`package.json` + `package-lock.json`), queries live vulnerability data from **OSV.dev** in high-efficiency batches, detects both direct and transitive vulnerabilities, calculates CVSS 3.1 severities, and recommends fixed versions.

Built in accordance with the **Implementation Plan — Vulnerability Scanner Build** specification.

---

## ⚡ Quick Start

```bash
# Clone and install dependencies
npm install

# Run automated test suite
npm test

# Scan the included vulnerable test fixture
npm run scan:vulnerable

# Scan the included clean test fixture
npm run scan:clean

# Scan any target project folder
node bin/scanner.js /path/to/any/npm-project
```

---

## 📖 CLI Usage

```text
USAGE:
  vuln-scanner [target-path] [options]

ARGUMENTS:
  target-path               Directory containing package.json (default: ".")

OPTIONS:
  --fail-on <level>         Fail (exit code 1) if vulnerabilities meet or exceed this level:
                            critical, high, medium, low, none (default: low)
  --no-dev                  Exclude devDependencies from scan
  --format <format>         Output report format: console, json, markdown (default: console)
  --output, -o <file>       Write report to specified file path
  --timeout <ms>            OSV HTTP request timeout in milliseconds (default: 15000)
  --version, -v             Print version information and exit
  --help, -h                Show help message
```

---

## 💡 Key Features

- **Transitive Dependency Detection**: Full lockfile resolution supporting npm lockfile **v1, v2, and v3** specifications.
- **OSV.dev Batch Querying**: Batch queries via `/v1/querybatch` scan hundreds of dependencies in a single HTTP request.
- **Precision Semver Matching**: Evaluates `[introduced, fixed)` and `[introduced, last_affected]` ranges to prevent false positives.
- **CVSS 3.1 Scoring Engine**: Mathematical Base Score computation directly from CVSS vectors.
- **Actionable Remediation**: Identifies the minimal safe upgrade version (`Upgrade to >= X.Y.Z`).
- **CI/CD Ready**: Deterministic exit codes (`0` for clean, `1` for threshold breach) and JSON/Markdown report exports.

---

## 📁 Repository Structure

```text
├── bin/
│   └── scanner.js                  # CLI binary executable
├── src/
│   ├── manifest/
│   │   └── parser.js               # package.json & package-lock.json parser (v1, v2, v3)
│   ├── osv/
│   │   └── client.js               # OSV REST API client with batching & caching
│   ├── matcher/
│   │   └── matcher.js              # Semver range evaluator & fix resolver
│   ├── scoring/
│   │   └── severity.js             # CVSS 3.1 base score engine & thresholds
│   ├── reporter/
│   │   ├── console.js              # Color-coded terminal UI
│   │   ├── json.js                 # Machine-readable JSON output
│   │   └── markdown.js             # PR & CI markdown summary
│   ├── scanner.js                  # Core scan orchestrator
│   └── cli.js                      # CLI arguments & controller
├── test-fixtures/
│   ├── vulnerable-npm-project/     # Test project with known CVEs
│   └── clean-npm-project/          # Test project with clean dependencies
├── tests/                          # 11 Automated unit and integration tests
├── docs/
│   ├── BRIEF_RESEARCH_SUMMARY.md   # Executive research & market comparison
│   ├── DETAILED_TECHNICAL_REPORT.md# Architectural specification & algorithms
│   └── TESTING_AND_DEMO_GUIDE.md   # Team presentation & demonstration guide
└── package.json
```

---

## 📄 Reports & Documentation

- [Executive Research Summary](docs/BRIEF_RESEARCH_SUMMARY.md)
- [Detailed Technical Architecture Report](docs/DETAILED_TECHNICAL_REPORT.md)
- [Testing & Demonstration Guide](docs/TESTING_AND_DEMO_GUIDE.md)
