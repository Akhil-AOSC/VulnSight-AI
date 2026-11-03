# Detailed Technical Architecture & Implementation Report: vuln-scanner

**Document Version**: 1.0.0  
**Project**: Dependency Vulnerability Scanner (SCA POC)  
**Date**: November 2, 2026  
**Status**: Ready for Code Review & Sign-Off  

---

## 1. Architectural Overview

`vuln-scanner` is designed around a modular, decoupled pipeline architecture:

```
[Target Project Folder]
        │
        ▼
1. Manifest Parser (src/manifest/parser.js)
   ├── package.json (Direct dependencies)
   └── package-lock.json (Lockfile v1, v2, v3 resolver)
        │
        ▼
   Normalized Dependency Graph: Array<{ name, version, isDirect, dependencyChain }>
        │
        ▼
2. OSV Client (src/osv/client.js)
   ├── Chunk dependencies into 500-item batches
   ├── POST /v1/querybatch (Bulk candidate discovery)
   └── GET /v1/vulns/{id} (Concurrency-limited detail retrieval + in-memory cache)
        │
        ▼
3. Semver Range Matcher (src/matcher/matcher.js)
   ├── Range parsing: [introduced, fixed), [introduced, last_affected]
   ├── Semver loose cleanup & coercion
   └── Fixed version resolver (calculates optimal upgrade target)
        │
        ▼
4. Severity & Scoring Engine (src/scoring/severity.js)
   ├── CVSS 3.1 Base Score calculator from vector string
   ├── Severity level normalization (CRITICAL, HIGH, MEDIUM, LOW)
   └── Severity ranking and fail-threshold comparator
        │
        ▼
5. Reporting & Presentation (src/reporter/*)
   ├── Console Reporter (picocolors terminal table & summary cards)
   ├── JSON Reporter (machine-readable CI/CD payload)
   └── Markdown Reporter (GitHub / GitLab PR comments)
        │
        ▼
6. CLI Process Controller (src/cli.js & bin/scanner.js)
   └── Process exit code: 0 (Clean / Below Threshold) | 1 (Threshold Breached) | 2 (Fatal Error)
```

---

## 2. Manifest & Lockfile Parser Internals (`src/manifest/parser.js`)

A common limitation in naive vulnerability scanners is only scanning direct dependencies listed in `package.json`. In reality, over 70% of vulnerabilities reside in **transitive** (nested) dependencies.

Our parser supports all three major iterations of the npm lockfile specification:

### 2.1. npm Lockfile v2 & v3 (`packages` map)
Modern npm versions store dependencies in a flattened map under `packages`.
- Root package is keyed as `""`.
- Dependencies are keyed as `node_modules/<pkg_name>` or nested `node_modules/<parent>/node_modules/<child>`.
- The parser normalizes names, extracts resolved versions, and constructs the dependency chain (e.g. `express -> qs`).
- Flags `isDirect` when the package name matches root `dependencies` or `devDependencies`.

### 2.2. npm Lockfile v1 (`dependencies` tree)
Legacy npm versions store a recursive tree under `dependencies`.
- The parser implements a recursive tree walk (`walkV1`).
- Preserves the traversal stack as `currentChain` to record the exact path of transitive inheritance.
- Filters out development dependencies when `--no-dev` is active.

### 2.3. Fallback Mode
When no lockfile is present, the parser attempts to read actual installed versions from `node_modules/<name>/package.json` to prevent range ambiguity. If `node_modules` is absent, it resolves declared semver ranges and logs an advisory warning recommending `npm install` to generate a lockfile for deterministic scanning.

---

## 3. OSV API Client & Batching Optimization (`src/osv/client.js`)

Directly making individual HTTP requests per dependency creates network bottlenecks and easily hits rate limits.

### 3.1. Batching with `/v1/querybatch`
The OSV API provides `/v1/querybatch`, accepting a batch of queries in a single HTTP POST request:

```json
POST https://api.osv.dev/v1/querybatch
Content-Type: application/json

{
  "queries": [
    { "package": { "name": "lodash", "ecosystem": "npm" }, "version": "4.17.15" },
    { "package": { "name": "express", "ecosystem": "npm" }, "version": "4.16.4" },
    { "package": { "name": "qs", "ecosystem": "npm" }, "version": "6.5.2" }
  ]
}
```

The batch endpoint returns minimal vulnerability markers `{ id: string, modified: string }` for matching packages, or `{}` for clean packages. This allows scanning **500 dependencies in a single round-trip HTTP request**.

### 3.2. Concurrency-Limited Detail Retrieval
For dependencies with identified vulnerabilities:
1. All unique vulnerability IDs across the scan are deduplicated into a set.
2. An in-memory cache (`this.cache`) prevents re-fetching previously retrieved advisories.
3. A concurrency pool (`CONCURRENCY_LIMIT = 10`) fetches full advisory documents from `GET /v1/vulns/{id}` in parallel with exponential backoff on HTTP 429 / network errors.

---

## 4. Semver Range Matching Engine (`src/matcher/matcher.js`)

OSV advisories define vulnerability ranges using events:
- `{ "introduced": "x.y.z" }`
- `{ "fixed": "x.y.z" }`
- `{ "last_affected": "x.y.z" }`

### 4.1. Range Evaluation Algorithm
```javascript
// Interval: [introduced, fixed)
if (isAfterIntro && isBeforeFixed) {
  isVulnerable = true;
}

// Interval: [introduced, last_affected]
if (isAfterIntro && isBeforeOrEqualLast) {
  isVulnerable = true;
}
```

### 4.2. Edge Case Handling
1. **Zero Introduction**: `{ "introduced": "0" }` is normalized to semver `0.0.0` so all prior versions match.
2. **Version Coercion**: Handles non-semver strings (e.g. `v1.2.3` or git tags) via `semver.clean` with fallback to `semver.coerce`.
3. **Multi-Branch Backport Fixes**: When an advisory contains multiple `fixed` versions (e.g. `3.10.2` and `4.17.21`), the engine determines the lowest fixed version that is **greater than the current installed version**, preventing the scanner from recommending a downgrade to a legacy major version.

---

## 5. Severity Calculation & Scoring (`src/scoring/severity.js`)

### 5.1. CVSS 3.1 Base Score Parser
When an advisory provides a CVSS v3.1 vector string (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), the engine parses the metrics and computes the exact Base Score according to the FIRST.org specification:

$$\text{ISS} = 1 - (1 - \text{Impact}_C) \times (1 - \text{Impact}_I) \times (1 - \text{Impact}_A)$$
$$\text{Exploitability} = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}$$

### 5.2. Severity Normalization Matrix

| Severity Level | CVSS Score Range | Numerical Rank | Fail-On Threshold Rank |
|---|---|---|---|
| **CRITICAL** | 9.0 – 10.0 | 4 | 4 |
| **HIGH** | 7.0 – 8.9 | 3 | 3 |
| **MEDIUM** | 4.0 – 6.9 | 2 | 2 |
| **LOW** | 0.1 – 3.9 | 1 | 1 |
| **UNKNOWN** | None / Unscored | 0 | 0 |

---

## 6. CI/CD Integration & Exit Code Contract

In continuous integration (CI) pipelines, scanners must provide deterministic exit codes:

| Condition | Exit Code | Purpose |
|---|:---:|---|
| **Clean scan** (0 findings) | `0` | Pipeline step passes |
| **Findings below threshold** (e.g. `--fail-on high` with only MEDIUM findings) | `0` | Pipeline step passes with warning |
| **Findings at or above threshold** (e.g. `--fail-on low` with any finding) | `1` | Pipeline step fails, blocking merge/deploy |
| **Fatal runtime error** (Invalid JSON, network failure, missing path) | `2` | Pipeline indicates configuration/infra error |

### Example GitHub Actions Workflow Step:
```yaml
- name: Scan Dependencies
  run: |
    node bin/scanner.js . --fail-on high --format markdown --output scan-report.md
- name: Publish Scan Summary
  if: always()
  run: cat scan-report.md >> $GITHUB_STEP_SUMMARY
```

---

## 7. Performance & Benchmarking

| Test Target | Dependencies Scanned | Direct / Transitive | OSV Roundtrips | Scan Duration |
|---|:---:|:---:|:---:|:---:|
| `sample-clean-app` | 2 | 2 direct, 0 transitive | 1 batch POST | **~0.5s** |
| `sample-vulnerable-app` | 4 | 3 direct, 1 transitive | 1 batch POST + detail GETs | **~1.6s** |
| Average response per batch query | Up to 500 pkgs | N/A | 1 HTTP request | **~400ms** |

---

## 8. Phase 2 Roadmap & Scaling Beyond the POC

1. **Multi-Ecosystem Manifest Parsers**:
   - Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock` (Ecosystem: `PyPI`).
   - Go: `go.mod`, `go.sum` (Ecosystem: `Go`).
   - Java: `pom.xml`, `build.gradle` (Ecosystem: `Maven`).
2. **Local OSV Database Caching**:
   - Download OSV ecosystem zip exports daily to enable 100% offline scanning in air-gapped environments.
3. **Automated Fix PR Generator**:
   - Integrate automated manifest editing (`npm install <pkg>@<fix>`) to produce automated pull requests.
4. **SARIF Output**:
   - Support OASIS SARIF v2.1.0 standard for direct integration into GitHub Advanced Security code scanning tabs.
