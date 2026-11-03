# Testing & Team Demonstration Guide: vuln-scanner

This guide provides step-by-step instructions for testing **`vuln-scanner`** and demonstrating its capabilities to your team.

---

## ⚡ Quick Test in 3 Commands

Open your terminal in this directory (`c:\Users\Admin\Downloads\Hacking Software`) and run:

```bash
# 1. Run all automated unit and integration tests (11 passing tests)
npm test

# 2. Scan the vulnerable sample project (shows 13 CVEs, transitive detection, and exit code 1)
npm run scan:vulnerable

# 3. Scan the clean sample project (shows 0 vulnerabilities and clean exit code 0)
npm run scan:clean
```

---

## 📋 Comprehensive Demonstration Walkthrough

When presenting to your team or stakeholders, follow these 5 demonstration steps:

### Demo 1: Transitive & Direct Vulnerability Detection
Show how `vuln-scanner` inspects direct dependencies as well as transitive dependencies buried inside other packages.

```bash
node bin/scanner.js ./test-fixtures/vulnerable-npm-project
```
**What to point out to the team:**
- **Direct vulnerabilities**: Shows `lodash@4.17.15` (Command Injection CVE-2021-23337) and `minimist@1.2.0` (Prototype Pollution CVE-2021-44906).
- **Transitive vulnerability**: Shows `qs@6.5.2` (CVE-2022-24999), which wasn't even listed in `package.json`! It was brought in via `express`. The tool flags it with `[TRANSITIVE via express → qs]`.
- **Recommended Remediation**: Point out the green fix lines (e.g., `Upgrade minimist to >= 1.2.6`).

---

### Demo 2: Clean Project Scan & CI Pass (Exit Code 0)
Show how the tool behaves when a project has no known vulnerabilities:

```bash
node bin/scanner.js ./test-fixtures/clean-npm-project
```
Check the exit code in PowerShell:
```powershell
$LASTEXITCODE
# Output: 0
```
Or in Bash / Git Bash:
```bash
echo $?
# Output: 0
```
**What to point out to the team:**
- Scans in less than 0.6 seconds.
- Returns clean exit code `0`, allowing CI/CD pipelines to proceed smoothly.

---

### Demo 3: CI/CD Policy Enforcement (`--fail-on`)
Show how teams can customize pipeline failure rules:

```bash
# Fail only on CRITICAL vulnerabilities (exits 1 because minimist has a 9.8 CVSS critical)
node bin/scanner.js ./test-fixtures/vulnerable-npm-project --fail-on critical

# Informational audit mode without blocking the pipeline (exits 0 with warnings)
node bin/scanner.js ./test-fixtures/vulnerable-npm-project --fail-on none
```

---

### Demo 4: Exporting Reports (JSON and Markdown)
Show how `vuln-scanner` integrates with CI artifacts and developer workflows:

#### 1. Machine-Readable JSON Export:
```bash
node bin/scanner.js ./test-fixtures/vulnerable-npm-project --format json --output ./report.json --fail-on none
```
Open `report.json` to inspect the full structured schema including CVSS scores, advisories, affected ranges, and metadata.

#### 2. Pull Request Markdown Export:
```bash
node bin/scanner.js ./test-fixtures/vulnerable-npm-project --format markdown --output ./report.md --fail-on none
```
Open `report.md` to see a GitHub/GitLab-ready markdown summary with OSV advisory links and severity tables.

---

### Demo 5: Running Unit & Integration Tests
Demonstrate the test suite that verifies manifest parsing, OSV batch querying, semver logic, and exit code handling:

```bash
npm test
```
Expected output:
```
✔ Integration: scan on vulnerable-npm-project detects known CVEs and breaches threshold
✔ Integration: scan on clean-npm-project passes with zero findings
✔ Manifest Parser: parses vulnerable fixture with lockfile v3
✔ Manifest Parser: parses clean fixture with zero transitive deps
✔ Manifest Parser: throws error when package.json does not exist
✔ Matcher: matches version inside [introduced, fixed) range
✔ Matcher: matches explicit version list
✔ Matcher: ignores vulnerabilities for different packages or ecosystems
✔ Severity: extracts CVSS 3.1 score and maps to CRITICAL
✔ Severity: falls back to database_specific MODERATE -> MEDIUM
✔ Severity: threshold evaluation matches severity ranks

tests 11
pass 11
fail 0
```

---

## 🎯 Talking Points for Your Team Presentation

1. **Why OSV.dev?**  
   Google’s OSV database is open, vendor-neutral, and standardizes data from GitHub Security Advisories, NVD, and OpenSSF. It eliminates proprietary per-seat licensing fees.
2. **High-Performance Batching**:  
   We utilized `/v1/querybatch` to query up to 500 packages per HTTP request, meaning entire dependency trees resolve in a single round-trip.
3. **Actionable Fix Guidance**:  
   Rather than just sounding alarms, the scanner extracts and recommends the exact minimal safe version (e.g. `Upgrade to >= 4.17.21`).
4. **CI-Ready**:  
   Standard exit codes (`0` for clean, `1` for threshold breach) make this immediately drop-in ready for GitHub Actions, GitLab CI, or Jenkins.
