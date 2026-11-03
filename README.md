# VulnSight-AI

An open-source dependency vulnerability scanner (software composition analysis) for npm and Python projects.
It reads your lockfile, checks every installed package against the free [OSV.dev](https://osv.dev) vulnerability
database, and tells you what is vulnerable, how it got into your project, and which version fixes it.

No dependencies, no account, no API key. Requires Node.js 18 or newer (22.5+ for the platform below).

## Multi-user platform (new)

```bash
node bin/vulnsight.js serve          # API + web app + background worker at http://localhost:4400
```

Sign up in the browser, connect a Git provider token (or add a public repo URL), and scan. Features:
organisations, teams and roles, GitHub/GitLab/Bitbucket repos, scheduled and webhook-triggered scans,
dependency + code + secret (+ container/IaC) scanning, finding triage, reports and SBOM export, and an
opt-in AI assistant. Data lives in `.vulnsight-data/`.

```bash
node bin/vulnsight.js scan . --scanners=sca,semgrep,gitleaks --format=markdown --output=report.md
```

Semgrep, Gitleaks, Trivy and Checkov must be installed separately; a missing scanner is reported, not fatal.
**Read [docs/STATUS.md](docs/STATUS.md) before relying on any of this** - it lists exactly what is verified,
what is partial, and what is not done. Security design: [docs/SECURITY.md](docs/SECURITY.md); operations:
[docs/OPERATIONS.md](docs/OPERATIONS.md).

## Quick start

```bash
node bin/vulnsight.js test examples/npm-app
```

Install it as a global `vulnsight` command from this folder:

```bash
npm link
```

```bash
vulnsight test path/to/your/project
```

## Web dashboard

```bash
node bin/vulnsight.js ui
```

Then open http://localhost:4321. From the dashboard you can run scans and review their results:

- Summary cards and a severity breakdown
- A per-package fix plan
- A searchable, filterable issues table where each row expands to show paths, IDs and the advisory link
- Scan history, saved to `~/.vulnsight/history.json` (last 50 scans)
- Light and dark mode

The dashboard only listens on `127.0.0.1` and rejects requests addressed to other host names, so other websites
can't use it to start scans. Use `--port=<n>` if 4321 is taken.

## Usage

```
vulnsight test [path] [options]

  --file=<lockfile>             Scan one file instead of auto-detecting
  --severity-threshold=<level>  Only report issues at or above low|medium|high|critical
  --dev                         Include development dependencies
  --json                        Print results as JSON
  --no-color                    Disable colored output
```

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json` (v1, v2, v3), `npm-shrinkwrap.json` |
| Python | `requirements*.txt` (pinned `==` versions, follows `-r`), `poetry.lock`, `Pipfile.lock` |

**Exit codes:** `0` no issues, `1` issues found, `2` error, `3` no supported files found.
This lets you fail a CI build on vulnerabilities, for example:

```yaml
# .github/workflows/security.yml
- run: node path/to/vulnsight-ai/bin/vulnsight.js test . --severity-threshold=high
```

## How it works

```
lockfile ──▶ parser ──▶ [name, version, paths] ──▶ OSV.dev /querybatch ──▶ OSV.dev /vulns/{id}
                                                                                 │
              report ◀── fix version + severity ◀── merge aliases (GHSA/CVE/PYSEC)┘
```

| File | Role |
|---|---|
| `src/parsers/npm.js` | Walks the lockfile from the root, resolving packages the same way Node does, to get each package's dependency path |
| `src/parsers/python.js` | Parses requirements, Poetry and Pipenv lockfiles, normalising names per PEP 503 |
| `src/osv.js` | Batched OSV.dev queries with retries and an in-memory cache |
| `src/scanner.js` | Merges duplicate advisories, picks the lowest fixed version above the installed one |
| `src/severity.js` | Uses the advisory's own rating, falling back to a CVSS v3 base score calculator |
| `src/report.js` | Text and JSON output, plus a per-package upgrade plan |
| `src/server.js` | Local dashboard server: serves `ui/` and the `/api/scans` endpoints, keeps scan history |
| `ui/` | Dashboard page (plain HTML, CSS and JavaScript, no build step) |

## Development

```bash
npm test
```

```bash
npm run scan:examples
```

The projects in `examples/` pin deliberately old, vulnerable versions. Don't deploy them.

## Known limitations

- Transitive npm fixes say which version of the vulnerable package fixes it, but not yet which version of the parent package pulls that in.
- `yarn.lock` and `pnpm-lock.yaml` are detected but not parsed yet.
- Unpinned Python requirements (`flask>=2.0`) are listed as not scanned.
- Version comparison covers semver and common PEP 440 forms, not every edge case of either spec.

## Roadmap

1. yarn and pnpm lockfiles, Maven, Go modules
2. Upgrade advice for the parent package of a transitive dependency (via the npm registry)
3. Source code scanning (SAST) with Semgrep rules, and secret detection
4. Container image and IaC scanning
5. Hosted multi-user dashboard and a GitHub App that opens fix pull requests
