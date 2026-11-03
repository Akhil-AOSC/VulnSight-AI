# API Documentation

> **Document ID:** VS-DOC-13  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Integration Engineers, Frontend Developers, DevOps Specialists  

---

## 1. API Architecture & Standards

VulnSight AI exposes a uniform RESTful API conforming to the following standards:
- **Base Endpoint:** `/api/v1`
- **Transport Security:** HTTPS only; strict TLS 1.3 recommended.
- **Authentication:** HTTP Bearer token via `Authorization: Bearer <session_token>`.
- **Payload Format:** JSON (`Content-Type: application/json; charset=utf-8`).
- **Error Format:** Standardized JSON error response:
  ```json
  { "error": "Human readable explanation", "errorId": "optional-uuid" }
  ```
- **Rate Limiting:** Sliding-window limiter enforcing 600 req/min per IP globally, and 20 attempts/15 min for authentication routes.

---

## 2. Authentication & Session Endpoints

### 2.1 Health Check
- **`GET /api/v1/health`**
- **Auth:** Public
- **Response:** `200 OK`
  ```json
  { "ok": true }
  ```

### 2.2 User Registration
- **`POST /api/v1/auth/signup`**
- **Auth:** Public (Rate limited: 20 per 15 min per IP)
- **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "Password-With-Upper-Lower-123",
    "name": "Jane Doe",
    "orgName": "Acme Corp"
  }
  ```
- **Response:** `201 Created`
  ```json
  {
    "token": "dGVzdC10b2tlbi1yYW5kb20tYnl0ZXM...",
    "userId": "usr_94a7e...",
    "orgId": "org_11b2c..."
  }
  ```

### 2.3 User Login
- **`POST /api/v1/auth/login`**
- **Auth:** Public (Rate limited: 10 per 15 min per email)
- **Request Body:**
  ```json
  { "email": "user@example.com", "password": "Password-With-Upper-Lower-123" }
  ```
- **Response:** `200 OK`
  ```json
  {
    "token": "dGVzdC10b2tlbi1yYW5kb20tYnl0ZXM...",
    "userId": "usr_94a7e...",
    "orgId": "org_11b2c..."
  }
  ```

### 2.4 User Profile & Current Context
- **`GET /api/v1/me`**
- **Auth:** Bearer
- **Response:** `200 OK`
  ```json
  {
    "id": "usr_94a7e...",
    "email": "user@example.com",
    "name": "Jane Doe",
    "orgs": [
      { "id": "org_11b2c...", "name": "Acme Corp", "role": "owner" }
    ]
  }
  ```

### 2.5 User Logout
- **`POST /api/v1/auth/logout`**
- **Auth:** Bearer
- **Response:** `200 OK`
  ```json
  { "ok": true }
  ```

---

## 3. Organization & Team Endpoints

### 3.1 Organization Overview & Metrics
- **`GET /api/v1/orgs/:org/overview`**
- **Auth:** Bearer (`repos:read`)
- **Response:** `200 OK`
  ```json
  {
    "repositories": 12,
    "scans": 148,
    "findings": { "critical": 2, "high": 7, "medium": 15, "low": 42 },
    "posture": { "score": 88, "grade": "B" },
    "recentScans": [ /* scan objects */ ]
  }
  ```

### 3.2 Organization Settings
- **`GET /api/v1/orgs/:org/settings`** & **`PATCH /api/v1/orgs/:org/settings`**
- **Auth:** Bearer (`org:settings`)
- **Request Body (PATCH):**
  ```json
  {
    "retentionDays": 180,
    "aiEnabled": true,
    "sendCode": false
  }
  ```

### 3.3 Member Management
- **`GET /api/v1/orgs/:org/members`** — List organization members.
- **`POST /api/v1/orgs/:org/members`** — Add user to organization (`201 Created`).
  ```json
  { "email": "colleague@example.com", "role": "developer" }
  ```
- **`PATCH /api/v1/orgs/:org/members/:userId`** — Update member role (`role`: `'admin' | 'developer' | 'viewer'`).
- **`DELETE /api/v1/orgs/:org/members/:userId`** — Remove user (refuses deletion of last owner).

### 3.4 Team Management
- **`GET /api/v1/orgs/:org/teams`** — List teams.
- **`POST /api/v1/orgs/:org/teams`** — Create team (`{ "name": "Backend Security" }`).
- **`DELETE /api/v1/orgs/:org/teams/:teamId`** — Remove team.
- **`POST /api/v1/orgs/:org/teams/:teamId/members/:userId`** — Assign user to team.
- **`DELETE /api/v1/orgs/:org/teams/:teamId/members/:userId`** — Remove user from team.

---

## 4. Git Provider Connections & Repositories

### 4.1 Connect Git Provider
- **`POST /api/v1/orgs/:org/connections`**
- **Auth:** Bearer (`providers:manage`)
- **Request Body:**
  ```json
  {
    "provider": "github",
    "label": "Engineering GitHub Token",
    "token": "ghp_PersonalAccessTokenWithRepoScope...",
    "account": "acme-engineering"
  }
  ```
- **Response:** `201 Created`

### 4.2 Add Repository to VulnSight AI
- **`POST /api/v1/orgs/:org/repos`**
- **Auth:** Bearer (`repos:write`)
- **Request Body:**
  ```json
  {
    "cloneUrl": "https://github.com/acme-engineering/payment-service.git",
    "provider": "github",
    "connectionId": "conn_55a2...",
    "defaultBranch": "main",
    "scanners": ["sca", "semgrep", "gitleaks", "trivy"],
    "threshold": "low"
  }
  ```
- **Response:** `201 Created`

### 4.3 Configure Scan Schedule
- **`PUT /api/v1/orgs/:org/repos/:repoId/schedule`**
- **Request Body:**
  ```json
  { "schedule": "daily" } // 'daily' | 'weekly' | 'monthly' | null
  ```

---

## 5. Scans & Finding Triage Endpoints

### 5.1 Trigger Repository Scan
- **`POST /api/v1/orgs/:org/repos/:repoId/scans`**
- **Auth:** Bearer (`scans:run`)
- **Request Body:**
  ```json
  { "branch": "main", "scanners": ["sca", "semgrep", "gitleaks"] }
  ```
- **Response:** `202 Accepted`
  ```json
  {
    "id": "scn_33f9...",
    "status": "queued",
    "branch": "main",
    "createdAt": "2026-11-03T11:00:00.000Z"
  }
  ```

### 5.2 Retrieve Scan Details & Findings
- **`GET /api/v1/orgs/:org/scans/:scanId`** — Get scan execution metadata and summary.
- **`GET /api/v1/orgs/:org/scans/:scanId/findings?severity=high&category=sca&page=1&pageSize=50`**
- **Response:** `200 OK`
  ```json
  {
    "items": [
      {
        "id": "fnd_88b1...",
        "fingerprint": "a3f5c7...",
        "category": "sca",
        "severity": "high",
        "cvssScore": 7.5,
        "title": "Prototype Pollution in minimist",
        "identifiers": { "primary": "CVE-2020-7598", "aliases": ["GHSA-vh95-rmgr-6w4m"] },
        "location": { "package": "minimist", "version": "0.0.8", "ecosystem": "npm", "direct": false },
        "remediation": { "fixedIn": "0.2.1" },
        "state": { "status": "open", "assigneeId": null, "note": null }
      }
    ],
    "total": 1,
    "page": 1,
    "pageSize": 50
  }
  ```

### 5.3 Triage Finding
- **`PATCH /api/v1/orgs/:org/repos/:repoId/findings/:fingerprint`**
- **Auth:** Bearer (`findings:write`)
- **Request Body:**
  ```json
  {
    "status": "mitigated",
    "note": "Input validated at API gateway layer; unreachable from external inputs",
    "assigneeId": "usr_94a7e..."
  }
  ```

### 5.4 Download Scan Compliance Report
- **`GET /api/v1/orgs/:org/scans/:scanId/report?format=cyclonedx`**
- **Query Parameter `format`:** `'json' | 'csv' | 'cyclonedx' | 'markdown'`
- **Response:** `200 OK` (Attachment with Content-Disposition header).

---

## 6. Governed AI Assistant Endpoints

### 6.1 Explain Finding
- **`POST /api/v1/orgs/:org/findings/:findingId/explain`**
- **Auth:** Bearer (`ai:use`)
- **Response:** `200 OK`
  ```json
  {
    "findingId": "fnd_88b1...",
    "text": "CVE-2020-7598 is a Prototype Pollution vulnerability...",
    "upgradeImpact": {
      "from": "0.0.8",
      "to": "0.2.1",
      "kind": "minor",
      "breakingChangeRisk": "medium"
    },
    "aiGenerated": true,
    "provider": "claude",
    "model": "claude-3-5-sonnet"
  }
  ```

### 6.2 Conversational Repository Q&A
- **`POST /api/v1/orgs/:org/repos/:repoId/ai/ask`**
- **Request Body:**
  ```json
  {
    "question": "Which critical vulnerabilities affect my database connections?",
    "history": []
  }
  ```

---

## 7. Webhook & Internal System Endpoints

### 7.1 Single-Use Grant Redemption (Internal)
- **`POST /api/v1/internal/scan-grant`**
- **Auth:** Public (Restricted to internal subnet / rate-limited to 60/min)
- **Request Body:**
  ```json
  { "scanId": "scn_33f9...", "secret": "32-byte-grant-secret" }
  ```
- **Response:** `200 OK`
  ```json
  { "token": "ghp_DecryptedCredential..." }
  ```

### 7.2 Git Provider Webhook Ingress
- **`POST /api/v1/webhooks/:repoId`**
- **Auth:** Public (Verified via `X-Hub-Signature-256` or `X-Gitlab-Token`)
- **Payload:** Raw Git push event JSON.
