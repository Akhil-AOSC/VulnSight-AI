# Sequence Diagrams

> **Document ID:** VS-DOC-10  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Developers, System Architects, Quality Assurance Engineers  

---

## 1. User-Initiated Scan Execution Workflow

This sequence illustrates the end-to-end lifecycle when a logged-in developer triggers an on-demand scan from the Web UI.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer (Browser)
    participant UI as Web SPA (views-main.js)
    participant API as API Server (api.js)
    participant Svc as Platform Service (service.js)
    participant DB as SQLite DB (db.js)
    participant Worker as Scan Worker Job
    participant Git as Remote Git Host
    participant Proxy as Egress Proxy

    Dev->>UI: Click "Scan repository"
    UI->>API: POST /api/v1/orgs/:org/repos/:repo/scans<br/>Authorization: Bearer <token>
    API->>Svc: startScan(ctx, repoId, options)
    Svc->>Svc: assertCan(role, 'scans:run')
    Svc->>Svc: validateRepoUrl & check SSRF
    Svc->>DB: INSERT INTO scans (status='queued')
    Svc->>DB: INSERT INTO scan_grants (scan_id, secret_hash, payload_enc)
    Svc->>Worker: Dispatch worker execution (ACA Job / Docker)
    Svc-->>API: Return HTTP 202 Accepted { scanId }
    API-->>UI: Return scan record { status: 'queued' }
    UI->>Dev: Show "Scan queued..." status badge

    Worker->>API: POST /api/v1/internal/scan-grant { scanId, secret }
    API->>Svc: redeemGrant(scanId, secret, ip)
    Svc->>DB: Match hash & mark used_at = now()
    Svc-->>Worker: Return decrypted provider token
    
    Worker->>Proxy: CONNECT git host on port 443
    Proxy->>Git: Establish TLS Tunnel
    Worker->>Git: git clone --depth 1 (via pinned IP)
    Worker->>Worker: Purge .git, remove symlinks, enforce byte limits
    Worker->>Worker: Run SCA, Semgrep, Gitleaks, Trivy, Checkov
    Worker->>API: Ingest Scan Results (or upload to Blob Storage)
    
    API->>Svc: ingestScanResults(scanId, rawData)
    Svc->>Svc: Deduplicate findings & compute fingerprints
    Svc->>DB: INSERT INTO findings & UPDATE scans (status='completed')
    Svc->>DB: Recalculate Security Posture Score
    UI->>API: GET /api/v1/orgs/:org/scans/:scan (polling or refresh)
    API-->>UI: Return updated scan with findings count
    UI->>Dev: Render findings table, posture grade, and fix plan
```

---

## 2. Webhook-Triggered Automated Scanning

This sequence illustrates an automated push-triggered scan originating from GitHub, GitLab, or Bitbucket.

```mermaid
sequenceDiagram
    autonumber
    participant Git as Git Provider (GitHub/GitLab)
    participant API as Ingress Gateway (api.js)
    participant Svc as Automation Service (service.js)
    participant DB as SQLite DB
    participant Queue as Platform Queue (queue.js)

    Git->>API: POST /api/v1/webhooks/:repoId<br/>Header: X-Hub-Signature-256 (or X-Gitlab-Token)
    API->>Svc: handleWebhook(repoId, headers, rawBody)
    Svc->>DB: Fetch repository config & encrypted webhook_secret
    Svc->>Svc: Verify HMAC-SHA256 signature (timing-safe compare)
    alt Invalid Signature
        Svc-->>API: Reject with HTTP 401 Unauthorized
        API-->>Git: 401 Unauthorized
    else Valid Signature
        Svc->>Svc: Extract ref/branch (e.g., 'refs/heads/main')
        Svc->>Svc: Check if branch is monitored in repo config
        alt Branch Not Monitored
            Svc-->>API: Return { ok: true, ignored: 'branch not monitored' }
        else Branch Monitored
            Svc->>DB: INSERT INTO jobs (type='scan', payload={repoId, branch})
            Svc-->>API: Return { ok: true, enqueued: true }
            API-->>Git: HTTP 200 OK
            Queue->>Queue: Poll ready jobs -> Trigger scan workflow
        end
    end
```

---

## 3. Secure Single-Use Credential Grant Exchange

This diagram details the protocol designed to eliminate long-lived Git credentials from worker startup configurations.

```mermaid
sequenceDiagram
    autonumber
    participant Orch as API Orchestrator
    participant DB as Database (scan_grants)
    participant ACA as Azure ARM / Job Runtime
    participant Worker as Scan Worker Container

    Orch->>Orch: Generate 32-byte cryptographically random secret
    Orch->>Orch: Compute SHA-256(secret)
    Orch->>DB: INSERT INTO scan_grants VALUES (scanId, secretHash, encToken, expiresAt)
    Orch->>ACA: Start Job Execution<br/>Env: [VS_SCAN_ID, VS_GRANT_SECRET, VS_GRANT_URL]
    Note over Orch,ACA: Persistent Git token is completely absent from job config
    ACA->>Worker: Spin up container with environment variables
    Worker->>Orch: POST /api/v1/internal/scan-grant<br/>{ scanId, secret }
    Orch->>DB: SELECT * FROM scan_grants WHERE scan_id = scanId
    alt Grant Not Found or Expired or Already Used
        DB-->>Orch: Record invalid / used
        Orch->>DB: Log security audit alert (potential token replay!)
        Orch-->>Worker: HTTP 400 Invalid Grant
        Worker->>Worker: Abort scan execution immediately
    else Grant Valid & Unused
        Orch->>DB: UPDATE scan_grants SET used_at = now() WHERE scan_id = scanId
        Orch->>Orch: Decrypt payload using AES-256-GCM Master Key
        Orch-->>Worker: HTTP 200 { token: "<decrypted-git-token>" }
        Worker->>Worker: Perform git clone
        Worker->>Worker: Zero out token in memory & environment
    end
```

---

## 4. Governed AI Remediation & Q&A Workflow

This sequence illustrates developer interaction with the AI Security Assistant, showcasing prompt isolation and consent verification.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant UI as Web SPA (views-more.js)
    participant API as API Server (api.js)
    participant AI as AI Subsystem (assistant.js)
    participant LLM as External LLM (Claude 3.5 / GPT-4o)
    participant DB as Database (ai_history)

    Dev->>UI: Click "Explain finding" or Ask Question
    UI->>API: POST /api/v1/orgs/:org/findings/:id/explain
    API->>AI: explainFinding(finding, { consent, provider })
    AI->>AI: Assert consent.aiEnabled === true
    alt AI Disabled by Org Admin
        AI-->>API: Throw ConsentError("AI is disabled for organisation")
        API-->>UI: HTTP 400 Consent Required
    else AI Permitted
        AI->>AI: Screen input against INJECTION_PATTERNS
        alt Prompt Injection Attempt Detected
            AI->>AI: Strip injection payload & tag "[withheld: suspicious content]"
        end
        AI->>AI: Wrap finding description in <untrusted> tags
        alt Finding Category == 'secret'
            AI->>AI: Strip all code evidence (Zero Secret Policy)
        else Finding Category != 'secret'
            AI->>AI: Include evidence ONLY IF consent.sendCode === true
        end
        AI->>LLM: Dispatch System Prompt + Sanitized Context
        LLM-->>AI: Return Remediation Guidance
        AI->>AI: Label payload { aiGenerated: true, provider, model }
        AI->>DB: INSERT INTO ai_history (org_id, finding_id, question, answer)
        AI-->>API: Return AI explanation
        API-->>UI: Return formatted markdown response
        UI->>Dev: Display guidance with "AI Generated" badge
    end
```

---

## 5. Finding Triage & Status Review Transition

This sequence illustrates the developer review workflow and state update lifecycle.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / Lead
    participant UI as Web SPA
    participant API as API Server
    participant Svc as Platform Service
    participant DB as SQLite DB

    Dev->>UI: Select Finding -> Change Status to "mitigated" (add note)
    UI->>API: PATCH /api/v1/orgs/:org/repos/:repo/findings/:fingerprint<br/>Body: { status: 'mitigated', note: 'WAF rule applied', assigneeId: null }
    API->>Svc: updateFinding(ctx, repoId, fingerprint, update)
    Svc->>Svc: assertCan(role, 'findings:write')
    Svc->>DB: UPSERT INTO finding_states (status, note, updated_by, updated_at)
    Svc->>DB: INSERT INTO finding_reviews (action='status_change', detail='open -> mitigated')
    Svc->>DB: INSERT INTO audit_logs (action='finding.triage_updated', target=fingerprint)
    Svc->>Svc: Recalculate Posture Score (mitigated findings excluded from penalty)
    Svc-->>API: Return updated finding state
    API-->>UI: HTTP 200 OK
    UI->>Dev: Update UI badge to "Mitigated" & refresh Posture Score
```
