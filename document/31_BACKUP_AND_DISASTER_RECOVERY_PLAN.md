# Backup & Disaster Recovery Plan

> **Document ID:** VS-DOC-31  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** SREs, Database Administrators, Incident Response Commanders  

---

## 1. Business Continuity Targets

VulnSight AI establishes strict Business Continuity and Disaster Recovery (BCDR) service level agreements:

- **Recovery Point Objective (RPO):** $\le 24\text{ hours}$ (Maximum acceptable data loss period; reducible to $< 1\text{ hour}$ with automated WAL archiving).
- **Recovery Time Objective (RTO):** $\le 4\text{ hours}$ (Maximum acceptable time to restore complete platform functionality).
- **Zero-Source Retention:** Cloned repository source code is never backed up because it is never retained on disk. Backups strictly capture metadata, user accounts, audit trails, and normalized findings.

---

## 2. Backup Strategy & Procedures

### 2.1 Online Non-Blocking Backups
The platform database uses SQLite in Write-Ahead Logging (WAL) mode. Backups must be performed using the native `VACUUM INTO` command, which produces an atomic, consistent point-in-time snapshot without blocking active readers or writers:

```bash
# Automated Operations CLI
node scripts/ops.js backup /path/to/platform.db /backups/platform-$(date +%Y%m%d%H%M%S).db
```
The script:
1. Validates that the destination file does not already exist (refuses to overwrite).
2. Executes `VACUUM INTO '<destination>'`.
3. Runs an immediate integrity check (`PRAGMA integrity_check`) on the resulting backup file.
4. Outputs the record counts of all backed-up entities.

### 2.2 Backup Component Separation
To guarantee confidentiality and disaster survivability:
1. **The Database Backup File:** Contains accounts, organization definitions, audit logs, scan history, and encrypted Git tokens (`token_enc`).
2. **The Master Encryption Key (`VULNSIGHT_MASTER_KEY`):** Must be stored **strictly separate** from the database backup file (e.g., in a separate cloud subscription Key Vault or offline password vault).
3. **Cryptographic Guarantee:** If a database backup is compromised or intercepted, an adversary cannot decrypt stored Git provider access tokens or webhook secrets without the master key.

---

## 3. Disaster Recovery & Restoration Procedures

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Disaster Recovery Operator
    participant Ops as Operations Tooling (scripts/ops.js)
    participant Disk as Local Storage
    participant DB as Platform Database

    Admin->>Ops: node scripts/ops.js verify /backups/backup.db
    Ops->>Ops: Run PRAGMA integrity_check & foreign_key_check
    Ops-->>Admin: Backup Verified Healthy (0 corruption errors)

    Admin->>Ops: node scripts/ops.js restore /backups/backup.db /data/platform.db
    Ops->>Disk: Rename current /data/platform.db -> platform.db.bak.<timestamp>
    Note over Ops,Disk: The existing database is kept aside; never deleted
    Ops->>Disk: Copy backup file to /data/platform.db
    Ops->>DB: Open restored database & apply any pending newer schema migrations
    Ops-->>Admin: Restore Complete. Database healthy and up to date.

    Admin->>Admin: Verify VULNSIGHT_MASTER_KEY loaded in environment
    Admin->>Admin: Start API Server & verify user login and provider decryption
```

### 3.1 Step-by-Step Restoration Runbook
1. **Quarantine / Backup Existing State:**
   Never delete the existing database file. The restore script automatically renames it to `platform.db.bak.<timestamp>` to prevent unrecoverable data loss during incident confusion.
2. **Execute Restoration:**
   ```bash
   node scripts/ops.js restore /backups/latest-verified.db /data/platform.db
   ```
3. **Verify Restored Integrity:**
   ```bash
   node scripts/ops.js verify /data/platform.db
   ```
4. **Boot Platform:** Start `node bin/vulnsight.js serve` with the identical `VULNSIGHT_MASTER_KEY`.
5. **Post-Restore Smoke Test:** Log in via the web dashboard, navigate to **Settings > Integrations**, and verify that existing Git provider connections can fetch remote branches.

---

## 4. Emergency Incident Tooling (`scripts/ops.js`)

VulnSight AI includes purpose-built operational command-line utilities for security and incident response teams that operate directly on the database file without requiring the API server to be online:

| Command | Operational Purpose & Usage Scenario |
| :--- | :--- |
| **`backup <db> <file>`** | Generates an atomic, consistent online backup of a running system. |
| **`verify <file>`** | Audits database integrity, asserts zero foreign key violations, counts rows. |
| **`restore <file> <db>`** | Restores from backup while safely preserving the current database aside. |
| **`rotate-key <db>`** | **Key Exposure Incident:** Re-encrypts every stored Git token and webhook secret from `OLD_KEY` to `NEW_KEY` in a single atomic transaction. |
| **`disable-user <db> <email>`** | **Account Compromise:** Immediately disables the target account and terminates all active bearer sessions instantly. |
| **`revoke-sessions <db>`** | **Global Incident:** Terminates every active session across all organizations, forcing immediate re-authentication. |
| **`new-key`** | Generates a fresh, high-entropy 32-byte base64 master key. |

---

## 5. BCDR Validation & Drill History

The disaster recovery procedures have been validated through automated end-to-end regression drills (`test/ops.test.js`):

| Drill Type | Drill Scenario & Verification | Result |
| :--- | :--- | :---: |
| **Backup, Corrupt, Restore** | Backed up a live database, wiped original database file with corrupt bytes, restored from backup, verified login and token decryption. | **PASSED** |
| **Token Safety in Backup** | Verified that a backup file without the master key cannot decrypt provider tokens. | **PASSED** |
| **Atomic Key Rotation** | Re-encrypted database with new master key; verified that all tokens decrypt with new key and that old key fails immediately. | **PASSED** |
| **Emergency Account Disable** | Disabled compromised account via CLI; verified active bearer sessions are destroyed and login rejected. | **PASSED** |
