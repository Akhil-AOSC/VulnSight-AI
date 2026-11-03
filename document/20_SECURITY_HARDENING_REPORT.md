# Security Hardening Report

> **Document ID:** VS-DOC-20  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** Security Engineers, System Administrators, DevOps Specialists  

---

## 1. Executive Hardening Summary

Security hardening in VulnSight AI is applied across five distinct operational layers: Runtime & Process, Container & OS, Network & Ingress, Database & Storage, and Cryptographic Management. This document details the specific configurations and commands implemented to achieve compliance with the **CIS Node.js Benchmark**, **CIS Docker Benchmark**, and **Azure Security Benchmark**.

```
+-----------------------------------------------------------------------------------+
|                        VulnSight AI Hardening Spectrum                            |
+-----------------------------------------------------------------------------------+
|  Application Runtime   | Node.js --max-old-space-size=768, Bounded libuv Worker   |
|  Container Execution   | Non-root UID 10001, --cap-drop ALL, no-new-privileges     |
|  Filesystem Boundary   | Read-only Root, tmpfs noexec/nosuid, Symlinks Purged     |
|  Network Confinement   | CONNECT-only Proxy, Port 443, DNS Pinning, Deny Direct   |
|  Data Integrity        | SQLite WAL Mode, AES-256-GCM, Atomic Migration Runner    |
+-----------------------------------------------------------------------------------+
```

---

## 2. Process & Runtime Hardening

### 2.1 Node.js Process Isolation
- **Memory Quotas:** Background scan child processes are launched with explicit V8 heap limits:
  ```bash
  node --max-old-space-size=768 src/platform/scan-child.js
  ```
  This prevents memory leaks or runaway processes from exhausting host memory.
- **Scrubbed Process Environment (`scrubbedEnv`):** When spawning scan workers or child processes, the host environment is aggressively filtered. Crucial system secrets are excluded:
  ```javascript
  // Whitelist of permitted environment variables:
  const keep = ['PATH', 'SystemRoot', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 
                'LANG', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'NODE_USE_ENV_PROXY'];
  ```
  `VULNSIGHT_MASTER_KEY`, `ANTHROPIC_API_KEY`, session secrets, and database paths are never leaked to child scanner processes.
- **Shell-Free Invocation:** Processes are spawned strictly via `execTool()` utilizing Node's `child_process.spawn()` with `shell: false`. Arguments are supplied as discrete array tokens, preventing shell expansion (`$`, `;`, `&&`, `|`) attacks.

### 2.2 Event Loop & Thread Pool Management
- **Async `scrypt` Execution:** Password verification and generation offload CPU-intensive hashing to libuv threads via `crypto.scrypt`.
- **Bounded Concurrency:** Concurrency is hard-limited to 2 active hash tasks (`MAX_HASHING = 2`).
- **Bounded Queue with Fast Rejection:** The hash queue caps pending requests at 50 (`MAX_HASH_QUEUE = 50`). When the queue fills during a distributed brute-force or DoS attack, the server sheds excess requests with `HTTP 503 Service Unavailable`, guaranteeing that HTTP routing and DNS lookups never stall.

---

## 3. Container & Operating System Hardening

### 3.1 Hardened Linux Container Configuration (`deploy/Dockerfile.worker`)
The worker container is configured in compliance with the CIS Docker Benchmark:

```dockerfile
# Alpine Minimal Linux Base (Reduced Attack Surface)
FROM alpine:3.20

# Run as dedicated unprivileged user
RUN adduser -D -u 10001 scanuser
USER 10001:10001
ENV HOME=/tmp
WORKDIR /app
```

### 3.2 Docker Runtime Execution Flags (`src/platform/sandbox.js`)
When launching Docker workers, the engine applies the following strict security flags:

```bash
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 1g --memory-swap 1g \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --network vulnsight-scan \
  --mount type=bind,source=/path/to/workspace,target=/work,readonly \
  --workdir /work \
  vulnsight-worker:latest
```

| Security Flag | Technical Benefit / Hardening Defense |
| :--- | :--- |
| `--user 10001:10001` | Runs as unprivileged non-root user; root exploits fail immediately. |
| `--read-only` | The container root filesystem is completely immutable; malware cannot write binaries. |
| `--cap-drop ALL` | Strips all Linux capabilities (including `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_CHOWN`). |
| `--security-opt no-new-privileges` | Prevents child processes from gaining elevated privileges via setuid binaries. |
| `--pids-limit 256` | Prevents fork bombs and process table exhaustion attacks. |
| `--memory 1g --cpus 1` | Caps hardware resource utilization, protecting neighboring tenant workloads. |
| `--tmpfs /tmp:noexec,nosuid` | Prevents execution of downloaded scripts or ELF binaries from `/tmp`. |
| `target=/work,readonly` | The repository workspace is mounted read-only for scanners that support it. |

---

## 4. Workspace & Filesystem Sanitization

Before scanners analyze checked-out code, the workspace is sanitized:
1. **Complete `.git` Deletion:** The hidden `.git` folder is recursively deleted, neutralizing hostile Git hooks (`pre-commit`, `post-checkout`, `fsmonitor`).
2. **Symlink Purge:** Recursive directory traversal scans for symbolic links (`fs.lstatSync().isSymbolicLink()`). Every discovered symlink is deleted via `fs.unlinkSync()`, preventing scanners from traversing into host system files (`/etc/passwd`, cloud secrets).
3. **Workspace Quotas:**
   - Maximum uncompressed size: **500 MB**
   - Maximum total files: **100,000 files**
   - Maximum execution runtime: **15 minutes**

---

## 5. Network & Egress Hardening

1. **Proxy CONNECT-Only Mode:** Outbound traffic from workers is restricted to port 443 via the CONNECT method. Plain HTTP methods (`GET`, `POST`) are permanently disabled.
2. **DNS Anti-Rebinding Check:** The proxy resolves hostnames internally. If any IP address resolves to private or loopback ranges, the socket is dropped before connecting.
3. **Direct Egress Blockade:** Network Security Groups in Azure and `--internal` bridge flags in Docker block all direct internet gateways. Workers are functionally cut off from the internet except through the proxy allowlist.

---

## 6. Database Hardening

1. **Write-Ahead Logging (WAL):** SQLite is initialized with `PRAGMA journal_mode = WAL;`, enabling non-blocking concurrent readers while maintaining atomic single-writer transactions.
2. **Foreign Key Enforcement:** Foreign key cascades are explicitly enforced with `PRAGMA foreign_keys = ON;`.
3. **Parameterized Queries Only:** Every database query in `src/platform/service.js` uses prepared statements with parameter placeholders (`?`). Dynamic SQL string concatenation is strictly prohibited.
