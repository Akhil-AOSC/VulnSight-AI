# Deployment Architecture & Guide

> **Document ID:** VS-DOC-29  
> **Status:** Approved Baseline  
> **Version:** 1.0.0  
> **Date:** November 2026  
> **Target Audience:** DevOps Engineers, Cloud Administrators, SREs  

---

## 1. Deployment Overview & Topologies

VulnSight AI supports two primary production deployment topologies:
1. **Azure Cloud-Native PaaS (Recommended):** Leverages Azure Container Apps, Container Apps Jobs, Key Vault, and Private Endpoints with Network Security Groups.
2. **On-Premise / Sovereign Docker Host:** Leverages hardened Docker containers, an internal Linux bridge network, and an automated egress proxy.

```
+-----------------------------------------------------------------------------------+
|                        VulnSight AI Deployment Options                            |
+-----------------------------------------------------------------------------------+
|  Topology A: Azure Cloud-Native  | Bicep IaC, ACA, ACA Jobs, Key Vault, ACR, LRS  |
|  Topology B: Hardened Docker     | docker-compose, setup-egress.sh, Internal Net  |
|  Topology C: Local Development   | node bin/vulnsight.js serve (In-process mode)  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Option A: Azure Cloud-Native Deployment Guide

### 2.1 Prerequisites
- Active Azure Subscription with Owner or User Access Administrator + Contributor permissions.
- Azure CLI (`az`) installed and authenticated via `az login`.
- Azure Bicep CLI (`bicep`) version 0.28.0 or newer.
- Container images built and pushed to a container registry:
  - `vulnsight-api:latest`
  - `vulnsight-worker:latest`

### 2.2 Step 1: Generate Cryptographic Master Key
The platform requires a 32-byte cryptographically secure master key (base64-encoded) to encrypt customer Git tokens:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
# Output Example: kF8/3jX...Qz4=
```

### 2.3 Step 2: Zero-Touch Dry Run (`what-if`)
Before creating any billable cloud resources, execute the deployment preview script:
```bash
az account set --subscription "<YOUR-SUBSCRIPTION-ID>"
chmod +x deploy/azure/whatif.sh
./deploy/azure/whatif.sh eastus
```
Carefully review the complete `what-if` output:
- **Resources to be Created:** Virtual Network, 4 Subnets, 3 Managed Identities, Key Vault, Storage Account, ACR Premium, Log Analytics, Application Insights, Container Apps Environment, API Container App, Scan Job.
- **Role Assignments:** `AcrPull`, `Container Apps Jobs Operator`, `Storage Blob Data Contributor`, `Key Vault Secrets User`.

### 2.4 Step 3: Execute Subscription Deployment
Once approved, execute the subscription-level deployment:
```bash
az deployment sub create \
  --location eastus \
  --template-file deploy/azure/subscription.bicep \
  --parameters \
    location=eastus \
    prefix=vulnsight \
    apiImage="myregistry.azurecr.io/vulnsight-api:1.0.0" \
    workerImage="myregistry.azurecr.io/vulnsight-worker:1.0.0" \
    masterKey="<GENERATED_MASTER_KEY_BASE64>"
```

### 2.5 Step 4: Post-Deployment Egress Verification
Before scanning production code, verify the egress boundary from within an active worker job:
1. Verify that direct outbound connections to the internet fail:
   `curl https://google.com` $\rightarrow$ **Connection refused / timed out**.
2. Verify that connections to cloud metadata fail:
   `curl http://169.254.169.254/latest/meta-data/` $\rightarrow$ **Connection refused**.
3. Verify that the egress proxy routes allowlisted hosts:
   `curl -x http://vulnsight-proxy:3128 https://api.osv.dev` $\rightarrow$ **HTTP 200 OK**.

---

## 3. Option B: On-Premise Docker Host Deployment Guide

For air-gapped, on-premise, or non-Azure environments:

### 3.1 Step 1: Bootstrap the Isolated Network and Proxy
Execute the egress configuration script:
```bash
chmod +x deploy/docker/setup-egress.sh
./deploy/docker/setup-egress.sh
```
This script creates the internal `vulnsight-scan` network with no default gateway and boots `vulnsight-egress-proxy`.

### 3.2 Step 2: Configure Environment Variables (`.env`)
Create an environment file on the host:
```ini
VULNSIGHT_SANDBOX=docker
VULNSIGHT_WORKER_IMAGE=vulnsight-worker:latest
VULNSIGHT_EGRESS_PROXY=http://vulnsight-egress-proxy:3128
VULNSIGHT_MASTER_KEY=<GENERATED_32_BYTE_BASE64_KEY>
VULNSIGHT_DATA=/var/lib/vulnsight/data
VULNSIGHT_TRUST_PROXY=1
VULNSIGHT_HSTS=1
```

### 3.3 Step 3: Launch with Docker Compose
```bash
docker compose -f deploy/docker-compose.yml up -d
```
The platform will listen on port 4400 on the host, with worker scans executing inside short-lived sibling containers on the internal bridge network.

---

## 4. Option C: Local Developer Sandbox Deployment

For local testing and evaluation:
```bash
git clone https://github.com/vulnsight/vulnsight-ai.git
cd vulnsight-ai
npm install
node bin/vulnsight.js serve
```
The server starts at `http://localhost:4400` in `process` sandbox mode using an embedded SQLite database stored in `.vulnsight-data/`.

> [!WARNING]
> `process` mode does not isolate the host filesystem. Never scan untrusted public repositories in `process` mode.
