# GCP Authentication Setup

How to configure Google Cloud Platform credentials for AuditKit scanning.

---

## Quick Start

```bash
# Option 1: gcloud CLI (easiest)
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-project-id

# Test it works
gcloud projects describe $GOOGLE_CLOUD_PROJECT

# Run scan
./auditkit scan -provider gcp -framework soc2
```

---

## Authentication Methods

AuditKit supports three authentication methods for GCP:

### Option 1: gcloud CLI (Recommended)

**Best for:** Local scanning, development

```bash
# Install gcloud CLI
# macOS: brew install google-cloud-sdk
# Linux: snap install google-cloud-cli
# Windows: Download from cloud.google.com/sdk

# Login and create application default credentials
gcloud auth application-default login

# List projects
gcloud projects list

# Set project
export GOOGLE_CLOUD_PROJECT=my-project-id
# Or use alternative variable name
export GCP_PROJECT=my-project-id
```

### Option 2: Service Account Key (JSON)

**Best for:** CI/CD pipelines, automation

```bash
# Set path to service account key file
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
export GOOGLE_CLOUD_PROJECT=my-project-id

# Run scan
./auditkit scan -provider gcp -framework soc2
```

**How to create service account:** See [Creating a Service Account](#creating-a-service-account-for-auditkit) below

### Option 3: GCE Metadata (Compute Engine)

**Best for:** Running AuditKit on GCP infrastructure

No configuration needed - automatically detected if running on:
- Compute Engine VM with service account
- GKE cluster with Workload Identity
- Cloud Run with service account
- Cloud Functions with service account

```bash
# Set project ID (required even with metadata)
export GOOGLE_CLOUD_PROJECT=my-project-id

# Run scan - credentials auto-detected
./auditkit scan -provider gcp -framework soc2
```

---

## Required IAM Permissions

AuditKit needs **Viewer** role to scan your GCP project.

### Viewer Role (Recommended)

**Role:** `roles/viewer`  
**Scope:** Project level

This provides read-only access to all resources in the project.

```bash
# Grant Viewer role to service account
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditkit@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

### Custom Role (Least Privilege)

If you need tighter control:

```yaml
title: "AuditKit Scanner"
description: "Read-only access for AuditKit compliance scanning"
stage: "GA"
includedPermissions:
- container.clusters.get
- container.clusters.list
- bigquery.datasets.get
- bigquery.datasets.list
- storage.buckets.get

(And add `gcloud services enable container.googleapis.com` and `gcloud services enable bigquery.googleapis.com` to the API-enablement block at lines 302-308.)
- storage.buckets.getIamPolicy
- storage.buckets.list
- compute.instances.get
- compute.instances.list
- compute.firewalls.get
- compute.firewalls.list
- compute.networks.get
- compute.networks.list
- iam.serviceAccounts.get
- iam.serviceAccounts.list
- iam.serviceAccountKeys.get
- iam.serviceAccountKeys.list
- sql.instances.get
- sql.instances.list
- cloudkms.cryptoKeys.get
- cloudkms.cryptoKeys.list
- cloudkms.keyRings.get
- cloudkms.keyRings.list
- logging.logEntries.list
- logging.sinks.get
- logging.sinks.list
```

Create the role:
```bash
gcloud iam roles create auditkit_scanner \
  --project=PROJECT_ID \
  --file=auditkit-role.yaml
```

---

## Creating a Service Account for AuditKit

### Step 1: Create Service Account

```bash
# Create service account
gcloud iam service-accounts create auditkit-scanner \
  --display-name="AuditKit Scanner" \
  --description="Read-only access for compliance scanning"
```

### Step 2: Grant Viewer Role

```bash
# Grant Viewer role at project level
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

### Step 3: Create Key File

```bash
# Generate JSON key file
gcloud iam service-accounts keys create ~/auditkit-key.json \
  --iam-account=auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com

# Secure the key file
chmod 600 ~/auditkit-key.json
```

### Step 4: Configure Environment Variables

```bash
export GOOGLE_APPLICATION_CREDENTIALS=~/auditkit-key.json
export GOOGLE_CLOUD_PROJECT=PROJECT_ID
```

### Step 5: Test Authentication

```bash
# Verify credentials work
gcloud auth list
gcloud projects describe $GOOGLE_CLOUD_PROJECT
```

### Step 6: Run Scan

```bash
./auditkit scan -provider gcp -framework soc2
```

---

## Multi-Project Scanning

**Free version:** Scan one project at a time

**Pro version:** Scan entire Organization/Folder automatically

### Community Edition - Switching Projects

```bash
# Scan first project
export GOOGLE_CLOUD_PROJECT=project-1
./auditkit scan -provider gcp -framework soc2 -output project1-results.json

# Scan second project
export GOOGLE_CLOUD_PROJECT=project-2
./auditkit scan -provider gcp -framework soc2 -output project2-results.json
```

### Pro Version - Organization Scanning

```bash
# Scan entire GCP Organization (Pro only)
./auditkit-pro scan -provider gcp -framework soc2 --scan-all

# Limit concurrency
./auditkit-pro scan -provider gcp --scan-all --max-concurrent 5

# Generate consolidated report
./auditkit-pro scan -provider gcp --scan-all -format pdf -output org-report.pdf
```

**Requirements for Organization scanning:**
- Service account needs `roles/viewer` at Organization or Folder level
- `resourcemanager.folders.list` and `resourcemanager.projects.list` permissions

**[Upgrade to Pro →](https://auditkit.io/pro/)**

---

## Troubleshooting

### "Error: GCP project not found"

**Cause:** Project ID not set

**Solution:**
```bash
# List projects
gcloud projects list

# Set project
export GOOGLE_CLOUD_PROJECT=correct-project-id
```

### "Error: Application default credentials not found"

**Cause:** Not authenticated

**Solution:**
```bash
gcloud auth application-default login
```

### "Error: Permission denied"

**Cause:** Service account lacks Viewer role

**Solution:**
```bash
# Grant Viewer role
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:SERVICE_ACCOUNT_EMAIL" \
  --role="roles/viewer"
```

### "Error: Service account key expired"

**Cause:** Service account key is too old (>90 days)

**Solution:**
```bash
# List keys
gcloud iam service-accounts keys list \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Delete old key
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Create new key
gcloud iam service-accounts keys create ~/new-key.json \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Update environment variable
export GOOGLE_APPLICATION_CREDENTIALS=~/new-key.json
```

### "Error: API not enabled"

**Cause:** Required GCP APIs not enabled

**Solution:**
```bash
# Enable required APIs
gcloud services enable cloudresourcemanager.googleapis.com
gcloud services enable iam.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable cloudkms.googleapis.com
gcloud services enable logging.googleapis.com
```

---

## Security Best Practices

### 1. Use Dedicated Service Account

Don't use your personal credentials or default service accounts.

```bash
gcloud iam service-accounts create auditkit-scanner
```

### 2. Rotate Service Account Keys Regularly

```bash
# Every 90 days
gcloud iam service-accounts keys create new-key.json \
  --iam-account=auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com

# Delete old key
gcloud iam service-accounts keys delete OLD_KEY_ID \
  --iam-account=auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com
```

### 3. Enable Cloud Audit Logging

Monitor what AuditKit accesses:

```bash
# Cloud Audit Logs automatically track all API calls
# View logs in Cloud Console > Logging > Logs Explorer
# Filter: protoPayload.authenticationInfo.principalEmail="auditkit-scanner@..."
```

### 4. Use Read-Only Access

AuditKit only needs Viewer role - never grant Editor or Owner.

### 5. Store Keys Securely

```bash
# Secure key file permissions
chmod 600 ~/auditkit-key.json

# Don't commit keys to version control
echo "*.json" >> .gitignore
```

---

## Finding Your Project ID

### Method 1: List All Projects

```bash
gcloud projects list
```

### Method 2: Get Current Project

```bash
gcloud config get-value project
```

### Method 3: From Console

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click project selector at top
3. Copy Project ID column

---

## GCP Service Coverage

**Free version includes:**
- Cloud Storage (6 checks)
- Cloud IAM (12 checks)
- Compute Engine (12 checks)
- VPC Networks (11 checks)
- Cloud SQL (10 checks)
- Cloud KMS (2 checks)
- Cloud Logging (4 checks)
- GKE (5 CIS checks)
- BigQuery (2 CIS checks)

**Pro version adds:**
- Deep GKE Security (10 further checks, 15 in total)
- Vertex AI Compliance (10 checks)

**[View full service coverage →](../providers/gcp.md)**

---

## Next Steps

- **[Run your first scan →](../getting-started.md)**
- **[CLI Reference →](../cli-reference.md)**
- **[GCP Service Coverage →](../providers/gcp.md)**
- **[Framework Guide →](../frameworks/)**
