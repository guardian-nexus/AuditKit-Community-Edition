# GCP Service Coverage

What AuditKit scans in Google Cloud Platform.

---

## Overview

**Community Edition:** 173 controls across 8 core services  
**Pro version:** 285 controls, including 15 GKE and 10 Vertex AI checks

**Supported frameworks:**
- SOC2 Type II
- PCI-DSS v4.0.1
- CMMC Level 1 and Level 2: all 110 practices reported; 11 reach a verdict on GCP (4 of the 17 Level 1, plus 7 Level 2); Pro adds deeper automation and the evidence package
- NIST 800-53 Rev 5 (141 controls, derived via crosswalk)
- HIPAA (30 safeguards, derived via crosswalk)

---

## Core Services (Free & Pro)

Every control the service checks emit, read from the scanner's source. The
identifier is the one the report carries; the framework pages say which
requirement each maps to.

### IAM

**Controls checked:** 12

- **CC6.1** - Service Account Key Rotation
- **CC6.3** - Primitive Role Usage
- **CIS-GCP-1.13** - API Keys Usage
- **CIS-GCP-1.9** - Service Account Admin Separation
- **CIS-GCP-1.2** - Corporate Login Enforcement
- **GCP-GKE-01** - GKE Workload Identity
- **GCP-IAM-03** - Default Service Account Disabled
- **CIS-GCP-1.16** - API Keys Rotated Every 90 Days
- **GCP-IAM-02** - Separation of Duties
- **CIS-GCP-1.10** - KMS Keys Not Publicly Accessible
- **CIS-GCP-1.12** - KMS Role Separation of Duties
- **CIS-GCP-1.7** - Service Account Roles at Project Level

### VPC

**Controls checked:** 12

- **CC6.6** - VPC Firewall Rules Check
- **CIS-GCP-3.1** - Default VPC Network Deleted
- **CC6.1** - Private Google Access
- **CIS-GCP-3.10** - VPC Flow Logs
- **CIS-GCP-3.3** - DNSSEC on Cloud DNS
- **CIS-GCP-2.17** - Load Balancer Logging
- **CIS-GCP-3.2** - Legacy Networks
- **CIS-GCP-3.6** - SSH Access from Internet
- **CIS-GCP-3.7** - RDP Access from Internet
- **GCP-NET-01** - HTTPS Load Balancer Configuration
- **CIS-GCP-3.11** - SSL Policy TLS Version
- **CIS-GCP-3.4** - DNSSEC Algorithm Not RSASHA1

### Compute Engine

**Controls checked:** 11

- **CC6.7** - Disk Encryption with CMEK
- **CC6.6** - Compute Instances - Public IP Addresses
- **CC7.1** - OS Patch Management
- **CIS-GCP-4.4** - OS Login Enabled
- **CIS-GCP-4.8** - Shielded VM Features
- **CIS-GCP-4.5** - Serial Port Access Disabled
- **CIS-GCP-4.6** - IP Forwarding Disabled
- **CIS-GCP-4.3** - Project-Wide SSH Keys
- **CIS-GCP-4.2** - Default SA Full Access
- **CIS-GCP-4.11** - Confidential Computing
- **CIS-GCP-4.9** - No Public IP Addresses

### Cloud SQL

**Controls checked:** 10

- **CC6.6** - Cloud SQL - Public IP
- **A1.2** - Cloud SQL - Automated Backups
- **CIS-GCP-6.8** - SQL Backup Retention
- **CC6.1** - Cloud SQL - SSL Enforcement
- **GCP-SQL-01** - PostgreSQL log_checkpoints Flag
- **CIS-GCP-6.2.2** - PostgreSQL log_connections Flag
- **CIS-GCP-6.1.2** - MySQL skip_show_database Flag
- **CIS-GCP-6.2.3** - PostgreSQL log_disconnections Flag
- **CIS-GCP-6.2.7** - PostgreSQL log_min_duration_statement Flag
- **CIS-GCP-6.3.6** - SQL Server Trace Flag 3625

### Cloud Storage

**Controls checked:** 6

- **CC6.1** - GCS Bucket Public Access Check
- **CC6.7** - GCS Bucket Encryption Check
- **A1.2** - GCS Bucket Versioning Check
- **CC7.2** - GCS Bucket Logging Check
- **CIS-GCP-5.2** - GCS Uniform Bucket-Level Access
- **GCP-STOR-01** - GCS Bucket Retention Policy

### GKE

**Controls checked:** 5

- **CIS-GKE-5.1.3** - GKE Binary Authorization
- **CIS-GKE-4.3.1** - GKE Network Policies
- **GCP-GKE-02** - Kubernetes Dashboard Disabled
- **CIS-GKE-4.2.1** - Pod Security Policy
- **CIS-GKE-5.2.2** - GKE Workload Identity

### Cloud Logging

**Controls checked:** 4

- **CIS-GCP-2.1** - Cloud Audit Logs Enabled
- **CIS-GCP-2.3** - Log Sinks Configured
- **CIS-GCP-2.4** - Log Retention Period
- **CIS-GCP-2.13** - DNS Logging Enabled

### BigQuery

**Controls checked:** 3

- **CIS-GCP-7.1** - BigQuery Datasets Not Public
- **CIS-GCP-7.3** - BigQuery CMEK Encryption
- **CIS-GCP-7.2** - BigQuery Tables CMEK Encryption

### Cloud KMS

**Controls checked:** 2

- **CIS-GCP-1.11** - KMS Key Rotation
- **CIS-GCP-1.12** - KMS Separation of Duties

### Framework suites

The framework suites add their own identifiers on top of the service checks: CIS (10), CMMC (9), PCI DSS (35), SOC 2 (23), vulnerability coverage (2). Those are described on the framework pages rather than here.


## Advanced Services

### GKE (Google Kubernetes Engine) - 5 checks free, 15 in Pro

The Community Edition covers CIS GCP 8.1-8.5 (Binary Authorization, Network Policies, Kubernetes Dashboard, Pod Security Policy, Workload Identity). AuditKit Pro adds ten deeper GKE security checks.

**Pro version required for the deep GKE checks:** $297/month

#### Workload Identity Validation (Community Edition, CIS GCP 8.5)
**What it checks:**
- Workload Identity enabled on clusters
- Pods use Workload Identity vs node service accounts
- Service account bindings configured

**Pass criteria:**
- Workload Identity enabled
- No pods use node service accounts
- Proper IAM bindings

#### Binary Authorization
**What it checks:**
- Binary Authorization enabled
- Container images signed
- Only trusted images deployed

**Pass criteria:**
- Binary Authorization enforced
- All images have attestations
- Policy violations blocked

#### Private Cluster Configuration
**What it checks:**
- Control plane private endpoints
- Nodes use private IPs only
- Authorized networks for access

**Pass criteria:**
- Private cluster enabled
- No public control plane access
- VPN/Cloud Interconnect for access

#### Network Policy Validation
**What it checks:**
- Network policies configured
- Pod-to-pod communication restricted
- Default deny policies

**Pass criteria:**
- Network policies enabled
- Explicit allow rules only
- Default deny in place

#### Shielded Nodes Assessment
**What it checks:**
- Shielded GKE nodes enabled
- Secure Boot enabled
- Integrity monitoring active

**Pass criteria:**
- All nodes are shielded
- Secure Boot verified
- Integrity alerts configured

#### Pod Security Standards
**What it checks:**
- Pod Security Policy/Standards enforced
- Privileged containers blocked
- Host namespace usage restricted

**Pass criteria:**
- Pod Security Standards enforced
- Restricted policy baseline
- Exceptions documented

#### Container-Optimized OS
**What it checks:**
- Nodes run Container-Optimized OS
- Automatic updates enabled
- Minimal OS footprint

**Pass criteria:**
- All nodes use COS
- Auto-upgrade enabled
- Security patches applied

#### Vulnerability Scanning
**What it checks:**
- Container scanning enabled
- Vulnerabilities detected and tracked
- Critical CVEs addressed

**Pass criteria:**
- Scanning enabled
- No critical/high vulnerabilities
- Remediation tracking

#### Secrets Management
**What it checks:**
- Kubernetes secrets encrypted at rest
- Secret Manager integration
- No secrets in environment variables

**Pass criteria:**
- CMEK encryption for secrets
- Secret Manager used for sensitive data
- Secrets never in plaintext

#### GKE Audit Logging
**What it checks:**
- GKE audit logs enabled
- API server logs collected
- Log retention configured

**Pass criteria:**
- All audit log types enabled
- Logs exported for analysis
- 1+ year retention

**[Try Pro free for 14 days →](https://auditkit.io/pro/)**

---

### Vertex AI - 10 Checks

**Pro version required:** $297/month

#### Model Encryption at Rest
**What it checks:**
- Model artifacts encrypted with CMEK
- Training data encrypted
- Managed datasets use encryption

**Pass criteria:**
- All models use CMEK
- Training data encrypted
- Keys managed in Cloud KMS

#### Endpoint Authentication
**What it checks:**
- Prediction endpoints require authentication
- IAM controls on endpoints
- No public prediction endpoints

**Pass criteria:**
- All endpoints require auth
- IAM roles properly scoped
- No anonymous access

#### Model Versioning Controls
**What it checks:**
- Model versioning enabled
- Version tracking and lineage
- Rollback capabilities

**Pass criteria:**
- Versions tracked
- Lineage documented
- Rollback tested

#### Audit Logging Configuration
**What it checks:**
- Vertex AI audit logs enabled
- Training and prediction logged
- Log export configured

**Pass criteria:**
- All operations logged
- Logs retained 1+ year
- Exported for analysis

#### Data Residency Compliance
**What it checks:**
- Data location constraints
- Regional endpoints used
- Cross-region restrictions

**Pass criteria:**
- Data stays in specified region
- Compliance with data residency laws
- Documented controls

#### Model Explainability Features
**What it checks:**
- Explainable AI features enabled
- Feature attributions available
- Model transparency documented

**Pass criteria:**
- Explainability enabled
- Attributions generated
- Documentation complete

#### Training Data Security
**What it checks:**
- Access controls on training datasets
- Data versioning and lineage
- PII detection and handling

**Pass criteria:**
- Strict access controls
- Data lineage tracked
- PII properly handled

#### Prediction Endpoint Security
**What it checks:**
- HTTPS-only endpoints
- Rate limiting configured
- DDoS protection enabled

**Pass criteria:**
- HTTPS enforced
- Rate limits set
- Cloud Armor configured

#### VPC Service Controls
**What it checks:**
- Service perimeters configured
- Vertex AI in VPC-SC perimeter
- Data exfiltration prevention

**Pass criteria:**
- VPC-SC enabled
- Vertex AI protected
- Policies enforced

#### CMEK for Datasets
**What it checks:**
- Managed datasets use CMEK
- Customer-controlled encryption
- Key rotation enabled

**Pass criteria:**
- All datasets use CMEK
- Keys managed properly
- Rotation scheduled

**[Try Pro free for 14 days →](https://auditkit.io/pro/)**

---

## Services Not Yet Supported

**Coming in future releases:**
- Cloud Functions
- Cloud Run
- Pub/Sub
- Dataflow
- Cloud Spanner

(BigQuery is already covered — see CIS GCP 7.1 and 7.2.)

**Vote for features:** [GitHub Issues](https://github.com/guardian-nexus/AuditKit-Community-Edition/issues)

---

## Running GCP Scans

### Community Edition

```bash
# Authenticate
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=my-project-id

# Scan for SOC2
./auditkit scan -provider gcp -framework soc2

# Scan for PCI-DSS
./auditkit scan -provider gcp -framework pci

# Scan for CMMC Level 1
./auditkit scan -provider gcp -framework cmmc

# Generate report
./auditkit scan -provider gcp -framework soc2 -format pdf -output gcp-report.pdf
```

### Pro Version

```bash
# Authenticate
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=my-project-id

# Scan for CMMC Level 2 (includes GKE + Vertex AI)
./auditkit-pro scan -provider gcp -framework cmmc

# Scan entire organization (Pro only)
./auditkit-pro scan -provider gcp -framework soc2 --scan-all

# Generate comprehensive report
./auditkit-pro scan -provider gcp -framework soc2 -format pdf -output gcp-pro-report.pdf
```

---

## Next Steps

- **[GCP Setup Guide →](../setup/gcp.md)**
- **[Getting Started →](../getting-started.md)**
- **[CLI Reference →](../cli-reference.md)**
- **[Try Pro for GKE/Vertex AI →](https://auditkit.io/pro/)**
