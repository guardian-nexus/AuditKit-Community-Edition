# GCP Service Coverage

What AuditKit scans in Google Cloud Platform.

---

## Overview

**Community Edition:** 135 controls across 8 core services  
**Pro version:** 210+ automated checks (178 core + 32 advanced)

**Supported frameworks:**
- SOC2 Type II
- PCI-DSS v4.0.1
- CMMC Level 1 and Level 2 (Pro)
- NIST 800-53 Rev 5
- HIPAA (17 safeguards, derived via crosswalk)

---

## Core Services (Free & Pro)

### Cloud Storage (GCS) - 4 Checks

#### CC6.2 - Public Access Controls
**What it checks:**
- Buckets with public access (allUsers or allAuthenticatedUsers)
- Bucket-level IAM policies allowing public read/write
- Object-level ACLs granting public access

**Pass criteria:**
- No buckets allow public access
- Bucket policies restrict to authorized users only
- Object ACLs are private

**Fix command:**
```bash
# Remove public access from bucket
gsutil iam ch -d allUsers:objectViewer gs://BUCKET_NAME
gsutil iam ch -d allAuthenticatedUsers:objectViewer gs://BUCKET_NAME

# Set uniform bucket-level access
gsutil uniformbucketlevelaccess set on gs://BUCKET_NAME
```

#### CC8.1 - Bucket Encryption (CMEK)
**What it checks:**
- Default encryption enabled on buckets
- Customer-managed encryption keys (CMEK) used
- Key rotation configured

**Pass criteria:**
- All buckets use CMEK for encryption
- Keys managed in Cloud KMS
- Automatic key rotation enabled

**Fix command:**
```bash
# Enable CMEK on bucket
gsutil encryption set \
  -k projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY \
  gs://BUCKET_NAME
```

#### CC7.3 - Uniform Bucket-Level Access
**What it checks:**
- Uniform bucket-level access enabled
- No object-level ACLs in use
- IAM-only access control

**Pass criteria:**
- All buckets use uniform bucket-level access
- Object ACLs disabled
- Access managed through IAM

**Fix command:**
```bash
gsutil uniformbucketlevelaccess set on gs://BUCKET_NAME
```

#### CC7.2 - Object Versioning
**What it checks:**
- Versioning enabled on buckets
- Previous versions retained
- Version lifecycle configured

**Pass criteria:**
- Versioning enabled on critical buckets
- Version retention policy configured

**Fix command:**
```bash
gsutil versioning set on gs://BUCKET_NAME
```

---

### Cloud IAM - 5 Checks

#### CC6.1 - Service Account Key Age
**What it checks:**
- Service account keys older than 90 days (PCI-DSS requirement)
- Number of keys per service account
- Last used date for keys

**Pass criteria:**
- All service account keys rotated within 90 days
- No unused keys present
- Maximum 2 keys per service account

**Fix command:**
```bash
# Create new key
gcloud iam service-accounts keys create new-key.json \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Delete old key
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL
```

#### CC6.7 - Primitive Role Usage
**What it checks:**
- Use of Owner, Editor, or Viewer roles (overly permissive)
- Predefined or custom roles preferred
- Principle of least privilege

**Pass criteria:**
- No primitive roles (Owner/Editor/Viewer) in use
- All access uses predefined or custom roles
- Roles follow least privilege

**Fix command:**
```bash
# Remove primitive role
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=user:USER_EMAIL \
  --role=roles/editor

# Add specific role
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=user:USER_EMAIL \
  --role=roles/compute.instanceAdmin.v1
```

#### CC6.6 - User MFA Enforcement
**What it checks:**
- 2-Step Verification enforced in Google Workspace
- Number of users without MFA
- Admin accounts require MFA

**Pass criteria:**
- 2-Step Verification enforced for all users
- Admin accounts use security keys

**Fix (manual verification):**
- Enforce 2-Step Verification in Google Workspace Admin Console
- Navigate to: https://admin.google.com/ac/security/2sv
- Requires Google Workspace (cannot be automated via API)

#### CC6.3 - Service Account Key Count
**What it checks:**
- Number of active keys per service account
- Unused keys present
- Key creation patterns

**Pass criteria:**
- Maximum 2 keys per service account
- All keys actively used

**Fix command:**
```bash
# List keys
gcloud iam service-accounts keys list \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Delete unused key
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL
```

#### CC6.8 - Service Account Permissions
**What it checks:**
- Service accounts with excessive permissions
- Service accounts used by humans (anti-pattern)
- Cross-project service account usage

**Pass criteria:**
- Service accounts follow least privilege
- No human use of service accounts
- Workload Identity used where possible

**Fix command:**
```bash
# Review and restrict permissions
gcloud projects get-iam-policy PROJECT_ID

# Remove unnecessary roles
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:SERVICE_ACCOUNT_EMAIL \
  --role=ROLE_TO_REMOVE
```

---

### Compute Engine - 3 Checks

#### CC6.4 - Public IP Assignments
**What it checks:**
- VMs with external IP addresses
- Unnecessary public exposure
- Private-only instances preferred

**Pass criteria:**
- Only necessary VMs have external IPs
- Internal-only VMs use Cloud NAT for outbound
- Bastion hosts properly configured

**Fix command:**
```bash
# Remove external IP
gcloud compute instances delete-access-config INSTANCE_NAME \
  --zone=ZONE \
  --access-config-name="External NAT"
```

#### CC7.1 - OS Patch Management
**What it checks:**
- OS Config management enabled
- Patch compliance status
- Automatic patch deployment configured

**Pass criteria:**
- OS Config enabled on all VMs
- Patches applied within 30 days
- Automated patching scheduled

**Fix (manual verification):**
- Enable OS Config in console
- Configure patch management policies
- Schedule patch windows

#### CC8.1 - Disk Encryption
**What it checks:**
- Boot disks encrypted at rest
- Data disks encrypted
- Customer-managed keys (CMEK) used

**Pass criteria:**
- All disks encrypted (default in GCP)
- CMEK used for sensitive data
- Keys managed in Cloud KMS

**Fix command:**
```bash
# Create disk with CMEK
gcloud compute disks create DISK_NAME \
  --kms-key=projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY
```

---

### VPC Networks - 3 Checks

#### CC6.5 - Firewall Rule Restrictions
**What it checks:**
- Overly permissive firewall rules
- Rules allowing 0.0.0.0/0 access
- Unused firewall rules

**Pass criteria:**
- No rules allowing 0.0.0.0/0 for production services
- Specific IP ranges defined
- Unused rules removed

**Fix command:**
```bash
# Delete overly permissive rule
gcloud compute firewall-rules delete RULE_NAME

# Create restricted rule
gcloud compute firewall-rules create RULE_NAME \
  --allow=tcp:443 \
  --source-ranges=SPECIFIC_IP_RANGE
```

#### CC6.9 - Default Network Usage
**What it checks:**
- Use of default VPC network
- Custom VPCs preferred
- Network segmentation

**Pass criteria:**
- Default network not in use
- Custom VPCs configured
- Network segmentation implemented

**Fix command:**
```bash
# Create custom VPC
gcloud compute networks create custom-vpc --subnet-mode=custom

# Delete default network (after migration)
gcloud compute networks delete default
```

#### SC.1.175 - Open Ingress Rules
**What it checks:**
- Firewall rules allowing 0.0.0.0/0 ingress
- Ports exposed to internet
- Unnecessary services accessible

**Pass criteria:**
- No production services exposed to 0.0.0.0/0
- Only specific IPs allowed
- Bastion/jump hosts properly configured

**Fix command:**
```bash
# Update rule to specific IPs
gcloud compute firewall-rules update RULE_NAME \
  --source-ranges=SPECIFIC_IP/32
```

---

### Cloud SQL - 4 Checks

#### CC6.10 - Public IP Exposure
**What it checks:**
- Cloud SQL instances with public IPs
- Authorized networks configured
- Private IP usage

**Pass criteria:**
- Instances use private IP only
- If public IP required, authorized networks configured
- Cloud SQL Proxy recommended

**Fix command:**
```bash
# Disable public IP
gcloud sql instances patch INSTANCE_NAME \
  --no-assign-ip

# Enable private IP
gcloud sql instances patch INSTANCE_NAME \
  --network=projects/PROJECT/global/networks/VPC_NAME
```

#### CC8.2 - SSL/TLS Enforcement
**What it checks:**
- SSL/TLS required for connections
- Certificate validation enabled
- Encrypted connections only

**Pass criteria:**
- SSL/TLS enforced on all instances
- No unencrypted connections allowed

**Fix command:**
```bash
gcloud sql instances patch INSTANCE_NAME \
  --require-ssl
```

#### CC7.4 - Automated Backups
**What it checks:**
- Automated backups enabled
- Backup retention period
- Point-in-time recovery

**Pass criteria:**
- Automated backups enabled
- 7+ day retention (30 days for PCI-DSS)
- Point-in-time recovery enabled

**Fix command:**
```bash
gcloud sql instances patch INSTANCE_NAME \
  --backup-start-time=02:00 \
  --enable-bin-log
```

#### CC9.1 - High Availability
**What it checks:**
- High availability configuration
- Regional instances
- Automatic failover

**Pass criteria:**
- HA enabled for production databases
- Regional configuration
- Tested failover procedures

**Fix command:**
```bash
gcloud sql instances patch INSTANCE_NAME \
  --availability-type=REGIONAL
```

---

### Cloud KMS - 2 Checks

#### CC8.3 - Automatic Key Rotation
**What it checks:**
- Key rotation enabled
- Rotation period configured
- Key version management

**Pass criteria:**
- Automatic rotation enabled
- 90-day rotation period (PCI-DSS)
- Key versions tracked

**Fix command:**
```bash
# Enable rotation
gcloud kms keys update KEY_NAME \
  --keyring=KEYRING \
  --location=LOCATION \
  --rotation-period=90d \
  --next-rotation-time=2025-11-01T00:00:00Z
```

#### CC6.11 - Key Usage Monitoring
**What it checks:**
- Cloud Audit Logs enabled for KMS
- Key usage tracked
- Unauthorized access attempts logged

**Pass criteria:**
- Audit logs enabled
- Logs exported to long-term storage
- Alerting configured

**Fix (manual verification):**
- Verify in Cloud Console > IAM > Audit Logs
- Ensure Cloud KMS API logging enabled

---

### Cloud Logging - 2 Checks

#### CC7.1 - Audit Log Configuration
**What it checks:**
- Admin Activity logs enabled (default)
- Data Access logs enabled
- System Event logs enabled

**Pass criteria:**
- All audit log types enabled
- Logs exported to Cloud Storage/BigQuery
- 1-year retention minimum (PCI-DSS)

**Fix command:**
```bash
# Enable Data Access logs
gcloud projects get-iam-policy PROJECT_ID > policy.yaml
# Edit policy.yaml to add auditConfigs
gcloud projects set-iam-policy PROJECT_ID policy.yaml
```

#### CC7.5 - Log Retention and Export
**What it checks:**
- Log retention period
- Log sinks configured
- Long-term storage setup

**Pass criteria:**
- Logs retained for 1+ year
- Exported to Cloud Storage or BigQuery
- Immutable storage for compliance

**Fix command:**
```bash
# Create log sink to Cloud Storage
gcloud logging sinks create SINK_NAME \
  storage.googleapis.com/BUCKET_NAME \
  --log-filter='resource.type="gce_instance"'
```

---

## Advanced Services (Pro Only)

### GKE (Google Kubernetes Engine) - 10 Checks

**Pro version required:** $297/month

#### Workload Identity Validation
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
- BigQuery
- Dataflow
- Cloud Spanner

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
./auditkit-pro scan -provider gcp -framework cmmc-l2

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
