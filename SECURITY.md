# Security Policy

## Overview

AuditKit is designed with security-first principles. This document outlines the permissions required, security considerations, and how to safely use AuditKit in your environment.

**This applies to both AuditKit (free) and AuditKit Pro.**

---

## Permissions Required

### AWS Permissions (Read-Only)

AuditKit requires **READ-ONLY** AWS permissions. No write, modify, or delete permissions are needed.

**Required IAM Permissions:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetAccountPasswordPolicy",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:GetAccountSummary",
        "iam:ListRoles",
        "s3:ListBuckets",
        "s3:GetBucketEncryption",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeImages",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpnGateways",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "kms:ListKeys",
        "kms:DescribeKey",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "config:DescribeConfigurationRecorders"
      ],
      "Resource": "*"
    }
  ]
}
```

**For Pro - Multi-Account Scanning:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts",
        "organizations:DescribeOrganization",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

**What these permissions do:**
- `List*` / `Describe*` / `Get*` - Read configuration data only
- **NO** `Create*` / `Update*` / `Delete*` / `Put*` permissions
- **NO** ability to modify your infrastructure

### Azure Permissions (Read-Only)

AuditKit requires **READ-ONLY** Azure permissions via the built-in Reader role or equivalent.

**Required Azure Role:**
- Built-in **"Reader"** role at Subscription scope

**OR Custom Role with these permissions:**
```json
{
  "permissions": [
    {
      "actions": [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/disks/read",
        "Microsoft.Network/networkSecurityGroups/read",
        "Microsoft.Network/virtualNetworks/read",
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleDefinitions/read",
        "Microsoft.Insights/activitylogs/read",
        "Microsoft.Security/assessments/read",
        "Microsoft.Resources/subscriptions/read"
      ],
      "notActions": [],
      "dataActions": [],
      "notDataActions": []
    }
  ]
}
```

**For Pro - Multi-Subscription Scanning:**
```json
{
  "permissions": [
    {
      "actions": [
        "Microsoft.Management/managementGroups/read",
        "Microsoft.Resources/subscriptions/read"
      ]
    }
  ]
}
```

**What these permissions do:**
- `*/read` - Read configuration data only
- **NO** `*/write` / `*/delete` / `*/action` permissions
- **NO** ability to modify your infrastructure

### GCP Permissions (Read-Only)

GCP support is available in both **Free** and **Pro** versions as of v0.7.0.

**Required GCP Roles (Free & Pro):**
- Built-in **"Viewer"** role at Project level
- Built-in **"Security Reviewer"** role (recommended for enhanced security checks)

**OR Custom Role with these permissions:**
```yaml
title: "AuditKit Scanner"
description: "Read-only access for compliance scanning"
includedPermissions:
- storage.buckets.list
- storage.buckets.get
- iam.serviceAccounts.list
- iam.serviceAccounts.get
- iam.serviceAccountKeys.list
- compute.instances.list
- compute.instances.get
- compute.disks.list
- compute.firewalls.list
- compute.networks.list
- compute.subnetworks.list
- sql.instances.list
- cloudkms.keyRings.list
- cloudkms.cryptoKeys.list
- logging.logEntries.list
- logging.sinks.list
```

**For Pro - GKE Advanced Scanning:**
```yaml
includedPermissions:
- container.clusters.list
- container.clusters.get
- container.nodes.list
- container.pods.list
- container.networkPolicies.list
- container.podSecurityPolicies.list
```

**For Pro - Vertex AI Scanning:**
```yaml
includedPermissions:
- aiplatform.models.list
- aiplatform.models.get
- aiplatform.endpoints.list
- aiplatform.datasets.list
- aiplatform.trainingPipelines.list
- aiplatform.featurestores.list
```

**For Pro - Multi-Project Scanning:**
```yaml
includedPermissions:
- resourcemanager.projects.list
- resourcemanager.folders.list
- resourcemanager.organizations.get
```

---

## Running Safely

### 1. Test in Sandbox First

Always test AuditKit in a non-production environment first:

**AWS:**
```bash
# Configure sandbox account credentials
aws configure --profile sandbox
export AWS_PROFILE=sandbox

# Run scan (Free or Pro)
./auditkit scan -provider aws -profile sandbox -verbose
# or
./auditkit-pro scan -provider aws -profile sandbox -verbose
```

**Azure:**
```bash
# Login to sandbox subscription
az login
az account set --subscription "sandbox-subscription-id"

# Run scan (Free or Pro)
./auditkit scan -provider azure -verbose
# or
./auditkit-pro scan -provider azure -verbose
```

**GCP (Free & Pro):**
```bash
# Authenticate to sandbox project
gcloud auth application-default login
gcloud config set project sandbox-project-id

# Run scan (Free or Pro)
./auditkit scan -provider gcp -verbose
# or
./auditkit-pro scan -provider gcp -verbose
```

### 2. Create Dedicated Read-Only User

**AWS - Create Read-Only IAM User:**
```bash
# Create dedicated user
aws iam create-user --user-name auditkit-scanner

# Attach read-only policy (use policy from above)
aws iam put-user-policy --user-name auditkit-scanner \
  --policy-name AuditKitReadOnly \
  --policy-document file://auditkit-policy.json

# Create access keys
aws iam create-access-key --user-name auditkit-scanner
```

**Azure - Create Read-Only Service Principal:**
```bash
# Create service principal with Reader role
az ad sp create-for-rbac --name "auditkit-scanner" \
  --role Reader \
  --scopes /subscriptions/{subscription-id}

# Output will show credentials to use
```

**GCP - Create Read-Only Service Account (Free & Pro):**
```bash
# Create service account
gcloud iam service-accounts create auditkit-scanner \
  --display-name "AuditKit Scanner"

# Grant Viewer role
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"

# Grant Security Reviewer role (recommended)
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"

# Create and download key
gcloud iam service-accounts keys create ~/auditkit-key.json \
  --iam-account=auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com
```

### 3. Audit Cloud Logs After Running

**AWS - Check CloudTrail:**
```bash
# Filter for recent read-only events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ReadOnly,AttributeValue=true \
  --max-results 50
```

**Azure - Check Activity Log:**
```bash
# View recent read operations
az monitor activity-log list \
  --caller auditkit-scanner \
  --status Succeeded
```

**GCP - Check Cloud Audit Logs (Free & Pro):**
```bash
# View recent admin activity
gcloud logging read "protoPayload.serviceName=compute.googleapis.com" \
  --limit 50 \
  --format json

# View recent IAM activity
gcloud logging read "protoPayload.serviceName=iam.googleapis.com" \
  --limit 50 \
  --format json
```

### 4. Use Policy Simulators

Test the policy before using it:

**AWS IAM Policy Simulator:**
```bash
# Simulate read operations (should succeed)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789:user/auditkit-scanner \
  --action-names iam:ListUsers s3:ListBuckets \
  --resource-arns "*"

# Simulate write operations (should fail)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789:user/auditkit-scanner \
  --action-names s3:DeleteBucket ec2:TerminateInstances \
  --resource-arns "*"
```

**GCP Policy Troubleshooter (Free & Pro):**
```bash
# Test permissions
gcloud iam service-accounts get-iam-policy \
  auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com

# Test specific permissions
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:auditkit-scanner@PROJECT_ID.iam.gserviceaccount.com"
```

---

## Data Privacy

### What Data Does AuditKit Access?

**AuditKit reads:**
- Configuration metadata (bucket names, instance IDs, user names)
- Security settings (encryption status, MFA status, firewall rules)
- Compliance-relevant configuration (logging, monitoring, access controls)
- Cloud resource metadata (all providers: AWS, Azure, GCP)
- Kubernetes cluster configuration (Pro only - GKE advanced scanning)
- AI/ML model metadata (Pro only - Vertex AI, Azure ML, SageMaker advanced features)

**AuditKit does NOT read:**
- Actual data stored in S3 buckets / Cloud Storage / Blob Storage
- Database contents
- Application logs content (only checks if logging is enabled)
- Secrets or credentials (except to verify they exist/are rotated)
- File contents or application code
- Container images (only metadata and scanning status)
- Model training data (only metadata and access controls)

### Where Does Data Go?

**AuditKit Free:**
- **Stores all results locally** on your machine
- **No data leaves your environment**
- **No telemetry or phone-home**
- **All network traffic goes directly to AWS/Azure APIs**
- **NO third-party services contacted**
- **NO external data transmission**

**AuditKit Pro:**
- **Stores all results locally** on your machine
- **License validation is offline** (hardware fingerprint only)
- **NO internet required after initial activation**
- **Works in air-gapped environments**
- **No scan data leaves your environment**
- **All compliance data stays local**
- **All network traffic goes directly to cloud provider APIs**

**You can verify this by:**
1. Monitoring network traffic during scans
2. Checking source code (free version is open source)
3. Running in air-gapped environments (after license activation for Pro)

---

## Authentication Methods

### AWS Authentication

AuditKit uses standard AWS SDK authentication:

1. **AWS Profile** (recommended for testing):
   ```bash
   aws configure --profile myprofile
   ./auditkit scan -provider aws -profile myprofile
   ```

2. **Environment Variables**:
   ```bash
   export AWS_ACCESS_KEY_ID="..."
   export AWS_SECRET_ACCESS_KEY="..."
   export AWS_SESSION_TOKEN="..."  # if using temporary credentials
   ./auditkit scan -provider aws
   ```

3. **IAM Role** (when running on EC2):
   ```bash
   # Automatically uses instance profile
   ./auditkit scan -provider aws
   ```

### Azure Authentication

AuditKit uses standard Azure SDK authentication:

1. **Azure CLI** (recommended for testing):
   ```bash
   az login
   ./auditkit scan -provider azure
   ```

2. **Service Principal**:
   ```bash
   export AZURE_CLIENT_ID="..."
   export AZURE_CLIENT_SECRET="..."
   export AZURE_TENANT_ID="..."
   export AZURE_SUBSCRIPTION_ID="..."
   ./auditkit scan -provider azure
   ```

3. **Managed Identity** (when running on Azure VM):
   ```bash
   # Automatically uses managed identity
   ./auditkit scan -provider azure
   ```

### GCP Authentication (Free & Pro)

AuditKit uses standard GCP SDK authentication:

1. **Application Default Credentials** (recommended):
   ```bash
   gcloud auth application-default login
   ./auditkit scan -provider gcp
   # or
   ./auditkit-pro scan -provider gcp
   ```

2. **Service Account Key File**:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
   ./auditkit scan -provider gcp
   # or
   ./auditkit-pro scan -provider gcp
   ```

3. **Compute Engine Service Account** (when running on GCE):
   ```bash
   # Automatically uses instance metadata
   ./auditkit scan -provider gcp
   # or
   ./auditkit-pro scan -provider gcp
   ```

4. **Project ID Configuration**:
   ```bash
   # Set via environment variable
   export GOOGLE_CLOUD_PROJECT="your-project-id"

   # Or set via gcloud
   gcloud config set project your-project-id

   # Or pass via command line
   ./auditkit scan -provider gcp -profile your-project-id
   ```

---

## Pro-Specific Security Considerations

### License Key Security

**AuditKit Pro uses a `.lic` license file:**

```bash
# Save the .lic file received after purchase/trial signup
mkdir -p ~/.auditkit-pro
cp ~/Downloads/license.lic ~/.auditkit-pro/license.lic

# Activation is automatic on first run — no separate activate command needed

# Legacy method (deprecated):
# export AUDITKIT_PRO_LICENSE=AKP-XXXXXXXX-XXXXXXXXXX-XXXXXXXX
```

**License Validation Security:**
- License files use Ed25519 asymmetric signatures for integrity verification
- The embedded public key in the binary is for VERIFICATION ONLY (cannot create licenses)
- License signing happens server-side with the private key on secure infrastructure
- Hardware fingerprinting prevents unauthorized sharing
- Offline validation after initial activation (no phone-home during scans)

**Best Practices:**
- Store `.lic` file at `~/.auditkit-pro/license.lic` (default location)
- Restrict file permissions: `chmod 600 ~/.auditkit-pro/license.lic`
- Don't commit `.lic` files to version control
- Contact support if license is compromised
- Use read-only filesystem mounts in containers when possible

### Hardware Lock

**Pro licenses are locked to one machine (both CLI and Desktop):**
- License validates machine fingerprint on first run
- Prevents unauthorized sharing
- Contact support to transfer license to a new machine

### Multi-Account Scanning Security

**Pro can scan multiple accounts - use cross-account roles:**

**AWS:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::MASTER_ACCOUNT:root"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "unique-external-id"
      }
    }
  }]
}
```

**Azure - Management Group Access:**
```bash
# Grant Reader at Management Group level
az role assignment create \
  --assignee {sp-id} \
  --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/{mg-id}
```

**GCP - Organization-Level Access:**
```bash
# Grant roles/viewer at organization level
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member="serviceAccount:auditkit@PROJECT.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

---

## Security Best Practices

### 1. Principle of Least Privilege

Only grant the specific permissions listed above. Do not use:
- `AdministratorAccess` policy (AWS)
- `Owner` or `Contributor` role (Azure)
- `roles/owner` or `roles/editor` (GCP)
- `*:*` wildcard permissions

### 2. Use Temporary Credentials

When possible, use temporary credentials:

**AWS:**
```bash
# Use AWS STS to get temporary credentials
aws sts get-session-token --duration-seconds 3600
```

**Azure:**
```bash
# Service principal credentials are inherently temporary
# Rotate secrets regularly
az ad sp credential reset --name auditkit-scanner
```

**GCP (Free & Pro):**
```bash
# Use short-lived tokens via Application Default Credentials
gcloud auth application-default login --no-launch-browser

# Refresh credentials
gcloud auth application-default print-access-token
```

### 3. Rotate Credentials Regularly

- **AWS:** Rotate access keys every 90 days
- **Azure:** Rotate service principal secrets every 90 days
- **GCP:** Rotate service account keys every 90 days
- Use cloud-native secrets management (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)

### 4. Monitor Scanner Activity

Set up alerts for:
- Unusual number of API calls
- API calls from unexpected locations
- Failed authentication attempts

**AWS CloudWatch Example:**
```bash
# Create alarm for excessive API calls
aws cloudwatch put-metric-alarm \
  --alarm-name "AuditKit-Excessive-Calls" \
  --metric-name CallCount \
  --threshold 10000
```

### 5. Scope Permissions When Possible

**AWS - Limit to specific resources:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetBucketEncryption"],
    "Resource": "arn:aws:s3:::my-specific-bucket"
  }]
}
```

**Azure - Limit to resource group:**
```bash
# Create role assignment at resource group scope
az role assignment create \
  --assignee {sp-id} \
  --role Reader \
  --scope /subscriptions/{sub-id}/resourceGroups/{rg-name}
```

**GCP - Limit to specific project (Free & Pro):**
```bash
# Grant viewer at project level only
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditkit@PROJECT.iam.gserviceaccount.com" \
  --role="roles/viewer"

# Limit to specific resources (example: storage only)
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:auditkit@PROJECT.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer" \
  --condition='resource.type=="storage.googleapis.com/Bucket"'
```

---

## Air-Gapped and Restricted Environments

### Running in Air-Gapped Environments

**AuditKit Free:**
- Fully functional offline (no internet required)
- All processing local
- No external dependencies after installation

**AuditKit Pro:**
- **Fully offline capable** - No internet connection required for activation or scanning
- License validation uses embedded Ed25519 public key (offline verification)
- Hardware fingerprint stored locally
- No phone-home during scans or activation
- Perfect for SCIFs, classified environments, and air-gapped networks

**Air-Gap Installation Process (Pro):**
```bash
# 1. Purchase license (requires internet to receive .lic file)
# You receive: license.lic (Ed25519-signed license file)

# 2. Transfer the .lic file and Pro binary to the air-gapped machine
#    (e.g., via USB or secure file transfer)

# 3. On air-gapped machine (fully offline):
mkdir -p ~/.auditkit-pro
cp /media/usb/license.lic ~/.auditkit-pro/license.lic

# Activation is automatic on first run (offline - no internet required)
./auditkit-pro scan -provider aws -framework cmmc
```

**How Offline Activation Works:**
- License files are pre-signed with Ed25519 on secure server
- Binary contains public verification key (can verify, cannot forge)
- First run validates signature locally and locks to hardware
- Creates hardware-locked state on disk
- No network calls during activation or scanning

### Export Control Compliance

**AuditKit Pro includes encryption and is subject to U.S. export controls.**

**Restricted Countries (CANNOT use AuditKit Pro):**
- Cuba
- Iran
- North Korea
- Syria
- Russia
- Belarus
- Any country under U.S. embargo

**By using AuditKit Pro, you certify:**
- You are not in a restricted country
- You will not export to restricted countries
- You comply with Export Administration Regulations (EAR)

**Violations may result in criminal penalties. See: 15 CFR Part 730-774**

---

## Reporting Security Issues

If you discover a security vulnerability in AuditKit:

**DO:**
- Email: security@auditkit.io
- Include detailed steps to reproduce
- Allow reasonable time for fix before public disclosure

**DON'T:**
- Open public GitHub issues for vulnerabilities
- Post on social media
- Exploit the vulnerability

**Response Time:**
- Initial acknowledgment: 24-48 hours
- Fix timeline: Based on severity (critical issues prioritized)

---

## Compliance Certifications

AuditKit is designed to help you achieve compliance, but the tool itself:

- **Open Source (Free version)**: Fully auditable code
- **No Data Collection**: Privacy-focused design
- **Read-Only**: Cannot modify your infrastructure
- **Local Execution**: All processing happens on your machine
- **Air-Gap Compatible**: Works in restricted environments

---

## Additional Security Resources

### Official Cloud Security Guides
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)

### Compliance Frameworks
- [NIST 800-53 Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CMMC Model Documentation](https://dodcio.defense.gov/CMMC/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)

### AuditKit Documentation
- [Getting Started](https://github.com/guardian-nexus/auditkit/blob/main/docs/getting-started.md)
- [AWS Setup Guide](https://github.com/guardian-nexus/auditkit/blob/main/docs/setup/aws.md)
- [Azure Setup Guide](https://github.com/guardian-nexus/auditkit/blob/main/docs/setup/azure.md)
- [GCP Setup Guide](https://github.com/guardian-nexus/auditkit/blob/main/docs/setup/gcp.md)

---

## Questions?

- **General Security Questions**: security@auditkit.io
- **Pro Support**: hello@auditkit.io
- **Documentation**: https://github.com/guardian-nexus/auditkit
- **Community**: GitHub Discussions

---

**Last Updated:** November 04, 2025
**Version:** 3.0 (v0.7.0)
