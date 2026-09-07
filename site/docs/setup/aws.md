# AWS Authentication Setup

How to configure AWS credentials for AuditKit scanning.

---

## Quick Start

```bash
# Option 1: AWS CLI (easiest)
aws configure

# Test it works
aws sts get-caller-identity

# Run scan
./auditkit scan -provider aws -framework soc2
```

---

## Authentication Methods

AuditKit supports three authentication methods for AWS:

### Option 1: AWS CLI Credentials (Recommended)

**Best for:** Local scanning, development

```bash
# Install AWS CLI
# macOS: brew install awscli
# Linux: apt-get install awscli
# Windows: Download from aws.amazon.com/cli

# Configure credentials
aws configure
```

You'll be prompted for:
- AWS Access Key ID
- AWS Secret Access Key  
- Default region (e.g., us-east-1)
- Default output format (json recommended)

**Credentials stored at:** `~/.aws/credentials`

### Option 2: Environment Variables

**Best for:** CI/CD pipelines, automation

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

# Run scan
./auditkit scan -provider aws -framework soc2
```

### Option 3: IAM Role (EC2/ECS/Lambda)

**Best for:** Running AuditKit on AWS infrastructure

No configuration needed - automatically detected if running on:
- EC2 instance with IAM role attached
- ECS task with task role
- Lambda function with execution role

```bash
# Just run scan - credentials auto-detected
./auditkit scan -provider aws -framework soc2
```

---

## Required IAM Permissions

AuditKit needs **read-only** access to scan your AWS account.

### Minimum Permissions (ReadOnlyAccess)

The easiest approach is to use AWS managed policy:

**Policy ARN:** `arn:aws:iam::aws:policy/ReadOnlyAccess`

### Custom Policy (Least Privilege)

If you need tighter control, here's a minimal policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketLogging",
        "s3:ListBucket",
        "s3:ListAllMyBuckets",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "rds:DescribeDBInstances",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "securityhub:DescribeHub"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Creating an IAM User for AuditKit

### Step 1: Create IAM User

```bash
# Via AWS CLI
aws iam create-user --user-name auditkit-scanner

# Via Console
# Go to IAM > Users > Add User > "auditkit-scanner"
```

### Step 2: Attach ReadOnlyAccess Policy

```bash
# Via AWS CLI
aws iam attach-user-policy \
  --user-name auditkit-scanner \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Via Console
# IAM > Users > auditkit-scanner > Permissions > Attach policies > ReadOnlyAccess
```

### Step 3: Create Access Keys

```bash
# Via AWS CLI
aws iam create-access-key --user-name auditkit-scanner

# Save the output - you'll need AccessKeyId and SecretAccessKey
```

### Step 4: Configure AuditKit

```bash
aws configure
# Enter the AccessKeyId and SecretAccessKey from step 3
```

---

## Multi-Account Scanning

**Free version:** Scan one account at a time by switching profiles

**Pro version:** Scan entire AWS Organization automatically

### Community Edition - Using Profiles

```bash
# Configure multiple profiles
aws configure --profile production
aws configure --profile staging
aws configure --profile development

# Scan each account
./auditkit scan -provider aws -framework soc2 --profile production
./auditkit scan -provider aws -framework soc2 --profile staging
./auditkit scan -provider aws -framework soc2 --profile development
```

### Pro Version - Organization Scanning

```bash
# Scan entire AWS Organization (Pro only)
./auditkit-pro scan -provider aws -framework soc2 --scan-all

# Limit concurrency
./auditkit-pro scan -provider aws --scan-all --max-concurrent 5

# Generate consolidated report
./auditkit-pro scan -provider aws --scan-all -format pdf -output org-report.pdf
```

**[Upgrade to Pro →](https://auditkit.io/pro/)**

---

## Troubleshooting

### "Error: AWS credentials not configured"

**Cause:** No credentials found

**Solution:**
```bash
aws configure
# Enter your credentials when prompted
```

### "Error: Access Denied"

**Cause:** IAM user lacks required permissions

**Solution:** Attach `ReadOnlyAccess` policy:
```bash
aws iam attach-user-policy \
  --user-name auditkit-scanner \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

### "Error: Region not found"

**Cause:** Default region not set

**Solution:**
```bash
export AWS_DEFAULT_REGION="us-east-1"
# Or run: aws configure
```

### "Error: MFA required"

**Cause:** Account requires MFA for API access

**Solution:** Use temporary credentials:
```bash
aws sts get-session-token --serial-number arn:aws:iam::ACCOUNT:mfa/USER --token-code 123456

# Use the temporary credentials returned
export AWS_ACCESS_KEY_ID="temp-key"
export AWS_SECRET_ACCESS_KEY="temp-secret"
export AWS_SESSION_TOKEN="temp-token"
```

---

## Security Best Practices

### 1. Use Dedicated IAM User

Don't use your personal credentials or root account.

```bash
aws iam create-user --user-name auditkit-scanner
```

### 2. Rotate Access Keys Regularly

```bash
# Every 90 days
aws iam create-access-key --user-name auditkit-scanner
aws iam delete-access-key --user-name auditkit-scanner --access-key-id OLD_KEY_ID
```

### 3. Enable CloudTrail Logging

Monitor what AuditKit accesses:

```bash
# CloudTrail logs all API calls made by AuditKit
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=auditkit-scanner
```

### 4. Use Read-Only Access

AuditKit only needs read permissions - never grant write access.

---

## Next Steps

- **[Run your first scan →](../getting-started.md)**
- **[CLI Reference →](../cli-reference.md)**
- **[AWS Service Coverage →](../providers/aws.md)**
- **[Framework Guide →](../frameworks/)**
