# AWS Service Coverage

What AuditKit scans in Amazon Web Services.

---

## Overview

**Coverage:** 219 controls across AWS services  
**Supported in:** Free and Pro versions

**Supported frameworks:**
- SOC2 Type II (38 criteria)
- PCI-DSS v4.0.1 (69 requirements)
- CMMC Level 1 and Level 2: all 110 practices reported; 13 of the 17 Level 1 practices automated, Level 2 automated in Pro
- NIST 800-53 Rev 5 (95 controls, derived via crosswalk)
- HIPAA (18 safeguards, derived via crosswalk)

---

## Covered Services

### S3 (Simple Storage Service)

**Controls checked:** 9

- **CC6.2** - S3 Public Access Block
- **CC6.3** - S3 Encryption at Rest
- **CC7.1** - S3 Access Logging
- **A1.2** - S3 Versioning for Backup
- **A1.2** - S3 Lifecycle Policies
- **CIS-2.1.2** - S3 MFA Delete
- **CIS-2.1.4** - S3 Server Access Logging
- **CIS-2.1.6** - S3 Object Lock
- **CIS-2.1.7** - S3 Account Public Access Block

**Example fixes:**
```bash
# Block public access
aws s3api put-public-access-block \
  --bucket BUCKET_NAME \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket BUCKET_NAME \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket BUCKET_NAME \
  --versioning-configuration Status=Enabled
```

---

### IAM (Identity & Access Management)

**Controls checked:** 30

- **CC6.4** - Zombie IAM Users
- **CC6.4** - Inactive IAM Users
- **CC6.4** - User Access Reviews
- **CC6.5** - Excessive Admin Users
- **CC6.5** - Least Privilege Access
- **CC6.5** - Service Account Security
- **CC6.6** - Root Account MFA
- **CC6.6** - Root Account Usage
- **CC6.7** - Password Policy
- **CC6.7** - Unused Credentials
- **CC6.8** - Access Key Rotation
- **CIS-1.1** - Account Contact Details
- **CIS-1.2** - Security Contact Information
- **CIS-1.3** - Credentials Unused 45+ Days
- **CIS-1.6** - Root Hardware MFA
- **CIS-1.10** - MFA for IAM Users
- **CIS-1.11** - Root Account Access Keys
- **CIS-1.12** - Credentials Unused 90 Days
- **CIS-1.13** - One Active Access Key Per User
- **CIS-1.15** - IAM Policies via Groups Only
- **CIS-1.16** - IAM Policies on Groups/Roles Only
- **CIS-1.17** - IAM Support Role
- **CIS-1.18** - IAM Master and Manager Roles
- **CIS-1.19** - IAM Instance Roles
- **CIS-1.20** - Password Expiration Policy
- **CIS-1.21** - Password Reuse Prevention
- **CIS-1.22** - IAM Policies Attached to Groups Only
- **CIS-1.22** - IAM User Access Review
- **CIS-17.1** - IAM Service-Linked Roles Configured
- **CIS-17.2** - IAM Permission Boundaries Configured

**Example fixes:**
```bash
# Enforce password policy
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 24

# Enable MFA for user
aws iam enable-mfa-device \
  --user-name USERNAME \
  --serial-number arn:aws:iam::ACCOUNT:mfa/USERNAME \
  --authentication-code-1 CODE1 \
  --authentication-code-2 CODE2

# Rotate access key
aws iam create-access-key --user-name USERNAME
aws iam delete-access-key --user-name USERNAME --access-key-id OLD_KEY_ID
```

---

### EC2 (Elastic Compute Cloud)

**Controls checked:** 11

- **CC6.1** - Open Security Groups
- **CC6.1** - Network Security - Open Ports
- **CC6.1** - Public EC2 Instances
- **CC6.3** - EBS Volume Encryption
- **CC7.2** - AMI Age and Patching
- **CIS-1.18** - EC2 Instance IAM Roles
- **CIS-2.2.2** - EBS Public Snapshots
- **CIS-5.2** - SSH Access from Internet
- **CIS-5.3** - RDP Access from Internet
- **CIS-5.4** - Default Security Group
- **CIS-5.6** - EC2 IMDSv2

**Example fixes:**
```bash
# Restrict security group
aws ec2 revoke-security-group-ingress \
  --group-id sg-XXXXXXXX \
  --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]'

aws ec2 authorize-security-group-ingress \
  --group-id sg-XXXXXXXX \
  --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=YOUR_IP/32}]'

# Enable EBS encryption by default
aws ec2 enable-ebs-encryption-by-default --region us-east-1

# Enforce IMDSv2
aws ec2 modify-instance-metadata-options \
  --instance-id i-XXXXXXXX \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

---

### CloudTrail

**Controls checked:** 11

- **CC7.1** - CloudTrail Logging Enabled
- **CC7.1** - Multi-Region CloudTrail
- **CC7.1** - CloudTrail Log Integrity
- **CIS-3.2** - CloudTrail Log File Validation
- **CIS-3.3** - CloudTrail CloudWatch Logs Integration
- **CIS-3.4** - CloudTrail S3 Bucket Policy
- **CIS-3.6** - CloudTrail S3 Bucket Logging
- **CIS-3.7** - CloudTrail Encryption at Rest
- **CIS-3.8** - CloudTrail KMS Key Rotation
- **CIS-3.10** - S3 Object-Level Logging (Write)
- **CIS-3.11** - S3 Object-Level Logging (Read)

**Example fixes:**
```bash
# Enable CloudTrail in all regions
aws cloudtrail create-trail \
  --name my-trail \
  --s3-bucket-name my-cloudtrail-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging --name my-trail

# Enable log file encryption
aws cloudtrail update-trail \
  --name my-trail \
  --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY_ID
```

---

### RDS (Relational Database Service)

**Controls checked:** 6

- **CC6.1** - RDS Public Access
- **CC6.3** - RDS Encryption at Rest
- **A1.2** - RDS Backup Retention
- **CIS-2.3.2** - RDS Automatic Minor Version Upgrade
- **CIS-2.3.4** - RDS Multi-AZ Deployment
- **CIS-2.3.5** - RDS Deletion Protection

**Example fixes:**
```bash
# Enable encryption (must be done at creation)
aws rds create-db-instance \
  --db-instance-identifier mydb \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY_ID

# Disable public access
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --no-publicly-accessible

# Enable automated backups
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --backup-retention-period 7 \
  --preferred-backup-window "03:00-04:00"
```

---

### VPC (Virtual Private Cloud)

**Controls checked:** 13

- **CC7.1** - VPC Flow Logs
- **CIS-5.1** - Default VPC in Use
- **CIS-5.5** - VPC Peering Routing
- **CIS-5.7** - VPC Endpoints for AWS Services
- **CIS-5.8** - VPC Peering Routing Least Access
- **CIS-5.9** - NACL Restricts SSH from Internet
- **CIS-5.10** - NACL Restricts RDP from Internet
- **CIS-5.11** - NACL Restricts SSH from Internet (IPv6)
- **CIS-5.12** - NACL Restricts RDP from Internet (IPv6)
- **CIS-5.13** - Security Groups Restrict Admin Ports
- **CIS-5.14** - EC2 Instances in Custom VPC
- **CIS-5.18** - Unused Security Groups Removed
- **CIS-5.20** - VPC Endpoints for S3

**Example fixes:**
```bash
# Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-XXXXXXXX \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs

# Restrict default security group
aws ec2 revoke-security-group-ingress \
  --group-id sg-default \
  --ip-permissions IpProtocol=-1,IpRanges='[{CidrIp=0.0.0.0/0}]'

aws ec2 revoke-security-group-egress \
  --group-id sg-default \
  --ip-permissions IpProtocol=-1,IpRanges='[{CidrIp=0.0.0.0/0}]'
```

---

### KMS (Key Management Service)

**Controls checked:** 1

- **CC5.2** - Encryption Key Management

There is no dedicated KMS check set. The KMS-adjacent checks live with the
service that uses the key: `CIS-3.7` and `CIS-3.8` under CloudTrail, `CIS-12.2`
under Secrets Manager, and `CIS-4.7` (a metric filter for key disable and delete
events) under CloudWatch monitoring.

**Example fixes:**
```bash
# Enable automatic key rotation
aws kms enable-key-rotation --key-id KEY_ID

# Update key policy for least privilege
aws kms put-key-policy \
  --key-id KEY_ID \
  --policy-name default \
  --policy file://policy.json
```

---

### GuardDuty

**Controls checked:** 2

- **CC7.2** - GuardDuty Threat Detection
- **CIS-9.1** - GuardDuty Enabled

**Example fixes:**
```bash
# Enable GuardDuty
aws guardduty create-detector --enable

# List findings
aws guardduty list-findings --detector-id DETECTOR_ID
```

---

### Config

**Controls checked:** 2

- **CC7.1** - AWS Config Recording
- **CIS-3.5** - AWS Config Recording Status

**Example fixes:**
```bash
# Enable AWS Config
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/ConfigRole

aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=my-config-bucket

aws configservice start-configuration-recorder --configuration-recorder-name default
```

---

### Security Hub

**Controls checked:** 2

- **CIS-4.16** - AWS Security Hub Enabled
- **CIS-9.3** - Security Hub Enabled

**Example fixes:**
```bash
# Enable Security Hub
aws securityhub enable-security-hub

# Enable CIS standard
aws securityhub batch-enable-standards \
  --standards-subscription-requests StandardsArn=arn:aws:securityhub:REGION::standards/cis-aws-foundations-benchmark/v/1.2.0
```

---

### Systems Manager

**Controls checked:** 6

- **CC7.1** - Patch Management
- **A1.1** - Processing Capacity Management
- **A1.1** - High Availability
- **CIS-10.1** - SSM Parameter Store Encryption
- **CIS-10.2** - SSM Session Manager Logging
- **CIS-10.3** - SSM Patch Compliance

**Example fixes:**
```bash
# Create patch baseline
aws ssm create-patch-baseline \
  --name "Production-Baseline" \
  --operating-system AMAZON_LINUX_2 \
  --approval-rules "PatchRules=[{PatchFilterGroup={PatchFilters=[{Key=CLASSIFICATION,Values=[Security,Bugfix]}]},ApprovalRules={ApproveAfterDays=7}}]"

# Create maintenance window
aws ssm create-maintenance-window \
  --name "Production-Patching" \
  --schedule "cron(0 2 ? * SUN *)" \
  --duration 4 \
  --cutoff 1 \
  --allow-unassociated-targets
```

---

## Controls by Framework

### SOC2 Type II (38 of the 43 criteria carry automated AWS checks)

The 43-criteria catalogue breaks down as:

**CC1 - Control Environment:** 5 criteria  
**CC2 - Communication:** 3 criteria  
**CC3 - Risk Assessment:** 4 criteria  
**CC4 - Monitoring:** 2 criteria  
**CC5 - Control Activities:** 3 criteria  
**CC6 - Logical Access:** 8 criteria  
**CC7 - System Operations:** 5 criteria  
**CC8 - Change Management:** 1 criterion  
**CC9 - Risk Mitigation:** 2 criteria  
**A1 - Availability:** 3 criteria  
**C1 - Confidentiality:** 2 criteria  
**PI1 - Processing Integrity:** 5 criteria (no automated AWS check - reported as MANUAL)

### PCI-DSS v4.0.1 (59 of the 312 catalogued requirements carry automated AWS checks; 69 across all providers)

Automated AWS checks map into all twelve requirement families (1 through 12). Requirements with no automated check are still reported and marked "No automated check covers this control" so they can be evidenced manually.

### CMMC Level 1 (17 practices, 13 automated)

**Access Control (AC):** 4 practices  
**Identification & Authentication (IA):** 2 practices  
**Media Protection (MP):** 1 practice  
**Physical Protection (PE):** 4 practices  
**System & Communications Protection (SC):** 2 practices  
**System & Information Integrity (SI):** 4 practices

### CMMC Level 2 (110 practices - reported free, automated in Pro)

All Level 1 practices plus 93 additional practices across 14 domains. The Community Edition reports all 110 for evidence tracking and marks the ones it cannot check automatically; automated Level 2 checks are an AuditKit Pro feature.

**[View CMMC details →](../frameworks/cmmc.md)**

---

## Running AWS Scans

```bash
# Configure credentials
aws configure

# Scan for SOC2
./auditkit scan -provider aws -framework soc2

# Scan for PCI-DSS
./auditkit scan -provider aws -framework pci

# Scan for CMMC Level 1
./auditkit scan -provider aws -framework cmmc

# Scan for CMMC Level 2 (Pro only)
./auditkit-pro scan -provider aws -framework cmmc

# Generate report
./auditkit scan -provider aws -framework soc2 -format pdf -output aws-report.pdf
```

---

## Multi-Account Scanning

**Free version:** One account at a time
```bash
# Switch profiles
auditkit scan -provider aws -profile production
auditkit scan -provider aws -profile staging
```

**Pro version:** Scan entire AWS Organization
```bash
# Scan all accounts
auditkit-pro scan -provider aws --scan-all

# Limit concurrency
auditkit-pro scan -provider aws --scan-all --max-concurrent 5

# Generate consolidated report
auditkit-pro scan -provider aws --scan-all -format pdf -output org-report.pdf
```

**[Try Pro free for 14 days →](https://auditkit.io/pro/)**

---

## Next Steps

- **[AWS Setup Guide →](../setup/aws.md)**
- **[Getting Started →](../getting-started.md)**
- **[CLI Reference →](../cli-reference.md)**
- **[Framework Guides →](../frameworks/)**
