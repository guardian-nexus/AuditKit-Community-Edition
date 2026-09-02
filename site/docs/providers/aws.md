# AWS Service Coverage

What AuditKit scans in Amazon Web Services.

---

## Overview

**Coverage:** 229 controls across AWS services  
**Supported in:** Free and Pro versions

**Supported frameworks:**
- SOC2 Type II (38 criteria)
- PCI-DSS v4.0.1 (69 requirements)
- CMMC Level 1 (17 practices) and Level 2 (110 practices - Pro)
- NIST 800-53 Rev 5 (144 controls, derived via crosswalk)
- HIPAA (17 safeguards, derived via crosswalk)

---

## Covered Services

### S3 (Simple Storage Service)

**Controls checked:** 8

- **CC6.2** - Bucket public access blocking
- **CC8.1** - Bucket encryption at rest
- **CC7.2** - Bucket versioning enabled
- **CC7.1** - Bucket logging enabled
- **CC6.12** - Bucket policies (overly permissive access)
- **SC.1.176** - Secure transport enforced (HTTPS only)
- **CC8.4** - Object encryption default
- **CC6.13** - MFA Delete enabled on critical buckets

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

**Controls checked:** 12

- **CC6.1** - Access key rotation (90 days for PCI-DSS, 180 for SOC2)
- **CC6.6** - MFA enforcement for users
- **CC6.7** - MFA for root account
- **IA.1.076** - Password policy strength
- **IA.1.077** - Password reuse prevention
- **CC6.8** - Unused IAM credentials
- **CC6.14** - IAM users with excessive permissions
- **AC.1.001** - Policies following least privilege
- **CC6.15** - Inactive users (90+ days)
- **CC6.16** - Root account usage
- **IA.2.081** - Multi-factor authentication required
- **CC6.17** - IAM roles for EC2 instances

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

**Controls checked:** 8

- **CC6.4** - Security group rules (overly permissive)
- **SC.1.175** - Open ports to 0.0.0.0/0
- **CC8.1** - EBS volume encryption
- **CC7.1** - Instance metadata v2 (IMDSv2) enforced
- **CC6.18** - Public IP assignments
- **SC.2.179** - Network isolation and segmentation
- **CC7.3** - CloudWatch monitoring enabled
- **SI.1.210** - Patch management via Systems Manager

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

**Controls checked:** 6

- **CC7.1** - CloudTrail enabled in all regions
- **AU.2.041** - Management events logged
- **AU.2.042** - Data events logged (S3, Lambda)
- **CC7.4** - Log file validation enabled
- **CC8.1** - CloudTrail logs encrypted with KMS
- **CC7.5** - CloudTrail logs stored in S3 with retention

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

- **CC8.1** - Database encryption at rest
- **CC8.2** - SSL/TLS in transit enforcement
- **CC7.4** - Automated backups enabled
- **CC6.19** - Public accessibility disabled
- **CC7.6** - Enhanced monitoring enabled
- **CC9.1** - Multi-AZ deployment for production

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

**Controls checked:** 5

- **SC.1.175** - VPC Flow Logs enabled
- **SC.2.179** - Network segmentation (public/private subnets)
- **CC6.20** - Default security group restricted
- **SC.1.176** - Network ACLs configured
- **CC6.21** - VPC peering security

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

**Controls checked:** 3

- **CC8.3** - Key rotation enabled
- **CC6.22** - Key policies (overly permissive)
- **CC7.7** - Key usage monitoring via CloudTrail

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

**Controls checked:** 3

- **SI.1.214** - GuardDuty enabled
- **IR.2.092** - Findings monitored
- **CC7.8** - High/critical findings addressed

**Example fixes:**
```bash
# Enable GuardDuty
aws guardduty create-detector --enable

# List findings
aws guardduty list-findings --detector-id DETECTOR_ID
```

---

### Config

**Controls checked:** 4

- **CM.2.061** - AWS Config enabled
- **CM.2.062** - Config rules deployed
- **CC7.9** - Configuration changes tracked
- **CC7.10** - Compliance dashboard available

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

**Controls checked:** 3

- **CA.2.158** - Security Hub enabled
- **CA.2.159** - Security standards enabled (CIS, PCI-DSS)
- **CC7.11** - Security findings aggregated

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

**Controls checked:** 4

- **SI.1.210** - Patch Manager configured
- **CM.2.063** - State Manager associations
- **CC7.12** - Session Manager for secure access
- **MA.2.111** - Maintenance windows defined

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

### SOC2 Type II (38 criteria)

**CC1 - Control Environment:** 5 controls  
**CC2 - Communication:** 4 controls  
**CC3 - Risk Assessment:** 6 controls  
**CC5 - Control Activities:** 7 controls  
**CC6 - Logical Access:** 18 controls  
**CC7 - System Operations:** 12 controls  
**CC8 - Change Management:** 6 controls  
**CC9 - Risk Mitigation:** 6 controls

### PCI-DSS v4.0.1 (69 requirements)

**Requirement 1 - Network Security:** 5 controls  
**Requirement 2 - Secure Configurations:** 4 controls  
**Requirement 3 - Cardholder Data Protection:** 6 controls  
**Requirement 8 - Access Control:** 8 controls  
**Requirement 10 - Logging:** 5 controls  
**Requirement 11 - Security Testing:** 2 controls

### CMMC Level 1 (17 practices)

**Access Control:** 3 practices  
**Identification & Authentication:** 2 practices  
**Media Protection:** 1 practice  
**Physical Protection:** 3 practices  
**System Protection:** 5 practices  
**System Integrity:** 3 practices

### CMMC Level 2 (110 practices - Pro only)

All Level 1 practices plus 93 additional practices across 14 domains.

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
./auditkit-pro scan -provider aws -framework cmmc-l2

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
