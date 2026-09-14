# AWS Service Coverage

What AuditKit scans in Amazon Web Services.

---

## Overview

**Coverage:** 228 controls across AWS services  
**Supported in:** Free and Pro versions

**Supported frameworks:**
- SOC2 Type II (38 criteria)
- PCI-DSS v4.0.1 (71 requirements)
- CMMC Level 1 and Level 2: all 110 practices reported; 5 of the 17 Level 1 practices reach a verdict on AWS, Level 2 automated in Pro
- NIST 800-53 Rev 5 (149 controls, derived via crosswalk)
- HIPAA (30 safeguards, derived via crosswalk)

---

## Covered Services

Every control the service checks emit, read from the scanner's source. The
identifier is the one the report carries; the framework pages say which
requirement each maps to.

### IAM

**Controls checked:** 22

- **CC6.6** - Root Account MFA
- **CC6.7** - Password Policy
- **CC6.8** - Access Key Rotation
- **CIS-2.4** - Root Account Access Keys
- **CIS-2.6** - Root Hardware MFA
- **CIS-2.10** - MFA for IAM Users
- **CIS-2.11** - Credentials Unused 90 Days
- **AWS-IAM-05** - One Active Access Key Per User
- **CIS-2.13** - IAM Policies via Groups Only
- **CIS-2.15** - IAM Support Role
- **CIS-2.16** - IAM Instance Roles
- **AWS-IAM-06** - Password Expiration Policy
- **CIS-2.9** - Password Reuse Prevention
- **CIS-2.2** - Account Contact Details
- **CIS-2.3** - Security Contact Information
- **AWS-IAM-01** - IAM Master and Manager Roles
- **AWS-IAM-04** - IAM User Access Review
- **CC6.4** - Zombie IAM Users
- **CC6.5** - Excessive Admin Users
- **CC6.6** - Root Account Usage
- **AWS-IAM-03** - IAM Service-Linked Roles Configured
- **AWS-IAM-02** - IAM Permission Boundaries Configured

### EC2

**Controls checked:** 10

- **CC6.1** - Open Security Groups
- **CC6.3** - EBS Volume Encryption
- **CC7.2** - AMI Age and Patching
- **CIS-6.3** - SSH Access from Internet
- **CIS-6.5** - Default Security Group
- **CIS-6.7** - EC2 IMDSv2
- **AWS-EC2-01** - EBS Public Snapshots
- **CIS-2.16** - EC2 Instance IAM Roles
- **CIS-6.4** - Security Groups Open to IPv6 Internet on Admin Ports
- **CIS-6.1.2** - CIFS Access Restricted to Trusted Networks

### VPC

**Controls checked:** 10

- **CC7.1** - VPC Flow Logs
- **AWS-VPC-01** - Default VPC in Use
- **CIS-6.6** - VPC Peering Routing
- **CIS-6.8** - VPC Endpoints for AWS Services
- **CIS-6.2** - NACL Restricts SSH from Internet
- **AWS-VPC-04** - NACL Restricts SSH from Internet (IPv6)
- **AWS-VPC-03** - NACL Restricts RDP from Internet (IPv6)
- **CIS-6.3** - Security Groups Restrict Admin Ports
- **AWS-VPC-02** - EC2 Instances in Custom VPC
- **AWS-VPC-05** - Unused Security Groups Removed

### CloudTrail

**Controls checked:** 9

- **CC7.1** - CloudTrail Logging Enabled
- **CIS-4.5** - CloudTrail Encryption at Rest
- **AWS-CLOUDTRAIL-01** - CloudTrail CloudWatch Logs Integration
- **CIS-4.4** - CloudTrail S3 Bucket Logging
- **CIS-4.2** - CloudTrail Log File Validation
- **AWS-CLOUDTRAIL-02** - CloudTrail S3 Bucket Policy
- **AWS-CLOUDTRAIL-03** - Customer-Managed KMS Key Rotation
- **CIS-4.8** - S3 Object-Level Logging (Write)
- **CIS-4.9** - S3 Object-Level Logging (Read)

### S3

**Controls checked:** 8

- **CC6.2** - S3 Public Access Block
- **CC6.3** - S3 Encryption at Rest
- **A1.2** - S3 Versioning for Backup
- **CC7.1** - S3 Access Logging
- **CIS-3.1.2** - S3 MFA Delete
- **AWS-S3-02** - S3 Server Access Logging
- **AWS-S3-01** - S3 Object Lock
- **CIS-3.1.4** - S3 Account Public Access Block

### EKS

**Controls checked:** 7

- **AWS-EKS-03** - EKS Cluster Endpoint Access
- **AWS-EKS-04** - EKS Cluster Logging
- **AWS-EKS-02** - EKS Cluster Encryption
- **AWS-EKS-05** - EKS Network Policy
- **AWS-EKS-06** - EKS Pod Security Policy
- **AWS-EKS-07** - EKS RBAC Configuration
- **AWS-EKS-01** - EKS Audit Logging

### RDS

**Controls checked:** 6

- **CC6.3** - RDS Encryption at Rest
- **CC6.1** - RDS Public Access
- **A1.2** - RDS Backup Retention
- **CIS-3.2.2** - RDS Automatic Minor Version Upgrade
- **CIS-3.2.4** - RDS Multi-AZ Deployment
- **AWS-RDS-01** - RDS Deletion Protection

### Redshift

**Controls checked:** 6

- **CC6.3** - Redshift Cluster Encryption
- **CC6.1** - Redshift Public Access
- **CC7.1** - Redshift Audit Logging
- **CC6.4** - Redshift SSL Required
- **CC7.5** - Redshift Auto Version Upgrade
- **A1.2** - Redshift Backup Retention

### ElastiCache

**Controls checked:** 5

- **CC6.3** - ElastiCache Encryption at Rest
- **CC6.4** - ElastiCache Encryption in Transit
- **CC7.5** - ElastiCache Auto Minor Version Upgrade
- **CC6.6** - ElastiCache Redis AUTH Token
- **A1.2** - ElastiCache Backup Retention

### Lambda

**Controls checked:** 5

- **AWS-LAMBDA-04** - Lambda Functions in VPC
- **AWS-LAMBDA-01** - Lambda Environment Encryption
- **AWS-LAMBDA-02** - Lambda Execution Role Permissions
- **AWS-LAMBDA-03** - Lambda Functions Not Public
- **AWS-LAMBDA-05** - Lambda X-Ray Tracing Enabled

### OpenSearch

**Controls checked:** 5

- **CC6.3** - OpenSearch Encryption at Rest
- **CC6.4** - OpenSearch Node-to-Node Encryption
- **CC6.1** - OpenSearch VPC Deployment
- **CC7.1** - OpenSearch Audit Logs
- **CC6.6** - OpenSearch Fine-Grained Access Control

### ECS

**Controls checked:** 4

- **AWS-ECS-03** - ECS Task Definition Logging
- **AWS-ECS-02** - ECS Secrets Management
- **AWS-ECS-01** - ECS Container Insights
- **AWS-ECS-04** - ECS Task Role Permissions

### GuardDuty, Security Hub and Inspector

**Controls checked:** 4

- **AWS-SECSVC-01** - GuardDuty Enabled
- **AWS-SECSVC-03** - Macie Enabled
- **CIS-5.16** - Security Hub Enabled
- **AWS-SECSVC-02** - Inspector Enabled

### API Gateway

**Controls checked:** 3

- **AWS-APIGW-02** - API Gateway Logging Enabled
- **AWS-APIGW-01** - API Gateway Authorization Enabled
- **AWS-APIGW-03** - API Gateway TLS 1.2+

### AWS Backup

**Controls checked:** 3

- **AWS-BACKUP-02** - AWS Backup Vault Encryption
- **AWS-BACKUP-01** - AWS Backup Plan Configured
- **AWS-BACKUP-03** - AWS Backup Vault Lock Enabled

### Elastic Beanstalk

**Controls checked:** 3

- **AWS-BEANSTALK-01** - Elastic Beanstalk Enhanced Health Reporting
- **AWS-BEANSTALK-03** - Elastic Beanstalk Managed Platform Updates
- **AWS-BEANSTALK-02** - Elastic Beanstalk Log Streaming

### AWS Config

**Controls checked:** 3

- **CC7.1** - AWS Config Recording
- **CIS-4.3** - AWS Config Recording Status
- **CC7.2** - GuardDuty Threat Detection

### DynamoDB

**Controls checked:** 3

- **AWS-DYNAMODB-03** - DynamoDB Point-in-Time Recovery
- **AWS-DYNAMODB-02** - DynamoDB Encryption at Rest
- **AWS-DYNAMODB-01** - DynamoDB Auto Scaling Enabled

### ECR

**Controls checked:** 3

- **AWS-ECR-02** - ECR Image Scanning Enabled
- **AWS-ECR-03** - ECR Immutable Tags
- **AWS-ECR-01** - ECR Encryption at Rest

### SNS and SQS

**Controls checked:** 3

- **AWS-MESSAGING-02** - SNS Topic Encryption
- **AWS-MESSAGING-03** - SQS Queue Encryption
- **AWS-MESSAGING-01** - Messaging Access Policies

### CloudWatch

**Controls checked:** 3

- **CC7.3** - Security Event Monitoring
- **CC7.4** - Alert Notifications
- **CIS-5.16** - AWS Security Hub Enabled

### Network Firewall

**Controls checked:** 3

- **AWS-NETFW-01** - Network Firewall AZ Deployment
- **AWS-NETFW-03** - Network Firewall Policy Rules
- **AWS-NETFW-02** - Network Firewall Logging

### Organizations

**Controls checked:** 3

- **CIS-2.1.2** - AWS Organizations SCPs Enabled
- **AWS-ORG-01** - Multi-Account Structure
- **CIS-4.1** - Organization-wide CloudTrail

### SageMaker

**Controls checked:** 3

- **CC6.3** - SageMaker Notebook Encryption
- **CC6.1** - SageMaker Direct Internet Access
- **CC6.6** - SageMaker Root Access

### Secrets Manager

**Controls checked:** 3

- **AWS-SECRETS-02** - Secrets Manager Rotation Enabled
- **AWS-SECRETS-01** - Secrets Manager KMS Encryption
- **AWS-SECRETS-03** - Unused Secrets Removed

### Systems Manager

**Controls checked:** 3

- **AWS-SSM-01** - SSM Parameter Store Encryption
- **AWS-SSM-03** - SSM Session Manager Logging
- **AWS-SSM-02** - SSM Patch Compliance

### Certificate Manager

**Controls checked:** 2

- **AWS-ACM-01** - ACM Certificate Auto-Renewal
- **AWS-ACM-02** - ACM Certificate In Use

### CloudFormation

**Controls checked:** 2

- **AWS-CFN-02** - CloudFormation Stack Policy Configured
- **AWS-CFN-01** - CloudFormation Drift Detection

### Systems

**Controls checked:** 2

- **CC7.1** - Patch Management
- **A1.1** - Processing Capacity Management

### IAM Access Analyzer

**Controls checked:** 1

- **CIS-2.18** - IAM Access Analyzer Enabled

### Aurora

**Controls checked:** 1

- **AWS-AURORA-01** - Aurora Backtrack Enabled

### Route 53

**Controls checked:** 1

- **AWS-ROUTE53-01** - Route53 DNSSEC Enabled

### Framework suites

The framework suites add their own identifiers on top of the service checks: CIS (25), CMMC (13), PCI DSS (43), SOC 2 (35), vulnerability coverage (2). Those are described on the framework pages rather than here.


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
