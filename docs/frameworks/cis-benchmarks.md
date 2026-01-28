# CIS Benchmarks - Security Configuration Standards

The Center for Internet Security (CIS) Benchmarks are globally recognized best practices for securing IT systems and data. AuditKit scans your cloud infrastructure against CIS Benchmarks to identify security misconfigurations.

---

## What Are CIS Benchmarks?

CIS Benchmarks provide:
- **Prescriptive guidance** for hardening cloud environments
- **Industry consensus** on security best practices
- **Detailed remediation steps** for each control
- **Risk-based prioritization** (Implementation Groups)

Unlike compliance frameworks (SOC2, PCI), CIS Benchmarks focus specifically on **technical security hardening**.

---

## Supported Benchmarks

### AWS Foundations Benchmark
**Status:**  Production (v0.7.0) - **ENHANCED COVERAGE**
**Controls:** 126+ unique controls implemented
**Command:** `./auditkit scan -provider aws -framework cis-aws`

**What's Covered:**
- **Section 1:** Identity and Access Management (IAM) - 18/22 automated controls (82% coverage)
  - CIS-1.3: Credentials unused 45+ days (NEW)
  - CIS-1.5: Root account MFA enabled (LABELED)
  - CIS-1.11: No root access keys (LABELED)
  - CIS-1.14: Access key rotation (90 days) (LABELED)
  - CIS-1.16: IAM policies on groups/roles only (NEW)
- **Section 2:** Storage (S3, EBS, RDS) - Multiple automated controls
  - CIS-2.1.x: S3 encryption, versioning, logging
- **Section 3:** Logging (CloudTrail, CloudWatch) - 11/11 automated controls (100% coverage)
  - CIS-3.1: CloudTrail enabled in all regions (LABELED)
  - CIS-3.9: VPC Flow Logs enabled (LABELED)
- **Section 4:** Monitoring (Metric Filters & Alarms) - 16/16 controls (100% coverage)
- **Section 5:** Networking (VPC, Security Groups) - 20/20 automated controls (100% coverage)
  - CIS-5.8: VPC peering routing least access (NEW)
  - CIS-5.20: VPC endpoints for S3 (NEW)
- **Sections 6-18:** Service-specific controls across EC2, RDS, Lambda, and more
- **Total Coverage:** 126+ controls (up from 58)

---

### Azure Foundations Benchmark
**Status:** Production (v0.7.0)
**Automated Controls:** ~40+ checks (CIS Microsoft Azure Foundations Benchmark v3.0)
**Command:** `./auditkit scan -provider azure -framework cis-azure`

**Current Coverage:**
- Identity and Access Management (Azure AD)
- Storage Accounts
- SQL Databases
- Virtual Machines
- Networking (NSGs, VNets)
- Monitoring and Logging
- Security Center

---

### GCP Foundations Benchmark
**Status:**  Production (v0.7.0) - **NEAR-COMPLETE COVERAGE**
**Controls:** 48 automated + 9 manual = 57 total checks
**Command:** `./auditkit scan -provider gcp -framework cis-gcp`

**What's Covered:**
- **Section 1:** Identity and Access Management - 9 automated controls
  - CIS-1.1, 1.4, 1.5, 1.7: Corporate login, service accounts, key rotation
  - NEW: CIS-1.9, 1.10: KMS separation of duties and key rotation
- **Section 2:** Logging and Monitoring - 8 automated + 9 manual = 17 controls
  - NEW: CIS-2.2, 2.3, 2.13: Log sinks, retention, DNS logging
  - Manual: CIS-2.4-2.12: Log metric filters and alerts
- **Section 3:** Networking - 6 automated controls
  - CIS-3.1, 3.3, 3.6-3.10: VPC, DNSSEC, firewall, flow logs
- **Section 4:** Compute Engine - 11 automated controls
  - CIS-4.1, 4.3-4.6, 4.8-4.9: Disk encryption, OS login, Shielded VM
- **Section 5:** Cloud Storage - 4 automated controls
  - CIS-5.1-5.3: Uniform access, encryption, versioning
- **Section 6:** Cloud SQL - 7 automated controls
  - CIS-6.1-6.3: Public IP, backups, SSL
  - NEW: CIS-6.1.1, 6.2.1, 6.2.2: Database security flags
- **Section 7:** BigQuery - 3 automated controls
  - NEW: CIS-7.1, 7.2, 7.3: Public access, CMEK encryption
- **Total Coverage:** 57 controls out of ~66 CIS GCP Foundations (86%)**

---

## CIS vs Other Frameworks

| Framework | Purpose | Focus | When to Use |
|-----------|---------|-------|-------------|
| **CIS Benchmarks** | Security hardening | Technical configuration | Proactive security posture |
| **SOC2** | Audit compliance | Trust services | SaaS sales requirements |
| **PCI-DSS** | Payment security | Cardholder data | Processing payments |
| **CMMC** | Defense contracts | CUI protection | DoW contractor requirements |
| **NIST 800-53** | Federal compliance | Risk management | Government work |

**Best Practice:** Use CIS Benchmarks alongside compliance frameworks for comprehensive security.

---

## Implementation Groups

CIS Benchmarks are organized into Implementation Groups (IGs) based on organization size and resources:

### IG1 - Basic Cyber Hygiene
**Target:** Small organizations, limited security resources  
**Controls:** ~56 essential safeguards  
**AuditKit Coverage:** All IG1 controls automated

**Example Controls:**
- Enable MFA for all users
- Encrypt data at rest
- Enable logging and monitoring
- Remove unnecessary services
- Patch systems regularly

### IG2 - Enterprise Security
**Target:** Medium organizations, dedicated security team  
**Controls:** IG1 + ~74 additional controls  
**AuditKit Coverage:** Most IG2 controls automated

**Example Controls:**
- Automated vulnerability scanning
- Network segmentation
- Centralized log management
- Incident response procedures
- Regular penetration testing

### IG3 - Advanced Security
**Target:** Large enterprises, mature security programs  
**Controls:** IG1 + IG2 + ~23 advanced controls  
**AuditKit Coverage:** Some IG3 controls (requires manual processes)

---

## How AuditKit Scans CIS Benchmarks

### Automated Checks (AWS Example)

**Section 1: IAM**
```bash
[PASS] Root account MFA enabled
[FAIL] IAM password policy requires minimum length of 14 characters
[FAIL] Access keys rotated within 90 days
[PASS] Credentials unused for 90 days are disabled
```

**Section 2: Storage**
```bash
[PASS] S3 buckets have encryption enabled
[FAIL] S3 buckets have MFA delete enabled
[PASS] EBS volumes are encrypted
[FAIL] RDS instances have automatic backups enabled
```

**Section 3: Logging**
```bash
[PASS] CloudTrail enabled in all regions
[PASS] CloudTrail log file validation enabled
[FAIL] CloudWatch log groups encrypted with KMS
```

---

## Running CIS Scans

### AWS Foundations Benchmark

**Basic scan:**
```bash
./auditkit scan -provider aws -framework cis-aws
```

**Verbose output:**
```bash
./auditkit scan -provider aws -framework cis-aws -verbose
```

**Generate PDF report:**
```bash
./auditkit scan -provider aws -framework cis-aws -format pdf -output cis-aws-report.pdf
```

**JSON output for automation:**
```bash
./auditkit scan -provider aws -framework cis-aws -format json -output cis-aws.json
```

---

## Example Output

```
CIS AWS Foundations Benchmark Scan Results
==========================================

Overall Compliance: Sample output (actual coverage depends on your infrastructure)

CRITICAL - Fix Immediately (5 failures):
  ✗ [CIS-1.4] Eliminate use of the root account
  ✗ [CIS-1.5] Ensure MFA is enabled for the root account
  ✗ [CIS-2.1.1] Ensure S3 bucket encryption is enabled
  ✗ [CIS-3.1] Ensure CloudTrail is enabled in all regions
  ✗ [CIS-5.2] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22

HIGH PRIORITY (8 failures):
  ✗ [CIS-1.14] Ensure access keys are rotated every 90 days
  ✗ [CIS-2.1.2] Ensure S3 bucket versioning is enabled
  ...

MEDIUM PRIORITY (9 failures):
  ...

PASSED (36 controls):
  [PASS] [CIS-1.6] Ensure hardware MFA is enabled for root account
  [PASS] [CIS-2.1.3] Ensure S3 bucket logging is enabled
  ...
```

---

## Remediation Examples

### CIS-1.5: Enable Root Account MFA

**Manual Steps:**
1. AWS Console → IAM → Dashboard
2. Click "Activate MFA on your root account"
3. Follow wizard to add virtual or hardware MFA

**AWS CLI:**
```bash
# Enable virtual MFA for root account
aws iam enable-mfa-device \
  --user-name root \
  --serial-number arn:aws:iam::ACCOUNT_ID:mfa/root \
  --authentication-code-1 123456 \
  --authentication-code-2 789012
```

**Terraform:**
```hcl
# Root account MFA must be configured manually
# Add to your security checklist
```

---

### CIS-2.1.1: Enable S3 Bucket Encryption

**AWS CLI:**
```bash
# Enable default encryption for all S3 buckets
aws s3api put-bucket-encryption \
  --bucket your-bucket-name \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

**Terraform:**
```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

---

## Frequently Asked Questions

### Q: Do I need to run CIS scans if I'm already SOC2 compliant?
**A:** Yes! SOC2 focuses on business controls and governance. CIS Benchmarks provide technical security hardening that goes beyond compliance requirements. Many SOC2-compliant companies still have security misconfigurations that CIS would catch.

### Q: How often should I run CIS scans?
**A:** 
- **Weekly:** For production environments
- **Daily:** For highly sensitive environments or during security initiatives
- **After changes:** Any infrastructure or configuration changes
- **Before audits:** To verify security posture

### Q: Does AuditKit replace tools like Prowler or AWS Security Hub?
**A:** No, AuditKit complements them. We focus on compliance frameworks and provide auditor-friendly reports. For comprehensive AWS-specific security scanning, use both AuditKit (for compliance reporting) and Prowler (for deep AWS security checks).

### Q: Which CIS version should I use - v1.4 or v3.0?
**A:** AuditKit combines both! v3.0 is newer and consolidated, but v1.4 has some additional checks that are still valuable. Our implementation gives you the best of both versions (126+ unique controls).

### Q: Can I export results to my SIEM or ticketing system?
**A:** Yes! Use JSON output:
```bash
./auditkit scan -provider aws -framework cis-aws -format json -output cis.json
```
Then parse the JSON in your automation workflows.

---

## Official CIS Resources

- **CIS Benchmarks:** https://www.cisecurity.org/cis-benchmarks
- **CIS AWS Benchmark v1.4:** Available from CIS website
- **CIS AWS Benchmark v3.0:** Available from CIS website
- **CIS Controls v8:** https://www.cisecurity.org/controls/v8

---

## Contributing

Help us expand CIS coverage:
- Add Azure CIS checks
- Add GCP CIS checks
- Improve remediation guidance
- Add Terraform/CloudFormation templates

**[Contributing Guide →](../../CONTRIBUTING.md)**

---

## Support

- **Issues:** [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Questions:** info@auditkit.io
- **Pro Support:** Priority email + Slack channel

---

**Last Updated:** October 2025  
**Next Update:** November 2025 (Azure & GCP CIS support)
