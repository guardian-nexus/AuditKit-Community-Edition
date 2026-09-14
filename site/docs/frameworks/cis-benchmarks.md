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
**Status:** Production (v1.0.0)
**Recommendations:** 70 in CIS AWS Foundations v7.0.0
**Command:** `./auditkit scan -provider aws -framework cis-aws`

**What's covered** (from the benchmark catalog and the scanner's source):

- **Section 2** (identity and access management): 26 recommendations, 13 marked Automated by CIS; AuditKit assesses 22 and reports 4 to document
- **Section 3** (storage): 9 recommendations, 6 marked Automated by CIS; AuditKit assesses 6 and reports 3 to document
- **Section 4** (logging): 10 recommendations, 7 marked Automated by CIS; AuditKit assesses 9 and reports 1 to document
- **Section 5** (monitoring): 16 recommendations, 1 marked Automated by CIS; AuditKit assesses 16 and reports 0 to document
- **Section 6** (networking): 9 recommendations, 7 marked Automated by CIS; AuditKit assesses 8 and reports 1 to document
- **Total:** 70 recommendations; 61 assessed, 9 reported to document


---

### Azure Foundations Benchmark
**Status:** Production
**Recommendations:** 127 in CIS Microsoft Azure Foundations v6.0.0
**Command:** `./auditkit scan -provider azure -framework cis-azure`

**What's covered** (from the benchmark catalog and the scanner's source):

- **Section 2** (Databricks): 12 recommendations, 6 marked Automated by CIS; AuditKit assesses 12 and reports 0 to document
- **Section 3**: 1 recommendations, 0 marked Automated by CIS; AuditKit assesses 1 and reports 0 to document
- **Section 5** (identity and access management): 15 recommendations, 5 marked Automated by CIS; AuditKit assesses 15 and reports 0 to document
- **Section 6** (logging and monitoring): 24 recommendations, 15 marked Automated by CIS; AuditKit assesses 23 and reports 1 to document
- **Section 7** (networking): 16 recommendations, 14 marked Automated by CIS; AuditKit assesses 15 and reports 1 to document
- **Section 8** (Defender for Cloud): 38 recommendations, 30 marked Automated by CIS; AuditKit assesses 35 and reports 3 to document
- **Section 9** (storage): 21 recommendations, 19 marked Automated by CIS; AuditKit assesses 21 and reports 0 to document
- **Total:** 127 recommendations; 122 assessed, 5 reported to document


---

### GCP Foundations Benchmark
**Status:** Production
**Recommendations:** 93 in CIS GCP Foundations v5.0.0
**Command:** `./auditkit scan -provider gcp -framework cis-gcp`

**What's covered** (from the benchmark catalog and the scanner's source):

- **Section 1** (identity and access management): 21 recommendations, 12 marked Automated by CIS; AuditKit assesses 15 and reports 6 to document
- **Section 2** (logging and monitoring): 17 recommendations, 14 marked Automated by CIS; AuditKit assesses 17 and reports 0 to document
- **Section 3** (networking): 12 recommendations, 8 marked Automated by CIS; AuditKit assesses 10 and reports 2 to document
- **Section 4** (virtual machines): 12 recommendations, 10 marked Automated by CIS; AuditKit assesses 10 and reports 2 to document
- **Section 5** (storage): 2 recommendations, 2 marked Automated by CIS; AuditKit assesses 1 and reports 1 to document
- **Section 6** (databases): 24 recommendations, 21 marked Automated by CIS; AuditKit assesses 22 and reports 2 to document
- **Section 7** (BigQuery): 4 recommendations, 3 marked Automated by CIS; AuditKit assesses 4 and reports 0 to document
- **Section 8**: 1 recommendations, 1 marked Automated by CIS; AuditKit assesses 1 and reports 0 to document
- **Total:** 93 recommendations; 80 assessed, 13 reported to document


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
**AuditKit Coverage:** AuditKit scans the CIS Foundations Benchmarks, which are not tagged by Implementation Group. Map benchmark findings to your IG tier manually.

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

### Q: Which CIS benchmark versions does AuditKit implement?
**A:** CIS AWS Foundations v7.0.0, CIS Microsoft Azure Foundations v6.0.0 and CIS GCP Foundations v5.0.0. Report identifiers use those versions' numbering, so they match the benchmark PDF you are hardening against.

### Q: Can I export results to my SIEM or ticketing system?
**A:** Yes! Use JSON output:
```bash
./auditkit scan -provider aws -framework cis-aws -format json -output cis.json
```
Then parse the JSON in your automation workflows.

---

## Official CIS Resources

- **CIS Benchmarks:** https://www.cisecurity.org/cis-benchmarks
- **CIS Benchmarks:** the AWS, Azure and GCP Foundations benchmarks are available from the CIS website
- **CIS Controls v8:** https://www.cisecurity.org/controls/v8

---

## Contributing

Help us expand CIS coverage:

- Improve remediation guidance
- Add Terraform/CloudFormation templates

**[Contributing Guide →](https://github.com/guardian-nexus/AuditKit-Community-Edition/blob/main/CONTRIBUTING.md)**

---

## Support

- **Issues:** [GitHub Issues](https://github.com/guardian-nexus/AuditKit-Community-Edition/issues)
- **Questions:** info@auditkit.io
- **Pro Support:** Priority email support

---

**Last Updated:** September 2026
