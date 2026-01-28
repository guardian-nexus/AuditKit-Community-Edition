# Getting Started with AuditKit

Get your first compliance scan running in 5 minutes.

---

## Prerequisites

- Cloud account access (AWS, Azure, or GCP)
- Cloud CLI installed and configured
- 5 minutes

---

## Installation

### Option 1: Download Binary (Fastest)

1. Go to [Releases](https://github.com/guardian-nexus/auditkit/releases)
2. Download binary for your OS (Linux, macOS, Windows)
3. Make it executable: `chmod +x auditkit`
4. Run: `./auditkit scan`

### Option 2: Build from Source

```bash
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner
go build ./cmd/auditkit
./auditkit scan
```

---

## Your First Scan

### AWS

```bash
# 1. Configure AWS credentials
aws configure

# 2. Run scan
./auditkit scan -provider aws -framework soc2

# 3. Generate PDF report
./auditkit scan -provider aws -framework soc2 -format pdf -output report.pdf
```

**Setup details:** [AWS Authentication →](./setup/aws.md)

### Azure

```bash
# 1. Login to Azure
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# 2. Run scan
./auditkit scan -provider azure -framework soc2

# 3. Generate PDF report
./auditkit scan -provider azure -framework soc2 -format pdf -output report.pdf
```

**Setup details:** [Azure Authentication →](./setup/azure.md)

### GCP

```bash
# 1. Login to GCP
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-project-id

# 2. Run scan
./auditkit scan -provider gcp -framework soc2

# 3. Generate PDF report
./auditkit scan -provider gcp -framework soc2 -format pdf -output report.pdf
```

**Setup details:** [GCP Authentication →](./setup/gcp.md)

---

## Understanding Your Results

### Terminal Output

```
AuditKit SOC2 Compliance Scan Results
=====================================
AWS Account: 123456789012
Scan Time: 2025-10-19 14:30:00

Compliance Score: 72.5%
Controls Passed: 46/64

Critical Issues: 3 (FIX IMMEDIATELY)
High Priority: 6
Medium Priority: 4

CRITICAL - Fix These NOW:
[FAIL] CC6.6 - User MFA Enforcement
[FAIL] CC6.2 - S3 Bucket Public Access
[FAIL] CC6.1 - IAM Key Rotation
```

**What this means:**
- **Compliance Score:** Percentage of passing controls
- **Critical Issues:** Security gaps requiring immediate attention
- **Each failed control shows:** What's wrong and how to fix it

### Report Types

**PDF Report** - For auditors and management
```bash
./auditkit scan -format pdf -output report.pdf
```

**HTML Report** - Interactive, great for teams
```bash
./auditkit scan -format html -output report.html
```

**JSON Report** - For automation/CI/CD
```bash
./auditkit scan -format json -output results.json
```

---

## Next Steps

### 1. Fix Critical Issues

AuditKit shows exact commands to fix each issue:

```bash
# Generate fix script
./auditkit fix -output fixes.sh

# Review the script
cat fixes.sh

# Run fixes (review first!)
bash fixes.sh
```

### 2. Track Your Progress

```bash
# Show improvement over time
./auditkit progress

# Compare last two scans
./auditkit compare
```

### 3. Scan Other Frameworks

```bash
# PCI-DSS
./auditkit scan -framework pci

# CMMC Level 1
./auditkit scan -framework cmmc

# NIST 800-53
./auditkit scan -framework 800-53

# All frameworks
./auditkit scan -framework all
```

**Framework details:** [Frameworks →](./frameworks/)

---

## Common Use Cases

### For Startups: SOC2 Preparation

**Goal:** Pass SOC2 Type II audit without hiring consultants

**Steps:**
1. Run initial scan: `./auditkit scan -framework soc2`
2. Fix critical issues (usually takes 1-2 days)
3. Re-scan weekly to track progress
4. Generate final report for auditor
5. Collect evidence using evidence tracker

**Timeline:** Most startups fix 80%+ of issues in 2-4 weeks

### For DoW Contractors: CMMC Compliance

**Goal:** Self-assess CMMC Level 1 before C3PAO assessment

**Steps:**
1. Run CMMC scan: `./auditkit scan -framework cmmc`
2. Fix automated controls (AC.1.001, AC.1.002, etc.)
3. Document manual controls (physical security, training)
4. Generate assessment report
5. Schedule C3PAO review with confidence

**Note:** Need CMMC Level 2 (110 practices)? [Try Pro free for 14 days →](https://auditkit.io/pro/)

### For Multi-Cloud: Unified Compliance

**Goal:** Single compliance view across AWS + Azure + GCP

**Steps:**
```bash
# Scan all providers
./auditkit scan -provider aws -framework soc2 -output aws-results.json
./auditkit scan -provider azure -framework soc2 -output azure-results.json
./auditkit scan -provider gcp -framework soc2 -output gcp-results.json

# Compare results
# (Unified reporting coming in v0.8.0)
```

---

## Troubleshooting

### "Error: AWS credentials not configured"

**Solution:**
```bash
aws configure
# Enter your AWS Access Key ID and Secret Access Key
```

**Details:** [AWS Setup →](./setup/aws.md)

### "Error: Azure subscription not found"

**Solution:**
```bash
az login
az account list  # Find your subscription ID
export AZURE_SUBSCRIPTION_ID="your-sub-id"
```

**Details:** [Azure Setup →](./setup/azure.md)

### "Error: GCP project not found"

**Solution:**
```bash
gcloud auth application-default login
gcloud projects list  # Find your project ID
export GOOGLE_CLOUD_PROJECT=your-project-id
```

**Details:** [GCP Setup →](./setup/gcp.md)

### "Compliance score is very low (< 30%)"

**Common cause:** Security services not enabled

**Solution:** Enable these first:
- **AWS:** GuardDuty, Config, CloudTrail, Security Hub
- **Azure:** Defender for Cloud, Azure Policy, Activity Logs
- **GCP:** Security Command Center, Cloud Logging, Cloud KMS

Then re-scan.

---

## Getting Help

- **Documentation:** [Full docs →](../)
- **Examples:** [Sample reports →](./examples/)
- **Issues:** [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **FAQ:** [Common questions →](./faq.md)
- **Newsletter:** [auditkit.substack.com](https://auditkit.substack.com)

---

## What's Next?

- **[CLI Reference](./cli-reference.md)** - All commands and flags
- **[Frameworks Guide](./frameworks/)** - Deep dive into SOC2, PCI-DSS, CMMC, etc.
- **[Cloud Setup](./setup/)** - Detailed authentication guides
- **[FAQ](./faq.md)** - Answers to common questions

**Ready for CMMC Level 2 or advanced GCP features?** [Try Pro free for 14 days →](https://auditkit.io/pro/)
