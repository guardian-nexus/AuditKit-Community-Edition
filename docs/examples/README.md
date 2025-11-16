# AuditKit Examples

This directory contains real-world examples demonstrating AuditKit's compliance scanning capabilities across AWS, Azure, and GCP environments.

**What's included:**
- Interactive HTML reports with evidence collection guides
- PDF reports ready for auditor submission
- Raw terminal scan outputs showing actual findings
- Console screenshots for verification workflows

All examples are generated from actual scans against test environments.

---

## Interactive HTML Reports

Professional, auditor-ready compliance reports with clickable tabs, severity badges, and direct cloud console links.

| Framework | Provider | Controls | View Report |
|-----------|----------|----------|-------------|
| **CMMC Level 2** | AWS | 127 practices | [View HTML](./reports/sample-aws-cmmc-level2-report.html) |
| **SOC2** | AWS | 49 controls | [View HTML](./reports/sample-aws-soc2-report.html) |
| **CMMC Level 1** | Azure | 17 practices | [View HTML](./reports/sample-azure-cmmc-report.html) |

**Features:**
- Visual compliance score dashboard
- Failed controls with remediation commands
- Passed controls with evidence
- Manual documentation requirements
- Direct links to AWS/Azure/GCP consoles

---

## PDF Reports

Print-ready compliance reports for stakeholder distribution and audit submissions.

| Framework | Provider | Download |
|-----------|----------|----------|
| CMMC Level 1 | AWS | [Download PDF](./reports/sample-aws-cmmc-report.pdf) |
| SOC2 | AWS | [Download PDF](./reports/sample-aws-soc2-report.pdf) |
| PCI-DSS | AWS | [Download PDF](./reports/sample-aws-pci-report.pdf) |
| CMMC Level 1 | Azure | [Download PDF](./reports/sample-azure-cmmc-report.pdf) |

---

## Terminal Scan Outputs

Raw command-line outputs showing how AuditKit displays findings in real-time.

- **[AWS SOC2 Scan](./scan-outputs/aws-soc2-scan.txt)** - 49 controls tested across IAM, S3, EC2, CloudTrail, Config
- **[AWS PCI-DSS Scan](./scan-outputs/aws-pci-scan.txt)** - Payment card data protection requirements
- **[AWS CMMC Scan](./scan-outputs/aws-cmmc-scan.txt)** - Defense contractor compliance requirements
- **[Azure CMMC Scan](./scan-outputs/azure-cmmc-scan.txt)** - Azure-specific CMMC controls

**What you'll see:**
```
✓ PASS | CC6.6 - Authentication Controls
  Root account has MFA enabled
  → Meets SOC2 CC6.6, PCI DSS 8.3.1

✗ FAIL | CC6.1 - Access Controls
  Issue: 1 security groups have SSH open to 0.0.0.0/0
  Fix: aws ec2 revoke-security-group-ingress --group-id sg-xxx
```

---

## Screenshots

Visual examples of AuditKit's output and HTML report features.

| Screenshot | Description |
|------------|-------------|
| [Azure Console Output](./screenshots/azure-cmmc-scan-console-output-sample.png) | Terminal scan in progress with color-coded results |
| [HTML Report Score](./screenshots/html-report-score.png) | Compliance dashboard with visual score indicator |
| [HTML Report Evidence](./screenshots/html-report-evidence.png) | Evidence collection guide with console URLs |
| [HTML Report Disclaimer](./screenshots/html-report-disclaimer.png) | Automated vs manual control breakdown |

---

## Try It Yourself

### Install AuditKit (Free - CMMC Level 1, SOC2, PCI-DSS)

```bash
# Download latest release
curl -LO https://github.com/guardian-nexus/auditkit/releases/latest/download/auditkit-linux-amd64.tar.gz

# Extract
tar -xzf auditkit-linux-amd64.tar.gz
chmod +x auditkit-linux-amd64

# Run your first scan
./auditkit-linux-amd64 scan -provider aws -framework soc2 -verbose

# Generate PDF report
./auditkit-linux-amd64 scan -provider aws -framework cmmc -format pdf -output my-report.pdf
```

### Upgrade to AuditKit Pro (CMMC Level 2 + Pro Features)

AuditKit Pro includes:
- **CMMC Level 2** - All 110 Level 2 practices (110 additional controls)
- **Evidence Package Generator** - C3PAO-ready ZIP files
- **Exception Management** - Track waivers with compensating controls
- **Continuous Monitoring** - Scheduled scans with alerting
- **Drift Detection** - Compare dev/staging/prod environments
- **Multi-Account Scanning** - AWS Orgs, Azure MGs, GCP Folders

**[Subscribe to AuditKit Pro →](../pro/)**

---

## Privacy Notice

All examples in this directory are generated from synthetic test environments. No real production data, account IDs, or sensitive information is included. Where account IDs appear (e.g., `1234567890`), they are dummy values for demonstration purposes.

---

**Questions?** Email [hello@auditkit.io](mailto:hello@auditkit.io) • [Documentation](../) • [AuditKit Pro](../pro/)
