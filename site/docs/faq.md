# Frequently Asked Questions

Common questions about AuditKit.

---

## General Questions

### Does this replace my auditor?

No. AuditKit automates the **technical controls** portion of compliance audits, but you still need:

- **SOC2:** CPA firm for certification ($15,000 - $30,000)
- **CMMC:** C3PAO for assessment ($25,000 - $150,000)
- **PCI-DSS:** QSA for certification ($15,000 - $50,000)

**What AuditKit replaces:** Technical consultant fees ($30,000 - $100,000) for infrastructure scanning and remediation

**What you still need:** Certified auditor/assessor for final certification

Think of AuditKit as doing the heavy lifting on infrastructure checks, so you can focus on organizational policies and procedures with your auditor.

### Is this a security scanner?

No. AuditKit checks **compliance controls**, not vulnerabilities. 

For security scanning, use tools like:
- **Prowler** - AWS security scanner
- **Scout Suite** - Multi-cloud security auditing
- **Trivy** - Container vulnerability scanning

AuditKit can integrate with Prowler for complete NIST 800-53 coverage.

### What's the difference between Free and Pro?

| Feature | Free | Pro ($297/mo) |
|---------|------|---------------|
| AWS/Azure/GCP/M365 | Full support | Full support |
| SOC2, PCI-DSS, NIST 800-53 | All frameworks | All frameworks |
| CMMC Level 1 | 17 practices | 17 practices |
| CMMC Level 2 | - | 110 practices (CUI) |
| GCP Core | 170+ checks | 170+ checks |
| GCP Advanced | - | GKE + Vertex AI (32 checks) |
| Multi-Account | One at a time | AWS Orgs, Azure Mgmt, GCP Folders |
| Support | Community | Priority + 14-day trial |

**[Try Pro free for 14 days →](https://auditkit.io/pro/)**

### How much does it cost?

**Free version:** $0 forever (open source)  
**Pro version:** $297/month with 14-day free trial

Compare to traditional costs:
- SOC2 consultant: $50,000+
- CMMC C3PAO assessment: $25,000+
- Compliance platforms (Vanta/Drata): $5,000+/year

**[Start Pro trial →](https://auditkit.io/pro/)**

---

## Technical Questions

### Which cloud providers are supported?

**Fully supported:**
- AWS (Amazon Web Services)
- Azure (Microsoft Azure)
- GCP (Google Cloud Platform)
- M365 (Microsoft 365) via ScubaGear integration

**Coverage:**
- AWS: 64+ SOC2 controls, 30+ PCI-DSS, 17 CMMC L1, 110 CMMC L2 (Pro)
- Azure: 64+ SOC2 controls, 30+ PCI-DSS, 17 CMMC L1, 110 CMMC L2 (Pro)
- GCP: 170+ core checks (Free), +32 advanced checks (Pro)
- M365: 29+ Entra ID rules via ScubaGear

### Which GCP services are scanned?

**Free version (170+ checks):**
- Cloud Storage (GCS)
- Cloud IAM
- Compute Engine
- VPC Networks
- Cloud SQL
- Cloud KMS
- Cloud Logging

**Pro version adds (20 additional checks):**
- GKE Security (10 checks)
- Vertex AI Compliance (10 checks)

**[View full GCP coverage →](./providers/gcp.md)**

### What frameworks are supported?

| Framework | Status | Coverage |
|-----------|--------|----------|
| SOC2 Type II | Production | 64 controls |
| PCI-DSS v4.0 | Production | 30+ controls |
| CMMC Level 1 | Production | 17 practices |
| CMMC Level 2 | Pro only | 110 practices |
| NIST 800-53 Rev 5 | Production | ~150 technical controls |
| HIPAA | Experimental | ~15 controls |

**[Framework details →](./frameworks/)**

### Can I scan multiple accounts/projects?

**Free version:** One account/project at a time. Switch between them:

```bash
# AWS - use profiles
auditkit scan -provider aws -profile production
auditkit scan -provider aws -profile staging

# Azure - change subscription
export AZURE_SUBSCRIPTION_ID="sub-1"
auditkit scan -provider azure

# GCP - change project
export GOOGLE_CLOUD_PROJECT=project-1
auditkit scan -provider gcp
```

**Pro version:** Scan entire organizations automatically:

```bash
# Scan AWS Organization
auditkit scan -provider aws --scan-all

# Scan Azure Management Group
auditkit scan -provider azure --scan-all

# Scan GCP Folders/Organization
auditkit scan -provider gcp --scan-all
```

**[Upgrade to Pro →](https://auditkit.io/pro/)**

### Why is my compliance score low?

Common reasons:

**1. Security services not enabled**

Enable these first:
- **AWS:** GuardDuty, Config, CloudTrail, Security Hub
- **Azure:** Defender for Cloud, Azure Policy, Activity Logs
- **GCP:** Security Command Center, Cloud Logging, Cloud KMS

**2. Basic security controls missing**
- MFA not enforced
- CloudTrail/logging not configured
- Encryption not enabled
- Public access on storage

**3. Old infrastructure**
- IAM keys older than 90 days
- Unpatched EC2 instances
- Legacy security groups

**Fix critical issues first, then re-scan.**

### Does AuditKit make any changes to my infrastructure?

**No.** AuditKit is **read-only**. It only:
- Reads configuration
- Checks security settings
- Generates reports

It **never** modifies your infrastructure.

The `auditkit fix` command generates a script for you to review and run manually.

### What permissions does AuditKit need?

**AWS:** `ReadOnlyAccess` managed policy  
**Azure:** `Reader` role  
**GCP:** `roles/viewer` role  

All read-only, no write permissions required.

**[Setup guides →](./setup/)**

---

## CMMC Questions

### What's the difference between CMMC Level 1 and Level 2?

**CMMC Level 1 (17 practices) - FREE**
- Protects Federal Contract Information (FCI)
- Basic cybersecurity hygiene
- Required for all DoW contractors
- Self-assessment allowed

**CMMC Level 2 (110 practices) - PRO**
- Protects Controlled Unclassified Information (CUI)
- Based on NIST SP 800-171 Rev 2
- Required for contractors handling CUI
- Requires C3PAO assessment

**Example CUI:** Technical specs, mission plans, personnel records, logistics data

**If your DoW contract mentions CUI, you need Level 2.**

### How much does CMMC Level 2 Pro cost?

**$297/month** with 14-day free trial (no credit card required)

Compare to:
- C3PAO assessment: $25,000 - $150,000
- CMMC consultants: $50,000+
- Traditional compliance platforms: $5,000+/year (without CMMC L2)

**[Try Pro free →](https://auditkit.io/pro/)**

### When is the CMMC deadline?

**November 10, 2025** - CMMC requirements start appearing in DoW contracts

DoW contractors must be compliant when specified in contract solicitations. Many contracts now include CMMC Level 1 or Level 2 requirements.

**[Start your assessment now →](./getting-started.md)**

### Can AuditKit prepare me for C3PAO assessment?

Yes, for **technical controls**. AuditKit automates:
- Technical security configuration checks
- Evidence collection guides
- Remediation commands
- Assessment reports

You still need to handle:
- Organizational policies
- Security awareness training
- Incident response procedures
- Physical security measures

**Timeline:** Most contractors fix 80%+ of technical issues in 2-4 weeks with AuditKit.

---

## Scanning Questions

### How long does a scan take?

**Single account scan:** 2-5 minutes

**Factors affecting speed:**
- Number of resources in your account
- Number of regions (AWS)
- Network latency
- API rate limits

**Pro multi-account scans:** 10-30 minutes depending on organization size

### Can I scan specific services only?

Not currently. AuditKit scans all supported services for the chosen framework.

**Workaround:** Run scan, then filter results in JSON output:

```bash
auditkit scan -format json -output results.json
jq '.controls[] | select(.category == "Storage")' results.json
```

### Can I run scans automatically?

Yes. AuditKit works great in CI/CD:

```bash
# In your CI pipeline
auditkit scan -provider aws -framework soc2 -format json -output results.json

# Check compliance score
SCORE=$(jq '.score' results.json)
if (( $(echo "$SCORE < 80" | bc -l) )); then
  echo "Compliance score too low: $SCORE%"
  exit 1
fi
```

**[CI/CD examples →](./examples/ci-cd/)**

### What if I get rate limited?

Cloud providers have API rate limits. If you hit them:

**AWS:**
```bash
# Reduce concurrent requests (Pro only)
auditkit scan --scan-all --max-concurrent 2
```

**All providers:**
- Run scans during off-peak hours
- Increase service quotas in cloud console
- Contact cloud provider support

---

## Reporting Questions

### What report formats are available?

**Terminal output** - Quick results
```bash
auditkit scan
```

**PDF** - For auditors and management
```bash
auditkit scan -format pdf -output report.pdf
```

**HTML** - Interactive, searchable
```bash
auditkit scan -format html -output report.html
```

**JSON** - For automation
```bash
auditkit scan -format json -output results.json
```

### Can I customize reports?

Not in the Free version. Reports follow standard compliance framework formats.

**Pro version:** Reports include:
- Watermarking with license info

### What's in the PDF report?

- Executive summary
- Compliance score and grade
- Passed controls (with evidence)
- Failed controls (with remediation)
- Evidence collection guides
- Compliance framework mapping
- Scan metadata (date, account, etc.)

**[View sample reports →](./examples/)**

---

## Integration Questions

### Does AuditKit integrate with Jira/Slack/ServiceNow?

Not yet. Currently on roadmap for Q1 2026.

**Workaround:** Use JSON output with custom scripts:

```bash
# Export results to JSON
auditkit scan -format json -output results.json

# Parse and create Jira tickets
python create-jira-tickets.py results.json
```

### Can I use AuditKit with Prowler?

Yes! AuditKit can import Prowler scan results directly:

```bash
# Run Prowler scan first
prowler aws --output-formats json -o prowler-output

# Import into AuditKit with framework mapping
auditkit integrate -source prowler -file prowler-output.json

# Generate PDF report from Prowler results
auditkit integrate -source prowler -file prowler-output.json -format pdf -output prowler-report.pdf
```

This maps Prowler findings to SOC2, PCI-DSS, CMMC, HIPAA, and other compliance frameworks.

**[Prowler integration guide →](./integrations/prowler.md)**

### How do I integrate M365?

AuditKit uses CISA ScubaGear for M365 scanning:

```powershell
# 1. Install ScubaGear (Windows PowerShell)
Install-Module -Name ScubaGear

# 2. Run ScubaGear
Invoke-SCuBA -ProductNames aad,exo,sharepoint,teams -OutPath ./ScubaResults

# 3. Import into AuditKit
auditkit integrate -source scubagear -file ScubaResults/ScubaResults.json
```

**[M365 setup guide →](./setup/m365.md)**

---

## Troubleshooting

### "Error: AWS credentials not configured"

**Solution:**
```bash
aws configure
# Enter your AWS Access Key ID and Secret Access Key
```

**[AWS setup guide →](./setup/aws.md)**

### "Error: Azure subscription not found"

**Solution:**
```bash
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

**[Azure setup guide →](./setup/azure.md)**

### "Error: GCP project not found"

**Solution:**
```bash
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=your-project-id
```

**[GCP setup guide →](./setup/gcp.md)**

### "Error: Permission denied"

**Cause:** IAM user/service account lacks required permissions

**Solution:**
- **AWS:** Attach `ReadOnlyAccess` policy
- **Azure:** Grant `Reader` role
- **GCP:** Grant `roles/viewer` role

**[Setup guides →](./setup/)**

### Scan results show "INFO" for many controls

**This is normal.** Some controls require manual verification:
- Physical security measures
- Security awareness training
- Vendor management processes
- Incident response procedures

Generate evidence tracker for manual controls:
```bash
auditkit evidence -format html -output evidence-tracker.html
```

---

## Comparison Questions

### AuditKit vs Vanta/Drata?

**Vanta/Drata:**
- Full compliance platforms ($5,000+/year)
- Include policy management, vendor tracking, employee training
- Automated evidence collection
- Great for SOC2, but expensive

**AuditKit:**
- Technical control scanning only
- Free for SOC2/PCI/CMMC L1
- $297/month for CMMC L2 + advanced features
- Open source, self-hosted

**Use AuditKit if:** You want technical scanning without paying for full compliance platform

### AuditKit vs Prowler/Scout Suite?

**Prowler/Scout Suite:**
- Security scanners (not compliance-focused)
- Check 1000+ security findings
- No compliance framework mapping
- No evidence collection guides

**AuditKit:**
- Compliance scanners (not security-focused)
- Check 150+ compliance controls
- Maps to SOC2, PCI-DSS, CMMC, NIST 800-53
- Includes evidence collection guides

**Use both:** Prowler for security, AuditKit for compliance

### AuditKit vs manual compliance?

**Manual compliance:**
- Take screenshots manually (days)
- Document everything in spreadsheets
- Hope you didn't miss anything
- Pay consultant $50,000+

**AuditKit:**
- Automated scanning (5 minutes)
- Generate reports instantly
- Evidence guides included
- Free (or $297/month for Pro)

**AuditKit saves:** 40+ hours per compliance cycle

---

## Getting More Help

**Documentation:**
- [Getting Started →](./getting-started.md)
- [Setup Guides →](./setup/)
- [CLI Reference →](./cli-reference.md)
- [Framework Guides →](./frameworks/)

**Support:**
- [GitHub Issues](https://github.com/guardian-nexus/AuditKit-Community-Edition/issues)
- [Newsletter](https://auditkit.substack.com)
- Pro Support: info@auditkit.io

**Try Pro:**
- [14-day free trial →](https://auditkit.io/pro/)
