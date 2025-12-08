# AuditKit - Open-Source Compliance Scanner

**Scan AWS, Azure, GCP, and M365 for SOC2, PCI-DSS, HIPAA, CMMC, CIS Benchmarks, and NIST 800-53 compliance. Get audit-ready reports in minutes.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.7.1-green.svg)](https://github.com/guardian-nexus/auditkit/releases)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)

---

## Quick Start

```bash
# Install
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner
go build ./cmd/auditkit

# Scan AWS
./auditkit scan -provider aws -framework soc2          # SOC2 compliance
./auditkit scan -provider aws -framework cis-aws       # CIS security hardening

# Scan Azure
./auditkit scan -provider azure -framework soc2        # SOC2 compliance
./auditkit scan -provider azure -framework cis-azure   # CIS security hardening

# Scan GCP
./auditkit scan -provider gcp -framework soc2          # SOC2 compliance
./auditkit scan -provider gcp -framework cis-gcp       # CIS security hardening

# Generate reports (PDF, HTML, CSV, JSON)
./auditkit scan -provider aws -framework soc2 -format pdf -output aws-soc2.pdf
./auditkit scan -provider gcp -framework pci -format html -output gcp-pci.html
```

**Setup:** [AWS](./docs/setup/aws.md) • [Azure](./docs/setup/azure.md) • [GCP](./docs/setup/gcp.md) • [M365](./docs/setup/m365.md)

---

## What It Does

AuditKit scans your cloud infrastructure for compliance gaps and security misconfigurations:

- **Automated Scanning:** ~150 technical controls per framework
- **Multi-Cloud Support:** AWS, Azure, GCP, M365 in one tool
- **Audit-Ready Reports:** PDF/HTML/JSON output with evidence
- **Fix Commands:** Exact CLI/Terraform commands to remediate issues
- **Framework Crosswalk:** One control fix improves multiple frameworks

**What it doesn't do:** Replace auditors, scan for vulnerabilities, or guarantee certification.

**[View Examples →](./docs/examples/)** • **[Read Documentation →](./docs/)**

---

## Supported Frameworks

### Compliance Frameworks

| Framework | AWS | Azure | GCP | Purpose |
|-----------|-----|-------|-----|---------|
| **SOC2 Type II** | 64 | 64 | 64 | SaaS customer requirements |
| **PCI-DSS v4.0** | All 12 Req | All 12 Req | All 12 Req | Payment card processing |
| **CMMC Level 1** | 17 | 17 | 17 | DoD contractor compliance (FCI) |
| **CMMC Level 2** | 110 | 110 | 110 | DoD contractor compliance (CUI) - [Pro](https://auditkit.io/pro) |
| **NIST 800-53 Rev 5** | ~150 | ~150 | ~150 | Federal contractor requirements / FedRAMP |
| **ISO 27001:2022** | ~60 | ~60 | ~60 | International information security |
| **HIPAA Security Rule** | 70 | 62 | 40 | Healthcare data protection |

### Security Hardening

| Framework | AWS | Azure | GCP | Purpose |
|-----------|-----|-------|-----|---------|
| **CIS Benchmarks** | 126+ | ~40+ | 61 | Industry security best practices |

**[Framework Details →](./docs/frameworks/)** • **[What's the difference? →](./docs/frameworks/#compliance-vs-security-hardening)**

---

## Free vs Pro

| Feature | Free | Pro ($297/mo) |
|---------|------|---------------|
| **Cloud Providers** | AWS, Azure, GCP, M365 | Same |
| **Compliance Frameworks** | SOC2, PCI-DSS, CMMC L1, NIST 800-53 | Same |
| **CIS Benchmarks** | AWS (126+ controls) | All clouds when available |
| **GCP Core** | 170+ checks | Same |
| **GCP Advanced** | - | GKE + Vertex AI (32 checks) |
| **Multi-Account** | - | AWS Orgs, Azure Mgmt, GCP Folders |
| **CMMC Level 2** | - | 110 practices (CUI handling) |
| **Desktop GUI** | - | Web dashboard at localhost:1337 |
| **Support** | Community (GitHub Issues) | Priority email + 14-day trial |

**[Compare Features →](./docs/pricing.md)** • **[Start Pro Trial →](https://auditkit.io/pro)**

---

## NEW: AuditKit Pro Desktop (v0.8.1)

**Pro customers now get a beautiful web-based dashboard** that runs locally on your machine.

![AuditKit Pro Desktop Dashboard](./docs/examples/screenshots/auditkitwebgui-dashboard.png)

### Desktop Features
- **Visual Dashboard** - Real-time compliance scores and trends
- **Scan History** - Browse all past scans with search and filtering
- **Findings Explorer** - Searchable table of all findings with severity filtering
- **Evidence Packages** - Generate audit-ready ZIP files from the browser
- **Exception Management** - Track waivers and compensating controls with full CRUD
- **Drift Detection** - Visual comparison of scans to identify configuration changes
- **Continuous Monitoring** - Schedule recurring scans with cron-style scheduling
- **100% Offline** - Runs locally, no cloud dependencies, air-gap compatible

### Screenshots

| Dashboard | Findings | Scan History |
|-----------|----------|--------------|
| <img src="./docs/examples/screenshots/auditkitwebgui-dashboard.png" width="280" alt="Dashboard"> | <img src="./docs/examples/screenshots/auditkitwebgui-findings.png" width="280" alt="Findings"> | <img src="./docs/examples/screenshots/auditkitwebgui-scanhistory.png" width="280" alt="Scan History"> |

### Quick Start (Pro Desktop)
```bash
# Set license and run
export AUDITKIT_PRO_LICENSE="your-license-key"
./auditkit-pro-desktop

# Browser opens automatically to http://localhost:1337
# Change port if needed: ./auditkit-pro-desktop --port 8080
```

**[Learn More About Pro →](https://auditkit.io/pro)** • **[Start 14-Day Trial →](https://buy.stripe.com/28E14m5MS5xM0mj4r7gnK01)**

---

## Why Use AuditKit?

**For Startups:** Free SOC2 prep without $50K consultants  
**For Security Teams:** CIS Benchmarks for proactive hardening  
**For DoD Contractors:** CMMC Level 1 (Free) or Level 2 (Pro) compliance  
**For Multi-Cloud:** Single tool for AWS + Azure + GCP + M365  
**For DevOps:** JSON output for CI/CD integration

---

## Installation

### Pre-built Binaries
Download from [GitHub Releases](https://github.com/guardian-nexus/auditkit/releases)

### From Source

**Option 1: Universal Scanner (All Clouds)**
```bash
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner
go build ./cmd/auditkit
./auditkit scan -provider aws -framework soc2
```

**Option 2: Provider-Specific Scanners (Smaller Binaries)**
```bash
# AWS-only scanner (~30% smaller)
go build -o auditkit-aws ./cmd/auditkit-aws
./auditkit-aws scan -framework soc2

# Azure-only scanner
go build -o auditkit-azure ./cmd/auditkit-azure
./auditkit-azure scan -framework soc2

# GCP-only scanner
go build -o auditkit-gcp ./cmd/auditkit-gcp
./auditkit-gcp scan -framework soc2
```

**Requirements:**
- Go 1.19+
- Cloud credentials configured (AWS CLI, Azure CLI, gcloud CLI)
- Read-only permissions (no write access needed)

**[Full Installation Guide →](./docs/installation.md)**

---

## Example Commands

### Compliance Scanning (All Clouds)
```bash
# AWS scans
./auditkit scan -provider aws -framework soc2       # SOC2 Type II
./auditkit scan -provider aws -framework pci        # PCI-DSS v4.0
./auditkit scan -provider aws -framework cmmc       # CMMC Level 1
./auditkit scan -provider aws -framework 800-53     # NIST 800-53 Rev 5

# Azure scans
./auditkit scan -provider azure -framework soc2     # SOC2 Type II
./auditkit scan -provider azure -framework pci      # PCI-DSS v4.0
./auditkit scan -provider azure -framework cmmc     # CMMC Level 1

# GCP scans
./auditkit scan -provider gcp -framework soc2       # SOC2 Type II
./auditkit scan -provider gcp -framework pci        # PCI-DSS v4.0
./auditkit scan -provider gcp -framework cmmc       # CMMC Level 1
```

### Security Hardening (CIS Benchmarks)
```bash
./auditkit scan -provider aws -framework cis-aws      # CIS AWS (58 controls)
./auditkit scan -provider azure -framework cis-azure  # CIS Azure (40+ controls)
./auditkit scan -provider gcp -framework cis-gcp      # CIS GCP (30+ controls)
```

### Report Generation
```bash
# PDF reports
./auditkit scan -provider aws -framework soc2 -format pdf -output aws-soc2.pdf
./auditkit scan -provider azure -framework pci -format pdf -output azure-pci.pdf
./auditkit scan -provider gcp -framework cmmc -format pdf -output gcp-cmmc.pdf

# HTML reports (interactive)
./auditkit scan -provider aws -framework cis-aws -format html -output cis-report.html

# JSON (for CI/CD pipelines)
./auditkit scan -provider gcp -framework all -format json -output compliance.json

# CSV (for spreadsheets)
./auditkit scan -provider azure -framework soc2 -format csv -output azure-soc2.csv
```

### Provider-Specific Scanners
```bash
# Using provider-specific binaries (smaller, faster)
./auditkit-aws scan -framework soc2 -format pdf -output aws-soc2.pdf
./auditkit-azure scan -framework pci -format html -output azure-pci.html
./auditkit-gcp scan -framework cmmc -format json -output gcp-cmmc.json
```

**[CLI Reference →](./docs/cli-reference.md)**

---

## Documentation

### Getting Started
- **[Quick Start Guide](./docs/getting-started.md)** - First scan in 5 minutes
- **[Cloud Provider Setup](./docs/setup/)** - AWS, Azure, GCP, M365 authentication
- **[Understanding Results](./docs/understanding-results.md)** - Pass/Fail/Info status explained

### Frameworks
- **[SOC2 Type II](./docs/frameworks/soc2.md)** - Trust Services Criteria
- **[PCI-DSS v4.0](./docs/frameworks/pci-dss.md)** - Payment card security
- **[CMMC](./docs/frameworks/cmmc.md)** - DoD contractor compliance
- **[CIS Benchmarks](./docs/frameworks/cis-benchmarks.md)** - Security hardening
- **[NIST 800-53](./docs/frameworks/nist-800-53.md)** - Federal requirements
- **[All Frameworks →](./docs/frameworks/)**

### Examples & Use Cases
- **[Sample Reports](./docs/examples/)** - See what output looks like
- **[Remediation Examples](./docs/examples/remediation.md)** - How to fix issues
- **[CI/CD Integration](./docs/examples/cicd.md)** - Automate compliance checks

### Reference
- **[CLI Reference](./docs/cli-reference.md)** - All commands and flags
- **[FAQ](./docs/faq.md)** - Common questions
- **[Troubleshooting](./docs/troubleshooting.md)** - Known issues and fixes

---

## What's New in v0.7.0

### New Features
- **CIS Benchmarks:** Security hardening for AWS (58 controls), Azure (~40+ controls), GCP (~30+ controls)
- **GCP Support:** 170+ automated security checks across Cloud Storage, IAM, Compute, VPC, SQL, KMS, Logging
- **NIST 800-53 Rev 5:** ~150 technical controls mapped from existing frameworks
- **ISO 27001:2022:** ~60 technical controls via 800-53 crosswalk
- **Multi-Cloud Reports:** Scan AWS, Azure, and GCP with unified reporting

### Coming November 2025
- FedRAMP baseline filtering (Low/Moderate/High)
- CIS Benchmarks expansion (more controls for Azure/GCP)
- Enhanced multi-account scanning

**[Full Release Notes →](./CHANGELOG.md)**

---

## CIS Benchmarks Explained

**What is CIS?** The Center for Internet Security publishes security configuration best practices used by organizations worldwide.

**Why add CIS to AuditKit?** 
- **Proactive security:** CIS catches misconfigurations before they become incidents
- **Complements compliance:** SOC2/PCI/CMMC focus on audit requirements; CIS focuses on technical hardening
- **Industry standard:** CIS Benchmarks are referenced by cyber insurance, security frameworks, and auditors

**Example:** Your AWS account might pass SOC2 compliance but still have security gaps that CIS would catch (weak password policies, unnecessary services enabled, missing encryption).

**[Learn more about CIS →](./docs/frameworks/cis-benchmarks.md)**

---

## Contributing

We need help with:
- **CIS Azure & GCP expansion** (add more controls to existing implementations)
- **Additional framework mappings** (GDPR, ISO 27001 expansion)
- **FedRAMP baseline filtering** for Low/Moderate/High
- **Prowler integration** for complete NIST 800-53 coverage
- **Kubernetes compliance** scanning
- **Automated evidence collection** workflows

**[Contributing Guide →](./CONTRIBUTING.md)** • **[Good First Issues →](https://github.com/guardian-nexus/auditkit/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)**

---

## Support

- **Community Support:** [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Security Issues:** [SECURITY.md](./SECURITY.md)
- **Newsletter:** [auditkit.substack.com](https://auditkit.substack.com)
- **Pro Support:** Priority email + Slack channel (info@auditkit.io)

---

## License

Apache 2.0 - Use freely, even commercially. See [LICENSE](./LICENSE) for details.

---

## About Guardian Nexus

AuditKit is built by current defense sector professionals with deep expertise in compliance and cloud security. We ship working software monthly instead of enterprise vaporware.

**Our Background:**
- Active security clearance holders
- 15+ years in defense sector compliance
- Former and current defense contractor (understand CMMC pain firsthand)
- Built compliance tools used by Fortune 500 companies

**Our Philosophy:**
- Ship features, not promises
- Open source first, Pro tier for advanced needs
- Documentation that doesn't suck
- Responsive support (we actually read your issues)

**Questions?** Email: hello@auditkit.io
