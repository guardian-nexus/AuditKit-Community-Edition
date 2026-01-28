# Compliance Frameworks

AuditKit supports multiple compliance frameworks for automated technical control scanning.

---

## Supported Frameworks

| Framework | Status | Automated Controls | Cloud Providers |
|-----------|--------|-------------------|-----------------|
| **[SOC2 Type II](./soc2.md)** | Production | 64 controls | AWS, Azure, GCP |
| **[PCI-DSS v4.0](./pci-dss.md)** | Production | All 12 requirements (60+ controls) | AWS, Azure, GCP |
| **[CMMC Level 1](./cmmc.md)** | Production | 17 practices | AWS, Azure, GCP |
| **[CMMC Level 2](./cmmc.md)** | Pro Only | 110 practices | AWS, Azure, GCP |
| **[CIS Benchmarks](./cis-benchmarks.md)** | Production | AWS: 126+, Azure: ~40+, GCP: 61 | AWS, Azure, GCP |
| **[NIST 800-53 Rev 5](./nist-800-53.md)** | Production | ~150 technical controls (covers FedRAMP) | AWS, Azure, GCP |
| **[ISO 27001:2022](./iso27001.md)** | Production | ~60 technical controls | AWS, Azure, GCP |
| **[HIPAA Security Rule](./hipaa.md)** | Production | Technical Safeguards (40-70 mappings) | AWS, Azure, GCP |

---

## Framework Categories

### Production Ready
Fully tested, comprehensive coverage, used in production environments:
- **SOC2 Type II** - For SaaS companies and startups
- **PCI-DSS v4.0** - For payment card processing
- **CMMC Level 1** - For all DoW contractors
- **CIS Benchmarks** - For security hardening (AWS: 126+ controls, Azure: ~40+ controls, GCP: 61 controls)
- **NIST 800-53** - For federal contractors and FedRAMP compliance
- **ISO 27001** - For international information security compliance
- **HIPAA Security Rule** - Technical safeguards for healthcare (Note: does not cover Administrative/Physical safeguards)

### Pro Only
Requires AuditKit Pro subscription:
- **CMMC Level 2** - For DoW contractors handling CUI

---

## Quick Comparison

### By Industry

**SaaS/Startups:** SOC2 Type II  
**E-commerce/Payment Processing:** PCI-DSS v4.0  
**DoW Contractors (FCI):** CMMC Level 1  
**DoW Contractors (CUI):** CMMC Level 2 (Pro)  
**Federal Contractors:** NIST 800-53 Rev 5  
**Healthcare:** HIPAA (experimental)  
**Security Hardening:** CIS Benchmarks

### By Requirements

**Customer demands compliance:** SOC2  
**Processing credit cards:** PCI-DSS  
**DoW contract requires it:** CMMC  
**Federal agency requires it:** NIST 800-53  
**Handling PHI:** HIPAA  
**Security best practices:** CIS Benchmarks

### By Timeline

**2-4 weeks:** CMMC Level 1, Basic SOC2 prep, CIS hardening  
**2-3 months:** SOC2 Type II certification  
**3-6 months:** CMMC Level 2, PCI-DSS  
**6-12 months:** NIST 800-53, HIPAA

---

## Framework Details

### SOC2 Type II
**Purpose:** Trust Services Criteria for service organizations  
**Certification:** Requires CPA firm audit  
**Cost:** $15,000 - $30,000 for audit  
**Timeline:** 3-6 months preparation + 3-12 month observation period

**[Learn more →](./soc2.md)**

### PCI-DSS v4.0
**Purpose:** Payment Card Industry Data Security Standard  
**Certification:** Requires QSA assessment  
**Cost:** $15,000 - $50,000 for assessment  
**Timeline:** 3-6 months preparation

**[Learn more →](./pci-dss.md)**

### CMMC
**Purpose:** Cybersecurity Maturity Model Certification for DoW  
**Certification:**  
- Level 1: Self-assessment  
- Level 2: C3PAO required ($25,000 - $150,000)

**Timeline:**  
- Level 1: 2-4 weeks  
- Level 2: 3-6 months

**[Learn more →](./cmmc.md)**

### CIS Benchmarks
**Purpose:** Security configuration best practices  
**Certification:** Not a certification - industry-recognized hardening standards  
**Cost:** Free to implement  
**Timeline:** 2-4 weeks for basic hardening (IG1)

**Current Coverage:**
- AWS: ~58 automated controls (Production)
- Azure: ~40+ automated controls (Production)
- GCP: ~30+ automated controls (Production)

**[Learn more →](./cis-benchmarks.md)**

### NIST 800-53 Rev 5
**Purpose:** Security controls for federal information systems  
**Certification:** Not a certification (used by FedRAMP, FISMA)  
**Coverage:** ~150 automated technical controls  
**Timeline:** 6-12 months for full implementation

**[Learn more →](./nist-800-53.md)**

### HIPAA
**Purpose:** Healthcare data protection  
**Status:** Experimental - technical safeguards only  
**Note:** Does not cover administrative or physical safeguards

**[Learn more →](./hipaa.md)**

---

## Scanning Frameworks

### Single Framework
```bash
# SOC2
auditkit scan -provider aws -framework soc2

# PCI-DSS
auditkit scan -provider aws -framework pci

# CMMC Level 1
auditkit scan -provider aws -framework cmmc

# CMMC Level 2 (Pro only)
auditkit-pro scan -provider aws -framework cmmc-l2

# CIS Benchmarks
auditkit scan -provider aws -framework cis-aws

# NIST 800-53
auditkit scan -provider aws -framework 800-53
```

### All Frameworks
```bash
# Scan all frameworks at once
auditkit scan -provider aws -framework all
```

---

## Framework Crosswalks

AuditKit maps controls across frameworks. For example:

**AWS IAM MFA enforcement** maps to:
- SOC2: CC6.6
- PCI-DSS: Requirement 8.3
- CMMC: IA.2.081
- CIS AWS: 1.5, 1.6
- NIST 800-53: IA-2, IA-2(1)
- HIPAA: 164.312(a)(2)(i)

This means fixing one control improves compliance across multiple frameworks.

---

## Compliance vs Security Hardening

### Compliance Frameworks (SOC2, PCI, CMMC, NIST 800-53)
- **Purpose:** Meet audit/certification requirements
- **Focus:** Business controls + technical controls
- **Output:** Pass/fail for specific requirements
- **Outcome:** Certification or authorization

### Security Hardening (CIS Benchmarks)
- **Purpose:** Reduce attack surface
- **Focus:** Technical configuration only
- **Output:** Detailed hardening guidance
- **Outcome:** Improved security posture

**Best Practice:** Use CIS Benchmarks alongside compliance frameworks. CIS provides technical depth that complements compliance requirements.

---

## Choosing the Right Framework

### Multiple Frameworks Required?

Many organizations need multiple frameworks:

**Common combinations:**
- SOC2 + PCI-DSS (SaaS with payment processing)
- SOC2 + CIS Benchmarks (SaaS with strong security posture)
- CMMC + NIST 800-53 (DoW + federal work)
- CMMC + CIS Benchmarks (DoW with hardening requirements)
- SOC2 + HIPAA (Healthcare SaaS)

**Good news:** AuditKit scans once, reports on all frameworks

### Framework Priorities

**If you need multiple frameworks:**
1. Start with broadest: SOC2 or NIST 800-53
2. Add security hardening: CIS Benchmarks
3. Add specific: PCI-DSS for payments, CMMC for DoW
4. Last: HIPAA (most organizational policies)

**Security-first approach:**
1. Start with CIS Benchmarks (security foundation)
2. Add compliance: SOC2, PCI, or CMMC as needed
3. Maintain both: CIS for ongoing hardening, compliance for audits

---

## Getting Help

**Framework-specific questions:**
- [SOC2 FAQ](./soc2.md#faq)
- [PCI-DSS FAQ](./pci-dss.md#faq)
- [CMMC FAQ](./cmmc.md#faq)
- [CIS Benchmarks FAQ](./cis-benchmarks.md#frequently-asked-questions)
- [NIST 800-53 FAQ](./nist-800-53.md#faq)

**General support:**
- [Main FAQ](../faq.md)
- [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- Email: info@auditkit.io

---

## Next Steps

- **[Choose your framework →](#framework-details)**
- **[Run your first scan →](../getting-started.md)**
- **[View provider coverage →](../providers/)**
- **[Compare Free vs Pro →](../pricing.md)**
