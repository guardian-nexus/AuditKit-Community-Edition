# FedRAMP Compliance

Federal Risk and Authorization Management Program guide.

---

## Overview

**FedRAMP** standardizes security assessments for cloud services used by US federal agencies.

**Who needs it:** Cloud service providers (CSPs) serving federal agencies
**Status in AuditKit:** Production
**Coverage:** Low: ~60, Moderate: ~150, High: ~200 technical controls
**What's covered:** Technical controls from NIST 800-53 Rev 5

---

## Important Disclaimer

**AuditKit's FedRAMP support covers technical controls only - NOT sufficient for FedRAMP authorization.**

**What AuditKit covers:**
- Technical control scanning based on NIST 800-53 Rev 5
- Automated verification of cloud configurations
- Baseline filtering (Low/Moderate/High impact levels)
- Remediation guidance with cloud-specific commands

**What AuditKit does NOT replace:**
- FedRAMP Third-Party Assessment Organization (3PAO) assessment
- Security Assessment Plan (SAP) development
- Security Assessment Report (SAR) creation
- Plan of Action and Milestones (POA&M) management
- Continuous monitoring requirements
- Formal authorization process

**Use for:** Technical control assessment and gap analysis as part of FedRAMP compliance program
**Don't use for:** Sole evidence of FedRAMP authorization or compliance attestation
**Hire a 3PAO for:** Complete FedRAMP authorization package and assessment

---

## FedRAMP Baselines

FedRAMP defines three security impact levels based on FIPS 199:

### Low Impact (125 controls total, ~60 automatable)

**When to use:**
- Low-impact SaaS applications
- Non-sensitive federal data
- No PII, no mission-critical systems

**Examples:**
- Collaboration tools (non-sensitive)
- Public-facing websites
- General productivity applications

**Timeline:** 3-6 months for initial authorization
**Cost:** $50,000 - $150,000 (3PAO + infrastructure)

**AuditKit Coverage:** ~60 technical controls that can be verified via cloud APIs

### Moderate Impact (325 controls total, ~150 automatable)

**When to use:** (Most common - 80%+ of FedRAMP authorizations)
- Most SaaS and cloud services
- Moderate-impact federal data
- Some PII, mission-supportive systems

**Examples:**
- CRM systems with PII
- Financial management systems
- HR and benefits platforms
- Most cloud infrastructure services

**Timeline:** 6-12 months for initial authorization
**Cost:** $250,000 - $500,000 (3PAO + infrastructure)

**AuditKit Coverage:** ~150 technical controls

### High Impact (421 controls total, ~200 automatable)

**When to use:**
- High-impact systems
- Law enforcement data
- Financial or health information
- National security systems

**Examples:**
- Critical mission systems
- Law enforcement databases
- National security applications

**Timeline:** 12-18 months for initial authorization
**Cost:** $500,000+ (3PAO + infrastructure)

**AuditKit Coverage:** ~200 technical controls

---

## Running FedRAMP Scans

**Note:** Dedicated FedRAMP baseline filtering coming in v0.8.0. For now, use NIST 800-53 which covers all FedRAMP requirements:

```bash
# NIST 800-53 (covers all FedRAMP baselines)
auditkit scan -provider aws -framework 800-53

# Generate PDF report
auditkit scan -provider aws -framework 800-53 -format pdf -output fedramp-report.pdf

# CSV export for POA&M tracking
auditkit scan -provider aws -framework 800-53 -format csv -output fedramp-gaps.csv
```

**FedRAMP baseline filtering:**
```bash
# FedRAMP Low baseline
auditkit scan -provider aws -framework fedramp-low

# FedRAMP Moderate baseline
auditkit scan -provider aws -framework fedramp-moderate

# FedRAMP High baseline
auditkit scan -provider aws -framework fedramp-high
```

---

## What AuditKit Checks

AuditKit scans for technical controls that map to FedRAMP baselines via NIST 800-53 Rev 5:

### Access Control (AC)
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-6: Least Privilege
- AC-17: Remote Access

### Audit and Accountability (AU)
- AU-2: Audit Events
- AU-3: Content of Audit Records
- AU-6: Audit Review
- AU-12: Audit Generation

### Configuration Management (CM)
- CM-2: Baseline Configuration
- CM-6: Configuration Settings
- CM-7: Least Functionality

### Identification and Authentication (IA)
- IA-2: User Identification and Authentication
- IA-2(1): Multi-factor Authentication
- IA-5: Authenticator Management

### System and Communications Protection (SC)
- SC-7: Boundary Protection
- SC-8: Transmission Confidentiality
- SC-13: Cryptographic Protection
- SC-28: Protection of Information at Rest

### System and Information Integrity (SI)
- SI-2: Flaw Remediation
- SI-3: Malicious Code Protection
- SI-4: Information System Monitoring

---

## FedRAMP Authorization Process

### 1. Prepare (Months 1-6)
- Choose authorization path (Agency, JAB, CSP Supplied)
- Select FedRAMP baseline (Low/Moderate/High)
- Implement technical controls (AuditKit helps here)
- Develop System Security Plan (SSP)

### 2. Assess (Months 7-9)
- Engage FedRAMP-approved 3PAO
- 3PAO performs Security Assessment
- Produce Security Assessment Report (SAR)
- Create Plan of Action & Milestones (POA&M)

### 3. Authorize (Months 10-12)
- Submit authorization package
- FedRAMP PMO review
- Agency or JAB authorization decision
- Receive Authority to Operate (ATO)

### 4. Monitor (Ongoing)
- Continuous monitoring
- Monthly vulnerability scanning
- Annual assessment
- Configuration management
- Incident reporting

---

## FedRAMP vs Other Frameworks

| Framework | Overlap with FedRAMP | Notes |
|-----------|---------------------|-------|
| **NIST 800-53** | 100% | FedRAMP is subset of 800-53 |
| **CMMC Level 2** | High | Both based on NIST 800-171 |
| **SOC2** | Medium | Similar technical controls |
| **ISO 27001** | High | Many aligned controls |
| **StateRAMP** | Very High | State-level equivalent |

**Key Differentiators:**
- FedRAMP requires formal 3PAO assessment
- Continuous monitoring mandatory
- FedRAMP PMO oversight
- Specific to federal cloud services
- Reciprocity across federal agencies

---

## Authorization Paths

### JAB Provisional ATO (P-ATO)
**Best for:** CSPs serving multiple agencies
**Timeline:** 12-18 months
**Cost:** Higher (multiple agency coordination)
**Benefit:** Highest level of reciprocity

### Agency ATO
**Best for:** CSPs serving specific agency
**Timeline:** 6-12 months
**Cost:** Lower (single agency)
**Benefit:** Faster, focused on agency needs

### CSP Supplied Package
**Best for:** Initial assessment, later pursuing JAB/Agency
**Timeline:** 6-9 months
**Cost:** CSP bears assessment cost
**Benefit:** Demonstrates readiness, pre-authorization

---

## Cost Breakdown

| Item | Low | Moderate | High |
|------|-----|----------|------|
| AuditKit Free | $0 | $0 | $0 |
| Infrastructure hardening | $20K-50K | $50K-150K | $150K-300K |
| 3PAO Initial Assessment | $50K-100K | $150K-300K | $300K-500K |
| Documentation (SSP/SAR/POA&M) | $20K-50K | $50K-100K | $100K-200K |
| Continuous monitoring tools | $10K-30K/year | $30K-80K/year | $80K-150K/year |
| Annual 3PAO assessment | $30K-60K | $75K-150K | $150K-300K |
| **Initial authorization** | **$100K-230K** | **$325K-630K** | **$730K-1.3M** |
| **Ongoing (annual)** | **$40K-90K** | **$105K-230K** | **$230K-450K** |

---

## Common FedRAMP Gaps

Based on 3PAO findings across hundreds of assessments:

1. **Incomplete continuous monitoring** (AC, SI families)
2. **Insufficient audit logging** (AU family)
3. **Weak access controls** (AC, IA families)
4. **Missing configuration baselines** (CM family)
5. **Inadequate incident response** (IR family)
6. **Poor change management** (CM family)
7. **Incomplete vulnerability management** (RA, SI families)
8. **Missing security awareness training** (AT family)

**AuditKit helps identify #1, #2, #3, #4, #6, #7** - you need policies and training for #5, #8

---

## FAQ

**Q: Do I need FedRAMP compliance?**
A: Only if you're a cloud service provider (CSP) serving federal agencies. If you're a federal contractor, you may need CMMC instead.

**Q: How long does FedRAMP authorization take?**
A: Low: 3-6 months, Moderate: 6-12 months, High: 12-18 months (from start to ATO).

**Q: Can I self-assess for FedRAMP?**
A: No. FedRAMP requires independent assessment by FedRAMP-approved 3PAO.

**Q: What's the difference between FedRAMP and NIST 800-53?**
A: FedRAMP is a specific subset of NIST 800-53 controls for cloud services, with additional continuous monitoring and authorization requirements.

**Q: Does FedRAMP authorization apply to all agencies?**
A: JAB P-ATO provides widest reciprocity. Agency ATOs are specific to that agency, though other agencies may leverage them.

**Q: How much does FedRAMP cost?**
A: Moderate (most common): $325K-630K initial, $105K-230K annual. See cost breakdown above.

**Q: What's the pass rate for FedRAMP?**
A: About 60-70% of CSPs pass initial assessment (with POA&Ms). Many take 2-3 attempts.

**Q: Can I start with FedRAMP Low and upgrade later?**
A: Yes, but most agencies require Moderate. Starting with Low may delay useful authorization.

**Q: Do cloud providers (AWS, Azure, GCP) help with FedRAMP?**
A: Yes! AWS, Azure, and GCP all have FedRAMP-authorized regions and inherit controls from their infrastructure. Use the Shared Responsibility Model.

---

## Recommended Path

### Months 1-3: Planning
- Determine correct baseline (Low/Moderate/High)
- Choose authorization path (JAB/Agency/CSP)
- Run AuditKit to identify gaps
- Begin SSP development

### Months 4-6: Implementation
- Remediate technical gaps (use AuditKit)
- Implement continuous monitoring
- Complete policies and procedures
- Engage 3PAO

### Months 7-9: Assessment
- 3PAO performs security assessment
- Address findings in real-time
- Develop POA&M for remaining gaps
- Complete SAR

### Months 10-12: Authorization
- Submit authorization package to FedRAMP PMO
- Address PMO feedback
- Agency/JAB authorization decision
- Receive ATO

### Ongoing: Maintain
- Monthly vulnerability scanning
- Continuous monitoring
- Quarterly POA&M updates
- Annual 3PAO assessment

---

## Next Steps

- **[Run FedRAMP technical scan](../getting-started.md)**
- **[Compare to NIST 800-53](./nist-800-53.md)**
- **[Find approved 3PAO](https://marketplace.fedramp.gov/assessors)**
- **[FedRAMP official site](https://www.fedramp.gov/)**
- **[FedRAMP Marketplace](https://marketplace.fedramp.gov/)**

**Remember:** AuditKit covers technical controls. Hire a FedRAMP-approved 3PAO for complete authorization package and formal assessment.
