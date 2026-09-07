# CMMC (Cybersecurity Maturity Model Certification)

Complete guide to CMMC Level 1 and Level 2 compliance with AuditKit.

---

## Overview

**CMMC** is a cybersecurity framework required for DoW contractors.

**Why CMMC matters:**
- In force since November 10, 2025, when the 48 CFR rule took effect
- Protects Federal Contract Information (FCI) and Controlled Unclassified Information (CUI)
- Phase 1 is live: self-assessment for Level 1 and Level 2 on applicable contracts
- Where a solicitation carries the CMMC clause, you cannot bid without meeting it

**Current status (September 2026):** the rollout is in Phase 1. On July 13, 2026
the Department of War suspended the move to Phase 2 pending a reform review, so
third-party C3PAO assessment is **not** currently mandated. Phase 1 obligations
continue unchanged: self-assessment, DFARS 252.204-7012, NIST SP 800-171 Rev 2,
SPRS score postings and annual affirmations.

**Certification:** C3PAO (CMMC Third-Party Assessor Organization) assessment applies from Phase 2, which is currently suspended. Level 2 is self-assessed under Phase 1.

---

## CMMC Levels

### Level 1: Foundational (17 Practices)

**Protects:** Federal Contract Information (FCI)  
**Required for:** All DoW contractors  
**Assessment:** Self-assessment allowed  
**Cost:** Free with AuditKit

**What is FCI?**
- Contract awards
- Pricing information
- Business plans
- Financial reports
- Technical data (non-sensitive)

**Timeline:** Required now for new contracts

### Level 2: Advanced (110 Practices)

**Protects:** Controlled Unclassified Information (CUI)  
**Required for:** DoW contractors handling CUI  
**Assessment:** Self-assessment under Phase 1. C3PAO assessment was scheduled for Phase 2, which is suspended.  
**Cost:** $297/month with AuditKit

**What is CUI?**
- Technical specifications
- Mission plans
- Personnel records
- Logistics data
- Operational procedures
- Export-controlled technical data

**Timeline:** In force since November 10, 2025 (Phase 1)

---

## CMMC Level 1 (Free)

### The 17 Practices

AuditKit reports all 17 practices. 13 carry an automated check on AWS and Azure, 9 on GCP; the rest are reported for evidence tracking:

#### Access Control (AC)
1. **AC.L1-3.1.1** - Limit system access to authorized users
2. **AC.L1-3.1.2** - Limit system access to the types of transactions and functions authorized users are permitted to execute
3. **AC.L1-3.1.20** - Verify and control connections to and use of external systems
4. **AC.L1-3.1.22** - Control information posted or processed on publicly accessible systems

#### Identification & Authentication (IA)
5. **IA.L1-3.5.1** - Identify system users, processes acting on behalf of users, and devices
6. **IA.L1-3.5.2** - Authenticate the identities of those users, processes and devices

#### Media Protection (MP)
7. **MP.L1-3.8.3** - Sanitize or destroy media containing FCI before disposal or reuse

#### Physical Protection (PE)
8. **PE.L1-3.10.1** - Limit physical access to systems, equipment and operating environments
9. **PE.L1-3.10.3** - Escort visitors and monitor visitor activity
10. **PE.L1-3.10.4** - Maintain audit logs of physical access
11. **PE.L1-3.10.5** - Control and manage physical access devices

#### System & Communications Protection (SC)
12. **SC.L1-3.13.1** - Monitor, control and protect communications at external and key internal boundaries
13. **SC.L1-3.13.5** - Implement subnetworks for publicly accessible components, separated from internal networks

#### System & Information Integrity (SI)
14. **SI.L1-3.14.1** - Identify, report and correct system flaws in a timely manner
15. **SI.L1-3.14.2** - Provide protection from malicious code at designated locations
16. **SI.L1-3.14.4** - Update malicious code protection mechanisms when new releases are available
17. **SI.L1-3.14.5** - Perform periodic scans of the system and real-time scans of files from external sources

These are the identifiers the scanner emits. The older `AC.1.001` form belongs to
CMMC 1.0, which was withdrawn; CMMC 2.0 identifies each practice by its domain,
level and NIST SP 800-171 Rev 2 requirement number.

### What AuditKit Checks (Level 1)

**Queried automatically from your cloud configuration (13 of the 17 on AWS and Azure, 9 of 17 on GCP):**
- IAM password policy configuration
- MFA enforcement
- Access key rotation
- CloudTrail/logging enabled
- Security group rules
- Public access on storage
- Encryption at rest
- Patch management

**No automated check - manual verification required (4 practices):**
- AC.L1-3.1.20 - Verify and control connections to external systems
- AC.L1-3.1.22 - Control publicly posted information
- SI.L1-3.14.4 - Update malicious code protection mechanisms
- SI.L1-3.14.5 - Perform periodic and real-time scans
- Physical security measures
- Visitor escort procedures
- Media sanitization procedures
- Network monitoring processes
- Vulnerability scanning schedule
- Security alert response
- System update procedures

### Running Level 1 Scan

```bash
# Scan for CMMC Level 1
auditkit scan -provider aws -framework cmmc
auditkit scan -provider azure -framework cmmc
auditkit scan -provider gcp -framework cmmc

# Generate assessment report
auditkit scan -provider aws -framework cmmc -format pdf -output cmmc-l1-report.pdf

# Generate evidence tracker for manual practices
# Evidence tracker (covers every framework; -framework and -format are not honoured here)
auditkit evidence -output cmmc-evidence.html
```

### Level 1 Timeline

**Typical preparation:** 2-4 weeks

**Steps:**
1. Run AuditKit scan
2. Fix automated findings (1-2 weeks)
3. Document manual practices (1-2 weeks)
4. Self-assess compliance
5. Include CMMC Level 1 statement in contract bids

---

## CMMC Level 2 (reported in Community, automated in Pro)

### The 110 Practices

Level 2 includes all 17 Level 1 practices plus 93 additional practices across 14 domains.

**Free in Community for reporting all 110 practices. Automated Level 2 checks require Pro:** $297/month with 14-day free trial

### CMMC Level 2 Domains

#### Access Control (AC) - 22 practices
- Least privilege
- Separation of duties
- Unsuccessful login attempts
- Remote access controls
- Session termination
- Access enforcement

#### Awareness & Training (AT) - 3 practices
- Security awareness training
- Role-based training
- Insider threat awareness
- Physical security training

#### Audit & Accountability (AU) - 9 practices
- Audit logging
- Audit review and analysis
- Audit retention
- Audit failure response
- Audit record generation

#### Configuration Management (CM) - 9 practices
- Baseline configurations
- Configuration change control
- Security impact analysis
- Access restrictions for change
- Configuration settings

#### Identification & Authentication (IA) - 11 practices
- MFA for all access
- Device identification
- Authenticator management
- Cryptographic authentication
- Password complexity

#### Incident Response (IR) - 3 practices
- Incident handling
- Incident monitoring
- Incident reporting
- Incident response testing
- Incident response training

#### Maintenance (MA) - 6 practices
- Controlled maintenance
- Remote maintenance controls
- Maintenance tools
- Maintenance personnel

#### Media Protection (MP) - 9 practices
- Media access controls
- Media marking
- Media storage and transport
- Media sanitization
- Media accountability

#### Personnel Security (PS) - 2 practices
- Personnel screening
- Termination procedures
- Personnel sanctions
- Transfer procedures

#### Physical Protection (PE) - 6 practices
- Physical access controls
- Physical access authorizations
- Visitor control
- Access logs
- Asset monitoring

(delete this heading and its two bullets entirely)

#### Risk Assessment (RA) - 3 practices
- Risk assessments
- Vulnerability scanning
- Remediation tracking
- Threat analysis

#### Security Assessment (CA) - 4 practices
- Security assessments
- Plan of Action & Milestones (POA&M)
- Security authorization
- Continuous monitoring

#### System & Communications Protection (SC) - 16 practices
- Boundary protection
- Network segmentation
- Cryptographic protection
- Mobile code restrictions
- Voice over IP protections
- Session authenticity
- Denial of service protection

#### System & Information Integrity (SI) - 7 practices
- Flaw remediation
- Malicious code protection
- System monitoring
- Security alerts and advisories
- Software update validation
- Spam protection
- Information input validation

### What AuditKit Checks (Level 2)

**Queried automatically from your cloud configuration (42 of the 110); the remaining 68 are
assessed as structured evidence guidance, telling you what an assessor needs to see:**
All technical controls across:
- IAM and authentication
- Network security
- Encryption
- Logging and monitoring
- Backup and recovery
- Vulnerability management
- Patch management
- Access controls
- Security groups/firewalls
- Key rotation
- Public access controls

**Structured evidence guidance (68 practices):**
Organizational controls:
- Policies and procedures
- Training programs
- Physical security
- Personnel screening
- Incident response plans
- Risk assessments
- Security assessments

### Running a Level 2 Scan

```bash
# Scan for CMMC Level 2 (requires Pro license)
auditkit-pro scan -provider aws -framework cmmc
auditkit-pro scan -provider azure -framework cmmc
auditkit-pro scan -provider gcp -framework cmmc

# Generate complete assessment report
auditkit-pro scan -provider aws -framework cmmc -format pdf -output cmmc-report.pdf

# Generate the evidence tracker (covers every framework; -framework does not scope it)
auditkit-pro evidence -output cmmc-evidence.html
```

### Level 2 Timeline

**Typical preparation:** 3-6 months

**Steps:**
1. Gap assessment (Week 1)
2. Technical remediation (Months 1-2)
3. Policy/procedure documentation (Months 2-4)
4. Training implementation (Months 3-5)
5. Pre-assessment audit (Month 5)
6. C3PAO assessment (Month 6) - applies if and when Phase 2 resumes

**[Start Pro trial →](https://auditkit.io/pro/)**

---

## Level 1 vs Level 2 Comparison

| Aspect | Level 1 | Level 2 |
|--------|---------|---------|
| **Practices** | 17 | 110 |
| **Protects** | FCI | CUI |
| **Assessment** | Self-assessment | Self-assessment (Phase 1); C3PAO deferred with Phase 2 |
| **Cost (AuditKit)** | Free | $297/month |
| **Cost (Assessment)** | $0 | $0 under Phase 1; $25,000-$150,000 if C3PAO resumes |
| **Timeline** | 2-4 weeks | 3-6 months |
| **Automated Checks** | 13 of 17 | 42 of 110 query the cloud |
| **Manual Docs** | 4 | 68 assessed as evidence guidance |
| **Required For** | All DoW contracts | CUI contracts |
| **Deadline** | Now | Now (Phase 1, self-assessment) |

---

## CMMC & NIST SP 800-171

**CMMC Level 2 is based on NIST SP 800-171 Rev 2**

AuditKit maps all 110 CMMC Level 2 practices to their corresponding NIST SP 800-171 controls.

**Example mapping:**
- CMMC AC.L1-3.1.2 → NIST 800-171 3.1.2
- CMMC IA.L2-3.5.3 → NIST 800-171 3.5.3
- CMMC SC.L1-3.13.1 → NIST 800-171 3.13.1

This means passing CMMC Level 2 = compliance with NIST SP 800-171.

---

## C3PAO Assessment Process

> **Note:** C3PAO assessment belongs to Phase 2 of the CMMC rollout, which the
> Department of War suspended on July 13, 2026. The section below describes the
> process for when it resumes. Under Phase 1 today, Level 2 is self-assessed.

### Before Assessment

**6-12 months before:**
1. Gap assessment with AuditKit
2. Remediate technical findings
3. Document policies/procedures
4. Implement training programs
5. Create POA&M for unresolved items

**3 months before:**
1. Pre-assessment scan
2. Fix remaining issues
3. Complete evidence collection
4. Schedule C3PAO

### During Assessment

**C3PAO will:**
- Review all 110 practices
- Interview personnel
- Inspect facilities
- Test technical controls
- Review documentation
- Verify evidence

**Timeline:** 3-7 days on-site

### After Assessment

**If you pass:**
- Receive CMMC certification
- Valid for 3 years
- Include in contract bids

**If you fail:**
- Receive POA&M with gaps
- Remediate and re-assess
- May require 3-6 months

---

## Cost Breakdown

### Level 1 Costs (Estimate)

| Item | Cost |
|------|------|
| AuditKit Free | $0 |
| Policy templates | $0-$500 |
| Training | $0-$1,000 |
| **Total** | **$0-$1,500** |

### Level 2 Costs (Estimate)

| Item | Cost Range |
|------|------------|
| AuditKit (annual) | $3,564 |
| C3PAO assessment | $25,000-$150,000 |
| Consultant (if needed) | $0-$50,000 |
| Training programs | $5,000-$15,000 |
| Physical security upgrades | $0-$25,000 |
| **Total** | **$33,564-$243,564** |

**Compare to:** Traditional full-service CMMC prep: $100,000-$325,000

---

## Common CMMC Failures

Based on C3PAO assessments, here are the most common failures:

### Level 1 Failures
1. Weak password policies
2. No MFA enforcement
3. Missing audit logs
4. Public-facing storage
5. No vulnerability scanning

### Level 2 Failures
1. Inadequate access controls (AC.L2-3.1.5, least privilege)
2. Missing audit logs (AU.L2-3.3.1)
3. No security awareness training (AT.L2-3.2.1)
4. Weak incident response (IR.L2-3.6.1)
5. No vulnerability management (RA.L2-3.11.2)
6. Missing system hardening (CM.L2-3.4.1, baseline configurations)
7. No cryptographic protection (SC.L2-3.13.11)
8. Inadequate media protection (MP.L2-3.8.1)

**AuditKit catches all technical failures before assessment.**

---

## CMMC Resources

**Official:**
- CMMC Model: https://dodcio.defense.gov/CMMC/
- CMMC FAQ: https://dodcio.defense.gov/CMMC/FAQ/
- C3PAO Directory: https://cyberab.org/Catalog

**AuditKit:**
- [Pro trial →](https://auditkit.io/pro/)
- [Getting started →](../getting-started.md)
- [CLI reference →](../cli-reference.md)

---

## Next Steps

### For Level 1:
1. [Run free CMMC scan →](../getting-started.md)
2. Fix technical findings
3. Document manual practices
4. Self-assess compliance
5. Include in contract bids

### For Level 2:
1. [Start Pro trial →](https://auditkit.io/pro/)
2. Download auditkit-pro binary
3. Run gap assessment
4. Remediate technical findings (2-4 months)
5. Document policies/procedures (2-4 months)
6. Schedule C3PAO assessment
7. Pass assessment, receive certification

**Questions?** Email info@auditkit.io

---

## Related Documentation

- **[Getting Started →](../getting-started.md)**
- **[CLI Reference →](../cli-reference.md)**
- **[Pricing (Free vs Pro) →](../../pricing.md)**
- **[Cloud Setup Guides →](../setup/)**
