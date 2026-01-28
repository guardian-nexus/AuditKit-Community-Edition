# CMMC (Cybersecurity Maturity Model Certification)

Complete guide to CMMC Level 1 and Level 2 compliance with AuditKit.

---

## Overview

**CMMC** is a cybersecurity framework required for DoW contractors.

**Why CMMC matters:**
- Required for all DoW contracts (as of November 10, 2025)
- Protects Federal Contract Information (FCI) and Controlled Unclassified Information (CUI)
- Mandatory for bidding on DoW contracts
- Failure to comply = cannot bid on DoW work

**Certification:** Requires third-party assessment by C3PAO (CMMC Third-Party Assessor Organization)

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
**Assessment:** C3PAO required  
**Cost:** $297/month with AuditKit Pro

**What is CUI?**
- Technical specifications
- Mission plans
- Personnel records
- Logistics data
- Operational procedures
- Export-controlled technical data

**Timeline:** Required starting November 10, 2025

---

## CMMC Level 1 (Free)

### The 17 Practices

AuditKit automates checks for these practices:

#### Access Control (AC)
1. **AC.1.001** - Limit system access to authorized users
2. **AC.1.002** - Limit system access to authorized transactions
3. **AC.1.003** - Control remote access sessions

#### Identification & Authentication (IA)
4. **IA.1.076** - Identify users
5. **IA.1.077** - Authenticate users

#### Media Protection (MP)
6. **MP.1.118** - Sanitize or destroy media

#### Physical Protection (PE)
7. **PE.1.131** - Limit physical access to systems
8. **PE.1.132** - Escort visitors
9. **PE.1.133** - Maintain audit logs of physical access

#### System & Communications Protection (SC)
10. **SC.1.175** - Monitor communications at external boundaries
11. **SC.1.176** - Control communications at external boundaries

#### System & Information Integrity (SI)
12. **SI.1.210** - Identify and manage information system flaws
13. **SI.1.211** - Identify malicious content
14. **SI.1.212** - Update malicious code protection
15. **SI.1.213** - Perform network scans
16. **SI.1.214** - Monitor system security alerts
17. **SI.1.217** - Update system components

### What AuditKit Checks (Level 1)

**Automated (8 practices):**
- IAM password policy configuration
- MFA enforcement
- Access key rotation
- CloudTrail/logging enabled
- Security group rules
- Public access on storage
- Encryption at rest
- Patch management

**Manual verification required (9 practices):**
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
auditkit evidence -framework cmmc -format html -output cmmc-evidence.html
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

## CMMC Level 2 (Pro)

### The 110 Practices

Level 2 includes all 17 Level 1 practices plus 93 additional practices across 14 domains.

**Pro version required:** $297/month with 14-day free trial

### CMMC Level 2 Domains

#### Access Control (AC) - 22 practices
- Least privilege
- Separation of duties
- Unsuccessful login attempts
- Remote access controls
- Session termination
- Access enforcement

#### Awareness & Training (AT) - 5 practices
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

#### Incident Response (IR) - 7 practices
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

#### Personnel Security (PS) - 5 practices
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

#### Recovery (RE) - 2 practices
- Backup and restore
- System recovery testing

#### Risk Assessment (RA) - 5 practices
- Risk assessments
- Vulnerability scanning
- Remediation tracking
- Threat analysis

#### Security Assessment (CA) - 7 practices
- Security assessments
- Plan of Action & Milestones (POA&M)
- Security authorization
- Continuous monitoring

#### System & Communications Protection (SC) - 15 practices
- Boundary protection
- Network segmentation
- Cryptographic protection
- Mobile code restrictions
- Voice over IP protections
- Session authenticity
- Denial of service protection

#### System & Information Integrity (SI) - 11 practices
- Flaw remediation
- Malicious code protection
- System monitoring
- Security alerts and advisories
- Software update validation
- Spam protection
- Information input validation

### What AuditKit Pro Checks (Level 2)

**Automated (33 practices):**
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

**Manual verification required (77 practices):**
Organizational controls:
- Policies and procedures
- Training programs
- Physical security
- Personnel screening
- Incident response plans
- Risk assessments
- Security assessments

### Running Level 2 Scan (Pro Only)

```bash
# Scan for CMMC Level 2 (requires Pro license)
auditkit-pro scan -provider aws -framework cmmc-l2
auditkit-pro scan -provider azure -framework cmmc-l2
auditkit-pro scan -provider gcp -framework cmmc-l2

# Generate complete assessment report
auditkit-pro scan -provider aws -framework cmmc-l2 -format pdf -output cmmc-l2-report.pdf

# Generate evidence tracker for all 110 practices
auditkit-pro evidence -framework cmmc-l2 -format html -output cmmc-l2-evidence.html
```

### Level 2 Timeline

**Typical preparation:** 3-6 months

**Steps:**
1. Gap assessment (Week 1)
2. Technical remediation (Months 1-2)
3. Policy/procedure documentation (Months 2-4)
4. Training implementation (Months 3-5)
5. Pre-assessment audit (Month 5)
6. C3PAO assessment (Month 6)

**[Start Pro trial →](https://auditkit.io/pro/)**

---

## Level 1 vs Level 2 Comparison

| Aspect | Level 1 | Level 2 |
|--------|---------|---------|
| **Practices** | 17 | 110 |
| **Protects** | FCI | CUI |
| **Assessment** | Self-assessment | C3PAO required |
| **Cost (AuditKit)** | Free | $297/month |
| **Cost (Assessment)** | $0 | $25,000-$150,000 |
| **Timeline** | 2-4 weeks | 3-6 months |
| **Automated Checks** | 8 | 33 |
| **Manual Docs** | 9 | 77 |
| **Required For** | All DoW contracts | CUI contracts |
| **Deadline** | Now | Nov 10, 2025 |

---

## CMMC & NIST SP 800-171

**CMMC Level 2 is based on NIST SP 800-171 Rev 2**

AuditKit Pro maps all 110 CMMC Level 2 practices to their corresponding NIST SP 800-171 controls.

**Example mapping:**
- CMMC AC.2.007 → NIST 800-171 3.1.2
- CMMC IA.2.081 → NIST 800-171 3.5.3
- CMMC SC.2.179 → NIST 800-171 3.13.1

This means passing CMMC Level 2 = compliance with NIST SP 800-171.

---

## C3PAO Assessment Process

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
| AuditKit Pro (annual) | $3,564 |
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
1. Inadequate access controls (AC.2.016)
2. Missing audit logs (AU.2.041)
3. No security awareness training (AT.2.056)
4. Weak incident response (IR.2.092)
5. No vulnerability management (RA.2.138)
6. Missing system hardening (CM.2.061)
7. No cryptographic protection (SC.2.179)
8. Inadequate media protection (MP.2.120)

**AuditKit Pro catches all technical failures before assessment.**

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
- **[Pricing (Free vs Pro) →](../pricing.md)**
- **[Cloud Setup Guides →](../setup/)**
