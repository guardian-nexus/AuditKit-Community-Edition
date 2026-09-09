# HIPAA Compliance

Health Insurance Portability and Accountability Act guide.

---

## Overview

**HIPAA** protects Protected Health Information (PHI) in the United States.

**Who needs it:** Healthcare providers, health plans, healthcare clearinghouses, business associates
**Status in AuditKit:** Production - Technical and part of Administrative Safeguards
**Coverage:** 27 of the 75 Security Rule safeguards carry an automated check on AWS (12 of 12 Technical, 15 of 31 Administrative)
**What's not covered:** Physical safeguards (164.310), organizational requirements (164.314) and policies/documentation (164.316); 16 of the 31 administrative safeguards

---

## Important Disclaimer

**AuditKit's HIPAA support covers the Technical Safeguards and part of the Administrative Safeguards - NOT sufficient for HIPAA certification.**

**What AuditKit covers:**

- Technical Safeguards (164.312) - Fully mapped across all cloud providers
- Framework crosswalk to existing SOC2/PCI-DSS controls
- Automated scanning of technical configurations

**What AuditKit does NOT cover:**

- Administrative Safeguards (164.308) beyond the 15 covered - risk analysis as a document, workforce training records, sanction policy, BAA management
- Physical Safeguards (164.310) - Facility access, workstation security
- Business Associate Agreements
- Risk assessments and documentation

**Use for:** Technical infrastructure assessment as part of HIPAA compliance program
**Don't use for:** Sole evidence of HIPAA certification or compliance attestation
**Hire a consultant for:** Complete HIPAA compliance program including administrative and physical safeguards

---

## HIPAA Security Rule

The HIPAA Security Rule has 3 types of safeguards:

### Administrative Safeguards (Not covered by AuditKit)
- Security management process
- Workforce security
- Information access management
- Security awareness training
- Security incident procedures
- Contingency plans
- Business associate agreements
- Evaluation procedures

### Physical Safeguards (Not covered by AuditKit)
- Facility access controls
- Workstation use and security
- Device and media controls

### Technical Safeguards (Partially covered)
**164.312(a)(1) - Access Control**

- Unique user identification
- Emergency access procedure
- Automatic logoff
- Encryption and decryption

**164.312(b) - Audit Controls**

- Hardware, software, and procedural mechanisms to record and examine activity

**164.312(c) - Integrity**

- Mechanisms to ensure ePHI is not improperly altered or destroyed

**164.312(d) - Person or Entity Authentication**

- Verify person or entity seeking access to ePHI is who/what they claim

**164.312(e) - Transmission Security**

- Implement technical security measures to guard against unauthorized access to ePHI transmitted over electronic networks

---

## What AuditKit Checks

### Access Control (164.312(a))
- IAM user identification
- MFA enforcement (164.312(a)(2)(i))
- Access key management
- Least privilege access

### Audit Controls (164.312(b))
- CloudTrail/Activity Logs enabled
- Log retention (6 years for HIPAA)
- Audit trail integrity

### Integrity (164.312(c)(1))
- Encryption at rest (164.312(a)(2)(iv))
- Backup and recovery
- Version control

### Authentication (164.312(d))
- Strong password policies
- MFA for authentication
- Service account management

### Transmission Security (164.312(e))
- Encryption in transit (164.312(e)(1))
- TLS/SSL enforcement
- Network security

---

## Running HIPAA Scan

```bash
# AWS
auditkit scan -provider aws -framework hipaa

# Azure
auditkit scan -provider azure -framework hipaa

# GCP
auditkit scan -provider gcp -framework hipaa

# Generate report (for internal use only)
auditkit scan -provider aws -framework hipaa -format pdf -output hipaa-report.pdf
```

**Warning:** This report is NOT sufficient for HIPAA compliance attestation

---

## What's Missing

AuditKit does NOT check:

**Administrative Safeguards:**

- Risk analysis and management
- Workforce training
- Security policies and procedures
- Business associate agreements
- Incident response plans
- Disaster recovery plans
- Access authorization procedures

**Physical Safeguards:**

- Data center physical security
- Workstation security
- Device disposal procedures
- Facility access controls
- Visitor logs

**Additional Technical Requirements:**

- Application-level access controls
- ePHI-specific encryption
- De-identification procedures
- Minimum necessary standard
- Emergency access procedures

---

## HIPAA vs Other Frameworks

| Framework | Coverage | Status |
|-----------|----------|--------|
| **SOC2** | Security controls | Production |
| **HIPAA** | Healthcare-specific Technical Safeguards | Production |
| **Overlap** | Significant - most technical controls map across both | Strong |

**Key differences:**

- HIPAA is healthcare-specific
- HIPAA requires 6-year log retention (vs 90 days for SOC2)
- HIPAA has specific PHI requirements
- HIPAA requires business associate agreements
- HIPAA requires extensive administrative and physical safeguards

**Recommendation:** Get SOC2 first (covers many technical controls), then add HIPAA-specific requirements (administrative, physical, BAAs)

---

## HIPAA Compliance Approach

### Phase 1: Infrastructure (Use AuditKit)
1. Run HIPAA scan
2. Fix technical controls
3. Enable encryption
4. Configure logging

### Phase 2: Administrative (Manual)
1. Conduct risk analysis
2. Write policies and procedures
3. Implement workforce training
4. Create incident response plan
5. Sign business associate agreements

### Phase 3: Physical (Manual)
1. Implement facility access controls
2. Secure workstations
3. Establish media disposal procedures
4. Create visitor logs

### Phase 4: Assessment (Hire Expert)
1. Hire HIPAA compliance consultant
2. Conduct full risk assessment
3. Create compliance documentation
4. Prepare for OCR audit

---

## Cost Breakdown

| Item | Cost (Estimate) |
|------|-----------------|
| AuditKit Free | $0 |
| HIPAA consultant | $25,000 - $100,000 |
| Risk assessment | $10,000 - $30,000 |
| Policy development | $5,000 - $20,000 |
| Training program | $5,000 - $15,000 |
| Ongoing compliance | $10,000 - $50,000/year |
| **Total** | **$55,000 - $215,000** |

**Timeline:** 6-12 months for initial compliance

---

## Common HIPAA Violations

Based on OCR enforcement actions:

1. **Lack of risk analysis** (most common)
2. Insufficient access controls
3. No encryption of ePHI
4. Missing business associate agreements
5. No breach notification procedures
6. Inadequate workforce training
7. No audit controls
8. Physical security gaps

**AuditKit helps with #2, #3, #7** - but you need consultants for the rest

---

## FAQ

**Q: Can I use AuditKit for HIPAA compliance?**
A: Yes, for the Technical Safeguards portion (164.312). You must separately address Administrative Safeguards (164.308) and Physical Safeguards (164.310) with policies, procedures, and a HIPAA consultant.

**Q: Is AuditKit HIPAA-compliant?**
A: AuditKit is a tool. Your organization must achieve HIPAA compliance through proper policies, procedures, and technical controls. AuditKit helps scan and document the technical controls portion.

**Q: What's a business associate agreement (BAA)?**  
A: Legal contract requiring vendors to protect PHI. You need BAAs with:

- Cloud providers (AWS, Azure, GCP)
- SaaS vendors
- Any vendor accessing PHI

**Q: Do I need to encrypt all data?**  
A: HIPAA requires either encryption OR equivalent alternative measures. Most organizations choose encryption (easier to prove).

**Q: How long do I need to keep audit logs?**  
A: 6 years per HIPAA requirements (much longer than other frameworks).

**Q: What if I have a breach?**  
A: Report to OCR within 60 days. Notify affected individuals. May face fines up to $50,000 per violation.

---

## Recommended Path

**For healthcare startups:**

1. **Month 1-2:** Technical controls with AuditKit
2. **Month 3-4:** Hire HIPAA consultant
3. **Month 5-8:** Implement policies and procedures
4. **Month 9-10:** Workforce training
5. **Month 11-12:** Mock audit and gap remediation
6. **Ongoing:** Annual risk assessments

**Don't skip the consultant.** HIPAA violations can result in fines up to $1.5 million per violation category per year.

---

## Next Steps

- **[Run HIPAA Technical Safeguards scan →](../getting-started.md)**
- **[Compare to SOC2 →](./soc2.md)**
- **[Find HIPAA consultant →](https://www.hhs.gov/hipaa)**
- **[HHS HIPAA guidance →](https://www.hhs.gov/hipaa/for-professionals/security/index.html)**

**Remember:** AuditKit covers Technical Safeguards. Hire a HIPAA compliance expert for Administrative and Physical Safeguards required for full compliance.
