# PCI-DSS v4.0 Compliance

Payment Card Industry Data Security Standard guide.

---

## Overview

**PCI-DSS** protects payment card data for businesses that store, process, or transmit cardholder information.

**Who needs it:** Merchants, service providers, payment processors, anyone handling credit/debit card data
**Status in AuditKit:** Production
**Coverage:** All 12 requirements (60+ controls across AWS, Azure, GCP)
**What's covered:** Technical controls for network security, encryption, access control, monitoring, testing, and policy

---

## Important Disclaimer

**AuditKit's PCI-DSS support covers technical and some organizational controls - assessment by QSA required for certification.**

**What AuditKit covers:**
- Network security controls (Req 1)
- Configuration management (Req 2)
- Data encryption at rest and in transit (Req 3, 4)
- Technical vulnerability management (Req 6, 11)
- Access controls and authentication (Req 7, 8)
- Audit logging and monitoring (Req 10)
- Documentation guidance for organizational controls (Req 5, 9, 12)

**What AuditKit does NOT replace:**
- Qualified Security Assessor (QSA) evaluation
- Penetration testing by approved vendors
- Quarterly ASV vulnerability scans
- Formal risk assessments
- Complete policy and procedure documentation

**Use for:** Technical control assessment and remediation as part of PCI-DSS compliance program
**Don't use for:** Sole evidence of PCI-DSS compliance
**Hire a QSA for:** Annual assessment and Report on Compliance (ROC) or Self-Assessment Questionnaire (SAQ) validation

---

## PCI-DSS v4.0

PCI-DSS v4.0 became mandatory on March 31, 2024. Key updates from v3.2.1:

**Major changes:**
- Enhanced multi-factor authentication requirements
- Stronger encryption standards
- More detailed logging requirements
- Quarterly vulnerability scanning now explicitly required
- Service provider responsibilities clarified

**Timeline:**
- March 31, 2024: v4.0 mandatory (v3.2.1 retired)
- March 31, 2025: All v4.0 future-dated requirements become effective

---

## The 12 Requirements

### Build and Maintain a Secure Network

**Requirement 1: Install and maintain network security controls**
- Firewalls between untrusted networks and CDE
- Network segmentation of cardholder data environment (CDE)
- Restrict inbound/outbound traffic to only what's necessary
- No direct public access from internet to CDE

**Requirement 2: Apply secure configurations to all system components**
- Change vendor-supplied defaults (passwords, SNMP strings)
- Disable unnecessary services and protocols
- Configure security parameters to prevent misuse
- Maintain configuration standards

### Protect Cardholder Data

**Requirement 3: Protect stored cardholder data**
- Minimize data retention (store only what's necessary)
- Encrypt cardholder data at rest (AES-256 or equivalent)
- Mask PAN when displayed (first 6 and last 4 digits max)
- Render cardholder data unreadable

**Requirement 4: Protect cardholder data with strong cryptography during transmission**
- Use TLS 1.2+ for transmission over open/public networks
- Never send unencrypted PANs via email, messaging, chat
- Verify certificates are valid and not expired
- Use only strong cryptographic protocols

### Maintain a Vulnerability Management Program

**Requirement 5: Protect all systems and networks from malicious software**
- Deploy anti-malware on all systems commonly affected
- Ensure anti-malware is current and actively running
- Generate audit logs and retain per Requirement 10

**Requirement 6: Develop and maintain secure systems and software**
- Patch critical vulnerabilities within 30 days
- Implement secure development lifecycle
- Deploy web application firewall (WAF) for public-facing applications
- Separate development/test from production

### Implement Strong Access Control Measures

**Requirement 7: Restrict access to system components and cardholder data by business need to know**
- Define access based on job function
- Implement least privilege
- Document and approve all access
- Review access rights every 6 months

**Requirement 8: Identify users and authenticate access to system components**
- Unique ID for each user
- Multi-factor authentication (MFA) for all access to CDE
- Strong password policies (minimum 12 characters for v4.0)
- Password change every 90 days
- Account lockout after 6 failed attempts
- Session timeout after 15 minutes of inactivity

### Regularly Monitor and Test Networks

**Requirement 9: Restrict physical access to cardholder data**
- Physical access controls (badges, locks, cameras)
- Visitor logs and escorts
- Secure media storage and destruction
- Point-of-sale device protection

**Requirement 10: Log and monitor all access to system components and cardholder data**
- Audit logs for all access to cardholder data
- Automated audit trails for critical events
- Log retention for at least 12 months (3 months readily available)
- Daily log review or automated alerting
- Time synchronization using NTP

**Requirement 11: Test security of systems and networks regularly**
- Quarterly external vulnerability scans by Approved Scanning Vendor (ASV)
- Internal vulnerability scans quarterly and after significant changes
- Annual penetration testing
- File integrity monitoring (FIM) on critical files
- Intrusion detection/prevention systems (IDS/IPS)

### Maintain an Information Security Policy

**Requirement 12: Support information security with organizational policies and programs**
- Establish, publish, maintain security policy
- Annual risk assessment
- Acceptable use policies for critical technologies
- Assign information security responsibilities
- Security awareness training for all personnel
- Service provider management program
- Incident response plan tested at least annually

---

## What AuditKit Checks

### Automated Technical Controls

**Network Security (Req 1):**
- VPC/VNet segmentation
- Security group/NSG rules for 0.0.0.0/0 exposure
- Firewall configuration
- Network ACLs

**Secure Configurations (Req 2):**
- Default password warnings
- Default security group checks
- Service configuration review

**Data Encryption (Req 3, 4):**
- Storage encryption at rest (S3, Azure Storage, GCS, EBS, managed disks)
- Database encryption (RDS, SQL Database, Cloud SQL)
- TLS/SSL enforcement
- Secure transport policies

**Vulnerability Management (Req 6, 11):**
- Patch management status (INFO - cannot auto-verify patching)
- WAF deployment guidance
- Change detection mechanisms (AWS Config, Azure Policy, GCP Security Command Center)

**Access Control (Req 7, 8):**
- IAM user least privilege
- MFA enforcement on all accounts
- Root/admin account usage
- Password policy compliance
- Access key rotation (90 days)

**Logging and Monitoring (Req 10):**
- CloudTrail/Activity Log/Cloud Audit Logs enabled
- Log retention configuration
- Log integrity validation
- Centralized logging

### INFO/MANUAL Controls

**Malware Protection (Req 5):**
- Guidance for endpoint protection deployment
- Anti-malware update verification
- Log retention for anti-malware events

**Physical Security (Req 9):**
- Cloud provider physical security documentation (inherited controls)
- Organizational physical access procedures
- Media handling and destruction procedures

**Organizational Controls (Req 12):**
- Security policy establishment
- Risk assessment procedures
- Acceptable use policies
- Security awareness training
- Service provider management
- Incident response planning

---

## Running PCI-DSS Scan

```bash
# AWS
auditkit scan -provider aws -framework pci

# Azure
auditkit scan -provider azure -framework pci

# GCP
auditkit scan -provider gcp -framework pci

# Generate report
auditkit scan -provider aws -framework pci -format pdf -output pci-report.pdf
```

**Note:** Report provides technical control assessment but does not replace QSA evaluation

---

## PCI-DSS Validation Levels

Your validation requirements depend on transaction volume:

### Level 1 (Highest)
**Volume:** 6 million+ transactions/year
**Validation:** Annual Report on Compliance (ROC) by QSA
**Scans:** Quarterly ASV scans
**Cost:** $15,000 - $50,000 for QSA assessment

### Level 2
**Volume:** 1-6 million transactions/year
**Validation:** Annual Self-Assessment Questionnaire (SAQ)
**Scans:** Quarterly ASV scans
**May require:** QSA validation depending on acquiring bank

### Level 3
**Volume:** 20,000 - 1 million e-commerce transactions/year
**Validation:** Annual SAQ
**Scans:** Quarterly ASV scans

### Level 4 (Lowest)
**Volume:** Fewer than 20,000 e-commerce transactions/year or up to 1 million other transactions/year
**Validation:** Annual SAQ
**Scans:** Quarterly ASV scans (recommended, may be required by acquirer)

---

## Self-Assessment Questionnaires (SAQs)

Different SAQs for different business models:

**SAQ A:** E-commerce with fully outsourced payment processing (no cardholder data touches your systems)
**SAQ A-EP:** E-commerce with outsourced processing but your website involved
**SAQ B:** Imprint machines or standalone dial-out terminals only
**SAQ B-IP:** Standalone, PTS-approved payment terminals with IP connection
**SAQ C:** Payment application systems connected to the internet
**SAQ C-VT:** Web-based virtual payment terminals
**SAQ D (Merchant):** All other merchants (most comprehensive)
**SAQ D (Service Provider):** All service providers

**Most cloud-hosted applications:** SAQ D-Merchant (all 12 requirements apply)

---

## Compliance Timeline

### New Merchant Timeline (from zero)
**Months 1-2:** Scope your CDE, inventory systems
**Months 3-4:** Implement technical controls (AuditKit helps here)
**Months 5-6:** Policies, procedures, documentation
**Month 7:** Remediate gaps from AuditKit scan
**Month 8:** Internal audit and testing
**Month 9:** Quarterly ASV scan (first of four)
**Month 10-11:** Address ASV findings
**Month 12:** QSA assessment or SAQ validation
**Ongoing:** Quarterly ASV scans, annual reassessment

### Existing Merchant (maintenance)
**Quarterly:** ASV vulnerability scans
**Quarterly:** Internal vulnerability scans
**Annually:** Penetration testing
**Annually:** QSA assessment or SAQ attestation
**Continuously:** Log monitoring, change management, access reviews

---

## Common PCI-DSS Violations

Based on Verizon Payment Security Reports:

1. **Insufficient logging and monitoring** (Req 10)
2. **Lack of network segmentation** (Req 1)
3. **Weak or default passwords** (Req 2, 8)
4. **Unencrypted cardholder data** (Req 3, 4)
5. **No MFA for remote access** (Req 8)
6. **Missing or outdated patches** (Req 6)
7. **No vulnerability scanning** (Req 11)
8. **Inadequate access controls** (Req 7)
9. **Missing security policies** (Req 12)
10. **No anti-malware or outdated definitions** (Req 5)

**AuditKit helps identify #1-8** - you need policies and procedures for #9-10

---

## PCI-DSS vs Other Frameworks

| Framework | Focus | Overlap with PCI-DSS |
|-----------|-------|---------------------|
| **SOC2** | Trust Services | Medium - encryption, access control, logging |
| **HIPAA** | Healthcare data | Medium - similar technical controls |
| **CMMC** | DoW contractors | High - many aligned security controls |
| **ISO 27001** | Information security | High - comprehensive security management |

**Key PCI-DSS differentiators:**
- Specific to payment card data
- Quarterly vulnerability scanning required
- 12-month log retention (longer than most frameworks)
- 90-day password rotation (stricter than SOC2)
- Annual penetration testing mandatory
- Enforced by payment brands (Visa, Mastercard, etc.)

**Best approach:** Implement PCI-DSS controls, map to other frameworks for efficiency

---

## Cost Breakdown

| Item | Level 1 | Level 2-4 |
|------|---------|-----------|
| AuditKit Free | $0 | $0 |
| QSA Assessment (ROC) | $15,000 - $50,000 | - |
| SAQ Validation | - | $2,000 - $10,000 |
| ASV Scans (quarterly) | $2,000 - $8,000/year | $2,000 - $8,000/year |
| Penetration Testing | $10,000 - $30,000 | $10,000 - $30,000 |
| Remediation costs | $20,000 - $100,000 | $10,000 - $50,000 |
| **First year total** | **$47,000 - $188,000** | **$24,000 - $98,000** |
| **Ongoing (annual)** | **$27,000 - $88,000** | **$22,000 - $88,000** |

**Note:** Costs vary significantly based on environment complexity, number of locations, and current security posture

---

## FAQ

**Q: Do I need PCI-DSS compliance?**
A: If you store, process, or transmit credit/debit card information, yes. Even if you use a payment processor, you may still have PCI-DSS obligations (depends on your SAQ type).

**Q: Can I self-assess or do I need a QSA?**
A: Depends on your validation level. Level 1 requires QSA. Levels 2-4 may self-assess with SAQ, but your acquiring bank may require QSA validation.

**Q: What happens if I'm not PCI-DSS compliant?**
A: Fines from $5,000 to $100,000 per month by payment brands. Loss of ability to process cards. Liability for breaches. Reputational damage.

**Q: How long does PCI-DSS compliance take?**
A: First-time: 6-12 months. Maintenance: ongoing quarterly scans and annual reassessment.

**Q: Do cloud providers make me PCI-DSS compliant?**
A: No. AWS, Azure, and GCP are PCI-DSS compliant (for their infrastructure), but you're responsible for your applications and configurations. Review the Shared Responsibility Model.

**Q: What is "cardholder data environment" (CDE)?**
A: The CDE includes systems that store, process, or transmit cardholder data, plus systems that connect to those systems. Proper network segmentation reduces CDE scope.

**Q: Can I store CVV/CVC codes?**
A: No. Never. Not even encrypted. It's explicitly forbidden by PCI-DSS. Only store PAN (and only if absolutely necessary).

**Q: What's an Approved Scanning Vendor (ASV)?**
A: PCI SSC-approved company authorized to perform external vulnerability scans. Required quarterly. Find list at pcisecuritystandards.org.

**Q: Is PCI-DSS compliance the same as being "secure"?**
A: No. PCI-DSS is a minimum baseline. Many breached companies were PCI-compliant at time of breach. Use PCI-DSS as foundation, add additional security controls.

---

## Recommended Path

**For e-commerce/online payments:**

1. **Months 1-3:** Technical infrastructure (AuditKit helps)
   - Network segmentation
   - Encryption at rest and in transit
   - Access controls and MFA
   - Logging and monitoring

2. **Months 4-6:** Policies and procedures
   - Security policy
   - Acceptable use policies
   - Incident response plan
   - Vendor management

3. **Months 7-9:** Testing and validation
   - First quarterly ASV scan
   - Internal vulnerability scans
   - Penetration test
   - Address findings

4. **Months 10-12:** Assessment
   - Complete SAQ or prepare for QSA
   - Gather evidence
   - Final remediation
   - Attestation of Compliance

5. **Ongoing:** Maintain compliance
   - Quarterly ASV scans
   - Quarterly internal scans
   - Annual penetration test
   - Annual reassessment
   - Continuous monitoring

**Don't skip the QSA or ignore timelines.** Non-compliance can result in losing ability to process payments.

---

## Reducing PCI-DSS Scope

**Strategies to minimize CDE scope:**

1. **Don't store cardholder data**
   - Use payment service providers (Stripe, Square, etc.)
   - Tokenization
   - Point-to-point encryption (P2PE)

2. **Network segmentation**
   - Isolate CDE from other networks
   - Reduce number of in-scope systems
   - Document network flows

3. **Outsource when possible**
   - Hosted payment pages
   - Payment gateways
   - Cloud-based solutions with PCI-DSS attestations

4. **Data minimization**
   - Only collect what's necessary
   - Don't store CVV/CVC
   - Truncate PAN for display
   - Purge data when no longer needed

**Smaller scope = lower costs and reduced complexity**

---

## Next Steps

- **[Run PCI-DSS technical scan ](../getting-started.md)**
- **[Compare to SOC2 ](./soc2.md)**
- **[Find QSA ](https://www.pcisecuritystandards.org/assessors_and_solutions/qualified_security_assessors)**
- **[Find ASV ](https://www.pcisecuritystandards.org/assessors_and_solutions/approved_scanning_vendors)**
- **[PCI SSC official site ](https://www.pcisecuritystandards.org/)**
- **[Download SAQs ](https://www.pcisecuritystandards.org/document_library)**

**Remember:** AuditKit covers technical controls. Hire a QSA for complete validation and annual assessment.
