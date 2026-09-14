# GDPR Compliance

Technical measures under Articles 25, 30 and 32 of the EU General Data Protection Regulation, automated where your cloud configuration can show them.

---

## Overview

**GDPR** governs how personal data of people in the EU and UK is processed, wherever the processor is located.

**Who needs it:** Any organisation processing personal data of people in the EU or UK
**Status in AuditKit:** Production
**Coverage:** 16 article paragraphs reach a verdict through the crosswalk (Articles 5, 24, 25, 30, 32, 33, 34 and 35); 11 more security-relevant obligations are listed in the report for you to document
**How it works:** Derived from your SOC2, PCI DSS and CMMC results through NIST 800-53

---

## Important Disclaimer

**AuditKit covers technical measures under Articles 25, 30 and 32. It does not make you GDPR compliant, and nothing it produces is legal advice.**

This is the same line every cloud-configuration tool draws: Prowler and Steampipe map Articles 25, 30 and 32 and nothing else, and AWS Audit Manager ships its GDPR framework as 378 manual controls with no automation at all. A scanner sees configuration; the Regulation is mostly about what you do with data and who you tell.

GDPR is mostly not a technical regulation. The bulk of it concerns lawful basis,
consent, data subject rights, records of processing, international transfers and
your relationship with processors. None of that is visible from a cloud
configuration scan, and no scanner can assess it.

**What AuditKit covers**

- Article 32(1)(a) - encryption of personal data
- Article 32(1)(b) - confidentiality, integrity and availability of systems
- Article 32(1)(c) - ability to restore availability after an incident
- Article 32(1)(d) - a process for testing and evaluating security measures
- Article 25 - data protection by design and by default, as far as access
  restriction and encryption defaults go
- Article 30(1) and 5(2) - logging that supports records of processing and
  accountability
- Articles 33 and 34 - the detection and alerting that a breach notification
  process depends on

**What AuditKit does not cover**

- Lawful basis for processing, and consent management
- Data subject access, rectification, erasure and portability requests
- Records of processing activities (Article 30) as a document
- Data Protection Impact Assessments, beyond flagging that risk assessment applies
- International transfer mechanisms, adequacy decisions and standard contractual clauses
- Appointing a Data Protection Officer
- Processor contracts under Article 28

The security-relevant obligations in that second list still appear in a GDPR
report - processor guarantees (Art 28), breach records (Art 33(5)), transfer
safeguards (Art 44, 46) - as rows marked MANUAL for you to document, never as
automated findings. Treat the output as evidence toward Articles 25, 30 and
32, not as a compliance verdict, and have a privacy professional review the
scope before relying on it with a supervisory authority.

---

## Running a GDPR scan

```bash
auditkit scan -provider aws -framework gdpr
auditkit scan -provider azure -framework gdpr
auditkit scan -provider gcp -framework gdpr
```

Reports work as they do for any other framework:

```bash
auditkit scan -provider aws -framework gdpr -format pdf -output gdpr-evidence.pdf
```

---

## How coverage is derived

AuditKit does not run separate GDPR checks. Each control it already assesses maps
to NIST 800-53, and 800-53 maps to the GDPR articles below. One S3 encryption
check therefore contributes to Article 32(1)(a) and Article 5(1)(f) at the same
time.

| Article | Subject | NIST 800-53 |
|---------|---------|-------------|
| Art 5(1)(f) | Integrity and confidentiality | SC-13, SC-28, AC-3 |
| Art 5(2) | Accountability | AU-2, AU-3, AU-12 |
| Art 24(1) | Responsibility of the controller | PM-1, PM-9 |
| Art 24(2) | Data protection policies | PL-1, PL-2 |
| Art 25(1) | Data protection by design | SA-8, SC-28 |
| Art 25(2) | Data protection by default | AC-6, CM-7 |
| Art 30(1) | Records of processing activities | AU-2, AU-3 |
| Art 32(1)(a) | Encryption of personal data | SC-13, SC-28 |
| Art 32(1)(b) | Confidentiality, integrity, availability | AC-2, AC-3, SC-7 |
| Art 32(1)(c) | Restore availability after an incident | CP-9, CP-10 |
| Art 32(1)(d) | Testing and evaluating measures | CA-2, CA-7 |
| Art 32(2) | Risk assessment | RA-3, RA-5 |
| Art 33(1) | Breach notification to the supervisory authority | IR-6 |
| Art 33(3) | Breach record content | AU-2, AU-6 |
| Art 34(1) | Breach notification to data subjects | IR-6 |
| Art 35(1) | Data Protection Impact Assessment | RA-3 |

Sixteen article paragraphs are in the crosswalk and every provider reaches all
sixteen. The report also lists the eleven security-relevant obligations the
crosswalk cannot reach - processor contracts, breach records, impact-assessment
content, transfers - as rows to document.

---

## Related

- **[NIST 800-53](./nist-800-53.md)** - the crosswalk GDPR coverage is derived through
- **[ISO 27001](./iso27001.md)** - frequently paired with GDPR in EU procurement
- **[SOC 2](./soc2.md)** - the criteria most GDPR technical measures come from

**[All frameworks](./)**
