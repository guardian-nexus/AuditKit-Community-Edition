# NIST CSF 2.0 Compliance

The NIST Cybersecurity Framework, version 2.0.

---

## Overview

**NIST CSF 2.0** is a voluntary framework for organising and communicating cybersecurity risk, released in February 2024.

**Who needs it:** Anyone who wants a common language for security posture; often asked for by insurers, boards and enterprise customers
**Status in AuditKit:** Production
**Coverage:** 83 subcategories (AWS 75, Azure 82, GCP 83)
**How it works:** Derived from your SOC2, PCI DSS and CMMC results through NIST 800-53

---

## Important Disclaimer

**CSF is a framework for organising risk management, not a certification. There is nothing to pass or fail.**

CSF 2.0 has six functions. AuditKit's scanning speaks to the technical parts of
four of them. Govern, added in 2.0 and arguably the most important change from
1.1, is almost entirely organisational: roles, policy, risk appetite, supply
chain strategy. A scanner cannot assess it.

**What AuditKit covers**

- **Identify** - asset inventory and risk assessment that follows from what the scan enumerates
- **Protect** - access control, data security, platform hardening
- **Detect** - logging, monitoring and alerting configuration
- **Respond** - the detection and notification prerequisites of an incident response process

**What AuditKit does not cover**

- **Govern** - organisational context, risk management strategy, roles and responsibilities, policy, oversight, supply chain risk management
- **Recover** - recovery plan execution, communications during recovery
- Anything requiring evidence of a process rather than a configuration

---

## Running a CSF scan

```bash
auditkit scan -provider aws -framework nist-csf
auditkit scan -provider azure -framework nist-csf
auditkit scan -provider gcp -framework nist-csf
```

`csf` is accepted as a shorthand:

```bash
auditkit scan -provider aws -framework csf -format pdf -output csf-posture.pdf
```

---

## Coverage by function

AuditKit does not run separate CSF checks. Every control it already assesses maps
to NIST 800-53, and 800-53 maps to CSF subcategories, so coverage is a
consequence of the SOC2, PCI DSS and CMMC scanning you already ran.

| Function | Subcategories in crosswalk | What drives coverage |
|----------|---------------------------|----------------------|
| **Identify** (ID) | 18 | Asset enumeration, risk assessment controls |
| **Protect** (PR) | 39 | Access control, encryption, platform hardening |
| **Detect** (DE) | 18 | Logging, monitoring, anomaly detection |
| **Respond** (RS) | 16 | Alerting and incident notification controls |
| **Recover** (RC) | 6 | Backup and restore controls |
| **Govern** (GV) | 0 | Organisational, not visible to a scanner |

97 subcategories are in the crosswalk. How many reach your report depends on the
provider: 75 on AWS, 82 on Azure, 83 on GCP.

The absence of Govern is not a gap in AuditKit so much as a statement about what
configuration scanning can see. If a customer asks for CSF 2.0 coverage, expect
to answer for Govern separately.

---

## Related

- **[NIST 800-53](./nist-800-53.md)** - the crosswalk CSF coverage is derived through
- **[SOC 2](./soc2.md)** - the criteria most CSF technical subcategories come from
- **[CMMC](./cmmc.md)** - also derived through 800-53, for defence contractors

**[All frameworks](./)**
