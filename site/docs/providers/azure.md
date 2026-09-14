# Azure Service Coverage

What AuditKit scans in Microsoft Azure.

---

## Overview

**Coverage:** 277 controls across Azure services  
**Supported in:** Free and Pro versions

**Supported frameworks:**
- SOC2 Type II (38 criteria)
- PCI-DSS v4.0.1 (63 requirements)
- CMMC Level 1 and Level 2: all 110 practices reported; 5 reach a verdict on Azure (4 of the 17 Level 1, plus 1 Level 2); Pro adds deeper automation and the evidence package
- NIST 800-53 Rev 5 (144 controls, derived via crosswalk)
- HIPAA (30 safeguards, derived via crosswalk)

---

## Covered Services

Every control the service checks emit, read from the scanner's source. The
identifier is the one the report carries; the framework pages say which
requirement each maps to.

### AKS

**Controls checked:** 15

- **CIS-AKS-5.4.1** - AKS Cluster Access
- **CIS-AKS-5.4.4** - AKS Network Policy
- **AZ-AKS-02** - AKS Azure Policy Add-on
- **CIS-AKS-5.5.1** - AKS Azure AD Integration
- **CIS-AKS-5.5.2** - AKS RBAC Enabled
- **CIS-AKS-5.4.2** - AKS Private Cluster
- **AZ-AKS-05** - AKS Managed Identity
- **AZ-AKS-03** - AKS Disk Encryption (CMK)
- **CIS-AKS-5.1.1** - AKS Defender for Containers
- **AZ-AKS-01** - AKS Auto-Upgrade
- **AZ-AKS-06** - AKS Node Pool Security
- **CIS-AKS-2.1.1** - AKS Audit Logging
- **AZ-AKS-08** - AKS Secrets Store CSI Driver
- **AZ-AKS-07** - AKS Pod Security Standards
- **AZ-AKS-04** - AKS Image Cleaner

### Defender for Cloud

**Controls checked:** 15

- **CIS-8.1.3.1** - Microsoft Defender for Servers
- **CIS-8.1.6.1** - Microsoft Defender for App Service
- **CIS-8.1.7.3** - Microsoft Defender for Azure SQL Databases
- **CIS-8.1.7.4** - Microsoft Defender for SQL Servers on Machines
- **CIS-8.1.7.2** - Microsoft Defender for Open-Source Relational Databases
- **CIS-8.1.7.1** - Microsoft Defender for Azure Cosmos DB
- **CIS-8.1.5.1** - Microsoft Defender for Storage
- **CIS-8.1.4.1** - Microsoft Defender for Containers
- **AZ-DEFENDER-03** - Microsoft Defender for DNS
- **CIS-8.1.8.1** - Microsoft Defender for Key Vault
- **CIS-8.1.2.1** - Microsoft Defender for APIs
- **CIS-8.1.9.1** - Microsoft Defender for Resource Manager
- **AZ-DEFENDER-01** - Auto-Provisioning of Defender Components
- **CIS-8.1.13** - Security Contact Email
- **CIS-8.1.14** - Security Alert Notifications

### SQL

**Controls checked:** 15

- **AZ-SQL-05** - SQL TDE Encryption
- **AZ-SQL-04** - SQL TDE Check
- **AZ-SQL-03** - SQL Transparent Data Encryption
- **AZ-SQL-02** - SQL Auditing
- **AZ-SQL-01** - SQL Server Auditing
- **AZ-SQL-13** - SQL Server Firewall and Public Access
- **AZ-SQL-06** - SQL Entra ID Authentication
- **CIS-8.1.7.3** - Microsoft Defender for SQL
- **AZ-SQL-07** - PostgreSQL Require Secure Transport
- **AZ-SQL-08** - PostgreSQL Logging Configuration
- **AZ-SQL-14** - PostgreSQL Public Network Access
- **AZ-SQL-09** - PostgreSQL Single Server (Legacy)
- **AZ-SQL-10** - MySQL Require Secure Transport
- **AZ-SQL-11** - MySQL TLS Version
- **AZ-SQL-12** - MySQL Audit Logging

### Storage Accounts

**Controls checked:** 13

- **CIS-9.3.8** - Storage Account Public Access
- **AZ-STORAGE-93** - Storage Encryption at Rest
- **AZ-STORAGE-94** - Storage Service Encryption
- **CIS-9.3.4** - Secure Transfer Required
- **AZ-STORAGE-03** - Infrastructure Encryption
- **CIS-9.3.2.2** - Public Network Access Disabled
- **CIS-9.3.6** - Minimum TLS Version
- **AZ-STORAGE-02** - Blob Anonymous Access
- **CIS-9.3.7** - Cross-Tenant Replication
- **AZ-STORAGE-95** - Blob Soft Delete
- **CIS-9.3.2.3** - Default Network Access Rule
- **CIS-9.3.1.1** - Storage Key Rotation
- **AZ-STORAGE-01** - Storage Logging

### Entra ID

**Controls checked:** 12

- **CIS-5.3.4** - Privileged Role Assignments
- **CIS-5.7** - Excessive Owner Assignments
- **CIS-5.3.7** - Contributor Role Assignments
- **CIS-5.1.3** - MFA for All Users
- **AZ-ENTRA-90** - MFA for Privileged Users
- **AZ-ENTRA-01** - Password Policy Configuration
- **AZ-ENTRA-91** - Conditional Access - Untrusted Locations
- **CIS-5.1.1** - Block Legacy Authentication
- **CIS-5.3.2** - Guest User Access Review
- **AZ-ENTRA-92** - Guest Invite Restrictions
- **PCI-8.2.8** - Session Timeout Configuration
- **PCI-8.2.6** - Remove Inactive Users

### App Service

**Controls checked:** 7

- **AZ-APPSVC-02** - App Service Authentication
- **AZ-APPSVC-03** - HTTPS Only Redirect
- **AZ-APPSVC-04** - TLS Version
- **AZ-APPSVC-05** - Client Certificates
- **AZ-APPSVC-06** - Managed Identity
- **AZ-APPSVC-07** - Runtime Versions
- **AZ-APPSVC-01** - FTP Deployment Disabled

### Virtual Machines

**Controls checked:** 7

- **CC6.3** - Disk Encryption at Rest
- **AZ-COMPUTE-01** - Managed Disks
- **CC7.1** - VM Monitoring Agents
- **PCI-5.2.1** - Endpoint Protection
- **AZ-COMPUTE-05** - VM Backup
- **AZ-COMPUTE-02** - Disk Network Access Restriction
- **CC6.1** - VM Public IP Exposure

### Networking

**Controls checked:** 7

- **CIS-7.1** - RDP Access from Internet
- **CIS-7.2** - SSH Access from Internet
- **AZ-NETWORK-01** - UDP Access from Internet
- **CIS-7.4** - HTTP(S) Access from Internet
- **CIS-7.5** - NSG Flow Log Retention
- **CIS-7.6** - Network Watcher Enabled
- **CIS-7.7** - Public IP Address Evaluation

### Key Vault

**Controls checked:** 5

- **AZ-KEYVAULT-01** - Key Vault Recovery Settings
- **AZ-KEYVAULT-02** - Key Vault RBAC Authorization
- **CIS-8.3.8** - Key Vault Private Endpoints
- **CIS-8.3.7** - Key Vault Network Access
- **CIS-6.1.1.4** - Key Vault Logging

### Identity

**Controls checked:** 3

- **CC6.6** - Global Administrator MFA
- **CC6.7** - Azure AD Password Policy
- **CC6.1** - Privileged Role Management

### Monitor

**Controls checked:** 3

- **CIS-6.1.1.2** - Activity Log Export and Retention
- **CIS-6.1.1.4** - Key Vault and NSG Diagnostic Logging
- **PCI-10.5.1** - Activity Log Retention - 12 Months Immediately Available

### Types

**Controls checked:** 1

- **CIS-5.3.2**

### Framework suites

The framework suites add their own identifiers on top of the service checks: CIS (91), CMMC (13), PCI DSS (39), SOC 2 (30), vulnerability coverage (2). Those are described on the framework pages rather than here.


## Controls by Framework

### SOC2 Type II (37 of the 43 criteria carry automated Azure checks)

**CC1 - Control Environment:** 5 criteria  
**CC2 - Communication:** 3 criteria  
**CC3 - Risk Assessment:** 4 criteria  
**CC4 - Monitoring:** 2 criteria  
**CC5 - Control Activities:** 3 criteria  
**CC6 - Logical Access:** 8 criteria  
**CC7 - System Operations:** 5 of 5 criteria  
**CC8 - Change Management:** 1 criterion  
**CC9 - Risk Mitigation:** 2 criteria  
**A1 - Availability:** 3 criteria  
**C1 - Confidentiality:** 2 criteria  
**PI1 - Processing Integrity:** no automated Azure check (reported as MANUAL)

### PCI-DSS v4.0.1 (63 requirements with automated checks)

Automated checks map into all twelve requirement families (1 through 12). Requirements with no automated check are still reported and marked "No automated check covers this control".

### CMMC Level 1 (17 practices, 13 automated)

**Access Control (AC):** 4 practices  
**Identification & Authentication (IA):** 2 practices  
**Media Protection (MP):** 1 practice  
**Physical Protection (PE):** 4 practices  
**System & Communications Protection (SC):** 2 practices  
**System & Information Integrity (SI):** 4 practices

### CMMC Level 2 (110 practices - reported free, automated in Pro)

All Level 1 practices plus 93 additional practices across 14 domains.

**[View CMMC details →](../frameworks/cmmc.md)**

---

## Running Azure Scans

```bash
# Configure credentials
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Scan for SOC2
./auditkit scan -provider azure -framework soc2

# Scan for PCI-DSS
./auditkit scan -provider azure -framework pci

# Scan for CMMC Level 1
./auditkit scan -provider azure -framework cmmc

# Scan for CMMC Level 2 (Pro only)
./auditkit-pro scan -provider azure -framework cmmc

# Generate report
./auditkit scan -provider azure -framework soc2 -format pdf -output azure-report.pdf
```

---

## Multi-Subscription Scanning

**Free version:** One subscription at a time
```bash
# Switch subscriptions
export AZURE_SUBSCRIPTION_ID="sub-1"
auditkit scan -provider azure -framework soc2

export AZURE_SUBSCRIPTION_ID="sub-2"
auditkit scan -provider azure -framework soc2
```

**Pro version:** Scan entire Management Group
```bash
# Scan all subscriptions
auditkit-pro scan -provider azure --scan-all

# Limit concurrency
auditkit-pro scan -provider azure --scan-all --max-concurrent 3

# Generate consolidated report
auditkit-pro scan -provider azure --scan-all -format pdf -output mgmt-group-report.pdf
```

**[Try Pro free for 14 days →](https://auditkit.io/pro/)**

---

## Azure-Specific Considerations

### Azure AD Premium Requirements

Some checks require Azure AD Premium licenses:
- Conditional Access (P1)
- Identity Protection (P2)
- Privileged Identity Management (P2)
- Risk-based policies (P2)

**Without Premium:** Manual verification required for these controls

### Defender for Cloud

**Free tier:** Basic security posture assessment  
**Standard tier:** Required for full vulnerability assessment, threat protection

AuditKit reports which features require Standard tier.

### Azure Policy vs Defender Recommendations

AuditKit checks both:
- **Azure Policy:** Preventive controls (deny/audit)
- **Defender for Cloud:** Detective controls (recommendations)

---

## Next Steps

- **[Azure Setup Guide →](../setup/azure.md)**
- **[Getting Started →](../getting-started.md)**
- **[CLI Reference →](../cli-reference.md)**
- **[Framework Guides →](../frameworks/)**
