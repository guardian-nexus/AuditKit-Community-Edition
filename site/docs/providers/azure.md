# Azure Service Coverage

What AuditKit scans in Microsoft Azure.

---

## Overview

**Coverage:** 174 controls across Azure services  
**Supported in:** Free and Pro versions

**Supported frameworks:**
- SOC2 Type II (37 criteria)
- PCI-DSS v4.0.1 (59 requirements)
- CMMC Level 1 and Level 2: all 110 practices reported; Level 1 automated, Level 2 automated in Pro
- NIST 800-53 Rev 5 (83 controls, derived via crosswalk)
- HIPAA (18 safeguards, derived via crosswalk)

---

## Covered Services

### Storage Accounts

**Controls checked:** 13

- **CIS-3.1** - Storage account public access blocked (SOC2 CC6.2)
- **CIS-3.3 / CIS-3.4** - Storage encryption at rest and storage service encryption (SOC2 CC6.3)
- **CIS-4.1** - Secure transfer (HTTPS) required (SOC2 CC6.7)
- **CIS-4.2** - Infrastructure encryption
- **CIS-4.3** - Storage account key rotation
- **CIS-4.6** - Public network access disabled
- **CIS-4.7** - Default network access rule set to Deny
- **CIS-4.10** - Blob soft delete enabled (SOC2 CC9.1)
- **CIS-4.12** - Storage logging
- **CIS-4.15** - Minimum TLS version
- **CIS-4.16** - Cross-tenant replication disabled
- **CIS-4.17** - Blob anonymous access disabled

**Example fixes:**
```bash
# Disable public blob access
az storage account update \
  --name STORAGE_ACCOUNT \
  --resource-group RESOURCE_GROUP \
  --allow-blob-public-access false

# Require secure transfer
az storage account update \
  --name STORAGE_ACCOUNT \
  --resource-group RESOURCE_GROUP \
  --https-only true

# Enable soft delete
az storage blob service-properties delete-policy update \
  --account-name STORAGE_ACCOUNT \
  --enable true \
  --days-retained 7
```

---

### Azure AD (Entra ID)

**Controls checked:** 17

- **CC6.1** - Privileged Role Management
- **CC6.1** - Guest User Access Control
- **CC6.6** - Global Administrator MFA
- **CC6.7** - Azure AD Password Policy
- **CC6.7** - Stale Account Detection
- **CIS-1.1** - MFA for All Users
- **CIS-1.2** - MFA for Privileged Users
- **CIS-1.3** - Password Policy Configuration
- **CIS-1.4** - Privileged and Owner Role Assignments
- **CIS-1.5** - App Registration Owner Requirements
- **CIS-1.6** - Contributor Role Assignments
- **CIS-1.7** - Guest User Access Review
- **CIS-1.8** - Guest Invite Restrictions
- **CIS-1.9** - Conditional Access Policies
- **CIS-1.10** - Block Legacy Authentication
- **CIS-1.11** - Guest Invite Restrictions
- **CIS-1.12** - Security Defaults or Conditional Access

**Example fixes:**
```bash
# (Most Azure AD configuration done via portal)

# Enable security defaults (basic MFA)
az rest --method PATCH \
  --uri https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy \
  --body '{"isEnabled": true}'

# List Conditional Access policies
az rest --method GET \
  --uri https://graph.microsoft.com/beta/identity/conditionalAccess/policies
```

**Note:** Full Azure AD configuration requires Azure AD Premium P1/P2 licenses

---

### Network Security Groups (NSGs)

**Controls checked:** 13

- **CIS-6.1** - Dangerous Open Ports
- **CIS-6.2** - RDP Access from Internet Restricted
- **CIS-6.3** - SSH Access from Internet Restricted
- **CIS-6.4** - SQL Server Port Access Restricted
- **CIS-6.5** - PostgreSQL Port Access Restricted
- **CIS-6.6** - MySQL Port Access Restricted
- **CIS-7.1** - RDP Access from Internet
- **CIS-7.2** - SSH Access from Internet
- **CIS-7.3** - UDP Access from Internet
- **CIS-7.4** - HTTP(S) Access from Internet
- **CIS-7.5** - NSG Flow Log Retention
- **CIS-7.6** - Network Watcher Enabled
- **CIS-7.7** - Public IP Address Evaluation

**Example fixes:**
```bash
# Delete overly permissive rule
az network nsg rule delete \
  --resource-group RESOURCE_GROUP \
  --nsg-name NSG_NAME \
  --name RULE_NAME

# Create restrictive rule
az network nsg rule create \
  --resource-group RESOURCE_GROUP \
  --nsg-name NSG_NAME \
  --name AllowSSHFromSpecificIP \
  --priority 100 \
  --source-address-prefixes YOUR_IP/32 \
  --destination-port-ranges 22 \
  --access Allow \
  --protocol Tcp

# Enable NSG flow logs
az network watcher flow-log create \
  --resource-group RESOURCE_GROUP \
  --nsg NSG_NAME \
  --name FlowLogName \
  --storage-account STORAGE_ACCOUNT \
  --enabled true
```

---

### Virtual Machines

**Controls checked:** 7

- **CC6.1** - VM Public IP Exposure
- **CC7.1** - VM Monitoring Agents
- **CIS-7.1** - Disk Encryption at Rest
- **CIS-7.3** - Managed Disks
- **CIS-7.4** - Endpoint Protection
- **CIS-7.6** - VM Backup
- **CIS-8.5** - Disk Network Access Restriction

**Example fixes:**
```bash
# Enable disk encryption
az vm encryption enable \
  --resource-group RESOURCE_GROUP \
  --name VM_NAME \
  --disk-encryption-keyvault KEY_VAULT_NAME

# Remove public IP
az network nic ip-config update \
  --resource-group RESOURCE_GROUP \
  --nic-name NIC_NAME \
  --name ipconfig1 \
  --remove PublicIpAddress

# Enable boot diagnostics
az vm boot-diagnostics enable \
  --resource-group RESOURCE_GROUP \
  --name VM_NAME \
  --storage STORAGE_ACCOUNT
```

---

### SQL Database

**Controls checked:** 12

- **CIS-3.1.7.3** - Microsoft Defender for SQL
- **CIS-5.1.1** - SQL Server Auditing
- **CIS-5.1.2** - SQL Server Firewall and Public Access
- **CIS-5.1.3** - SQL Transparent Data Encryption
- **CIS-5.1.4** - SQL Entra ID Authentication
- **CIS-5.2.1** - PostgreSQL Require Secure Transport
- **CIS-5.2.2** - PostgreSQL Logging Configuration
- **CIS-5.2.5** - PostgreSQL Public Network Access
- **CIS-5.2.6** - PostgreSQL Single Server (Legacy)
- **CIS-5.3.1** - MySQL Require Secure Transport
- **CIS-5.3.2** - MySQL TLS Version
- **CIS-5.3.3** - MySQL Audit Logging

**Example fixes:**
```bash
# Enable TDE (enabled by default for new databases)
az sql db tde set \
  --resource-group RESOURCE_GROUP \
  --server SQL_SERVER \
  --database DATABASE_NAME \
  --status Enabled

# Enable auditing
az sql server audit-policy update \
  --resource-group RESOURCE_GROUP \
  --name SQL_SERVER \
  --state Enabled \
  --storage-account STORAGE_ACCOUNT

# Remove public firewall rule
az sql server firewall-rule delete \
  --resource-group RESOURCE_GROUP \
  --server SQL_SERVER \
  --name AllowAllAzureIPs
```

---

### Key Vault

**Controls checked:** 9

- **CIS-3.3.5** - Key Vault Recovery Settings
- **CIS-3.3.6** - Key Vault RBAC Authorization
- **CIS-3.3.7** - Key Vault Private Endpoints
- **CIS-6.1.4** - Key Vault Logging
- **CIS-8.1** - Key Vault Recoverable
- **CIS-8.2** - Key Vault Keys Have Expiration Dates
- **CIS-8.3** - Key Vault Network Access
- **CIS-8.4** - Key Vault Secrets Have Expiration Dates
- **CIS-8.6** - Key Vault Certificates Auto-Renew

**Example fixes:**
```bash
# Enable soft delete
az keyvault update \
  --name KEY_VAULT_NAME \
  --enable-soft-delete true \
  --retention-days 90

# Enable purge protection
az keyvault update \
  --name KEY_VAULT_NAME \
  --enable-purge-protection true

# Enable diagnostic logging
az monitor diagnostic-settings create \
  --resource /subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/VAULT_NAME \
  --name DiagnosticLogs \
  --logs '[{"category":"AuditEvent","enabled":true}]' \
  --storage-account STORAGE_ACCOUNT
```

---

### Azure Policy

**Controls checked:** 2

- **CC5.3** - Policies and Procedures
- **CIS-5.2.2** - Create Alert for Policy Assignment Changes

**Example fixes:**
```bash
# Assign built-in policy
az policy assignment create \
  --name 'RequireEncryption' \
  --policy '/providers/Microsoft.Authorization/policyDefinitions/POLICY_ID' \
  --scope /subscriptions/SUBSCRIPTION_ID

# List non-compliant resources
az policy state list --filter "isCompliant eq false"
```

---

### Defender for Cloud

**Controls checked:** 15

- **CIS-2.1.1** - Microsoft Defender for Servers
- **CIS-2.1.2** - Microsoft Defender for App Service
- **CIS-2.1.3** - Microsoft Defender for Azure SQL Databases
- **CIS-2.1.4** - Microsoft Defender for SQL Servers on Machines
- **CIS-2.1.5** - Microsoft Defender for Open-Source Relational Databases
- **CIS-2.1.6** - Microsoft Defender for Azure Cosmos DB
- **CIS-2.1.7** - Microsoft Defender for Storage
- **CIS-2.1.8** - Microsoft Defender for Containers
- **CIS-2.1.9** - Microsoft Defender for DNS
- **CIS-2.1.10** - Microsoft Defender for Key Vault
- **CIS-2.1.11** - Microsoft Defender for APIs
- **CIS-2.1.12** - Microsoft Defender for Resource Manager
- **CIS-2.1.17** - Auto-Provisioning of Defender Components
- **CIS-2.1.19** - Security Contact Email
- **CIS-2.1.20** - Security Alert Notifications

**Example fixes:**
```bash
# Enable Defender for Cloud (via portal or ARM template)
# Standard tier required for full features

# View security alerts
az security alert list

# View security recommendations
az security assessment list
```

---

### Activity Logs

**Controls checked:** 3

- **CIS-5.1.2** - Activity Log Export and Retention
- **CIS-5.1.5** - Key Vault and NSG Diagnostic Logging
- **PCI-10.5.1** - Activity Log Retention - 12 Months Immediately Available

**Example fixes:**
```bash
# Create diagnostic setting for Activity Log
az monitor diagnostic-settings create \
  --name ActivityLogExport \
  --resource /subscriptions/SUBSCRIPTION_ID \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true}]' \
  --storage-account STORAGE_ACCOUNT

# Create activity log alert
az monitor activity-log alert create \
  --name SecurityGroupChange \
  --resource-group RESOURCE_GROUP \
  --condition category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/write
```

---

### Azure Monitor

**Controls checked:** 8

- **CIS-5.2.1** - Create Alert for Authorization Changes
- **CIS-5.2.2** - Create Alert for Policy Assignment Changes
- **CIS-5.2.3** - Create Alert for NSG Changes
- **CIS-5.2.4** - Create Alert for Security Group Changes
- **CIS-5.2.5** - Create Alert for Security Solutions Changes
- **CIS-5.2.6** - Create Alert for SQL Firewall Changes
- **CIS-5.2.7** - Create Alert for Key Vault Deletion
- **CIS-5.2.8** - Create Alert for Storage Account Deletion

**Example fixes:**
```bash
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group RESOURCE_GROUP \
  --workspace-name WORKSPACE_NAME

# Set retention policy
az monitor log-analytics workspace update \
  --resource-group RESOURCE_GROUP \
  --workspace-name WORKSPACE_NAME \
  --retention-time 90

# Create alert rule
az monitor metrics alert create \
  --name HighCPU \
  --resource-group RESOURCE_GROUP \
  --scopes /subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM_NAME \
  --condition "avg Percentage CPU > 80" \
  --window-size 5m \
  --evaluation-frequency 1m
```

---

### Virtual Networks

**Controls checked:** 4

- **CIS-6.1** - Dangerous Open Ports
- **CIS-7.5** - NSG Flow Log Retention
- **CIS-7.6** - Network Watcher Enabled
- **CIS-7.7** - Public IP Address Evaluation

**Example fixes:**
```bash
# Enable DDoS Protection
az network ddos-protection create \
  --resource-group RESOURCE_GROUP \
  --name DDoSPlan

az network vnet update \
  --resource-group RESOURCE_GROUP \
  --name VNET_NAME \
  --ddos-protection true \
  --ddos-protection-plan DDoSPlan

# Create private endpoint
az network private-endpoint create \
  --resource-group RESOURCE_GROUP \
  --name PrivateEndpoint \
  --vnet-name VNET_NAME \
  --subnet SUBNET_NAME \
  --private-connection-resource-id RESOURCE_ID \
  --connection-name Connection
```

---

## Controls by Framework

### SOC2 Type II (37 of the 43 criteria carry automated Azure checks)

**CC1 - Control Environment:** 5 criteria  
**CC2 - Communication:** 3 criteria  
**CC3 - Risk Assessment:** 4 criteria  
**CC4 - Monitoring:** 2 criteria  
**CC5 - Control Activities:** 3 criteria  
**CC6 - Logical Access:** 8 criteria  
**CC7 - System Operations:** 4 of 5 criteria  
**CC8 - Change Management:** 1 criterion  
**CC9 - Risk Mitigation:** 2 criteria  
**A1 - Availability:** 3 criteria  
**C1 - Confidentiality:** 2 criteria  
**PI1 - Processing Integrity:** no automated Azure check (reported as MANUAL)

### PCI-DSS v4.0.1 (59 requirements with automated checks)

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
