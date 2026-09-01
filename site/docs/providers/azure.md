# Azure Service Coverage

What AuditKit scans in Microsoft Azure.

---

## Overview

**Coverage:** 178 controls across Azure services  
**Supported in:** Free and Pro versions

**Supported frameworks:**
- SOC2 Type II (38 criteria)
- PCI-DSS v4.0.1 (48 requirements)
- CMMC Level 1 (17 practices) and Level 2 (110 practices - Pro)
- NIST 800-53 Rev 5 (128 controls, derived via crosswalk)
- HIPAA (experimental - ~10 controls)

---

## Covered Services

### Storage Accounts

**Controls checked:** 8

- **CC6.2** - Public blob access disabled
- **CC8.1** - Storage encryption at rest (Microsoft-managed or customer-managed keys)
- **CC8.2** - Secure transfer (HTTPS) required
- **CC7.2** - Blob soft delete enabled
- **CC6.23** - Shared access signature (SAS) token security
- **CC7.13** - Storage account firewall rules
- **CC6.24** - Storage account key rotation
- **SC.1.176** - Network access restrictions

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

**Controls checked:** 12

- **CC6.6** - MFA enforcement for all users
- **IA.2.081** - Conditional Access policies configured
- **CC6.7** - MFA for admin accounts
- **CC6.25** - Identity Protection enabled
- **CC6.26** - Privileged Identity Management (PIM) configured
- **IA.1.076** - Password policy strength
- **CC6.27** - Guest user restrictions
- **CC6.28** - Legacy authentication blocked
- **CC6.29** - Self-service password reset enabled
- **CC6.30** - Risk-based sign-in policies
- **CC7.14** - Sign-in logs retained
- **AU.2.041** - Audit logs enabled

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

**Controls checked:** 6

- **SC.1.175** - Overly permissive inbound rules
- **CC6.31** - Rules allowing 0.0.0.0/0 access
- **SC.2.179** - Network segmentation
- **CC6.32** - Unused or default NSG rules
- **CC7.15** - NSG flow logs enabled
- **SC.1.176** - Just-in-time VM access configured

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

- **CC8.1** - Disk encryption enabled (Azure Disk Encryption)
- **CC6.33** - Public IP assignments
- **CC7.16** - Azure Monitor agent installed
- **SI.1.210** - Update Management configured
- **CC6.34** - Just-in-time VM access
- **CC7.17** - Boot diagnostics enabled
- **MA.2.111** - Maintenance configurations

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

**Controls checked:** 6

- **CC8.1** - Transparent Data Encryption (TDE) enabled
- **CC8.2** - SSL/TLS enforcement
- **AU.2.042** - Auditing enabled
- **CC6.35** - Firewall rules configured (no 0.0.0.0/0)
- **CC9.1** - High availability configured
- **CC7.18** - Advanced Threat Protection enabled

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

**Controls checked:** 5

- **CC8.3** - Key rotation policies configured
- **CC6.36** - Access policies follow least privilege
- **CC7.19** - Soft delete enabled
- **CC7.20** - Purge protection enabled
- **AU.2.043** - Diagnostic logging enabled

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

**Controls checked:** 4

- **CM.2.061** - Policy assignments configured
- **CC7.21** - Compliance dashboard monitored
- **CM.2.062** - Resource compliance tracked
- **CC6.37** - Deny policies for critical controls

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

**Controls checked:** 5

- **CC7.22** - Defender for Cloud enabled
- **SI.1.214** - Security alerts configured
- **CA.2.158** - Secure score monitored
- **RA.2.138** - Vulnerability assessments enabled
- **IR.2.092** - Security recommendations addressed

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

**Controls checked:** 4

- **AU.2.041** - Activity log collection enabled
- **CC7.23** - Log retention configured (90+ days)
- **CC7.24** - Log export to storage account
- **AU.2.044** - Activity log alerts configured

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

**Controls checked:** 5

- **SI.1.214** - Log Analytics workspace configured
- **CC7.25** - Monitoring agents deployed
- **AU.2.045** - Log retention policy set
- **CC7.26** - Custom alerts configured
- **IR.2.093** - Alert action groups defined

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

**Controls checked:** 5

- **SC.1.175** - NSG flow logs enabled
- **SC.2.179** - Subnets properly segmented
- **CC6.38** - Service endpoints configured
- **CC6.39** - Private endpoints for PaaS services
- **SC.1.176** - DDoS Protection Standard enabled

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

### SOC2 Type II (38 criteria)

**CC1 - Control Environment:** 5 controls  
**CC2 - Communication:** 4 controls  
**CC3 - Risk Assessment:** 6 controls  
**CC5 - Control Activities:** 7 controls  
**CC6 - Logical Access:** 18 controls  
**CC7 - System Operations:** 12 controls  
**CC8 - Change Management:** 6 controls  
**CC9 - Risk Mitigation:** 6 controls

### PCI-DSS v4.0.1 (48 requirements)

**Requirement 1 - Network Security:** 5 controls  
**Requirement 2 - Secure Configurations:** 4 controls  
**Requirement 3 - Cardholder Data Protection:** 6 controls  
**Requirement 8 - Access Control:** 8 controls  
**Requirement 10 - Logging:** 5 controls  
**Requirement 11 - Security Testing:** 2 controls

### CMMC Level 1 (17 practices)

**Access Control:** 3 practices  
**Identification & Authentication:** 2 practices  
**Media Protection:** 1 practice  
**Physical Protection:** 3 practices  
**System Protection:** 5 practices  
**System Integrity:** 3 practices

### CMMC Level 2 (110 practices - Pro only)

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
./auditkit-pro scan -provider azure -framework cmmc-l2

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
