# Azure Arc On-Premises Scanning (Pro Only)

Scan your on-premises servers connected via Azure Arc.

---

## Overview

**Status:** Pro only
**Coverage:** Defender for Cloud assessments + Guest Configuration compliance
**Supported in:** AuditKit Pro v0.8.2+

Azure Arc extends Azure management to your on-premises servers. AuditKit Pro can scan Arc-enabled machines for compliance by pulling:

- **Defender for Cloud Assessments** - Security recommendations and vulnerabilities
- **Guest Configuration Compliance** - Azure Policy compliance status
- **Agent Health** - Arc agent connectivity monitoring

**Supported frameworks:**
- SOC2 Type II
- PCI-DSS v4.0
- CMMC Level 2 (Pro)
- NIST 800-53 Rev 5
- ISO 27001

**[Upgrade to Pro](https://auditkit.io/pro/)**

---

## Prerequisites

Before scanning Arc machines, you need:

1. **Azure Arc-enabled servers** - On-prem machines with the Arc agent installed
2. **Microsoft Defender for Cloud** - Enabled on your subscription (for security assessments)
3. **Azure credentials** - `az login` or service principal configured
4. **Reader access** - To the subscription containing Arc machines

### Verify Arc Machines Are Connected

```bash
# List Arc-enabled servers in your subscription
az connectedmachine list --query "[].{name:name, status:status}" -o table
```

### Enable Defender for Cloud

For security assessments, enable Defender for Servers on Arc machines:

1. Azure Portal > Microsoft Defender for Cloud
2. Environment Settings > Your Subscription
3. Enable "Servers" plan
4. Arc machines will be auto-enrolled

---

## Setup

### 1. Configure Azure Credentials

```bash
# Interactive login
az login

# Set subscription containing Arc machines
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Verify access
az account show
```

### 2. Service Principal (Optional)

For automation/CI/CD:

```bash
# Create service principal with Reader access
az ad sp create-for-rbac \
  --name "auditkit-arc-scanner" \
  --role Reader \
  --scopes /subscriptions/YOUR_SUBSCRIPTION_ID

# Set environment variables
export AZURE_CLIENT_ID="app-id-from-output"
export AZURE_CLIENT_SECRET="password-from-output"
export AZURE_TENANT_ID="tenant-from-output"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

---

## Usage

### CLI

```bash
# Scan Arc machines against PCI-DSS
auditkit-pro scan -provider arc -framework pci

# Scan against SOC2
auditkit-pro scan -provider arc -framework soc2

# Scan against CMMC Level 2
auditkit-pro scan -provider arc -framework cmmc

# Generate PDF report
auditkit-pro scan -provider arc -framework pci -format pdf -output arc-compliance.pdf

# Verbose output
auditkit-pro scan -provider arc -framework soc2 -verbose
```

### Desktop GUI

1. Open AuditKit Pro Desktop (`http://localhost:1337`)
2. Click "Run Scan"
3. Select "Azure Arc (On-Prem)" as provider
4. Choose framework(s)
5. Click "Start Scan"

---

## What Gets Scanned

### 1. Arc Agent Health

Checks connectivity status of all Arc-enabled servers:

- **PASS** - Agent connected and reporting
- **FAIL** - Agent disconnected or expired

**Frameworks:** PCI 10.1, SOC2 CC7.1, ISO 27001 A.12.4, CMMC AU.L2-3.3.1

### 2. Defender for Cloud Assessments

Pulls security recommendations from Microsoft Defender:

| Assessment Type | Framework Mapping |
|-----------------|-------------------|
| System updates missing | PCI 6.2, SOC2 CC7.1, CMMC SI.L2-3.14.1 |
| Endpoint protection issues | PCI 5.1, SOC2 CC6.8, CMMC SI.L2-3.14.2 |
| Disk encryption | PCI 3.4, SOC2 CC6.1, CMMC SC.L2-3.13.11 |
| Vulnerability findings | PCI 11.2, SOC2 CC7.1, CMMC RA.L2-3.11.2 |
| Network/firewall issues | PCI 1.3, SOC2 CC6.6, CMMC SC.L2-3.13.1 |
| Access control issues | PCI 8.2, SOC2 CC6.1, CMMC AC.L2-3.1.1 |
| Logging/monitoring gaps | PCI 10.2, SOC2 CC7.2, CMMC AU.L2-3.3.1 |

### 3. Guest Configuration Compliance

Reports on Azure Policy Guest Configuration assignments:

- Windows security baselines
- Linux security baselines
- Custom configuration policies

**Frameworks:** PCI 2.2, SOC2 CC6.1, ISO 27001 A.12.6

---

## Required Permissions

The scanning identity needs:

| Permission | Scope | Purpose |
|------------|-------|---------|
| Reader | Subscription | List Arc machines, read assessments |
| Security Reader | Subscription | Read Defender for Cloud data |

```bash
# Assign Reader role
az role assignment create \
  --assignee YOUR_SP_OR_USER \
  --role Reader \
  --scope /subscriptions/YOUR_SUBSCRIPTION_ID

# Assign Security Reader role
az role assignment create \
  --assignee YOUR_SP_OR_USER \
  --role "Security Reader" \
  --scope /subscriptions/YOUR_SUBSCRIPTION_ID
```

---

## Limitations

- **Requires Defender for Cloud** - Security assessments only available if Defender is enabled
- **Agent must be connected** - Disconnected machines show limited data
- **Azure-only** - This scans Arc machines in Azure; standalone on-prem scanning not supported
- **No agentless scanning** - Machines must have Arc agent installed

---

## Troubleshooting

### "No Arc machines found"

```bash
# Verify Arc machines exist
az connectedmachine list -o table

# Check subscription
echo $AZURE_SUBSCRIPTION_ID
az account show --query id
```

### "Failed to get assessments"

- Ensure Defender for Cloud is enabled
- Verify Security Reader role is assigned
- Some machines may not have assessments if recently onboarded

### "Authentication failed"

```bash
# Re-authenticate
az login

# Or check service principal
az ad sp show --id $AZURE_CLIENT_ID
```

---

## Related

- [Azure Provider Setup](./azure.md)
- [CMMC Framework](../frameworks/cmmc.md)
- [SOC2 Framework](../frameworks/soc2.md)

---

**[Upgrade to Pro](https://auditkit.io/pro/)** to enable Azure Arc on-premises scanning.
