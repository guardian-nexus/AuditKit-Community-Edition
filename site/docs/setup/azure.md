# Azure Authentication Setup

How to configure Azure credentials for AuditKit scanning.

---

## Quick Start

```bash
# Option 1: Azure CLI (easiest)
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Test it works
az account show

# Run scan
./auditkit scan -provider azure -framework soc2
```

---

## Authentication Methods

AuditKit supports three authentication methods for Azure:

### Option 1: Azure CLI (Recommended)

**Best for:** Local scanning, development

```bash
# Install Azure CLI
# macOS: brew install azure-cli
# Linux: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
# Windows: Download from docs.microsoft.com/cli/azure

# Login
az login

# List subscriptions
az account list --output table

# Set subscription
export AZURE_SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789012"

# Or set default subscription
az account set --subscription "12345678-1234-1234-1234-123456789012"
```

### Option 2: Service Principal (Environment Variables)

**Best for:** CI/CD pipelines, automation

```bash
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Run scan
./auditkit scan -provider azure -framework soc2
```

**How to create service principal:** See [Creating a Service Principal](#creating-a-service-principal-for-auditkit) below

### Option 3: Managed Identity (Azure VMs)

**Best for:** Running AuditKit on Azure infrastructure

No configuration needed - automatically detected if running on:
- Azure Virtual Machine with managed identity
- Azure Container Instance with managed identity
- Azure Functions with managed identity

```bash
# Set subscription ID (required even with managed identity)
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Run scan - identity auto-detected
./auditkit scan -provider azure -framework soc2
```

---

## Required Permissions

AuditKit needs **Reader** role to scan your Azure subscription.

### Reader Role (Recommended)

**Role:** `Reader`  
**Scope:** Subscription level

This provides read-only access to all resources in the subscription.

### Custom Role (Least Privilege)

If you need tighter control:

```json
{
  "Name": "AuditKit Scanner",
  "Description": "Read-only access for AuditKit compliance scanning",
  "Actions": [
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Sql/servers/read",
    "Microsoft.Sql/servers/databases/read",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Security/pricings/read",
    "Microsoft.Insights/activityLogs/read"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/YOUR-SUBSCRIPTION-ID"
  ]
}
```

---

## Creating a Service Principal for AuditKit

### Step 1: Create Service Principal

```bash
# Create service principal with Reader role
az ad sp create-for-rbac \
  --name "auditkit-scanner" \
  --role "Reader" \
  --scopes "/subscriptions/YOUR-SUBSCRIPTION-ID"
```

**Output:**
```json
{
  "appId": "12345678-1234-1234-1234-123456789012",
  "displayName": "auditkit-scanner",
  "password": "your-client-secret",
  "tenant": "87654321-4321-4321-4321-210987654321"
}
```

**Save these values:**
- `appId` = AZURE_CLIENT_ID
- `password` = AZURE_CLIENT_SECRET
- `tenant` = AZURE_TENANT_ID

### Step 2: Configure Environment Variables

```bash
export AZURE_CLIENT_ID="12345678-1234-1234-1234-123456789012"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="87654321-4321-4321-4321-210987654321"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

### Step 3: Test Authentication

```bash
az login --service-principal \
  -u $AZURE_CLIENT_ID \
  -p $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID

az account show
```

### Step 4: Run Scan

```bash
./auditkit scan -provider azure -framework soc2
```

---

## Multi-Subscription Scanning

**Free version:** Scan one subscription at a time

**Pro version:** Scan entire Management Group automatically

### Community Edition - Switching Subscriptions

```bash
# Scan first subscription
export AZURE_SUBSCRIPTION_ID="sub-1-id"
./auditkit scan -provider azure -framework soc2 -output sub1-results.json

# Scan second subscription
export AZURE_SUBSCRIPTION_ID="sub-2-id"
./auditkit scan -provider azure -framework soc2 -output sub2-results.json
```

### Pro Version - Management Group Scanning

```bash
# Scan entire Management Group (Pro only)
./auditkit-pro scan -provider azure -framework soc2 --scan-all

# Limit concurrency
./auditkit-pro scan -provider azure --scan-all --max-concurrent 3

# Generate consolidated report
./auditkit-pro scan -provider azure --scan-all -format pdf -output mgmt-group-report.pdf
```

**[Upgrade to Pro →](https://auditkit.io/pro/)**

---

## Troubleshooting

### "Error: Azure credentials not configured"

**Cause:** Not logged in

**Solution:**
```bash
az login
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

### "Error: Subscription not found"

**Cause:** Subscription ID not set or incorrect

**Solution:**
```bash
# List all subscriptions
az account list --output table

# Set correct subscription
export AZURE_SUBSCRIPTION_ID="correct-subscription-id"
```

### "Error: Access Denied" or "Authorization Failed"

**Cause:** Service principal lacks Reader role

**Solution:**
```bash
# Assign Reader role
az role assignment create \
  --assignee $AZURE_CLIENT_ID \
  --role "Reader" \
  --scope "/subscriptions/YOUR-SUBSCRIPTION-ID"
```

### "Error: Invalid client secret"

**Cause:** Service principal secret expired or incorrect

**Solution:**
```bash
# Reset credential
az ad sp credential reset --id $AZURE_CLIENT_ID

# Use new password as AZURE_CLIENT_SECRET
```

### "Error: Tenant not found"

**Cause:** Wrong tenant ID

**Solution:**
```bash
# List tenants
az account list --output table

# Use correct tenant ID
export AZURE_TENANT_ID="correct-tenant-id"
```

---

## Security Best Practices

### 1. Use Dedicated Service Principal

Don't use your personal credentials.

```bash
az ad sp create-for-rbac --name "auditkit-scanner" --role "Reader"
```

### 2. Rotate Client Secrets Regularly

```bash
# Every 90 days
az ad sp credential reset --id $AZURE_CLIENT_ID
```

### 3. Enable Activity Log Monitoring

Monitor what AuditKit accesses:

```bash
# View activity logs
az monitor activity-log list --caller auditkit-scanner@YOUR-TENANT
```

### 4. Scope Permissions Appropriately

Only grant Reader access at the subscription level:

```bash
az role assignment create \
  --assignee $AZURE_CLIENT_ID \
  --role "Reader" \
  --scope "/subscriptions/YOUR-SUBSCRIPTION-ID"
```

---

## Finding Your IDs

### Find Subscription ID

```bash
# List all subscriptions
az account list --query "[].{Name:name, ID:id}" --output table
```

### Find Tenant ID

```bash
# Show current account details
az account show --query tenantId --output tsv
```

### Find Service Principal ID

```bash
# List service principals
az ad sp list --display-name "auditkit-scanner" --query "[].appId" --output tsv
```

---

## Next Steps

- **[Run your first scan →](../getting-started.md)**
- **[CLI Reference →](../cli-reference.md)**
- **[Azure Service Coverage →](../providers/azure.md)**
- **[Framework Guide →](../frameworks/)**
