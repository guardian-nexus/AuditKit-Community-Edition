package checks

import (
	"context"
	"fmt"
)

// AzureCISManualChecks handles Azure Monitor alert requirements that cannot be fully automated
type AzureCISManualChecks struct {
	subscriptionID string
}

func NewAzureCISManualChecks(subscriptionID string) *AzureCISManualChecks {
	return &AzureCISManualChecks{
		subscriptionID: subscriptionID,
	}
}

func (c *AzureCISManualChecks) Name() string {
	return "CIS Azure Manual & Informational Checks"
}

func (c *AzureCISManualChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Section 1: Identity - Manual/Graph API Required
	results = append(results, c.checkAppRegistrationOwnership())
	results = append(results, c.checkGuestInviteSettings())
	results = append(results, c.checkSecurityDefaults())

	// Section 5: Logging and Monitoring - Azure Monitor Alert Configuration
	// These require manual verification as Azure Monitor alert rules are complex
	results = append(results, c.checkMonitorAlertAuthChanges())
	results = append(results, c.checkMonitorAlertPolicyChanges())
	results = append(results, c.checkMonitorAlertNSGChanges())
	results = append(results, c.checkMonitorAlertSecurityGroupChanges())
	results = append(results, c.checkMonitorAlertSecuritySolutions())
	results = append(results, c.checkMonitorAlertSQLFirewall())
	results = append(results, c.checkMonitorAlertKeyVaultDeletion())
	results = append(results, c.checkMonitorAlertStorageAccountDeletion())

	// Section 6: Network Security - Additional Manual Checks
	results = append(results, c.checkRDPRestricted())
	results = append(results, c.checkSSHRestricted())
	results = append(results, c.checkSQLPortRestricted())
	results = append(results, c.checkPostgreSQLPortRestricted())
	results = append(results, c.checkMySQLPortRestricted())

	// Section 8: Key Vault - Manual/SDK Limited
	results = append(results, c.checkKeyVaultRecoveryLevel())
	results = append(results, c.checkKeyVaultKeyExpiration())
	results = append(results, c.checkKeyVaultSecretExpiration())
	results = append(results, c.checkKeyVaultCertificateExpiration())

	return results, nil
}

func (c *AzureCISManualChecks) checkMonitorAlertAuthChanges() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.1",
		Name:        "[CIS Azure 5.2.1] Create Alert for Authorization Changes",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    fmt.Sprintf("MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for authorization changes in subscription %s", c.subscriptionID),
		Remediation: "Create Azure Monitor alert for authorization operations",
		RemediationDetail: `Create an alert rule for authorization changes:

1. Azure Portal → Monitor → Alerts → Alert Rules
2. Create Alert Rule:
   - Resource: Your subscription
   - Condition: Activity Log - Administrative
   - Operation Name: Microsoft.Authorization/roleAssignments/write OR delete
   - Alert rule name: "Authorization-Changes-Alert"
3. Configure Action Group for notifications
4. Save alert rule

Azure CLI:
az monitor activity-log alert create \
  --name "Authorization-Changes-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Administrative and operationName=Microsoft.Authorization/roleAssignments/write \
  --action-group <action-group-id>`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Alert Rules → Screenshot showing alert rule for Microsoft.Authorization operations",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.1",
			"SOC2":      "CC7.2",
			"PCI-DSS":   "10.2.2",
		},
	}
}

func (c *AzureCISManualChecks) checkMonitorAlertPolicyChanges() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.2",
		Name:        "[CIS Azure 5.2.2] Create Alert for Policy Assignment Changes",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for policy assignment changes",
		Remediation: "Create Azure Monitor alert for policy operations",
		RemediationDetail: `Create an alert rule for policy changes:

Azure CLI:
az monitor activity-log alert create \
  --name "Policy-Changes-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Administrative and operationName=Microsoft.Authorization/policyAssignments/write \
  --action-group <action-group-id>

Operations to monitor:
- Microsoft.Authorization/policyAssignments/write
- Microsoft.Authorization/policyAssignments/delete
- Microsoft.Authorization/policyDefinitions/write
- Microsoft.Authorization/policyDefinitions/delete`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing alert rule for policy assignment operations",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.2",
			"SOC2":      "CC7.2",
			"PCI-DSS":   "10.2.2",
		},
	}
}

func (c *AzureCISManualChecks) checkMonitorAlertNSGChanges() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.3",
		Name:        "[CIS Azure 5.2.3] Create Alert for NSG Changes",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for Network Security Group changes",
		Remediation: "Create Azure Monitor alert for NSG operations",
		RemediationDetail: `Create an alert rule for NSG changes:

Azure CLI:
az monitor activity-log alert create \
  --name "NSG-Changes-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/write \
  --action-group <action-group-id>

Also monitor:
- Microsoft.Network/networkSecurityGroups/delete
- Microsoft.Network/networkSecurityGroups/securityRules/write
- Microsoft.Network/networkSecurityGroups/securityRules/delete`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing alert rule for NSG write/delete operations",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.3",
			"SOC2":      "CC7.2",
			"PCI-DSS":   "10.2.7",
		},
	}
}

func (c *AzureCISManualChecks) checkMonitorAlertSecurityGroupChanges() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.4",
		Name:        "[CIS Azure 5.2.4] Create Alert for Security Group Changes",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for security group modifications",
		Remediation: "Create Azure Monitor alert for security group operations",
		RemediationDetail: `Create an alert rule for security group changes:

Azure CLI:
az monitor activity-log alert create \
  --name "Security-Group-Changes-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Security and operationName=Microsoft.Security/securityGroups/write \
  --action-group <action-group-id>`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing alert rule for security group operations",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.4",
			"SOC2":      "CC7.2",
			"PCI-DSS":   "10.2.1",
		},
	}
}

func (c *AzureCISManualChecks) checkMonitorAlertSecuritySolutions() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.5",
		Name:        "[CIS Azure 5.2.5] Create Alert for Security Solutions Changes",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for security solution changes",
		Remediation: "Create Azure Monitor alert for security solution operations",
		RemediationDetail: `Create an alert rule for security solution changes:

Azure CLI:
az monitor activity-log alert create \
  --name "Security-Solutions-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Security and operationName=Microsoft.Security/securitySolutions/write \
  --action-group <action-group-id>

Monitor operations:
- Microsoft.Security/securitySolutions/write
- Microsoft.Security/securitySolutions/delete`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing alert rule for security solutions",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.5",
			"SOC2":      "CC7.2",
		},
	}
}

func (c *AzureCISManualChecks) checkMonitorAlertSQLFirewall() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.6",
		Name:        "[CIS Azure 5.2.6] Create Alert for SQL Firewall Changes",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for SQL firewall rule changes",
		Remediation: "Create Azure Monitor alert for SQL firewall operations",
		RemediationDetail: `Create an alert rule for SQL firewall changes:

Azure CLI:
az monitor activity-log alert create \
  --name "SQL-Firewall-Changes-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Administrative and operationName=Microsoft.Sql/servers/firewallRules/write \
  --action-group <action-group-id>

Monitor operations:
- Microsoft.Sql/servers/firewallRules/write
- Microsoft.Sql/servers/firewallRules/delete`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing alert rule for SQL firewall operations",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.6",
			"SOC2":      "CC7.2",
			"PCI-DSS":   "10.2.7",
		},
	}
}

func (c *AzureCISManualChecks) checkMonitorAlertKeyVaultDeletion() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.7",
		Name:        "[CIS Azure 5.2.7] Create Alert for Key Vault Deletion",
		Status:      "INFO",
		Severity:    "CRITICAL",
		Priority:    PriorityCritical,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for Key Vault deletion operations",
		Remediation: "Create Azure Monitor alert for Key Vault deletions",
		RemediationDetail: `Create an alert rule for Key Vault deletion:

Azure CLI:
az monitor activity-log alert create \
  --name "KeyVault-Deletion-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Administrative and operationName=Microsoft.KeyVault/vaults/delete \
  --action-group <action-group-id>`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing alert rule for Key Vault deletion",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.7",
			"SOC2":      "CC6.3",
			"PCI-DSS":   "10.2.7",
		},
	}
}

func (c *AzureCISManualChecks) checkMonitorAlertStorageAccountDeletion() CheckResult {
	return CheckResult{
		Control:     "CIS-5.2.8",
		Name:        "[CIS Azure 5.2.8] Create Alert for Storage Account Deletion",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Azure Monitor alert exists for Storage Account deletion",
		Remediation: "Create Azure Monitor alert for Storage Account deletions",
		RemediationDetail: `Create an alert rule for Storage Account deletion:

Azure CLI:
az monitor activity-log alert create \
  --name "Storage-Deletion-Alert" \
  --resource-group "monitoring-rg" \
  --scope /subscriptions/<subscription-id> \
  --condition category=Administrative and operationName=Microsoft.Storage/storageAccounts/delete \
  --action-group <action-group-id>`,
		ScreenshotGuide: "Azure Portal → Monitor → Alerts → Screenshot showing alert rule for Storage Account deletion",
		ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2/subscriptionId/%s", c.subscriptionID),
		Frameworks: map[string]string{
			"CIS-Azure": "5.2.8",
			"SOC2":      "CC9.1",
			"PCI-DSS":   "10.2.7",
		},
	}
}

// ===== SECTION 1: IDENTITY & ACCESS MANAGEMENT =====

func (c *AzureCISManualChecks) checkAppRegistrationOwnership() CheckResult {
	return CheckResult{
		Control:     "CIS-1.5",
		Name:        "[CIS Azure 1.5] App Registration Owner Requirements",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK REQUIRED: Verify all App Registrations have at least one owner assigned",
		Remediation: "Ensure every App Registration has assigned owners",
		RemediationDetail: `CIS Azure 1.5: Ensure that 'Owners' are defined for each registered application

App Registrations without owners cannot be managed if the creator leaves.

Verification:
1. Azure Portal → Azure AD → App registrations
2. Review each application
3. Click on each → Owners
4. Ensure at least one owner is assigned

Azure CLI:
# List app registrations
az ad app list --query "[].{DisplayName:displayName, AppId:appId}" -o table

# For each app, check owners via Microsoft Graph API or Portal`,
		ScreenshotGuide: "Azure AD → App registrations → For each app → Owners → Screenshot showing owner assignments",
		ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
		Frameworks: map[string]string{
			"CIS-Azure": "1.5",
			"SOC2":      "CC6.1",
		},
	}
}

func (c *AzureCISManualChecks) checkGuestInviteSettings() CheckResult {
	return CheckResult{
		Control:     "CIS-1.11",
		Name:        "[CIS Azure 1.11] Guest Invite Restrictions",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK REQUIRED: Verify guest invite settings are restricted per CIS requirements",
		Remediation: "Configure guest user access and invitation settings",
		RemediationDetail: `CIS Azure 1.11: Ensure that 'Guest invite restrictions' is set to 'Only users assigned to specific admin roles can invite guest users'

Verification:
1. Azure Portal → Azure AD → External identities → External collaboration settings
2. Verify "Guest invite settings" = "Only users assigned to specific admin roles can invite guest users"

This prevents regular users from inviting external guests.`,
		ScreenshotGuide: "Azure AD → External identities → External collaboration settings → Screenshot showing restricted invite settings",
		ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/Settings",
		Frameworks: map[string]string{
			"CIS-Azure": "1.11",
			"SOC2":      "CC6.1",
			"PCI-DSS":   "7.1",
		},
	}
}

func (c *AzureCISManualChecks) checkSecurityDefaults() CheckResult {
	return CheckResult{
		Control:     "CIS-1.12",
		Name:        "[CIS Azure 1.12] Security Defaults or Conditional Access",
		Status:      "INFO",
		Severity:    "CRITICAL",
		Priority:    PriorityCritical,
		Evidence:    "MANUAL CHECK REQUIRED: Verify Security Defaults OR Conditional Access policies are enabled",
		Remediation: "Enable Security Defaults or implement Conditional Access policies",
		RemediationDetail: `CIS Azure 1.12: Ensure Either Security Defaults is Enabled OR Conditional Access Policies are Configured

You must have ONE of these enabled:
1. Security Defaults (simple, automatic protection)
   OR
2. Conditional Access Policies (advanced, granular control)

Verification:
1. Azure Portal → Azure AD → Properties → Manage Security defaults
   - If enabled, screenshot and document
2. If disabled, verify Conditional Access policies exist:
   - Azure AD → Security → Conditional Access → Policies
   - Ensure policies covering MFA, trusted locations, etc.

Azure CLI:
az rest --method GET --url https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy`,
		ScreenshotGuide: "Azure AD → Properties → Security defaults = Enabled, OR Azure AD → Conditional Access → Active policies screenshot",
		ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties",
		Frameworks: map[string]string{
			"CIS-Azure": "1.12",
			"SOC2":      "CC6.6",
			"PCI-DSS":   "8.3.1",
			"HIPAA":     "164.312(a)(2)(i)",
		},
	}
}

// ===== SECTION 6: NETWORK SECURITY =====

func (c *AzureCISManualChecks) checkRDPRestricted() CheckResult {
	return CheckResult{
		Control:     "CIS-6.2",
		Name:        "[CIS Azure 6.2] RDP Access from Internet Restricted",
		Status:      "INFO",
		Severity:    "CRITICAL",
		Priority:    PriorityCritical,
		Evidence:    "MANUAL CHECK REQUIRED: Verify NO Network Security Groups allow RDP (port 3389) from Internet (0.0.0.0/0)",
		Remediation: "Remove any NSG rules allowing RDP from 0.0.0.0/0",
		RemediationDetail: `CIS Azure 6.2: Ensure that RDP access from the Internet is evaluated and restricted

Check all NSGs for rules allowing:
- Source: Any/Internet/0.0.0.0/0
- Destination Port: 3389
- Action: Allow

Azure CLI to find offending rules:
az network nsg list --query "[].{Name:name, ResourceGroup:resourceGroup}" -o table
az network nsg rule list --nsg-name <nsg-name> --resource-group <rg> --query "[?direction=='Inbound' && access=='Allow' && destinationPortRange contains '3389']"

Remove dangerous rules:
az network nsg rule delete --name <rule-name> --nsg-name <nsg-name> --resource-group <rg>`,
		ScreenshotGuide: "Network security groups → Inbound security rules → Screenshot showing NO rules with 3389 from Internet",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
		Frameworks: map[string]string{
			"CIS-Azure": "6.2",
			"SOC2":      "CC6.1",
			"PCI-DSS":   "1.2.1",
			"HIPAA":     "164.312(a)(1)",
		},
	}
}

func (c *AzureCISManualChecks) checkSSHRestricted() CheckResult {
	return CheckResult{
		Control:     "CIS-6.3",
		Name:        "[CIS Azure 6.3] SSH Access from Internet Restricted",
		Status:      "INFO",
		Severity:    "CRITICAL",
		Priority:    PriorityCritical,
		Evidence:    "MANUAL CHECK REQUIRED: Verify NO Network Security Groups allow SSH (port 22) from Internet",
		Remediation: "Remove any NSG rules allowing SSH from 0.0.0.0/0",
		RemediationDetail: `CIS Azure 6.3: Ensure that SSH access from the Internet is evaluated and restricted

Check all NSGs for rules allowing:
- Source: Any/Internet/0.0.0.0/0
- Destination Port: 22
- Action: Allow

Azure CLI:
az network nsg rule list --nsg-name <nsg-name> --resource-group <rg> --query "[?direction=='Inbound' && access=='Allow' && destinationPortRange contains '22']"`,
		ScreenshotGuide: "Network security groups → Inbound security rules → Screenshot showing NO rules with port 22 from Internet",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
		Frameworks: map[string]string{
			"CIS-Azure": "6.3",
			"SOC2":      "CC6.1",
			"PCI-DSS":   "1.2.1",
		},
	}
}

func (c *AzureCISManualChecks) checkSQLPortRestricted() CheckResult {
	return CheckResult{
		Control:     "CIS-6.4",
		Name:        "[CIS Azure 6.4] SQL Server Port Access Restricted",
		Status:      "INFO",
		Severity:    "CRITICAL",
		Priority:    PriorityCritical,
		Evidence:    "MANUAL CHECK REQUIRED: Verify NO NSGs allow SQL Server port (1433) from Internet",
		Remediation: "Remove any NSG rules allowing port 1433 from 0.0.0.0/0",
		RemediationDetail: `CIS Azure 6.4: Ensure that SQL Server port (1433) access from the Internet is restricted

Check all NSGs for rules allowing:
- Source: Any/Internet/0.0.0.0/0
- Destination Port: 1433
- Action: Allow`,
		ScreenshotGuide: "Network security groups → Inbound rules → NO rules allowing 1433 from Internet",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
		Frameworks: map[string]string{
			"CIS-Azure": "6.4",
			"SOC2":      "CC6.1",
			"PCI-DSS":   "1.2.1, 2.2.2",
		},
	}
}

func (c *AzureCISManualChecks) checkPostgreSQLPortRestricted() CheckResult {
	return CheckResult{
		Control:           "CIS-6.5",
		Name:              "[CIS Azure 6.5] PostgreSQL Port Access Restricted",
		Status:            "INFO",
		Severity:          "HIGH",
		Priority:          PriorityHigh,
		Evidence:          "MANUAL CHECK REQUIRED: Verify NO NSGs allow PostgreSQL port (5432) from Internet",
		Remediation:       "Remove any NSG rules allowing port 5432 from 0.0.0.0/0",
		RemediationDetail: `CIS Azure 6.5: Ensure that PostgreSQL port (5432) access from the Internet is restricted`,
		ScreenshotGuide:   "Network security groups → Inbound rules → NO rules allowing 5432 from Internet",
		ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
		Frameworks: map[string]string{
			"CIS-Azure": "6.5",
			"SOC2":      "CC6.1",
			"PCI-DSS":   "1.2.1",
		},
	}
}

func (c *AzureCISManualChecks) checkMySQLPortRestricted() CheckResult {
	return CheckResult{
		Control:           "CIS-6.6",
		Name:              "[CIS Azure 6.6] MySQL Port Access Restricted",
		Status:            "INFO",
		Severity:          "HIGH",
		Priority:          PriorityHigh,
		Evidence:          "MANUAL CHECK REQUIRED: Verify NO NSGs allow MySQL port (3306) from Internet",
		Remediation:       "Remove any NSG rules allowing port 3306 from 0.0.0.0/0",
		RemediationDetail: `CIS Azure 6.6: Ensure that MySQL port (3306) access from the Internet is restricted`,
		ScreenshotGuide:   "Network security groups → Inbound rules → NO rules allowing 3306 from Internet",
		ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
		Frameworks: map[string]string{
			"CIS-Azure": "6.6",
			"SOC2":      "CC6.1",
			"PCI-DSS":   "1.2.1",
		},
	}
}

// ===== SECTION 8: KEY VAULT =====

func (c *AzureCISManualChecks) checkKeyVaultRecoveryLevel() CheckResult {
	return CheckResult{
		Control:     "CIS-8.1",
		Name:        "[CIS Azure 8.1] Key Vault Recoverable",
		Status:      "INFO",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Evidence:    "MANUAL CHECK REQUIRED: Verify all Key Vaults have soft-delete and purge protection enabled",
		Remediation: "Enable soft-delete and purge protection for all Key Vaults",
		RemediationDetail: `CIS Azure 8.1: Ensure that the key vault is recoverable

All Key Vaults must have:
1. Soft Delete enabled (90+ day retention)
2. Purge Protection enabled

Azure CLI:
az keyvault list --query "[].{Name:name, ResourceGroup:resourceGroup}" -o table
az keyvault show --name <vault-name> --query "{SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection}"

Enable for vault:
az keyvault update --name <vault-name> --enable-soft-delete true --retention-days 90
az keyvault update --name <vault-name> --enable-purge-protection true`,
		ScreenshotGuide: "Key Vault → Properties → Screenshot showing Soft-delete (90 days) and Purge protection both enabled",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
		Frameworks: map[string]string{
			"CIS-Azure": "8.1",
			"SOC2":      "CC9.1",
			"PCI-DSS":   "3.5.2",
		},
	}
}

func (c *AzureCISManualChecks) checkKeyVaultKeyExpiration() CheckResult {
	return CheckResult{
		Control:     "CIS-8.2",
		Name:        "[CIS Azure 8.2] Key Vault Keys Have Expiration Dates",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK REQUIRED: Verify all cryptographic keys have expiration dates set",
		Remediation: "Set expiration dates for all keys in Key Vaults",
		RemediationDetail: `CIS Azure 8.2: Ensure that key vault keys have an expiration date set

Azure CLI:
az keyvault key list --vault-name <vault-name> --query "[?attributes.expires == null].{Name:name, Enabled:attributes.enabled}" -o table

Set expiration:
az keyvault key set-attributes --vault-name <vault-name> --name <key-name> --expires "2025-12-31T23:59:59Z"`,
		ScreenshotGuide: "Key Vault → Keys → Each key → Properties → Screenshot showing expiration date configured",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
		Frameworks: map[string]string{
			"CIS-Azure": "8.2",
			"SOC2":      "CC6.8",
			"PCI-DSS":   "3.6.4",
		},
	}
}

func (c *AzureCISManualChecks) checkKeyVaultSecretExpiration() CheckResult {
	return CheckResult{
		Control:     "CIS-8.4",
		Name:        "[CIS Azure 8.4] Key Vault Secrets Have Expiration Dates",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK REQUIRED: Verify all secrets have expiration dates set",
		Remediation: "Set expiration dates for all secrets in Key Vaults",
		RemediationDetail: `CIS Azure 8.4: Ensure that secrets in Azure Key Vault have an expiration date set

Azure CLI:
az keyvault secret list --vault-name <vault-name> --query "[?attributes.expires == null].{Name:name, Enabled:attributes.enabled}" -o table

Set expiration:
az keyvault secret set-attributes --vault-name <vault-name> --name <secret-name> --expires "2025-12-31T23:59:59Z"`,
		ScreenshotGuide: "Key Vault → Secrets → Each secret → Properties → Screenshot showing expiration date",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
		Frameworks: map[string]string{
			"CIS-Azure": "8.4",
			"SOC2":      "CC6.7",
			"PCI-DSS":   "8.2.4",
		},
	}
}

func (c *AzureCISManualChecks) checkKeyVaultCertificateExpiration() CheckResult {
	return CheckResult{
		Control:     "CIS-8.6",
		Name:        "[CIS Azure 8.6] Key Vault Certificates Auto-Renew",
		Status:      "INFO",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Evidence:    "MANUAL CHECK REQUIRED: Verify certificates have auto-renewal configured",
		Remediation: "Configure auto-renewal for certificates in Key Vaults",
		RemediationDetail: `CIS Azure 8.6: Ensure that certificate auto-renewal is enabled for certificates stored in Azure Key Vault

Azure CLI:
az keyvault certificate list --vault-name <vault-name> --query "[].{Name:name, AutoRenew:policy.lifetimeActions}" -o table

Verify each certificate has:
- Lifetime action configured
- Auto-renewal enabled before expiration`,
		ScreenshotGuide: "Key Vault → Certificates → Each cert → Policy → Screenshot showing auto-renewal enabled",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
		Frameworks: map[string]string{
			"CIS-Azure": "8.6",
			"SOC2":      "CC6.7",
		},
	}
}
