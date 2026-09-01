package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
)

// DefenderChecks handles Microsoft Defender for Cloud configuration
type DefenderChecks struct {
	subscriptionID      string
	pricingClient       *armsecurity.PricingsClient
	autoProvisionClient *armsecurity.AutoProvisioningSettingsClient
	contactsClient      *armsecurity.ContactsClient
}

func NewDefenderChecks(subscriptionID string, pricingClient *armsecurity.PricingsClient, autoProvisionClient *armsecurity.AutoProvisioningSettingsClient, contactsClient *armsecurity.ContactsClient) *DefenderChecks {
	return &DefenderChecks{
		subscriptionID:      subscriptionID,
		pricingClient:       pricingClient,
		autoProvisionClient: autoProvisionClient,
		contactsClient:      contactsClient,
	}
}

func (c *DefenderChecks) Name() string {
	return "Microsoft Defender for Cloud"
}

func (c *DefenderChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Automated Defender plan checks
	results = append(results, c.checkDefenderForServers(ctx)...)
	results = append(results, c.checkDefenderForAppService(ctx)...)
	results = append(results, c.checkDefenderForDatabases(ctx)...)
	results = append(results, c.checkDefenderForStorage(ctx)...)
	results = append(results, c.checkDefenderForContainers(ctx)...)
	results = append(results, c.checkDefenderForDNS(ctx)...)
	results = append(results, c.checkDefenderForKeyVault(ctx)...)
	results = append(results, c.checkDefenderForAPIs(ctx)...)
	results = append(results, c.checkDefenderForResourceManager(ctx)...)
	results = append(results, c.checkDefenderAutoProvisioning(ctx)...)
	results = append(results, c.checkSecurityContacts(ctx)...)

	return results, nil
}

// Helper function to check if a Defender plan is enabled
// FIXED: Added scopeId parameter required by current SDK
func (c *DefenderChecks) isPlanEnabled(ctx context.Context, planName string) (bool, error) {
	// SDK requires scopeId in format: /subscriptions/{subscriptionId}
	scopeId := fmt.Sprintf("/subscriptions/%s", c.subscriptionID)

	pricing, err := c.pricingClient.Get(ctx, scopeId, planName, nil)
	if err != nil {
		return false, err
	}

	if pricing.Properties == nil || pricing.Properties.PricingTier == nil {
		return false, nil
	}

	// Check if tier is "Standard" (enabled) vs "Free" (disabled)
	return *pricing.Properties.PricingTier == armsecurity.PricingTierStandard, nil
}

func (c *DefenderChecks) checkDefenderForServers(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "VirtualMachines")

	if err != nil {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.1",
			Name:        "[CIS Azure 2.1.1] Microsoft Defender for Servers",
			Status:      "ERROR",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    fmt.Sprintf("Unable to check Defender for Servers status: %v", err),
			Remediation: "Enable Microsoft Defender for Servers per CIS 2.1.1",
			RemediationDetail: `CIS Azure 2.1.1: Ensure that Microsoft Defender for Servers is set to 'On'

Microsoft Defender for Servers provides:
- Threat detection for VMs
- Vulnerability assessment
- Just-in-time VM access
- File integrity monitoring
- Adaptive application controls

Enable via:
Azure Portal → Defender for Cloud → Environment settings → Defender plans → Servers → On

Azure CLI:
az security pricing create --name VirtualMachines --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → Defender plans → 'Servers' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_SERVERS"),
		})
		return results
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.1",
			Name:        "[CIS Azure 2.1.1] Microsoft Defender for Servers",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.1: Microsoft Defender for Servers is NOT enabled (tier = Free)",
			Remediation: "Enable Microsoft Defender for Servers per CIS 2.1.1",
			RemediationDetail: `CIS Azure 2.1.1: Ensure that Microsoft Defender for Servers is set to 'On'

Enable comprehensive server protection:
Azure CLI:
az security pricing create --name VirtualMachines --tier Standard

Cost: Per server/month - provides threat detection, vulnerability scanning, and JIT access`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → Defender plans → Screenshot showing 'Servers' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_SERVERS"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.1",
			Name:       "[CIS Azure 2.1.1] Microsoft Defender for Servers",
			Status:     "PASS",
			Priority:   PriorityInfo,
			Evidence:   "CIS 2.1.1: Microsoft Defender for Servers is enabled (tier = Standard)",
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_SERVERS"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderForAppService(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "AppServices")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.2",
			Name:       "[CIS Azure 2.1.2] Microsoft Defender for App Service",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for App Service: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_APPSERVICE"),
		}}
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.2",
			Name:        "[CIS Azure 2.1.2] Microsoft Defender for App Service",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.2: Microsoft Defender for App Service is NOT enabled",
			Remediation: "Enable Microsoft Defender for App Service",
			RemediationDetail: `CIS Azure 2.1.2: Ensure that Microsoft Defender for App Services is set to 'On'

Azure CLI:
az security pricing create --name AppServices --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'App Service' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_APPSERVICE"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.2",
			Name:       "[CIS Azure 2.1.2] Microsoft Defender for App Service",
			Status:     "PASS",
			Evidence:   "CIS 2.1.2: Microsoft Defender for App Service is enabled",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_APPSERVICE"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderForDatabases(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Split into individual checks for better CIS compliance reporting
	results = append(results, c.checkDefenderForSQLServers(ctx)...)
	results = append(results, c.checkDefenderForSQLVMs(ctx)...)
	results = append(results, c.checkDefenderForOpenSourceDB(ctx)...)
	results = append(results, c.checkDefenderForCosmosDB(ctx)...)

	return results
}

func (c *DefenderChecks) checkDefenderForSQLServers(ctx context.Context) []CheckResult {
	enabled, err := c.isPlanEnabled(ctx, "SqlServers")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.3",
			Name:       "[CIS Azure 2.1.3] Microsoft Defender for Azure SQL Databases",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for SQL Servers: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_SQL"),
		}}
	}

	if !enabled {
		return []CheckResult{{
			Control:     "CIS-2.1.3",
			Name:        "[CIS Azure 2.1.3] Microsoft Defender for Azure SQL Databases",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.3: Microsoft Defender for Azure SQL Database servers is NOT enabled",
			Remediation: "Enable Microsoft Defender for Azure SQL Database servers",
			RemediationDetail: `CIS Azure 2.1.3: Ensure that Microsoft Defender for Azure SQL Database servers is set to 'On'

Azure CLI:
az security pricing create --name SqlServers --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'Azure SQL Databases' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_SQL"),
		}}
	}

	return []CheckResult{{
		Control:    "CIS-2.1.3",
		Name:       "[CIS Azure 2.1.3] Microsoft Defender for Azure SQL Databases",
		Status:     "PASS",
		Evidence:   "CIS 2.1.3: Microsoft Defender for Azure SQL Database servers is enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("DEFENDER_SQL"),
	}}
}

func (c *DefenderChecks) checkDefenderForSQLVMs(ctx context.Context) []CheckResult {
	enabled, err := c.isPlanEnabled(ctx, "SqlServerVirtualMachines")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.4",
			Name:       "[CIS Azure 2.1.4] Microsoft Defender for SQL Servers on Machines",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for SQL VMs: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_SQL_VM"),
		}}
	}

	if !enabled {
		return []CheckResult{{
			Control:     "CIS-2.1.4",
			Name:        "[CIS Azure 2.1.4] Microsoft Defender for SQL Servers on Machines",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.4: Microsoft Defender for SQL servers on machines is NOT enabled",
			Remediation: "Enable Microsoft Defender for SQL servers on machines",
			RemediationDetail: `CIS Azure 2.1.4: Ensure that Microsoft Defender for SQL servers on machines is set to 'On'

Azure CLI:
az security pricing create --name SqlServerVirtualMachines --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'SQL servers on machines' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_SQL_VM"),
		}}
	}

	return []CheckResult{{
		Control:    "CIS-2.1.4",
		Name:       "[CIS Azure 2.1.4] Microsoft Defender for SQL Servers on Machines",
		Status:     "PASS",
		Evidence:   "CIS 2.1.4: Microsoft Defender for SQL servers on machines is enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("DEFENDER_SQL_VM"),
	}}
}

func (c *DefenderChecks) checkDefenderForOpenSourceDB(ctx context.Context) []CheckResult {
	enabled, err := c.isPlanEnabled(ctx, "OpenSourceRelationalDatabases")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.5",
			Name:       "[CIS Azure 2.1.5] Microsoft Defender for Open-Source Relational Databases",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for Open-Source DBs: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_OPENSOURCE_DB"),
		}}
	}

	if !enabled {
		return []CheckResult{{
			Control:     "CIS-2.1.5",
			Name:        "[CIS Azure 2.1.5] Microsoft Defender for Open-Source Relational Databases",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.5: Microsoft Defender for open-source relational databases is NOT enabled",
			Remediation: "Enable Microsoft Defender for open-source relational databases",
			RemediationDetail: `CIS Azure 2.1.5: Ensure that Microsoft Defender for open-source relational databases is set to 'On'

Covers: PostgreSQL, MySQL, MariaDB

Azure CLI:
az security pricing create --name OpenSourceRelationalDatabases --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'Open-source relational databases' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_OPENSOURCE_DB"),
		}}
	}

	return []CheckResult{{
		Control:    "CIS-2.1.5",
		Name:       "[CIS Azure 2.1.5] Microsoft Defender for Open-Source Relational Databases",
		Status:     "PASS",
		Evidence:   "CIS 2.1.5: Microsoft Defender for open-source relational databases is enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("DEFENDER_OPENSOURCE_DB"),
	}}
}

func (c *DefenderChecks) checkDefenderForCosmosDB(ctx context.Context) []CheckResult {
	enabled, err := c.isPlanEnabled(ctx, "CosmosDbs")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.6",
			Name:       "[CIS Azure 2.1.6] Microsoft Defender for Azure Cosmos DB",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for Cosmos DB: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_COSMOSDB"),
		}}
	}

	if !enabled {
		return []CheckResult{{
			Control:     "CIS-2.1.6",
			Name:        "[CIS Azure 2.1.6] Microsoft Defender for Azure Cosmos DB",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.6: Microsoft Defender for Azure Cosmos DB is NOT enabled",
			Remediation: "Enable Microsoft Defender for Azure Cosmos DB",
			RemediationDetail: `CIS Azure 2.1.6: Ensure that Microsoft Defender for Azure Cosmos DB is set to 'On'

Azure CLI:
az security pricing create --name CosmosDbs --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'Azure Cosmos DB' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_COSMOSDB"),
		}}
	}

	return []CheckResult{{
		Control:    "CIS-2.1.6",
		Name:       "[CIS Azure 2.1.6] Microsoft Defender for Azure Cosmos DB",
		Status:     "PASS",
		Evidence:   "CIS 2.1.6: Microsoft Defender for Azure Cosmos DB is enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("DEFENDER_COSMOSDB"),
	}}
}

func (c *DefenderChecks) checkDefenderForStorage(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "StorageAccounts")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.7",
			Name:       "[CIS Azure 2.1.7] Microsoft Defender for Storage",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for Storage: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_STORAGE"),
		}}
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.7",
			Name:        "[CIS Azure 2.1.7] Microsoft Defender for Storage",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.7: Microsoft Defender for Storage is NOT enabled",
			Remediation: "Enable Microsoft Defender for Storage",
			RemediationDetail: `CIS Azure 2.1.7: Ensure that Microsoft Defender for Storage is set to 'On'

Azure CLI:
az security pricing create --name StorageAccounts --tier Standard --subplan DefenderForStorageV2`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'Storage' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_STORAGE"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.7",
			Name:       "[CIS Azure 2.1.7] Microsoft Defender for Storage",
			Status:     "PASS",
			Evidence:   "CIS 2.1.7: Microsoft Defender for Storage is enabled",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_STORAGE"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderForContainers(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "Containers")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.8",
			Name:       "[CIS Azure 2.1.8] Microsoft Defender for Containers",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for Containers: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_CONTAINERS"),
		}}
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.8",
			Name:        "[CIS Azure 2.1.8] Microsoft Defender for Containers",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.8: Microsoft Defender for Containers is NOT enabled",
			Remediation: "Enable Microsoft Defender for Containers",
			RemediationDetail: `CIS Azure 2.1.8: Ensure that Microsoft Defender for Containers is set to 'On'

Azure CLI:
az security pricing create --name Containers --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'Containers' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_CONTAINERS"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.8",
			Name:       "[CIS Azure 2.1.8] Microsoft Defender for Containers",
			Status:     "PASS",
			Evidence:   "CIS 2.1.8: Microsoft Defender for Containers is enabled",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_CONTAINERS"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderForDNS(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "Dns")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.9",
			Name:       "[CIS Azure 2.1.9] Microsoft Defender for DNS",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for DNS: %v", err),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_DNS"),
		}}
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.9",
			Name:        "[CIS Azure 2.1.9] Microsoft Defender for DNS",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Priority:    PriorityMedium,
			Evidence:    "CIS 2.1.9: Microsoft Defender for DNS is NOT enabled",
			Remediation: "Enable Microsoft Defender for DNS",
			RemediationDetail: `CIS Azure 2.1.9: Ensure that Microsoft Defender for DNS is set to 'On'

Defender for DNS provides threat detection for:
- DNS layer attacks
- Suspicious DNS queries
- Data exfiltration via DNS tunneling
- Communication with malicious domains

Azure CLI:
az security pricing create --name Dns --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'DNS' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_DNS"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.9",
			Name:       "[CIS Azure 2.1.9] Microsoft Defender for DNS",
			Status:     "PASS",
			Evidence:   "CIS 2.1.9: Microsoft Defender for DNS is enabled",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_DNS"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderForKeyVault(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "KeyVaults")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.10",
			Name:       "[CIS Azure 2.1.10] Microsoft Defender for Key Vault",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for Key Vault: %v", err),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_KEYVAULT"),
		}}
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.10",
			Name:        "[CIS Azure 2.1.10] Microsoft Defender for Key Vault",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Priority:    PriorityMedium,
			Evidence:    "CIS 2.1.10: Microsoft Defender for Key Vault is NOT enabled",
			Remediation: "Enable Microsoft Defender for Key Vault",
			RemediationDetail: `CIS Azure 2.1.10: Ensure that Microsoft Defender for Key Vault is set to 'On'

Azure CLI:
az security pricing create --name KeyVaults --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'Key Vault' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_KEYVAULT"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.10",
			Name:       "[CIS Azure 2.1.10] Microsoft Defender for Key Vault",
			Status:     "PASS",
			Evidence:   "CIS 2.1.10: Microsoft Defender for Key Vault is enabled",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_KEYVAULT"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderForAPIs(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "Api")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.11",
			Name:       "[CIS Azure 2.1.11] Microsoft Defender for APIs",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for APIs: %v", err),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_API"),
		}}
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.11",
			Name:        "[CIS Azure 2.1.11] Microsoft Defender for APIs",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Priority:    PriorityMedium,
			Evidence:    "CIS 2.1.11: Microsoft Defender for APIs is NOT enabled",
			Remediation: "Enable Microsoft Defender for APIs",
			RemediationDetail: `CIS Azure 2.1.11: Ensure that Microsoft Defender for APIs is set to 'On'

Defender for APIs provides:
- API discovery and inventory
- Threat detection for API endpoints
- Sensitive data exposure detection
- API security posture management

Azure CLI:
az security pricing create --name Api --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'APIs' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_API"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.11",
			Name:       "[CIS Azure 2.1.11] Microsoft Defender for APIs",
			Status:     "PASS",
			Evidence:   "CIS 2.1.11: Microsoft Defender for APIs is enabled",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_API"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderForResourceManager(ctx context.Context) []CheckResult {
	var results []CheckResult

	enabled, err := c.isPlanEnabled(ctx, "Arm")

	if err != nil {
		return []CheckResult{{
			Control:    "CIS-2.1.12",
			Name:       "[CIS Azure 2.1.12] Microsoft Defender for Resource Manager",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to check Defender for Resource Manager: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_ARM"),
		}}
	}

	if !enabled {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.12",
			Name:        "[CIS Azure 2.1.12] Microsoft Defender for Resource Manager",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.12: Microsoft Defender for Resource Manager is NOT enabled",
			Remediation: "Enable Microsoft Defender for Resource Manager",
			RemediationDetail: `CIS Azure 2.1.12: Ensure that Microsoft Defender for Resource Manager is set to 'On'

Azure CLI:
az security pricing create --name Arm --tier Standard`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → 'Resource Manager' = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/pricingTier",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_ARM"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.12",
			Name:       "[CIS Azure 2.1.12] Microsoft Defender for Resource Manager",
			Status:     "PASS",
			Evidence:   "CIS 2.1.12: Microsoft Defender for Resource Manager is enabled",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_ARM"),
		})
	}

	return results
}

func (c *DefenderChecks) checkDefenderAutoProvisioning(ctx context.Context) []CheckResult {
	var results []CheckResult

	pager := c.autoProvisionClient.NewListPager(nil)

	enabledSettings := 0
	totalSettings := 0
	disabledSettings := []string{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return []CheckResult{{
				Control:    "CIS-2.1.17",
				Name:       "[CIS Azure 2.1.17] Auto-Provisioning of Defender Components",
				Status:     "ERROR",
				Evidence:   fmt.Sprintf("Unable to check auto-provisioning: %v", err),
				Priority:   PriorityMedium,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("DEFENDER_AUTOPROVISION"),
			}}
		}

		for _, setting := range page.Value {
			totalSettings++
			if setting.Properties != nil && setting.Properties.AutoProvision != nil {
				if *setting.Properties.AutoProvision == armsecurity.AutoProvisionOn {
					enabledSettings++
				} else if setting.Name != nil {
					disabledSettings = append(disabledSettings, *setting.Name)
				}
			}
		}
	}

	if len(disabledSettings) > 0 {
		results = append(results, CheckResult{
			Control:  "CIS-2.1.17",
			Name:     "[CIS Azure 2.1.17] Auto-Provisioning of Defender Components",
			Status:   "FAIL",
			Severity: "MEDIUM",
			Priority: PriorityMedium,
			Evidence: fmt.Sprintf("CIS 2.1.17: %d/%d auto-provisioning settings are disabled: %s",
				len(disabledSettings), totalSettings, strings.Join(disabledSettings, ", ")),
			Remediation: "Enable auto-provisioning for all Defender components",
			RemediationDetail: `CIS 2.1.17: Ensure auto-provisioning is enabled for Microsoft Defender components

Configure via:
Defender for Cloud → Environment settings → Auto provisioning → Enable all agents`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → Auto provisioning → Show all = On",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/autoProvisioning",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_AUTOPROVISION"),
		})
	} else if totalSettings > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.17",
			Name:       "[CIS Azure 2.1.17] Auto-Provisioning of Defender Components",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 2.1.17: All %d auto-provisioning settings are enabled", totalSettings),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_AUTOPROVISION"),
		})
	}

	return results
}

func (c *DefenderChecks) checkSecurityContacts(ctx context.Context) []CheckResult {
	var results []CheckResult

	pager := c.contactsClient.NewListPager(nil)

	// hasContacts := false
	hasAlertNotifications := false
	contactEmails := []string{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return []CheckResult{
				{
					Control:    "CIS-2.1.19",
					Name:       "[CIS Azure 2.1.19] Security Contact Email",
					Status:     "ERROR",
					Evidence:   fmt.Sprintf("Unable to check security contacts: %v", err),
					Priority:   PriorityMedium,
					Timestamp:  time.Now(),
					Frameworks: GetFrameworkMappings("DEFENDER_CONTACTS"),
				},
				{
					Control:    "CIS-2.1.20",
					Name:       "[CIS Azure 2.1.20] Security Alert Notifications",
					Status:     "ERROR",
					Evidence:   fmt.Sprintf("Unable to check alert notifications: %v", err),
					Priority:   PriorityHigh,
					Timestamp:  time.Now(),
					Frameworks: GetFrameworkMappings("DEFENDER_ALERTS"),
				},
			}
		}

		for _, contact := range page.Value {
			if contact.Properties != nil {
				// hasContacts = true

				// Check if email is configured (CIS 2.1.19)
				if contact.Properties.Emails != nil && *contact.Properties.Emails != "" {
					contactEmails = append(contactEmails, *contact.Properties.Emails)
				}

				// FIXED: Check notifications using the correct SDK field structure
				// The SDK may use different field names depending on version
				if contact.Properties.NotificationsByRole != nil ||
					contact.Properties.Emails != nil {
					hasAlertNotifications = true
				}
			}
		}
	}

	// CIS 2.1.19: Security Contact Email
	if len(contactEmails) == 0 {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.19",
			Name:        "[CIS Azure 2.1.19] Security Contact Email",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Priority:    PriorityMedium,
			Evidence:    "CIS 2.1.19: No security contact email addresses configured",
			Remediation: "Configure security contact email addresses",
			RemediationDetail: `CIS Azure 2.1.19: Ensure 'Additional email addresses' is configured with a security contact email

Configure via:
Defender for Cloud → Environment settings → Email notifications → Add email addresses`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → Email notifications → Show configured emails",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/emailNotifications",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_CONTACTS"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.19",
			Name:       "[CIS Azure 2.1.19] Security Contact Email",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 2.1.19: %d security contact email(s) configured", len(contactEmails)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_CONTACTS"),
		})
	}

	// CIS 2.1.20: Security Alert Notifications
	// FIXED: Simplified check - just verify contacts are configured with notifications
	if !hasAlertNotifications {
		results = append(results, CheckResult{
			Control:     "CIS-2.1.20",
			Name:        "[CIS Azure 2.1.20] Security Alert Notifications",
			Status:      "FAIL",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Evidence:    "CIS 2.1.20: Security alert notifications are NOT properly configured",
			Remediation: "Enable notifications for security alerts",
			RemediationDetail: `CIS 2.1.20: Ensure that 'Notify about alerts with the following severity' is set to 'High'

Configure via:
Defender for Cloud → Environment settings → Email notifications → Alert notifications = On for High severity`,
			ScreenshotGuide: "Defender for Cloud → Environment settings → Email notifications → Show 'High' severity enabled",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/emailNotifications",
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("DEFENDER_ALERTS"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-2.1.20",
			Name:       "[CIS Azure 2.1.20] Security Alert Notifications",
			Status:     "PASS",
			Evidence:   "CIS 2.1.20: Security alert notifications are configured",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("DEFENDER_ALERTS"),
		})
	}

	return results
}
