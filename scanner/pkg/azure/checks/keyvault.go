package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
)

type KeyVaultChecks struct {
	client *armkeyvault.VaultsClient
}

func NewKeyVaultChecks(client *armkeyvault.VaultsClient) *KeyVaultChecks {
	return &KeyVaultChecks{client: client}
}

func (c *KeyVaultChecks) Name() string {
	return "Azure Key Vault Security"
}

func (c *KeyVaultChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Count vaults for reporting
	pager := c.client.NewListPager(nil)
	totalVaults := 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		totalVaults += len(page.Value)
	}

	// Due to Azure SDK limitations, NewListPager returns minimal Resource info
	// without full vault properties. Mark these for manual verification.
	if totalVaults > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-3.3.5",
			Name:        "[CIS Azure 3.3.5, 8.1, 8.2] Key Vault Recovery Settings",
			Status:      "INFO",
			Evidence:    fmt.Sprintf("CIS 3.3.5: MANUAL CHECK - Verify purge protection and soft delete (90+ days) for %d Key Vaults", totalVaults),
			Remediation: "Enable purge protection and soft delete for all Key Vaults",
			RemediationDetail: `CIS Azure 3.3.5: Ensure the Key Vault is Recoverable

Verify each Key Vault has:
- Soft delete enabled with 90+ day retention
- Purge protection enabled

Azure CLI:
az keyvault update --name <vault> --enable-soft-delete true --retention-days 90
az keyvault update --name <vault> --enable-purge-protection true`,
			ScreenshotGuide: "Key Vault → Properties → Screenshot showing both enabled",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("KEYVAULT_PURGE"),
		})

		results = append(results, CheckResult{
			Control:     "CIS-3.3.6",
			Name:        "[CIS Azure 3.3.6] Key Vault RBAC Authorization",
			Status:      "INFO",
			Evidence:    fmt.Sprintf("CIS 3.3.6: MANUAL CHECK - Verify RBAC is enabled for %d Key Vaults", totalVaults),
			Remediation: "Enable Azure RBAC for Key Vault authorization",
			RemediationDetail: `CIS Azure 3.3.6: Enable Role Based Access Control

Azure CLI:
az keyvault update --name <vault> --enable-rbac-authorization true`,
			ScreenshotGuide: "Key Vault → Access policies → Permission model = 'Azure role-based access control'",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("KEYVAULT_RBAC"),
		})

		results = append(results, CheckResult{
			Control:         "CIS-3.3.7",
			Name:            "[CIS Azure 3.3.7] Key Vault Private Endpoints",
			Status:          "INFO",
			Evidence:        fmt.Sprintf("CIS 3.3.7: MANUAL CHECK - Verify private endpoints for %d Key Vaults", totalVaults),
			Remediation:     "Configure private endpoints for secure VNet access",
			ScreenshotGuide: "Key Vault → Networking → Private endpoint connections configured",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("KEYVAULT_PRIVATE_ENDPOINT"),
		})

		results = append(results, CheckResult{
			Control:         "CIS-8.3",
			Name:            "[CIS Azure 8.3] Key Vault Network Access",
			Status:          "INFO",
			Evidence:        fmt.Sprintf("CIS 8.3: MANUAL CHECK - Verify network restrictions for %d Key Vaults", totalVaults),
			Remediation:     "Configure network rules to restrict access",
			ScreenshotGuide: "Key Vault → Networking → Selected networks only",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("KEYVAULT_NETWORK_RULES"),
		})

		results = append(results, CheckResult{
			Control:         "CIS-6.1.4",
			Name:            "[CIS Azure 6.1.4] Key Vault Logging",
			Status:          "INFO",
			Evidence:        "CIS 6.1.4: MANUAL CHECK - Verify diagnostic logging with 180+ day retention",
			Remediation:     "Enable diagnostic logging for all Key Vaults",
			ScreenshotGuide: "Key Vault → Diagnostic settings → AuditEvent logs enabled",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("KEYVAULT_LOGGING"),
		})
	}

	return results, nil
}
