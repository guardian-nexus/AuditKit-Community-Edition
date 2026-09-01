package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

type StorageChecks struct {
	client *armstorage.AccountsClient
}

func NewStorageChecks(client *armstorage.AccountsClient) *StorageChecks {
	return &StorageChecks{client: client}
}

func (c *StorageChecks) Name() string {
	return "Azure Storage Security"
}

func (c *StorageChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Run all CIS Azure storage checks
	results = append(results, c.CheckPublicAccess(ctx)...)
	results = append(results, c.CheckEncryption(ctx)...)
	results = append(results, c.CheckSecureTransfer(ctx)...)
	results = append(results, c.CheckBlobSoftDelete(ctx)...)
	results = append(results, c.CheckNetworkRestrictions(ctx)...)

	// NEW CIS v3.0 Section 4 checks
	results = append(results, c.CheckInfrastructureEncryption(ctx)...)
	results = append(results, c.CheckPublicNetworkAccess(ctx)...)
	results = append(results, c.CheckMinimumTLS(ctx)...)
	results = append(results, c.CheckBlobAnonymousAccess(ctx)...)
	results = append(results, c.CheckCrosstenantReplication(ctx)...)
	results = append(results, c.CheckKeyRotation(ctx)...)
	results = append(results, c.CheckStorageLogging(ctx)...)

	return results, nil
}

func (c *StorageChecks) CheckPublicAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	publicAccounts := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return append(results, CheckResult{
				Control:    "CIS-3.1",
				Name:       "[CIS Azure 3.1] Storage Account Public Access",
				Status:     "ERROR",
				Evidence:   fmt.Sprintf("Unable to check storage accounts: %v", err),
				Severity:   "HIGH",
				Priority:   PriorityHigh,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
			})
		}

		for _, account := range page.Value {
			totalAccounts++

			if account.Properties != nil && account.Properties.AllowBlobPublicAccess != nil {
				if *account.Properties.AllowBlobPublicAccess {
					publicAccounts = append(publicAccounts, *account.Name)
				}
			} else {
				publicAccounts = append(publicAccounts, *account.Name)
			}
		}
	}

	if len(publicAccounts) > 0 {
		displayAccounts := publicAccounts
		if len(publicAccounts) > 3 {
			displayAccounts = publicAccounts[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-3.1",
			Name:        "[CIS Azure 3.1, 3.2] Storage Account Public Access",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CIS 3.1: %d/%d storage accounts allow public blob access: %s", len(publicAccounts), totalAccounts, strings.Join(displayAccounts, ", ")),
			Remediation: "Disable public blob access per CIS Azure 3.1",
			RemediationDetail: fmt.Sprintf(`CIS Azure 3.1: Ensure that 'Public access level' is disabled for storage blobs
CIS Azure 3.2: Ensure default network access rule for Storage Accounts is set to deny

Azure CLI:
az storage account update \
  --name %s \
  --resource-group <rg> \
  --allow-blob-public-access false \
  --default-action Deny`, publicAccounts[0]),
			ScreenshotGuide: fmt.Sprintf("Azure Portal → Storage accounts → %s → Configuration → Screenshot 'Allow Blob public access' = Disabled", publicAccounts[0]),
			ConsoleURL:      fmt.Sprintf("https://portal.azure.com/#@/resource/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/%s/configuration", publicAccounts[0]),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-3.1",
			Name:       "[CIS Azure 3.1] Storage Account Public Access",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 3.1, 3.2: All %d storage accounts block public access", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
		})
	}

	return results
}

func (c *StorageChecks) CheckEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	unencryptedAccounts := []string{}
	weakEncryption := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++
			accountName := *account.Name

			if account.Properties != nil && account.Properties.Encryption != nil {
				if account.Properties.Encryption.KeySource == nil {
					unencryptedAccounts = append(unencryptedAccounts, accountName)
				} else if *account.Properties.Encryption.KeySource == armstorage.KeySourceMicrosoftStorage {
					continue
				}

				if account.Properties.Encryption.Services != nil {
					services := account.Properties.Encryption.Services
					if services.Blob != nil && services.Blob.Enabled != nil && !*services.Blob.Enabled {
						weakEncryption = append(weakEncryption, fmt.Sprintf("%s (blob)", accountName))
					}
					if services.File != nil && services.File.Enabled != nil && !*services.File.Enabled {
						weakEncryption = append(weakEncryption, fmt.Sprintf("%s (file)", accountName))
					}
				}
			} else {
				unencryptedAccounts = append(unencryptedAccounts, accountName)
			}
		}
	}

	if len(unencryptedAccounts) > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-3.3",
			Name:        "[CIS Azure 3.3, 3.4] Storage Encryption at Rest",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CIS 3.3: %d storage accounts lack encryption", len(unencryptedAccounts)),
			Remediation: "Enable encryption (automatic for new accounts)",
			RemediationDetail: `CIS Azure 3.3: Ensure storage for critical data is encrypted with Customer Managed Key
CIS Azure 3.4: Ensure that storage account encryption is enabled

Storage encryption is enabled by default for all new accounts using Microsoft-managed keys.
For enhanced security (CIS 3.3), use customer-managed keys in Azure Key Vault.`,
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_ENCRYPTION"),
		})
	} else if len(weakEncryption) > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-3.4",
			Name:        "[CIS Azure 3.4] Storage Service Encryption",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 3.4: %d storage services have encryption disabled: %s", len(weakEncryption), strings.Join(weakEncryption[:min(3, len(weakEncryption))], ", ")),
			Remediation: "Enable encryption for all storage services",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("STORAGE_ENCRYPTION"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-3.3",
			Name:       "[CIS Azure 3.3, 3.4] Storage Encryption at Rest",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 3.3, 3.4: All %d storage accounts encrypted", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_ENCRYPTION"),
		})
	}

	return results
}

func (c *StorageChecks) CheckSecureTransfer(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	insecureAccounts := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++

			if account.Properties != nil && account.Properties.EnableHTTPSTrafficOnly != nil {
				if !*account.Properties.EnableHTTPSTrafficOnly {
					insecureAccounts = append(insecureAccounts, *account.Name)
				}
			} else {
				insecureAccounts = append(insecureAccounts, *account.Name)
			}
		}
	}

	if len(insecureAccounts) > 0 {
		displayAccounts := insecureAccounts
		if len(insecureAccounts) > 3 {
			displayAccounts = insecureAccounts[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-4.1",
			Name:        "[CIS Azure 4.1] Secure Transfer Required",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 4.1: %d storage accounts allow unencrypted transfers: %s", len(insecureAccounts), strings.Join(displayAccounts, ", ")),
			Remediation: "Enable secure transfer (HTTPS only) per CIS Azure 4.1",
			RemediationDetail: fmt.Sprintf(`CIS Azure 4.1: Ensure that 'Secure transfer required' is set to 'Enabled'

Azure CLI:
az storage account update \
  --name %s \
  --https-only true`, insecureAccounts[0]),
			ScreenshotGuide: "Storage account → Configuration → Secure transfer required = Enabled",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_SECURE_TRANSFER"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-4.1",
			Name:       "[CIS Azure 4.1] Secure Transfer Required",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 4.1: All %d storage accounts require HTTPS", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_SECURE_TRANSFER"),
		})
	}

	return results
}

func (c *StorageChecks) CheckInfrastructureEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	noInfraEncryption := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++

			// Check for infrastructure encryption
			if account.Properties != nil && account.Properties.Encryption != nil {
				if account.Properties.Encryption.RequireInfrastructureEncryption != nil {
					if !*account.Properties.Encryption.RequireInfrastructureEncryption {
						noInfraEncryption = append(noInfraEncryption, *account.Name)
					}
				} else {
					// Not set means not enabled
					noInfraEncryption = append(noInfraEncryption, *account.Name)
				}
			} else {
				noInfraEncryption = append(noInfraEncryption, *account.Name)
			}
		}
	}

	if len(noInfraEncryption) > 0 {
		displayAccounts := noInfraEncryption
		if len(noInfraEncryption) > 3 {
			displayAccounts = noInfraEncryption[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-4.2",
			Name:        "[CIS Azure 4.2] Infrastructure Encryption",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 4.2: %d storage accounts lack infrastructure encryption: %s", len(noInfraEncryption), strings.Join(displayAccounts, ", ")),
			Remediation: "Enable infrastructure encryption (must be set at creation)",
			RemediationDetail: `CIS Azure 4.2: Ensure that 'Enable Infrastructure Encryption' is Set to 'Enabled'

IMPORTANT: Infrastructure encryption can only be enabled when creating a storage account.
For existing accounts, you must:
1. Create new storage account with infrastructure encryption
2. Migrate data to new account
3. Update application connection strings

Azure CLI (new account):
az storage account create \
  --name <new-account> \
  --resource-group <rg> \
  --encryption-services blob file \
  --require-infrastructure-encryption`,
			ScreenshotGuide: "For NEW accounts: Storage account creation → Advanced → Infrastructure encryption = Enabled",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_ENCRYPTION"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-4.2",
			Name:       "[CIS Azure 4.2] Infrastructure Encryption",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 4.2: All %d storage accounts have infrastructure encryption", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_ENCRYPTION"),
		})
	}

	return results
}

func (c *StorageChecks) CheckPublicNetworkAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	publicAccessAccounts := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++

			// Check PublicNetworkAccess property
			if account.Properties != nil && account.Properties.PublicNetworkAccess != nil {
				if *account.Properties.PublicNetworkAccess != armstorage.PublicNetworkAccessDisabled {
					publicAccessAccounts = append(publicAccessAccounts, *account.Name)
				}
			} else {
				// If not set, assume enabled (default)
				publicAccessAccounts = append(publicAccessAccounts, *account.Name)
			}
		}
	}

	if len(publicAccessAccounts) > 0 {
		displayAccounts := publicAccessAccounts
		if len(publicAccessAccounts) > 3 {
			displayAccounts = publicAccessAccounts[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-4.6",
			Name:        "[CIS Azure 4.6] Public Network Access Disabled",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 4.6: %d storage accounts allow public network access: %s", len(publicAccessAccounts), strings.Join(displayAccounts, ", ")),
			Remediation: "Disable public network access, use private endpoints",
			RemediationDetail: fmt.Sprintf(`CIS Azure 4.6: Ensure that Public Network Access is Disabled for storage accounts

Azure CLI:
az storage account update \
  --name %s \
  --resource-group <rg> \
  --public-network-access Disabled

Then configure Private Endpoints for access from VNets.`, publicAccessAccounts[0]),
			ScreenshotGuide: "Storage account → Networking → Public network access = Disabled + Private endpoints configured",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_NETWORK_RULES"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-4.6",
			Name:       "[CIS Azure 4.6] Public Network Access Disabled",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 4.6: All %d storage accounts disable public network access", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_NETWORK_RULES"),
		})
	}

	return results
}

func (c *StorageChecks) CheckMinimumTLS(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	weakTLS := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++

			// Check minimum TLS version
			if account.Properties != nil && account.Properties.MinimumTLSVersion != nil {
				tlsVersion := *account.Properties.MinimumTLSVersion
				// CIS requires TLS 1.2 minimum
				if tlsVersion != armstorage.MinimumTLSVersionTLS12 && tlsVersion != armstorage.MinimumTLSVersionTLS13 {
					weakTLS = append(weakTLS, fmt.Sprintf("%s (TLS %s)", *account.Name, tlsVersion))
				}
			} else {
				// Not set means TLS 1.0 might be allowed
				weakTLS = append(weakTLS, *account.Name)
			}
		}
	}

	if len(weakTLS) > 0 {
		displayAccounts := weakTLS
		if len(weakTLS) > 3 {
			displayAccounts = weakTLS[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-4.15",
			Name:        "[CIS Azure 4.15] Minimum TLS Version",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 4.15: %d storage accounts allow TLS < 1.2: %s", len(weakTLS), strings.Join(displayAccounts, ", ")),
			Remediation: "Set minimum TLS version to 1.2",
			RemediationDetail: fmt.Sprintf(`CIS Azure 4.15: Ensure the 'Minimum TLS version' is set to 'Version 1.2'

Azure CLI:
az storage account update \
  --name %s \
  --resource-group <rg> \
  --min-tls-version TLS1_2`, weakTLS[0]),
			ScreenshotGuide: "Storage account → Configuration → Minimum TLS version = Version 1.2",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_SECURE_TRANSFER"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-4.15",
			Name:       "[CIS Azure 4.15] Minimum TLS Version",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 4.15: All %d storage accounts require TLS 1.2+", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_SECURE_TRANSFER"),
		})
	}

	return results
}

func (c *StorageChecks) CheckBlobAnonymousAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	anonymousAccess := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++

			// This is similar to AllowBlobPublicAccess but explicitly for CIS 4.17
			if account.Properties != nil && account.Properties.AllowBlobPublicAccess != nil {
				if *account.Properties.AllowBlobPublicAccess {
					anonymousAccess = append(anonymousAccess, *account.Name)
				}
			}
		}
	}

	if len(anonymousAccess) > 0 {
		displayAccounts := anonymousAccess
		if len(anonymousAccess) > 3 {
			displayAccounts = anonymousAccess[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-4.17",
			Name:        "[CIS Azure 4.17] Blob Anonymous Access",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CIS 4.17: %d storage accounts allow blob anonymous access: %s", len(anonymousAccess), strings.Join(displayAccounts, ", ")),
			Remediation: "Disable anonymous blob access at storage account level",
			RemediationDetail: fmt.Sprintf(`CIS Azure 4.17: Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'

Azure CLI:
az storage account update \
  --name %s \
  --resource-group <rg> \
  --allow-blob-public-access false`, anonymousAccess[0]),
			ScreenshotGuide: "Storage account → Configuration → Allow Blob public access = Disabled",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-4.17",
			Name:       "[CIS Azure 4.17] Blob Anonymous Access",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 4.17: All %d storage accounts block anonymous blob access", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_PUBLIC_ACCESS"),
		})
	}

	return results
}

func (c *StorageChecks) CheckCrosstenantReplication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	crossTenantEnabled := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++

			// Check AllowCrossTenantReplication
			if account.Properties != nil && account.Properties.AllowCrossTenantReplication != nil {
				if *account.Properties.AllowCrossTenantReplication {
					crossTenantEnabled = append(crossTenantEnabled, *account.Name)
				}
			}
		}
	}

	if len(crossTenantEnabled) > 0 {
		displayAccounts := crossTenantEnabled
		if len(crossTenantEnabled) > 3 {
			displayAccounts = crossTenantEnabled[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-4.16",
			Name:        "[CIS Azure 4.16] Cross-Tenant Replication",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 4.16: %d storage accounts allow cross-tenant replication: %s", len(crossTenantEnabled), strings.Join(displayAccounts, ", ")),
			Remediation: "Disable cross-tenant replication unless required",
			RemediationDetail: fmt.Sprintf(`CIS Azure 4.16: Ensure Cross Tenant Replication is not enabled

Azure CLI:
az storage account update \
  --name %s \
  --resource-group <rg> \
  --allow-cross-tenant-replication false`, crossTenantEnabled[0]),
			ScreenshotGuide: "Storage account → Object replication → Allow cross tenant replication = Disabled",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_NETWORK_RULES"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-4.16",
			Name:       "[CIS Azure 4.16] Cross-Tenant Replication",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 4.16: All %d storage accounts block cross-tenant replication", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_NETWORK_RULES"),
		})
	}

	return results
}

func (c *StorageChecks) CheckBlobSoftDelete(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// CIS 4.10 - Soft delete requires checking blob service properties
	// This requires additional API calls per storage account

	results = append(results, CheckResult{
		Control:     "CIS-4.10",
		Name:        "[CIS Azure 4.10] Blob Soft Delete",
		Status:      "INFO",
		Evidence:    "CIS 4.10: MANUAL CHECK - Verify soft delete is enabled for blobs with 7-365 day retention",
		Remediation: "Enable soft delete with appropriate retention",
		RemediationDetail: `CIS Azure 4.10: Ensure Soft Delete is Enabled for Azure Containers and Blob Storage

Requirements:
- Blob soft delete: Enabled with 7-365 days retention
- Container soft delete: Enabled with 7-365 days retention

Azure CLI:
az storage account blob-service-properties update \
  --account-name <account> \
  --enable-delete-retention true \
  --delete-retention-days 7

Azure Portal:
Storage account → Data protection → Enable soft delete for blobs and containers`,
		ScreenshotGuide: "Storage account → Data protection → Screenshot showing:\n- Soft delete for blobs = Enabled (7-365 days)\n- Soft delete for containers = Enabled (7-365 days)",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("STORAGE_SOFT_DELETE"),
	})

	return results
}

func (c *StorageChecks) CheckNetworkRestrictions(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListPager(nil)

	openAccounts := []string{}
	totalAccounts := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			totalAccounts++

			// Check CIS 4.7: Default action should be Deny
			if account.Properties != nil && account.Properties.NetworkRuleSet != nil {
				acls := account.Properties.NetworkRuleSet

				if acls.DefaultAction != nil && *acls.DefaultAction == armstorage.DefaultActionAllow {
					hasRestrictions := false
					if acls.IPRules != nil && len(acls.IPRules) > 0 {
						hasRestrictions = true
					}
					if acls.VirtualNetworkRules != nil && len(acls.VirtualNetworkRules) > 0 {
						hasRestrictions = true
					}

					if !hasRestrictions {
						openAccounts = append(openAccounts, *account.Name)
					}
				}
			} else {
				openAccounts = append(openAccounts, *account.Name)
			}
		}
	}

	if len(openAccounts) > 0 {
		displayAccounts := openAccounts
		if len(openAccounts) > 3 {
			displayAccounts = openAccounts[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-4.7",
			Name:        "[CIS Azure 4.7] Default Network Access Rule",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 4.7: %d storage accounts have default action 'Allow': %s", len(openAccounts), strings.Join(displayAccounts, ", ")),
			Remediation: "Set default network action to Deny",
			RemediationDetail: fmt.Sprintf(`CIS Azure 4.7: Ensure Default Network Access Rule for Storage Accounts is Set to Deny

Azure CLI:
az storage account update \
  --name %s \
  --resource-group <rg> \
  --default-action Deny

Then whitelist specific VNets or IP ranges.`, openAccounts[0]),
			ScreenshotGuide: "Storage → Networking → Firewalls and virtual networks → Selected networks (not 'All networks')",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("STORAGE_NETWORK_RULES"),
		})
	} else if totalAccounts > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-4.7",
			Name:       "[CIS Azure 4.7] Default Network Access Rule",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 4.7: All %d storage accounts default to Deny", totalAccounts),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("STORAGE_NETWORK_RULES"),
		})
	}

	return results
}

func (c *StorageChecks) CheckKeyRotation(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// CIS 4.3, 4.4: Key rotation requires tracking last rotation date
	// This would need additional tracking/database

	results = append(results, CheckResult{
		Control:     "CIS-4.3",
		Name:        "[CIS Azure 4.3, 4.4] Storage Key Rotation",
		Status:      "INFO",
		Evidence:    "CIS 4.3, 4.4: MANUAL CHECK - Verify storage account keys are rotated periodically",
		Remediation: "Implement 90-day key rotation policy",
		RemediationDetail: `CIS Azure 4.3: Ensure that 'Enable key rotation reminders' is enabled
CIS Azure 4.4: Ensure that Storage Account Access Keys are Periodically Regenerated

Best practices:
- Rotate keys every 90 days
- Use Azure AD authentication instead of keys when possible
- Enable key expiration reminders
- Track last rotation date

Azure CLI to rotate:
az storage account keys renew \
  --account-name <account> \
  --resource-group <rg> \
  --key primary`,
		ScreenshotGuide: "1. Storage account → Access keys\n2. Document last rotation date\n3. Show key rotation schedule/policy\n4. Demonstrate Azure AD authentication usage where possible",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("STORAGE_ENCRYPTION"),
	})

	return results
}

func (c *StorageChecks) CheckStorageLogging(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// CIS 4.12, 4.13, 4.14: Storage logging
	results = append(results, CheckResult{
		Control:     "CIS-4.12",
		Name:        "[CIS Azure 4.12-4.14] Storage Logging",
		Status:      "INFO",
		Evidence:    "CIS 4.12-4.14: MANUAL CHECK - Verify storage logging enabled for Queue, Blob, and Table services",
		Remediation: "Enable logging for Read, Write, Delete requests",
		RemediationDetail: `CIS Azure 4.12: Ensure Storage Logging is Enabled for Queue Service for Read, Write, and Delete requests
CIS Azure 4.13: Ensure Storage logging is Enabled for Blob Service for Read, Write, and Delete requests
CIS Azure 4.14: Ensure Storage Logging is Enabled for Table Service for Read, Write, and Delete Requests

Azure CLI (example for blob):
az storage logging update \
  --account-name <account> \
  --services b \
  --log rwd \
  --retention 90`,
		ScreenshotGuide: "Storage account → Diagnostic settings → Show logging enabled for:\n- Queue service (read/write/delete)\n- Blob service (read/write/delete)\n- Table service (read/write/delete)",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("ACTIVITY_LOG"),
	})

	return results
}
