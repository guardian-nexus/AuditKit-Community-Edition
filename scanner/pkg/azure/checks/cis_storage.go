package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// CISStorageChecks answers the storage recommendations in CIS Microsoft Azure
// Foundations v6.0.0 section 9 that no other check covers.
//
// Three clients are needed because the settings live in three places: the
// account itself, the blob service, and the file service. A check that only had
// the account client could not see soft delete or versioning at all, which is
// why those recommendations had no answer before.
type CISStorageChecks struct {
	accounts *armstorage.AccountsClient
	blob     *armstorage.BlobServicesClient
	file     *armstorage.FileServicesClient
}

func NewCISStorageChecks(accounts *armstorage.AccountsClient, blob *armstorage.BlobServicesClient,
	file *armstorage.FileServicesClient) *CISStorageChecks {
	return &CISStorageChecks{accounts: accounts, blob: blob, file: file}
}

func (c *CISStorageChecks) Name() string { return "CIS Azure Storage" }

// account is one storage account plus the service-level settings that hang off
// it, gathered once so fourteen checks do not each re-enumerate the estate.
type account struct {
	name, group string
	props       *armstorage.AccountProperties
	sku         *armstorage.SKU
	blobProps   *armstorage.BlobServicePropertiesProperties
	fileProps   *armstorage.FileServicePropertiesProperties
}

func resourceGroupOf(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (c *CISStorageChecks) gather(ctx context.Context) ([]account, error) {
	if c.accounts == nil {
		return nil, fmt.Errorf("storage accounts client not configured")
	}
	var out []account
	pager := c.accounts.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range page.Value {
			if a == nil || a.Name == nil {
				continue
			}
			acc := account{name: *a.Name, group: resourceGroupOf(deref(a.ID)), props: a.Properties, sku: a.SKU}
			if c.blob != nil && acc.group != "" {
				if r, err := c.blob.GetServiceProperties(ctx, acc.group, acc.name, nil); err == nil {
					acc.blobProps = r.BlobServiceProperties.BlobServiceProperties
				}
			}
			if c.file != nil && acc.group != "" {
				if r, err := c.file.GetServiceProperties(ctx, acc.group, acc.name, nil); err == nil {
					acc.fileProps = r.FileServiceProperties.FileServiceProperties
				}
			}
			out = append(out, acc)
		}
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// verdict turns "these accounts failed" into a result, so fourteen checks do
// not each repeat the same twenty lines.
func verdict(id, name, sev, remediation, detail, guide string, offenders []string, total int,
	fw map[string]string) CheckResult {
	base := CheckResult{
		Control: id, Name: name, Timestamp: time.Now(), Frameworks: fw,
		ScreenshotGuide: guide,
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Storage%2FStorageAccounts",
	}
	if total == 0 {
		base.Status, base.Evidence, base.Priority = "PASS", "No storage accounts exist in this subscription", PriorityInfo
		return base
	}
	if len(offenders) == 0 {
		base.Status = "PASS"
		base.Evidence = fmt.Sprintf("All %d storage account(s) satisfy this", total)
		base.Priority = PriorityInfo
		return base
	}
	shown := offenders
	if len(shown) > 5 {
		shown = shown[:5]
	}
	base.Status, base.Severity = "FAIL", sev
	base.Evidence = fmt.Sprintf("%d of %d storage account(s) do not: %v", len(offenders), total, shown)
	base.Remediation, base.RemediationDetail = remediation, detail
	base.Priority = PriorityHigh
	if sev == "MEDIUM" {
		base.Priority = PriorityMedium
	}
	return base
}

func (c *CISStorageChecks) Run(ctx context.Context) ([]CheckResult, error) {
	accts, err := c.gather(ctx)
	if err != nil {
		return []CheckResult{{
			Control: "CIS-9.3.2.2", Name: "Azure Storage Security",
			Status: "ERROR", Severity: "MEDIUM", Priority: PriorityMedium,
			Evidence:   fmt.Sprintf("Unable to enumerate storage accounts: %v", err),
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-Azure": "9.3.2.2", "SOC2": "CC6.6"},
		}}, nil
	}
	n := len(accts)
	var results []CheckResult
	collect := func(id, name, sev, rem, detail, guide string, soc2 string, bad []string) {
		results = append(results, verdict(id, name, sev, rem, detail, guide, bad, n,
			map[string]string{"CIS-Azure": strings.TrimPrefix(id, "CIS-"), "SOC2": soc2}))
	}

	// --- file service ---
	var bad []string
	for _, a := range accts {
		if a.fileProps == nil || a.fileProps.ShareDeleteRetentionPolicy == nil ||
			a.fileProps.ShareDeleteRetentionPolicy.Enabled == nil || !*a.fileProps.ShareDeleteRetentionPolicy.Enabled {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.1.1", "File Share Soft Delete Enabled", "MEDIUM",
		"Enable soft delete on the file service so a deleted share can be recovered",
		"az storage account file-service-properties update --enable-delete-retention true --delete-retention-days 7 --account-name <name>",
		"Storage account -> File shares -> Soft delete -> Screenshot showing it enabled with a retention period", "A1.2", bad)

	bad = nil
	for _, a := range accts {
		if a.fileProps == nil || a.fileProps.ProtocolSettings == nil || a.fileProps.ProtocolSettings.Smb == nil ||
			a.fileProps.ProtocolSettings.Smb.Versions == nil || !strings.Contains(*a.fileProps.ProtocolSettings.Smb.Versions, "SMB3.1.1") {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.1.2", "SMB Protocol Version 3.1.1 or Higher", "MEDIUM",
		"Restrict the file service to SMB 3.1.1 so older, weaker dialects cannot be negotiated",
		"az storage account file-service-properties update --versions SMB3.1.1 --account-name <name>",
		"Storage account -> File shares -> Security -> Screenshot the permitted SMB versions", "CC6.7", bad)

	bad = nil
	for _, a := range accts {
		ok := false
		if a.fileProps != nil && a.fileProps.ProtocolSettings != nil && a.fileProps.ProtocolSettings.Smb != nil &&
			a.fileProps.ProtocolSettings.Smb.ChannelEncryption != nil {
			ok = strings.Contains(*a.fileProps.ProtocolSettings.Smb.ChannelEncryption, "AES-256-GCM")
		}
		if !ok {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.1.3", "SMB Channel Encryption AES-256-GCM", "MEDIUM",
		"Require AES-256-GCM channel encryption on the file service",
		"az storage account file-service-properties update --channel-encryption AES-256-GCM --account-name <name>",
		"Storage account -> File shares -> Security -> Screenshot the channel encryption setting", "CC6.7", bad)

	// --- blob service ---
	bad = nil
	for _, a := range accts {
		if a.blobProps == nil || a.blobProps.DeleteRetentionPolicy == nil ||
			a.blobProps.DeleteRetentionPolicy.Enabled == nil || !*a.blobProps.DeleteRetentionPolicy.Enabled {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.2.1", "Blob Soft Delete Enabled", "MEDIUM",
		"Enable soft delete for blobs so a deleted object can be recovered",
		"az storage account blob-service-properties update --enable-delete-retention true --delete-retention-days 7 --account-name <name>",
		"Storage account -> Data protection -> Screenshot blob soft delete enabled", "A1.2", bad)

	bad = nil
	for _, a := range accts {
		if a.blobProps == nil || a.blobProps.ContainerDeleteRetentionPolicy == nil ||
			a.blobProps.ContainerDeleteRetentionPolicy.Enabled == nil || !*a.blobProps.ContainerDeleteRetentionPolicy.Enabled {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.2.2", "Container Soft Delete Enabled", "MEDIUM",
		"Enable soft delete for containers so a deleted container can be recovered",
		"az storage account blob-service-properties update --enable-container-delete-retention true --container-delete-retention-days 7 --account-name <name>",
		"Storage account -> Data protection -> Screenshot container soft delete enabled", "A1.2", bad)

	bad = nil
	for _, a := range accts {
		if a.blobProps == nil || a.blobProps.IsVersioningEnabled == nil || !*a.blobProps.IsVersioningEnabled {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.2.3", "Blob Versioning Enabled", "MEDIUM",
		"Enable blob versioning so an overwrite does not destroy the previous content",
		"az storage account blob-service-properties update --enable-versioning true --account-name <name>",
		"Storage account -> Data protection -> Screenshot versioning enabled", "A1.2", bad)

	// --- account level ---
	bad = nil
	for _, a := range accts {
		if a.props == nil || a.props.AllowSharedKeyAccess == nil || *a.props.AllowSharedKeyAccess {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.3.1.3", "Shared Key Access Disabled", "HIGH",
		"Disable shared key access so callers must authenticate as an identity rather than with an account key",
		"az storage account update --name <name> --allow-shared-key-access false",
		"Storage account -> Configuration -> Screenshot 'Allow storage account key access' set to Disabled", "CC6.1", bad)

	bad = nil
	for _, a := range accts {
		if a.props == nil || a.props.PublicNetworkAccess == nil ||
			*a.props.PublicNetworkAccess != armstorage.PublicNetworkAccessDisabled {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.3.2.2", "Public Network Access Disabled", "HIGH",
		"Disable public network access and reach the account over a private endpoint",
		"az storage account update --name <name> --public-network-access Disabled",
		"Storage account -> Networking -> Screenshot public network access disabled", "CC6.6", bad)

	bad = nil
	for _, a := range accts {
		if a.props == nil || a.props.NetworkRuleSet == nil || a.props.NetworkRuleSet.DefaultAction == nil ||
			*a.props.NetworkRuleSet.DefaultAction != armstorage.DefaultActionDeny {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.3.2.3", "Default Network Rule Set to Deny", "HIGH",
		"Set the default network rule to Deny so only the networks you name can reach the account",
		"az storage account update --name <name> --default-action Deny",
		"Storage account -> Networking -> Screenshot the default rule set to Deny", "CC6.6", bad)

	bad = nil
	for _, a := range accts {
		if a.props == nil || len(a.props.PrivateEndpointConnections) == 0 {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.3.2.1", "Private Endpoints Used for Storage Accounts", "MEDIUM",
		"Create a private endpoint for each account so traffic does not traverse the public network",
		"az network private-endpoint create --name <pe> --vnet-name <vnet> --subnet <subnet> --private-connection-resource-id <account id> --group-id blob --connection-name <conn>",
		"Storage account -> Networking -> Private endpoint connections -> Screenshot the approved connection", "CC6.6", bad)

	bad = nil
	for _, a := range accts {
		if a.props == nil || a.props.DefaultToOAuthAuthentication == nil || !*a.props.DefaultToOAuthAuthentication {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.3.3.1", "Portal Defaults to Entra Authorization", "MEDIUM",
		"Default the portal to Microsoft Entra authorization so browsing data does not fall back to account keys",
		"az storage account update --name <name> --default-to-oauth-authentication true",
		"Storage account -> Configuration -> Screenshot 'Default to Microsoft Entra authorization' enabled", "CC6.1", bad)

	bad = nil
	for _, a := range accts {
		if a.props == nil || a.props.AllowBlobPublicAccess == nil || *a.props.AllowBlobPublicAccess {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.3.8", "Blob Anonymous Access Disabled", "CRITICAL",
		"Disable anonymous blob access so no container can be made public",
		"az storage account update --name <name> --allow-blob-public-access false",
		"Storage account -> Configuration -> Screenshot 'Allow Blob anonymous access' set to Disabled", "CC6.1", bad)

	bad = nil
	for _, a := range accts {
		redundant := false
		if a.sku != nil && a.sku.Name != nil {
			s := string(*a.sku.Name)
			redundant = strings.Contains(s, "GRS") || strings.Contains(s, "GZRS")
		}
		if !redundant {
			bad = append(bad, a.name)
		}
	}
	collect("CIS-9.3.11", "Geo-Redundant Storage on Critical Accounts", "MEDIUM",
		"Use geo-redundant storage for accounts whose loss would interrupt the business; record which accounts are critical",
		"az storage account update --name <name> --sku Standard_GRS",
		"Storage account -> Redundancy -> Screenshot the replication setting for each critical account", "A1.2", bad)

	// Key regeneration age is not exposed on the account, only the key metadata,
	// and the portal shows it. Reported as a manual verification rather than a
	// pass nobody measured.
	results = append(results, CheckResult{
		Control:         "CIS-9.3.1.2",
		Name:            "Storage Account Keys Periodically Regenerated",
		Status:          "MANUAL",
		Evidence:        "MANUAL CHECK: Confirm the access keys on each storage account have been regenerated within your rotation period",
		Remediation:     "Regenerate each access key on a schedule and record the date, or disable shared key access entirely so the keys do not matter",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Storage account -> Access keys -> Screenshot the key rotation reminder and the last rotation date",
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Storage%2FStorageAccounts",
		Frameworks:      map[string]string{"CIS-Azure": "9.3.1.2", "SOC2": "CC6.1"},
	})

	return results, nil
}
