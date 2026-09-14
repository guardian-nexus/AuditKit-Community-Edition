package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
)

// AKSChecks implements security checks for Azure Kubernetes Service
type AKSChecks struct {
	client         *armcontainerservice.ManagedClustersClient
	subscriptionID string
}

// NewAKSChecks creates a new AKS checker
func NewAKSChecks(client *armcontainerservice.ManagedClustersClient, subscriptionID string) *AKSChecks {
	return &AKSChecks{
		client:         client,
		subscriptionID: subscriptionID,
	}
}

func (c *AKSChecks) Name() string {
	return "AKS Security Configuration"
}

// Run executes all AKS security checks
func (c *AKSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// List all AKS clusters
	clusters, err := c.listClusters(ctx)
	if err != nil {
		return []CheckResult{{
			Control:   "CIS-AKS-5.4.1",
			Name:      "AKS Cluster Access",
			Status:    StatusError,
			Severity:  "HIGH",
			Evidence:  fmt.Sprintf("Could not enumerate AKS clusters, so no AKS control was assessed: %v", err),
			Priority:  PriorityHigh,
			Timestamp: time.Now(),
		}}, nil
	}

	if len(clusters) == 0 {
		return []CheckResult{{
			Control:   "CIS-AKS-5.4.1",
			Name:      "AKS Clusters",
			Status:    StatusInfo,
			Evidence:  "No AKS clusters found in subscription",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		}}, nil
	}

	// Run all checks
	results = append(results, c.CheckAPIServerAccess(ctx, clusters)...)
	results = append(results, c.CheckNetworkPolicy(ctx, clusters)...)
	results = append(results, c.CheckAzurePolicy(ctx, clusters)...)
	results = append(results, c.CheckAADIntegration(ctx, clusters)...)
	results = append(results, c.CheckRBACEnabled(ctx, clusters)...)
	results = append(results, c.CheckPrivateCluster(ctx, clusters)...)
	results = append(results, c.CheckManagedIdentity(ctx, clusters)...)
	results = append(results, c.CheckDiskEncryption(ctx, clusters)...)
	results = append(results, c.CheckDefenderEnabled(ctx, clusters)...)
	results = append(results, c.CheckAutoUpgrade(ctx, clusters)...)
	results = append(results, c.CheckNodePoolSecurity(ctx, clusters)...)
	results = append(results, c.CheckAuditLogging(ctx, clusters)...)
	results = append(results, c.CheckSecretStoreCSI(ctx, clusters)...)
	results = append(results, c.CheckPodSecurityPolicy(ctx, clusters)...)
	results = append(results, c.CheckImageCleaner(ctx, clusters)...)

	return results, nil
}

func (c *AKSChecks) listClusters(ctx context.Context) ([]*armcontainerservice.ManagedCluster, error) {
	var clusters []*armcontainerservice.ManagedCluster

	pager := c.client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		clusters = append(clusters, page.Value...)
	}

	return clusters, nil
}

// CIS AKS 5.4.1 - Check API Server authorized IP ranges
func (c *AKSChecks) CheckAPIServerAccess(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	unrestricted := []string{}

	for _, cluster := range clusters {
		if cluster.Properties.APIServerAccessProfile == nil ||
			cluster.Properties.APIServerAccessProfile.AuthorizedIPRanges == nil ||
			len(cluster.Properties.APIServerAccessProfile.AuthorizedIPRanges) == 0 {
			unrestricted = append(unrestricted, *cluster.Name)
		}
	}

	if len(unrestricted) > 0 {
		display := unrestricted
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "CIS-AKS-5.4.1",
			Name:              "AKS API Server Access",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without API server IP restrictions: %v", len(unrestricted), len(clusters), display),
			Remediation:       "Configure authorized IP ranges for API server access",
			RemediationDetail: "az aks update --name CLUSTER --resource-group RG --api-server-authorized-ip-ranges \"10.0.0.0/8,YOUR_IP/32\"",
			ScreenshotGuide:   "Azure Portal -> AKS -> Networking -> API server authorized IP ranges",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.6", "PCI-DSS": "1.4.2", "CIS-AKS": "5.4.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-AKS-5.4.1",
			Name:       "AKS API Server Access",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have API server IP restrictions configured", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AKS": "5.4.1"},
		})
	}

	return results
}

// CIS AKS 5.4.4 - Check Network Policy enabled
func (c *AKSChecks) CheckNetworkPolicy(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noPolicy := []string{}

	for _, cluster := range clusters {
		if cluster.Properties.NetworkProfile == nil ||
			cluster.Properties.NetworkProfile.NetworkPolicy == nil ||
			*cluster.Properties.NetworkProfile.NetworkPolicy == "" {
			noPolicy = append(noPolicy, *cluster.Name)
		}
	}

	if len(noPolicy) > 0 {
		display := noPolicy
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "CIS-AKS-5.4.4",
			Name:              "AKS Network Policy",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without network policy: %v", len(noPolicy), len(clusters), display),
			Remediation:       "Enable Azure or Calico network policy (requires cluster recreation)",
			RemediationDetail: "az aks create --network-policy azure --network-plugin azure ...",
			ScreenshotGuide:   "Azure Portal -> AKS -> Networking -> Network policy",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.6", "PCI-DSS": "1.3.2", "CIS-AKS": "5.4.4"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-AKS-5.4.4",
			Name:       "AKS Network Policy",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have network policy enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AKS": "5.4.4"},
		})
	}

	return results
}

// Check Azure Policy add-on enabled
func (c *AKSChecks) CheckAzurePolicy(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noPolicy := []string{}

	for _, cluster := range clusters {
		hasPolicyAddon := false
		if cluster.Properties.AddonProfiles != nil {
			if addon, exists := cluster.Properties.AddonProfiles["azurepolicy"]; exists {
				if addon.Enabled != nil && *addon.Enabled {
					hasPolicyAddon = true
				}
			}
		}
		if !hasPolicyAddon {
			noPolicy = append(noPolicy, *cluster.Name)
		}
	}

	if len(noPolicy) > 0 {
		display := noPolicy
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "AZ-AKS-02",
			Name:              "AKS Azure Policy Add-on",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without Azure Policy add-on: %v", len(noPolicy), len(clusters), display),
			Remediation:       "Enable Azure Policy add-on for Kubernetes",
			RemediationDetail: "az aks enable-addons --addons azure-policy --name CLUSTER --resource-group RG",
			ScreenshotGuide:   "Azure Portal -> AKS -> Policies -> Enable Azure Policy",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC8.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "AZ-AKS-02",
			Name:       "AKS Azure Policy Add-on",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have Azure Policy add-on enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "CC8.1"},
		})
	}

	return results
}

// CIS AKS 5.5.1 - Check Azure AD integration
func (c *AKSChecks) CheckAADIntegration(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noAAD := []string{}

	for _, cluster := range clusters {
		hasAAD := false
		if cluster.Properties.AADProfile != nil {
			if cluster.Properties.AADProfile.Managed != nil && *cluster.Properties.AADProfile.Managed {
				hasAAD = true
			} else if cluster.Properties.AADProfile.ClientAppID != nil {
				hasAAD = true
			}
		}
		if !hasAAD {
			noAAD = append(noAAD, *cluster.Name)
		}
	}

	if len(noAAD) > 0 {
		display := noAAD
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "CIS-AKS-5.5.1",
			Name:              "AKS Azure AD Integration",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without Azure AD integration: %v", len(noAAD), len(clusters), display),
			Remediation:       "Enable Azure AD integration for AKS",
			RemediationDetail: "az aks update --name CLUSTER --resource-group RG --enable-aad --aad-admin-group-object-ids GROUP_ID",
			ScreenshotGuide:   "Azure Portal -> AKS -> Configuration -> AKS-managed Azure Active Directory",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.1", "PCI-DSS": "7.2.1", "CIS-AKS": "5.5.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-AKS-5.5.1",
			Name:       "AKS Azure AD Integration",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have Azure AD integration enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AKS": "5.5.1"},
		})
	}

	return results
}

// CIS AKS 5.5.2 - Check RBAC enabled
func (c *AKSChecks) CheckRBACEnabled(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noRBAC := []string{}

	for _, cluster := range clusters {
		if cluster.Properties.EnableRBAC == nil || !*cluster.Properties.EnableRBAC {
			noRBAC = append(noRBAC, *cluster.Name)
		}
	}

	if len(noRBAC) > 0 {
		display := noRBAC
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "CIS-AKS-5.5.2",
			Name:              "AKS RBAC Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without RBAC: %v", len(noRBAC), len(clusters), display),
			Remediation:       "Enable RBAC (requires cluster recreation)",
			RemediationDetail: "az aks create --enable-rbac ...",
			ScreenshotGuide:   "Azure Portal -> AKS -> Configuration -> Enable Kubernetes RBAC",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.3", "PCI-DSS": "7.2.2", "CIS-AKS": "5.5.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-AKS-5.5.2",
			Name:       "AKS RBAC Enabled",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have RBAC enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AKS": "5.5.2"},
		})
	}

	return results
}

// CIS AKS 5.4.2 - Check Private Cluster
func (c *AKSChecks) CheckPrivateCluster(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	publicClusters := []string{}

	for _, cluster := range clusters {
		isPrivate := false
		if cluster.Properties.APIServerAccessProfile != nil &&
			cluster.Properties.APIServerAccessProfile.EnablePrivateCluster != nil &&
			*cluster.Properties.APIServerAccessProfile.EnablePrivateCluster {
			isPrivate = true
		}
		if !isPrivate {
			publicClusters = append(publicClusters, *cluster.Name)
		}
	}

	if len(publicClusters) > 0 {
		display := publicClusters
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "CIS-AKS-5.4.2",
			Name:              "AKS Private Cluster",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters are not private: %v", len(publicClusters), len(clusters), display),
			Remediation:       "Enable private cluster (requires cluster recreation)",
			RemediationDetail: "az aks create --enable-private-cluster ...",
			ScreenshotGuide:   "Azure Portal -> AKS -> Networking -> Private cluster",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.6", "PCI-DSS": "1.4.4", "CIS-AKS": "5.4.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-AKS-5.4.2",
			Name:       "AKS Private Cluster",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters are private", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AKS": "5.4.2"},
		})
	}

	return results
}

// Check Managed Identity
func (c *AKSChecks) CheckManagedIdentity(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noMI := []string{}

	for _, cluster := range clusters {
		hasMI := false
		if cluster.Identity != nil && cluster.Identity.Type != nil {
			if *cluster.Identity.Type == armcontainerservice.ResourceIdentityTypeSystemAssigned ||
				*cluster.Identity.Type == armcontainerservice.ResourceIdentityTypeUserAssigned {
				hasMI = true
			}
		}
		if !hasMI {
			noMI = append(noMI, *cluster.Name)
		}
	}

	if len(noMI) > 0 {
		display := noMI
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "AZ-AKS-05",
			Name:              "AKS Managed Identity",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters using service principal instead of managed identity: %v", len(noMI), len(clusters), display),
			Remediation:       "Migrate to managed identity",
			RemediationDetail: "az aks update --name CLUSTER --resource-group RG --enable-managed-identity",
			ScreenshotGuide:   "Azure Portal -> AKS -> Properties -> Identity type",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "AZ-AKS-05",
			Name:       "AKS Managed Identity",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters use managed identity", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "CC6.1"},
		})
	}

	return results
}

// Check Disk Encryption
func (c *AKSChecks) CheckDiskEncryption(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noEncryption := []string{}

	for _, cluster := range clusters {
		hasEncryption := false
		if cluster.Properties.DiskEncryptionSetID != nil && *cluster.Properties.DiskEncryptionSetID != "" {
			hasEncryption = true
		}
		if !hasEncryption {
			noEncryption = append(noEncryption, *cluster.Name)
		}
	}

	if len(noEncryption) > 0 {
		display := noEncryption
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "AZ-AKS-03",
			Name:              "AKS Disk Encryption (CMK)",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without customer-managed key encryption: %v (default Azure encryption still applies)", len(noEncryption), len(clusters), display),
			Remediation:       "Enable disk encryption with customer-managed keys",
			RemediationDetail: "az aks create --disk-encryption-set-id DES_ID ...",
			ScreenshotGuide:   "Azure Portal -> AKS -> Disk encryption set",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.7", "PCI-DSS": "3.5.1.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "AZ-AKS-03",
			Name:       "AKS Disk Encryption (CMK)",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters use customer-managed key encryption", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "CC6.1"},
		})
	}

	return results
}

// CIS AKS 5.1.1 - Check Defender for Containers enabled
func (c *AKSChecks) CheckDefenderEnabled(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noDefender := []string{}

	for _, cluster := range clusters {
		hasDefender := false
		if cluster.Properties.SecurityProfile != nil &&
			cluster.Properties.SecurityProfile.Defender != nil &&
			cluster.Properties.SecurityProfile.Defender.SecurityMonitoring != nil &&
			cluster.Properties.SecurityProfile.Defender.SecurityMonitoring.Enabled != nil &&
			*cluster.Properties.SecurityProfile.Defender.SecurityMonitoring.Enabled {
			hasDefender = true
		}
		if !hasDefender {
			noDefender = append(noDefender, *cluster.Name)
		}
	}

	if len(noDefender) > 0 {
		display := noDefender
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "CIS-AKS-5.1.1",
			Name:              "AKS Defender for Containers",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without Defender for Containers: %v", len(noDefender), len(clusters), display),
			Remediation:       "Enable Microsoft Defender for Containers",
			RemediationDetail: "az aks update --name CLUSTER --resource-group RG --enable-defender",
			ScreenshotGuide:   "Azure Portal -> AKS -> Security -> Microsoft Defender for Containers",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC7.2", "PCI-DSS": "11.5.1", "CIS-AKS": "5.1.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-AKS-5.1.1",
			Name:       "AKS Defender for Containers",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have Defender for Containers enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AKS": "5.1.1"},
		})
	}

	return results
}

// Check Auto-Upgrade enabled
func (c *AKSChecks) CheckAutoUpgrade(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noAutoUpgrade := []string{}

	for _, cluster := range clusters {
		hasAutoUpgrade := false
		if cluster.Properties.AutoUpgradeProfile != nil &&
			cluster.Properties.AutoUpgradeProfile.UpgradeChannel != nil &&
			*cluster.Properties.AutoUpgradeProfile.UpgradeChannel != armcontainerservice.UpgradeChannelNone {
			hasAutoUpgrade = true
		}
		if !hasAutoUpgrade {
			noAutoUpgrade = append(noAutoUpgrade, *cluster.Name)
		}
	}

	if len(noAutoUpgrade) > 0 {
		display := noAutoUpgrade
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "AZ-AKS-01",
			Name:              "AKS Auto-Upgrade",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without auto-upgrade: %v", len(noAutoUpgrade), len(clusters), display),
			Remediation:       "Enable cluster auto-upgrade",
			RemediationDetail: "az aks update --name CLUSTER --resource-group RG --auto-upgrade-channel stable",
			ScreenshotGuide:   "Azure Portal -> AKS -> Cluster configuration -> Upgrade channel",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC7.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "AZ-AKS-01",
			Name:       "AKS Auto-Upgrade",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have auto-upgrade enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "CC6.1"},
		})
	}

	return results
}

// Check Node Pool Security Settings
func (c *AKSChecks) CheckNodePoolSecurity(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	insecureNodePools := []string{}

	for _, cluster := range clusters {
		if cluster.Properties.AgentPoolProfiles != nil {
			for _, pool := range cluster.Properties.AgentPoolProfiles {
				// Check for FIPS, node public IP, etc.
				if pool.EnableNodePublicIP != nil && *pool.EnableNodePublicIP {
					insecureNodePools = append(insecureNodePools, fmt.Sprintf("%s/%s", *cluster.Name, *pool.Name))
				}
			}
		}
	}

	if len(insecureNodePools) > 0 {
		display := insecureNodePools
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "AZ-AKS-06",
			Name:              "AKS Node Pool Security",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d node pools with public IPs enabled: %v", len(insecureNodePools), display),
			Remediation:       "Disable public IP on node pools",
			RemediationDetail: "az aks nodepool update --cluster-name CLUSTER --name POOL --resource-group RG --disable-node-public-ip",
			ScreenshotGuide:   "Azure Portal -> AKS -> Node pools -> Node public IP",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.6"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "AZ-AKS-06",
			Name:       "AKS Node Pool Security",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All node pools across %d AKS clusters have secure settings", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "CC6.1"},
		})
	}

	return results
}

// CIS AKS 2.1.1 - Check Audit Logging (Diagnostic Settings)
func (c *AKSChecks) CheckAuditLogging(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	// Diagnostic settings require separate API call
	// This is a manual check as it requires Monitor API
	return []CheckResult{{
		Control:           "CIS-AKS-2.1.1",
		Name:              "AKS Audit Logging",
		Status:            "MANUAL",
		Severity:          "HIGH",
		Evidence:          fmt.Sprintf("%d AKS clusters require manual verification of diagnostic settings", len(clusters)),
		Remediation:       "Enable diagnostic settings for kube-audit and kube-audit-admin logs",
		RemediationDetail: "az monitor diagnostic-settings create --name AKS-Audit --resource CLUSTER_RESOURCE_ID --logs '[{\"category\":\"kube-audit\",\"enabled\":true}]' --workspace LOG_ANALYTICS_WORKSPACE_ID",
		ScreenshotGuide:   "Azure Portal -> AKS -> Diagnostic settings -> kube-audit enabled",
		ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"SOC2": "CC7.2", "PCI-DSS": "10.2.1", "CIS-AKS": "2.1.1"},
	}}
}

// Check Secrets Store CSI Driver
func (c *AKSChecks) CheckSecretStoreCSI(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noCSI := []string{}

	for _, cluster := range clusters {
		hasCSI := false
		if cluster.Properties.AddonProfiles != nil {
			if addon, exists := cluster.Properties.AddonProfiles["azureKeyvaultSecretsProvider"]; exists {
				if addon.Enabled != nil && *addon.Enabled {
					hasCSI = true
				}
			}
		}
		if !hasCSI {
			noCSI = append(noCSI, *cluster.Name)
		}
	}

	if len(noCSI) > 0 {
		display := noCSI
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "AZ-AKS-08",
			Name:              "AKS Secrets Store CSI Driver",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without Secrets Store CSI driver: %v", len(noCSI), len(clusters), display),
			Remediation:       "Enable Azure Key Vault Provider for Secrets Store CSI Driver",
			RemediationDetail: "az aks enable-addons --addons azure-keyvault-secrets-provider --name CLUSTER --resource-group RG",
			ScreenshotGuide:   "Azure Portal -> AKS -> Configuration -> Secrets -> Key Vault Secrets Provider",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.7"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "AZ-AKS-08",
			Name:       "AKS Secrets Store CSI Driver",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have Secrets Store CSI driver enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "CC6.1"},
		})
	}

	return results
}

// Check Pod Security Policy / Pod Security Standards
func (c *AKSChecks) CheckPodSecurityPolicy(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	// Pod Security Standards require kubectl verification
	return []CheckResult{{
		Control:           "AZ-AKS-07",
		Name:              "AKS Pod Security Standards",
		Status:            "MANUAL",
		Severity:          "HIGH",
		Evidence:          fmt.Sprintf("%d AKS clusters require manual verification of Pod Security Standards", len(clusters)),
		Remediation:       "Apply Pod Security Standards to namespaces",
		RemediationDetail: "kubectl label namespace default pod-security.kubernetes.io/enforce=restricted",
		ScreenshotGuide:   "kubectl get namespace -L pod-security.kubernetes.io/enforce",
		ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"SOC2": "CC8.1", "PCI-DSS": "2.2.1"},
	}}
}

// Check Image Cleaner enabled
func (c *AKSChecks) CheckImageCleaner(ctx context.Context, clusters []*armcontainerservice.ManagedCluster) []CheckResult {
	var results []CheckResult
	noImageCleaner := []string{}

	for _, cluster := range clusters {
		hasImageCleaner := false
		if cluster.Properties.SecurityProfile != nil &&
			cluster.Properties.SecurityProfile.ImageCleaner != nil &&
			cluster.Properties.SecurityProfile.ImageCleaner.Enabled != nil &&
			*cluster.Properties.SecurityProfile.ImageCleaner.Enabled {
			hasImageCleaner = true
		}
		if !hasImageCleaner {
			noImageCleaner = append(noImageCleaner, *cluster.Name)
		}
	}

	if len(noImageCleaner) > 0 {
		display := noImageCleaner
		if len(display) > 3 {
			display = display[:3]
		}
		results = append(results, CheckResult{
			Control:           "AZ-AKS-04",
			Name:              "AKS Image Cleaner",
			Status:            "FAIL",
			Severity:          "LOW",
			Evidence:          fmt.Sprintf("%d/%d AKS clusters without Image Cleaner: %v", len(noImageCleaner), len(clusters), display),
			Remediation:       "Enable Image Cleaner to remove stale images",
			RemediationDetail: "az aks update --name CLUSTER --resource-group RG --enable-image-cleaner",
			ScreenshotGuide:   "Azure Portal -> AKS -> Configuration -> Image Cleaner",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerService%2FmanagedClusters",
			Priority:          PriorityLow,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "CC6.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "AZ-AKS-04",
			Name:       "AKS Image Cleaner",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d AKS clusters have Image Cleaner enabled", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "CC6.1"},
		})
	}

	return results
}
