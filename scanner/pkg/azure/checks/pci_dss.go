package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

// AzurePCIChecks implements PCI-DSS v4.0.1 requirements for Azure
type AzurePCIChecks struct {
	storageClient *armstorage.AccountsClient
	networkClient *armnetwork.SecurityGroupsClient
	roleClient    *armauthorization.RoleAssignmentsClient
	sqlClient     *armsql.DatabasesClient
	monitorClient *armmonitor.ActivityLogsClient
	// graphClient and diagnosticClient are optional; the v4.x checks degrade to
	// documentation results when they are nil.
	graphClient      *msgraphsdk.GraphServiceClient
	diagnosticClient *armmonitor.DiagnosticSettingsClient
	subscriptionID   string
}

func NewAzurePCIChecks(
	storageClient *armstorage.AccountsClient,
	networkClient *armnetwork.SecurityGroupsClient,
	roleClient *armauthorization.RoleAssignmentsClient,
	sqlClient *armsql.DatabasesClient,
	monitorClient *armmonitor.ActivityLogsClient,
	graphClient *msgraphsdk.GraphServiceClient,
	diagnosticClient *armmonitor.DiagnosticSettingsClient,
	subscriptionID string,
) *AzurePCIChecks {
	return &AzurePCIChecks{
		storageClient:    storageClient,
		networkClient:    networkClient,
		roleClient:       roleClient,
		sqlClient:        sqlClient,
		monitorClient:    monitorClient,
		graphClient:      graphClient,
		diagnosticClient: diagnosticClient,
		subscriptionID:   subscriptionID,
	}
}

func (c *AzurePCIChecks) Name() string {
	return "Azure PCI-DSS v4.0.1 Requirements"
}

func (c *AzurePCIChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Requirement 1: Network Security
	results = append(results, c.CheckReq1_NetworkSegmentation(ctx)...)

	// Requirement 2: Default Passwords
	results = append(results, c.CheckReq2_DefaultPasswords(ctx)...)

	// Requirement 3: Encryption at Rest
	results = append(results, c.CheckReq3_StorageEncryption(ctx)...)

	// Requirement 4: Encryption in Transit
	results = append(results, c.CheckReq4_TransitEncryption(ctx)...)

	// Requirement 5: Malware Protection
	results = append(results, c.CheckReq5_MalwareProtection(ctx)...)

	// Requirement 6: Secure Systems
	results = append(results, c.CheckReq6_SecureSystems(ctx)...)

	// Requirement 7: Access Control
	results = append(results, c.CheckReq7_AccessControl(ctx)...)

	// Requirement 8: Authentication (Azure AD checks)
	results = append(results, c.CheckReq8_Authentication(ctx)...)

	// Requirement 9: Physical Access Controls
	results = append(results, c.CheckReq9_PhysicalAccess(ctx)...)

	// Requirement 10: Logging
	results = append(results, c.CheckReq10_Logging(ctx)...)

	// Requirement 11: Security Testing
	results = append(results, c.CheckReq11_SecurityTesting(ctx)...)

	// v4.x requirements that became mandatory on 31 March 2025
	results = append(results, c.CheckFutureDated(ctx)...)

	// Requirement 12: Information Security Policy
	results = append(results, c.CheckReq12_SecurityPolicy(ctx)...)

	return results, nil
}

// Requirement 1: Network segmentation for CDE
func (c *AzurePCIChecks) CheckReq1_NetworkSegmentation(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for network segmentation using NSGs
	pager := c.networkClient.NewListAllPager(nil)

	nsgCount := 0
	subnetAssociations := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, nsg := range page.Value {
			nsgCount++

			// Check if NSG is associated with subnets
			if nsg.Properties != nil && nsg.Properties.Subnets != nil {
				subnetAssociations += len(nsg.Properties.Subnets)
			}
		}
	}

	if nsgCount == 0 {
		results = append(results, CheckResult{
			Control:           "PCI-1.4.2",
			Name:              "[PCI-DSS] Network Segmentation",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "PCI-DSS 1.4.2 VIOLATION: No Network Security Groups found - no network segmentation",
			Remediation:       "Create NSGs for network segmentation",
			RemediationDetail: "Create separate VNets/subnets for CDE with restrictive NSGs",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "Azure Portal → Virtual networks → Show segmented CDE network",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FvirtualNetworks",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "1.4.2",
			},
		})
	} else if subnetAssociations < nsgCount {
		results = append(results, CheckResult{
			Control:           "PCI-1.3.1",
			Name:              "[PCI-DSS] NSG Subnet Associations",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS 1.4.2: %d NSGs but only %d subnet associations - incomplete segmentation", nsgCount, subnetAssociations),
			Remediation:       "Associate NSGs with all subnets",
			RemediationDetail: "Every subnet should have an NSG for proper segmentation",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "1.3.1",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-1.4.2",
			Name:      "[PCI-DSS] Network Segmentation",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d NSGs with %d subnet associations configured", nsgCount, subnetAssociations),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "1.4.2",
			},
		})
	}

	return results
}

// Requirement 3: Storage encryption for cardholder data
func (c *AzurePCIChecks) CheckReq3_StorageEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.storageClient.NewListPager(nil)

	unencryptedStorage := []string{}
	noCustomerKeys := []string{}
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
				// PCI prefers customer-managed keys
				if account.Properties.Encryption.KeySource != nil {
					if *account.Properties.Encryption.KeySource == armstorage.KeySourceMicrosoftStorage {
						noCustomerKeys = append(noCustomerKeys, accountName)
					}
				}
			} else {
				unencryptedStorage = append(unencryptedStorage, accountName)
			}
		}
	}

	if len(unencryptedStorage) > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-3.5.1",
			Name:              "[PCI-DSS] Storage Encryption (Mandatory)",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS 3.5.1 VIOLATION: %d storage accounts NOT encrypted", len(unencryptedStorage)),
			Remediation:       "Enable encryption immediately",
			RemediationDetail: "All storage must be encrypted for PCI compliance",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "Storage account → Encryption → Show encryption enabled",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "3.4, 3.4.1",
			},
		})
	}

	if len(noCustomerKeys) > 0 && len(noCustomerKeys) == totalAccounts {
		results = append(results, CheckResult{
			Control:           "PCI-3.6.1",
			Name:              "[PCI-DSS] Encryption Key Management",
			Status:            "INFO",
			Evidence:          fmt.Sprintf("PCI-DSS 3.6.1: All storage uses Microsoft-managed keys - consider customer-managed keys for CDE"),
			Remediation:       "Consider Azure Key Vault for customer-managed keys",
			RemediationDetail: "Use customer-managed keys for cardholder data storage",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "3.5, 3.6",
			},
		})
	}

	return results
}

// Requirement 4: Encryption in transit
func (c *AzurePCIChecks) CheckReq4_TransitEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check storage accounts for HTTPS enforcement
	pager := c.storageClient.NewListPager(nil)

	noHTTPS := []string{}
	noTLS12 := []string{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, account := range page.Value {
			accountName := *account.Name

			if account.Properties != nil {
				// Check HTTPS enforcement
				if account.Properties.EnableHTTPSTrafficOnly == nil || !*account.Properties.EnableHTTPSTrafficOnly {
					noHTTPS = append(noHTTPS, accountName)
				}

				// Check minimum TLS version (PCI requires TLS 1.2+)
				if account.Properties.MinimumTLSVersion == nil || *account.Properties.MinimumTLSVersion == armstorage.MinimumTLSVersionTLS10 || *account.Properties.MinimumTLSVersion == armstorage.MinimumTLSVersionTLS11 {
					noTLS12 = append(noTLS12, accountName)
				}
			}
		}
	}

	if len(noHTTPS) > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-4.2.1",
			Name:              "[PCI-DSS] HTTPS Enforcement",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS 4.2.1 VIOLATION: %d storage accounts allow HTTP: %s", len(noHTTPS), strings.Join(noHTTPS[:min(3, len(noHTTPS))], ", ")),
			Remediation:       "Enable HTTPS-only immediately",
			RemediationDetail: fmt.Sprintf("az storage account update --name %s --https-only true", noHTTPS[0]),
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "4.2.1",
			},
		})
	}

	if len(noTLS12) > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-4.2.1",
			Name:              "[PCI-DSS] TLS 1.2+ Required",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS 4.2.1: %d storage accounts allow TLS < 1.2: %s", len(noTLS12), strings.Join(noTLS12[:min(3, len(noTLS12))], ", ")),
			Remediation:       "Set minimum TLS version to 1.2",
			RemediationDetail: fmt.Sprintf("az storage account update --name %s --min-tls-version TLS1_2", noTLS12[0]),
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Storage → Configuration → Minimum TLS version = 1.2",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "4.2.1",
			},
		})
	}

	return results
}

// Requirement 7: Access control
func (c *AzurePCIChecks) CheckReq7_AccessControl(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for excessive privileged roles
	pager := c.roleClient.NewListPager(nil)

	ownerCount := 0
	contributorCount := 0
	userAccessAdminCount := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, assignment := range page.Value {
			if assignment.Properties != nil && assignment.Properties.RoleDefinitionID != nil {
				roleID := *assignment.Properties.RoleDefinitionID

				// Check for privileged roles
				if strings.Contains(roleID, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635") {
					ownerCount++
				} else if strings.Contains(roleID, "b24988ac-6180-42a0-ab88-20f7382dd24c") {
					contributorCount++
				} else if strings.Contains(roleID, "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9") {
					userAccessAdminCount++
				}
			}
		}
	}

	totalPrivileged := ownerCount + contributorCount + userAccessAdminCount

	if totalPrivileged > 5 {
		results = append(results, CheckResult{
			Control:           "PCI-7.2.1",
			Name:              "[PCI-DSS] Least Privilege Violation",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS 7.2.1: %d users with privileged access (Owner: %d, Contributor: %d, UAA: %d) - excessive", totalPrivileged, ownerCount, contributorCount, userAccessAdminCount),
			Remediation:       "Implement least privilege - use specific roles",
			RemediationDetail: "Review each privileged user and downgrade to specific roles",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Subscription → Access control → Show minimal privileged users",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "7.1, 7.1.2",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-7.2.1",
			Name:      "[PCI-DSS] Least Privilege",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d privileged users (acceptable for PCI)", totalPrivileged),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "7.2.1",
			},
		})
	}

	return results
}

// Requirement 8: Authentication
func (c *AzurePCIChecks) CheckReq8_Authentication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// MFA and password policy require Graph API - provide guidance
	results = append(results, CheckResult{
		Control:           "PCI-8.4.2",
		Name:              "[PCI-DSS] MFA for ALL Access",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.4.2: MANUAL CHECK - Verify MFA enabled for ALL users accessing the CDE (cloud portal, CLI and API all count as non-console access under 8.4.2)",
		Remediation:       "Enable MFA for every user - no exceptions",
		RemediationDetail: "Azure AD → Users → Per-user MFA → Enable for ALL",
		ScreenshotGuide:   "Azure AD → Users → Show MFA status = Enabled/Enforced for ALL users",
		Priority:          PriorityCritical,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.4.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-8.3.9",
		Name:              "[PCI-DSS] 90-Day Password Rotation",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.3.9: MANUAL CHECK - Passwords MUST expire every 90 days maximum",
		Remediation:       "Configure 90-day password expiration",
		RemediationDetail: "Azure AD → Password policy → Maximum age = 90 days",
		Priority:          PriorityCritical,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.3.9",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-8.2.8",
		Name:              "[PCI-DSS] 15-Minute Session Timeout",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.2.8: Configure 15-minute idle timeout for all sessions",
		Remediation:       "Set session timeout to 15 minutes",
		RemediationDetail: "Azure AD → Conditional Access → Session policy = 15 minutes",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.2.8",
		},
	})

	return results
}

// Requirement 10: Logging
func (c *AzurePCIChecks) CheckReq10_Logging(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check if Activity Log is configured (simplified check)
	// Note: Full check requires querying log analytics workspace

	results = append(results, CheckResult{
		Control:           "PCI-10.2.1",
		Name:              "[PCI-DSS] Audit Logging Implementation",
		Status:            "INFO",
		Evidence:          "PCI-DSS 10.2.1.1: Verify Activity Log is exported to storage/workspace",
		Remediation:       "Configure Activity Log export with 12-month retention",
		RemediationDetail: "Monitor → Activity log → Export → Storage account with 365+ day retention",
		ScreenshotGuide:   "Monitor → Activity log → Diagnostic settings → Show export configured",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/activityLog",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "10.1, 10.2.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-10.5.1",
		Name:              "[PCI-DSS] 12-Month Log Retention",
		Status:            "INFO",
		Evidence:          "PCI-DSS 10.5.1: Logs must be retained for 12+ months (3 months readily available)",
		Remediation:       "Configure storage lifecycle for 365+ day retention",
		RemediationDetail: "Storage account → Lifecycle management → Archive after 90 days, delete after 365+",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "10.5.1",
		},
	})

	return results
}

// Requirement 2: Default Passwords
func (c *AzurePCIChecks) CheckReq2_DefaultPasswords(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-2.2.2",
		Name:              "[PCI-DSS] Change Default Passwords",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS 2.2.4 requires changing vendor defaults before deploying systems",
		Remediation:       "Ensure all default passwords are changed",
		RemediationDetail: "1. Change default passwords on all Azure services and third-party systems\n2. Review VM images for default credentials\n3. Change default database passwords\n4. Document password change procedures",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document password change procedures and verification checklist",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Compute/VirtualMachinesMenuBlade/overview",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 2.2.2, 2.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-2.2.4",
		Name:              "[PCI-DSS] Disable Default Network Configurations",
		Status:            "INFO",
		Evidence:          "MANUAL: Review Virtual Network default configurations and remove unnecessary default rules",
		Remediation:       "Disable or customize default network configurations",
		RemediationDetail: "Review NSG rules for overly permissive default rules",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Virtual Networks → Network Security Groups → Show customized, restrictive rules",
		ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FnetworkSecurityGroups",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 2.2.4",
		},
	})

	return results
}

// Requirement 5: Malware Protection
func (c *AzurePCIChecks) CheckReq5_MalwareProtection(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-5.2.1",
		Name:              "[PCI-DSS] Anti-Malware Protection",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 5.2.1 requires anti-malware on all systems commonly affected by malware",
		Remediation:       "Deploy and maintain anti-malware solution",
		RemediationDetail: "1. Deploy Microsoft Defender for Cloud or third-party endpoint protection\n2. Ensure anti-malware is active and up-to-date on all VMs\n3. Configure automatic updates and periodic scans\n4. Document anti-malware solution and update schedule",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Security Center → Recommendations → Show anti-malware deployed on all VMs",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.2.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-5.3.1",
		Name:              "[PCI-DSS] Anti-Malware Updates",
		Status:            "INFO",
		Evidence:          "MANUAL: Verify anti-malware mechanisms are current, actively running, and generating logs",
		Remediation:       "Ensure anti-malware auto-updates are enabled",
		RemediationDetail: "Configure automatic signature updates and verify audit logs show active scanning",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Defender for Cloud → Show automatic updates enabled and recent scan logs",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.3.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-5.3.4",
		Name:              "[PCI-DSS] Anti-Malware Scan Logs",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI requires anti-malware logs be retained and reviewed periodically",
		Remediation:       "Configure log retention and review procedures",
		RemediationDetail: "1. Enable logging for all anti-malware events\n2. Configure log retention (minimum per Req 10)\n3. Establish periodic review process\n4. Document review findings",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Show anti-malware logs with retention policy and review documentation",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.3.4",
		},
	})

	return results
}

// Requirement 6: Secure Systems
func (c *AzurePCIChecks) CheckReq6_SecureSystems(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-6.3.3",
		Name:              "[PCI-DSS] Security Patching",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 6.3.3 requires critical security patches within 30 days",
		Remediation:       "Implement patch management process",
		RemediationDetail: "1. Use Azure Update Management for automated patching\n2. Implement automated patching where possible\n3. Document patch management procedures\n4. Track critical patches and ensure 30-day compliance",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Automation → Update Management → Show patch compliance status",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Automation/AutomationMenuBlade/updateManagement",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 6.3.3",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-6.2.1",
		Name:              "[PCI-DSS] Secure Development Lifecycle",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement secure software development lifecycle for custom applications",
		Remediation:       "Establish SDLC with security review process",
		RemediationDetail: "1. Implement code review process\n2. Conduct security testing before deployment\n3. Use Azure DevOps with security scanning\n4. Document SDLC procedures",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document SDLC procedures and security review checkpoints",
		ConsoleURL:        "https://dev.azure.com/",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 6.2.1, 6.5",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-6.4.2",
		Name:              "[PCI-DSS] Web Application Firewall",
		Status:            "INFO",
		Evidence:          "MANUAL: Deploy WAF for public-facing web applications",
		Remediation:       "Implement Azure Application Gateway with WAF",
		RemediationDetail: "PCI requires WAF or regular code reviews for public-facing web apps",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Application Gateway → WAF → Show policies protecting web applications",
		ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FapplicationGateways",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 6.4.2",
		},
	})

	return results
}

// Requirement 9: Physical Access Controls
func (c *AzurePCIChecks) CheckReq9_PhysicalAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-9.1.1",
		Name:              "[PCI-DSS] Physical Access Controls",
		Status:            "INFO",
		Evidence:          "INFO: Azure data centers have physical security controls (inherited control). Review Azure compliance documentation.",
		Remediation:       "Document Azure physical security inheritance",
		RemediationDetail: "1. Review Azure PCI-DSS Attestation of Compliance (AOC)\n2. Download Azure PCI-DSS Responsibility Matrix from Service Trust Portal\n3. Document inherited physical controls\n4. Focus on organizational physical security for offices with cardholder data access",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Service Trust Portal → Download PCI-DSS AOC showing physical security controls",
		ConsoleURL:        "https://servicetrust.microsoft.com/",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.1.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-9.2.1",
		Name:              "[PCI-DSS] Physical Access Procedures",
		Status:            "INFO",
		Evidence:          "MANUAL: Develop procedures to control physical access to facilities with systems that store, process, or transmit cardholder data",
		Remediation:       "Document physical access procedures for your facilities",
		RemediationDetail: "1. Implement badge/access card system for facility entry\n2. Establish visitor log procedures\n3. Differentiate badges for employees vs visitors\n4. Require escort for visitors in sensitive areas\n5. Document all procedures",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document physical access control procedures, visitor logs, and badge system",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.2.1, 9.3",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-9.4.1",
		Name:              "[PCI-DSS] Media Physical Security",
		Status:            "INFO",
		Evidence:          "MANUAL: Physically secure all media containing cardholder data (backups, portable devices)",
		Remediation:       "Implement physical controls for backup media and portable devices",
		RemediationDetail: "1. Store backup media in secure, locked location\n2. Maintain inventory of all media with cardholder data\n3. Review media inventory at least annually\n4. Securely destroy media when no longer needed (Req 9.4.6)",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Show backup media inventory, secure storage documentation, and destruction procedures",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.4.1, 9.5, 9.8",
		},
	})

	return results
}

// Requirement 11: Security Testing
func (c *AzurePCIChecks) CheckReq11_SecurityTesting(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-11.3.2",
		Name:              "[PCI-DSS] Quarterly Vulnerability Scans",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.3.2: PCI requires QUARTERLY vulnerability scans by Approved Scanning Vendor (ASV)",
		Remediation:       "Schedule quarterly ASV scans",
		RemediationDetail: "1. Engage PCI-approved ASV\n2. Schedule quarterly external scans\n3. Internal scans can use Defender for Cloud vulnerability assessment",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document ASV scan reports dated within last 90 days",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/22",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.3.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-11.4.3",
		Name:              "[PCI-DSS] Annual Penetration Testing",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.4.3: PCI requires ANNUAL penetration testing of CDE",
		Remediation:       "Schedule annual penetration test",
		RemediationDetail: "Annual external and internal penetration testing required",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document penetration test reports with dates and findings",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.4.3",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-11.5.2",
		Name:              "[PCI-DSS] File Integrity Monitoring",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.5.2: Deploy file integrity monitoring on critical systems",
		Remediation:       "Implement FIM solution",
		RemediationDetail: "Use Azure File Integrity Monitoring in Defender for Cloud or third-party FIM tools",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Defender for Cloud → File Integrity Monitoring → Show FIM enabled",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/18",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.5.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-11.5.2",
		Name:              "[PCI-DSS] Change Detection Mechanisms",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement change detection for critical files and configurations",
		Remediation:       "Enable change detection mechanisms",
		RemediationDetail: "Use Azure Policy and Defender for Cloud for configuration monitoring",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Azure Policy → Compliance → Show change detection policies enabled",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Compliance",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.5.2",
		},
	})

	return results
}

// Requirement 12: Information Security Policy
func (c *AzurePCIChecks) CheckReq12_SecurityPolicy(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-12.1.1",
		Name:              "[PCI-DSS] Security Policy Establishment",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 12.1.1 requires establishing, publishing, maintaining, and disseminating a security policy",
		Remediation:       "Create and maintain comprehensive information security policy",
		RemediationDetail: "1. Establish security policy addressing PCI-DSS requirements\n2. Review policy at least annually\n3. Update when environment changes\n4. Communicate to all relevant personnel\n5. Document policy review and approval",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document current security policy, annual review dates, and communication records",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.1.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.3.1",
		Name:              "[PCI-DSS] Risk Assessment Process",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement risk assessment process performed at least annually and upon significant changes",
		Remediation:       "Establish annual risk assessment process",
		RemediationDetail: "1. Perform formal risk assessment at least annually\n2. Identify critical assets and threats\n3. Assess likelihood and impact\n4. Document risk assessment results\n5. Update after significant infrastructure changes",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document risk assessments with dates, findings, and mitigation plans",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.3.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.2.1",
		Name:              "[PCI-DSS] Acceptable Use Policies",
		Status:            "INFO",
		Evidence:          "MANUAL: Develop usage policies for critical technologies (remote access, wireless, mobile devices, email, internet)",
		Remediation:       "Create and enforce acceptable use policies",
		RemediationDetail: "1. Define acceptable use for all critical technologies\n2. Require management approval for use of technologies\n3. Require authentication for use of technology\n4. Maintain list of authorized devices and personnel\n5. Document acceptable use policies",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document acceptable use policies, approval records, and technology inventory",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.2.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.1.4",
		Name:              "[PCI-DSS] Assign Security Responsibilities",
		Status:            "INFO",
		Evidence:          "MANUAL: Assign individual or team responsibility for information security management",
		Remediation:       "Document security responsibilities and assignments",
		RemediationDetail: "1. Formally assign information security responsibilities\n2. Define roles and responsibilities for PCI-DSS compliance\n3. Document organizational structure for security\n4. Ensure adequate resources allocated",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document organizational chart showing security responsibilities and role assignments",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.1.4, 12.5.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.6.1",
		Name:              "[PCI-DSS] Security Awareness Program",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement formal security awareness program for all personnel",
		Remediation:       "Establish security awareness and training program",
		RemediationDetail: "1. Provide security awareness training upon hire and at least annually\n2. Train personnel on their responsibilities for protecting cardholder data\n3. Require personnel acknowledge understanding\n4. Document training completion and acknowledgments",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document training program, completion records, and acknowledgment forms",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.6.1, 12.6.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.8.1",
		Name:              "[PCI-DSS] Service Provider Management",
		Status:            "INFO",
		Evidence:          "MANUAL: Maintain and implement policies for service providers who handle cardholder data",
		Remediation:       "Implement service provider management procedures",
		RemediationDetail: "1. Maintain list of service providers\n2. Establish written agreement including PCI-DSS responsibilities\n3. Ensure service providers acknowledge responsibility\n4. Monitor service provider PCI-DSS compliance status at least annually",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document service provider list, contracts, and annual compliance verification",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.8.1, 12.8.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.10.1",
		Name:              "[PCI-DSS] Incident Response Plan",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement an incident response plan for security incidents",
		Remediation:       "Create and test incident response plan",
		RemediationDetail: "1. Create incident response plan\n2. Assign roles and responsibilities\n3. Include specific incident response procedures\n4. Test plan at least annually\n5. Update plan based on test results and industry developments",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document incident response plan, test results, and update history",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.10.1",
		},
	})

	return results
}

// CheckFutureDated covers the PCI DSS v4.x requirements that became mandatory on
// 31 March 2025.
//
// 8.6.1, 8.6.3 and 10.4.1.1 are read from configuration when the Graph and
// diagnostic-settings clients are available. The rest are documentation checks:
// hardcoded credentials and failure-response procedures are not observable from
// cloud configuration.
func (c *AzurePCIChecks) CheckFutureDated(ctx context.Context) []CheckResult {
	results := []CheckResult{
		{
			Control:           "PCI-4.2.1.1",
			Name:              "[PCI-DSS] Trusted Key and Certificate Inventory",
			Status:            "INFO",
			Evidence:          "PCI-DSS Req 4.2.1.1 (mandatory since 31 Mar 2025): maintain an inventory of trusted keys and certificates used to protect PAN in transit",
			Remediation:       "Maintain a documented certificate inventory",
			RemediationDetail: "1. List certificates: az keyvault certificate list --vault-name NAME\n2. Record issuer, expiry and the service each protects\n3. Review at least annually and on renewal",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "Key Vault certificate list, plus the maintained inventory document",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 4.2.1.1"},
		},
		{
			Control:           "PCI-8.6.2",
			Name:              "[PCI-DSS] No Hardcoded Application Credentials",
			Status:            "INFO",
			Evidence:          "PCI-DSS Req 8.6.2 (mandatory since 31 Mar 2025): passwords for application and system accounts must not be hard coded in scripts, configuration files or source code",
			Remediation:       "Move credentials to Key Vault",
			RemediationDetail: "1. Scan repositories for embedded client secrets\n2. Move them to Key Vault\n3. Use managed identities rather than client secrets where possible",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Key Vault secret inventory, plus evidence of secret scanning in CI",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 8.6.2"},
		},
		{
			Control:           "PCI-10.7.3",
			Name:              "[PCI-DSS] Security Control Failure Response",
			Status:            "INFO",
			Evidence:          "PCI-DSS Req 10.7.3 (mandatory since 31 Mar 2025): document how security control failures are responded to, including restoring the function and recording the duration and cause",
			Remediation:       "Document the failure response procedure",
			RemediationDetail: "Record: how the failure is identified, who restores the control, the start and end time of the outage, the cause, and what was changed to prevent recurrence.",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "The documented procedure, plus a worked example from a real or exercised failure",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 10.7.3"},
		},
	}

	results = append(results, c.checkAppCredentials(ctx)...)
	results = append(results, c.checkDiagnosticRouting(ctx)...)
	results = append(results, CheckResult{
		Control:           "PCI-10.7.2",
		Name:              "[PCI-DSS] Security Control Failure Detection",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 10.7.2 (mandatory since 31 Mar 2025): failures of critical security control systems must be detected and alerted on, including logging, network controls and change detection",
		Remediation:       "Alert on the disabling of security controls",
		RemediationDetail: "1. Create activity log alerts for diagnostic setting deletion and NSG rule changes\n2. Alert on Defender for Cloud plans being turned off\n3. Attach an action group with a notification target",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Activity log alert rules covering diagnostic settings and security control changes",
		ConsoleURL:        "https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade",
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"PCI-DSS": "Req 10.7.2"},
	})
	return results
}

// checkAppCredentials covers 8.6.1 and 8.6.3. A client secret on an app
// registration is a long-lived credential that a person can copy and reuse,
// which is the Azure equivalent of a GCP user-managed service account key.
// Certificate credentials and managed identities do not carry that risk.
func (c *AzurePCIChecks) checkAppCredentials(ctx context.Context) []CheckResult {
	manual := func(reason string) []CheckResult {
		return []CheckResult{
			{
				Control:           "PCI-8.6.1",
				Name:              "[PCI-DSS] Application Account Credential Management",
				Status:            "INFO",
				Evidence:          "PCI-DSS Req 8.6.1 (mandatory since 31 Mar 2025): " + reason + ". Review app registrations for client secrets by hand",
				Remediation:       "Review app registrations for client secrets",
				RemediationDetail: "1. az ad app list --all --query \"[].{name:displayName,id:appId}\"\n2. Replace client secrets with certificates or managed identities",
				Priority:          PriorityHigh,
				ScreenshotGuide:   "App registrations showing no client secrets, or documented exceptions",
				ConsoleURL:        "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
				Timestamp:         time.Now(),
				Frameworks:        map[string]string{"PCI-DSS": "Req 8.6.1"},
			},
		}
	}

	if c.graphClient == nil {
		return manual("Microsoft Graph client unavailable")
	}

	apps, err := c.graphClient.Applications().Get(ctx, nil)
	if err != nil {
		return manual(fmt.Sprintf("unable to query app registrations (%v)", err))
	}

	withSecrets := []string{}
	staleSecrets := []string{}
	for _, app := range apps.GetValue() {
		name := "unnamed"
		if app.GetDisplayName() != nil {
			name = *app.GetDisplayName()
		}
		creds := app.GetPasswordCredentials()
		if len(creds) == 0 {
			continue
		}
		withSecrets = append(withSecrets, name)
		for _, cred := range creds {
			if cred.GetStartDateTime() == nil {
				continue
			}
			if days := int(time.Since(*cred.GetStartDateTime()).Hours() / 24); days > 90 {
				staleSecrets = append(staleSecrets, fmt.Sprintf("%s (%d days)", name, days))
			}
		}
	}

	results := []CheckResult{}
	if len(withSecrets) > 0 {
		shown := withSecrets
		if len(shown) > 3 {
			shown = shown[:3]
		}
		results = append(results, CheckResult{
			Control:           "PCI-8.6.1",
			Name:              "[PCI-DSS] Application Account Credential Management",
			Status:            "FAIL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 8.6.1 (mandatory since 31 Mar 2025): %d app registration(s) hold client secrets, which are long-lived credentials usable outside Azure: %s", len(withSecrets), strings.Join(shown, ", ")),
			Remediation:       "Replace client secrets with managed identities or certificates",
			RemediationDetail: "1. Prefer a managed identity, which removes the credential entirely\n2. Otherwise use a certificate credential\n3. Where a secret is unavoidable, document the exceptional circumstance",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "App registration showing no client secrets",
			ConsoleURL:        "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 8.6.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "PCI-8.6.1",
			Name:       "[PCI-DSS] Application Account Credential Management",
			Status:     "PASS",
			Evidence:   "PCI-DSS Req 8.6.1: no app registration holds a client secret",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"PCI-DSS": "Req 8.6.1"},
		})
	}

	if len(staleSecrets) > 0 {
		shown := staleSecrets
		if len(shown) > 3 {
			shown = shown[:3]
		}
		results = append(results, CheckResult{
			Control:           "PCI-8.6.3",
			Name:              "[PCI-DSS] Application Account Credential Rotation",
			Status:            "FAIL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 8.6.3 (mandatory since 31 Mar 2025): %d client secret(s) older than 90 days: %s", len(staleSecrets), strings.Join(shown, ", ")),
			Remediation:       "Rotate or eliminate long-lived client secrets",
			RemediationDetail: "1. Prefer removing the secret in favour of a managed identity\n2. Otherwise create a replacement, update consumers, then delete the old secret\n3. Set the rotation frequency from your targeted risk analysis (Req 12.3.1)",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "App registration credential list showing ages within your defined rotation period",
			ConsoleURL:        "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 8.6.3"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "PCI-8.6.3",
			Name:       "[PCI-DSS] Application Account Credential Rotation",
			Status:     "PASS",
			Evidence:   "PCI-DSS Req 8.6.3: no client secret is older than 90 days",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"PCI-DSS": "Req 8.6.3"},
		})
	}
	return results
}

// checkDiagnosticRouting covers 10.4.1.1. Activity logs routed to a Log
// Analytics workspace are what make automated review possible; reading the
// activity log blade by hand is not automated review.
func (c *AzurePCIChecks) checkDiagnosticRouting(ctx context.Context) []CheckResult {
	fail := func(status, evidence string) []CheckResult {
		return []CheckResult{
			{
				Control:           "PCI-10.4.1.1",
				Name:              "[PCI-DSS] Automated Audit Log Review",
				Status:            status,
				Evidence:          evidence,
				Remediation:       "Route activity logs to Log Analytics and alert on them",
				RemediationDetail: "1. Configure a subscription diagnostic setting to a Log Analytics workspace\n2. Create alert rules for the events your risk analysis identifies\n3. Attach an action group so alerts reach someone",
				Priority:          PriorityHigh,
				ScreenshotGuide:   "Diagnostic settings sending to Log Analytics, plus the alert rules defined on it",
				ConsoleURL:        "https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade",
				Timestamp:         time.Now(),
				Frameworks:        map[string]string{"PCI-DSS": "Req 10.4.1.1"},
			},
		}
	}

	if c.diagnosticClient == nil || c.subscriptionID == "" {
		return fail("INFO", "PCI-DSS Req 10.4.1.1 (mandatory since 31 Mar 2025): audit log reviews must be automated. Diagnostic settings client unavailable, verify by hand")
	}

	routed := []string{}
	pager := c.diagnosticClient.NewListPager("/subscriptions/"+c.subscriptionID, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fail("INFO", fmt.Sprintf("PCI-DSS Req 10.4.1.1 (mandatory since 31 Mar 2025): unable to read diagnostic settings (%v), verify by hand", err))
		}
		for _, ds := range page.Value {
			if ds == nil || ds.Properties == nil {
				continue
			}
			if ds.Properties.WorkspaceID != nil && *ds.Properties.WorkspaceID != "" {
				name := ""
				if ds.Name != nil {
					name = *ds.Name
				}
				routed = append(routed, name)
			}
		}
	}

	if len(routed) == 0 {
		return fail("FAIL", "PCI-DSS Req 10.4.1.1 (mandatory since 31 Mar 2025): no subscription diagnostic setting routes activity logs to a Log Analytics workspace, so log review is not automated")
	}

	return []CheckResult{
		{
			Control:           "PCI-10.4.1.1",
			Name:              "[PCI-DSS] Automated Audit Log Review",
			Status:            "PASS",
			Evidence:          fmt.Sprintf("PCI-DSS Req 10.4.1.1: %d diagnostic setting(s) route activity logs to Log Analytics: %s", len(routed), strings.Join(routed, ", ")),
			Remediation:       "Confirm alert rules act on the routed logs",
			RemediationDetail: "Routing alone is not review. Ensure alert rules exist for the events your risk analysis identifies.",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Log Analytics alert rules defined against the routed activity logs",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 10.4.1.1"},
		},
	}
}
