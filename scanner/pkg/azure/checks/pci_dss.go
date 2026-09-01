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
)

// AzurePCIChecks implements PCI-DSS v4.0.1 requirements for Azure
type AzurePCIChecks struct {
	storageClient *armstorage.AccountsClient
	networkClient *armnetwork.SecurityGroupsClient
	roleClient    *armauthorization.RoleAssignmentsClient
	sqlClient     *armsql.DatabasesClient
	monitorClient *armmonitor.ActivityLogsClient
}

func NewAzurePCIChecks(
	storageClient *armstorage.AccountsClient,
	networkClient *armnetwork.SecurityGroupsClient,
	roleClient *armauthorization.RoleAssignmentsClient,
	sqlClient *armsql.DatabasesClient,
	monitorClient *armmonitor.ActivityLogsClient,
) *AzurePCIChecks {
	return &AzurePCIChecks{
		storageClient: storageClient,
		networkClient: networkClient,
		roleClient:    roleClient,
		sqlClient:     sqlClient,
		monitorClient: monitorClient,
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
			Control:           "PCI-1.2.1",
			Name:              "[PCI-DSS] Network Segmentation",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "PCI-DSS 1.2.1 VIOLATION: No Network Security Groups found - no network segmentation",
			Remediation:       "Create NSGs for network segmentation",
			RemediationDetail: "Create separate VNets/subnets for CDE with restrictive NSGs",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "Azure Portal → Virtual networks → Show segmented CDE network",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FvirtualNetworks",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "1.2.1",
			},
		})
	} else if subnetAssociations < nsgCount {
		results = append(results, CheckResult{
			Control:           "PCI-1.2.3",
			Name:              "[PCI-DSS] NSG Subnet Associations",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS 1.2.3: %d NSGs but only %d subnet associations - incomplete segmentation", nsgCount, subnetAssociations),
			Remediation:       "Associate NSGs with all subnets",
			RemediationDetail: "Every subnet should have an NSG for proper segmentation",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "1.2.3",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-1.2.1",
			Name:      "[PCI-DSS] Network Segmentation",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d NSGs with %d subnet associations configured", nsgCount, subnetAssociations),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "1.2.1",
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
			Control:           "PCI-3.4",
			Name:              "[PCI-DSS] Storage Encryption (Mandatory)",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS 3.4 VIOLATION: %d storage accounts NOT encrypted", len(unencryptedStorage)),
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
			Control:           "PCI-3.5",
			Name:              "[PCI-DSS] Encryption Key Management",
			Status:            "INFO",
			Evidence:          fmt.Sprintf("PCI-DSS 3.5: All storage uses Microsoft-managed keys - consider customer-managed keys for CDE"),
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
			Control:           "PCI-4.1",
			Name:              "[PCI-DSS] HTTPS Enforcement",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS 4.1 VIOLATION: %d storage accounts allow HTTP: %s", len(noHTTPS), strings.Join(noHTTPS[:min(3, len(noHTTPS))], ", ")),
			Remediation:       "Enable HTTPS-only immediately",
			RemediationDetail: fmt.Sprintf("az storage account update --name %s --https-only true", noHTTPS[0]),
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "4.1",
			},
		})
	}

	if len(noTLS12) > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-4.1",
			Name:              "[PCI-DSS] TLS 1.2+ Required",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS 4.1: %d storage accounts allow TLS < 1.2: %s", len(noTLS12), strings.Join(noTLS12[:min(3, len(noTLS12))], ", ")),
			Remediation:       "Set minimum TLS version to 1.2",
			RemediationDetail: fmt.Sprintf("az storage account update --name %s --min-tls-version TLS1_2", noTLS12[0]),
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Storage → Configuration → Minimum TLS version = 1.2",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "4.1",
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
			Control:           "PCI-7.1",
			Name:              "[PCI-DSS] Least Privilege Violation",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS 7.1: %d users with privileged access (Owner: %d, Contributor: %d, UAA: %d) - excessive", totalPrivileged, ownerCount, contributorCount, userAccessAdminCount),
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
			Control:   "PCI-7.1",
			Name:      "[PCI-DSS] Least Privilege",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d privileged users (acceptable for PCI)", totalPrivileged),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "7.1",
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
		Control:           "PCI-8.3.1",
		Name:              "[PCI-DSS] MFA for ALL Access",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.3.1: MANUAL CHECK - Verify MFA enabled for ALL users with console access",
		Remediation:       "Enable MFA for every user - no exceptions",
		RemediationDetail: "Azure AD → Users → Per-user MFA → Enable for ALL",
		ScreenshotGuide:   "Azure AD → Users → Show MFA status = Enabled/Enforced for ALL users",
		Priority:          PriorityCritical,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.3.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-8.2.4",
		Name:              "[PCI-DSS] 90-Day Password Rotation",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.2.4: MANUAL CHECK - Passwords MUST expire every 90 days maximum",
		Remediation:       "Configure 90-day password expiration",
		RemediationDetail: "Azure AD → Password policy → Maximum age = 90 days",
		Priority:          PriorityCritical,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.2.4",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-8.1.8",
		Name:              "[PCI-DSS] 15-Minute Session Timeout",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.1.8: Configure 15-minute idle timeout for all sessions",
		Remediation:       "Set session timeout to 15 minutes",
		RemediationDetail: "Azure AD → Conditional Access → Session policy = 15 minutes",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.1.8",
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
		Control:           "PCI-10.1",
		Name:              "[PCI-DSS] Audit Logging Implementation",
		Status:            "INFO",
		Evidence:          "PCI-DSS 10.1: Verify Activity Log is exported to storage/workspace",
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
		Control:           "PCI-10.5.3",
		Name:              "[PCI-DSS] 12-Month Log Retention",
		Status:            "INFO",
		Evidence:          "PCI-DSS 10.5.3: Logs must be retained for 12+ months (3 months readily available)",
		Remediation:       "Configure storage lifecycle for 365+ day retention",
		RemediationDetail: "Storage account → Lifecycle management → Archive after 90 days, delete after 365+",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "10.5.3",
		},
	})

	return results
}

// Requirement 2: Default Passwords
func (c *AzurePCIChecks) CheckReq2_DefaultPasswords(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-2.1",
		Name:              "[PCI-DSS] Change Default Passwords",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS 2.1 requires changing vendor defaults before deploying systems",
		Remediation:       "Ensure all default passwords are changed",
		RemediationDetail: "1. Change default passwords on all Azure services and third-party systems\n2. Review VM images for default credentials\n3. Change default database passwords\n4. Document password change procedures",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document password change procedures and verification checklist",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Compute/VirtualMachinesMenuBlade/overview",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 2.1, 2.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-2.2.2",
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
			"PCI-DSS": "Req 2.2.2",
		},
	})

	return results
}

// Requirement 5: Malware Protection
func (c *AzurePCIChecks) CheckReq5_MalwareProtection(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-5.1",
		Name:              "[PCI-DSS] Anti-Malware Protection",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 5.1 requires anti-malware on all systems commonly affected by malware",
		Remediation:       "Deploy and maintain anti-malware solution",
		RemediationDetail: "1. Deploy Microsoft Defender for Cloud or third-party endpoint protection\n2. Ensure anti-malware is active and up-to-date on all VMs\n3. Configure automatic updates and periodic scans\n4. Document anti-malware solution and update schedule",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Security Center → Recommendations → Show anti-malware deployed on all VMs",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/0",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.1, 5.2.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-5.2.3",
		Name:              "[PCI-DSS] Anti-Malware Updates",
		Status:            "INFO",
		Evidence:          "MANUAL: Verify anti-malware mechanisms are current, actively running, and generating logs",
		Remediation:       "Ensure anti-malware auto-updates are enabled",
		RemediationDetail: "Configure automatic signature updates and verify audit logs show active scanning",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Defender for Cloud → Show automatic updates enabled and recent scan logs",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.2.3, 5.3.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-5.3.2",
		Name:              "[PCI-DSS] Anti-Malware Scan Logs",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI requires anti-malware logs be retained and reviewed periodically",
		Remediation:       "Configure log retention and review procedures",
		RemediationDetail: "1. Enable logging for all anti-malware events\n2. Configure log retention (minimum per Req 10)\n3. Establish periodic review process\n4. Document review findings",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Show anti-malware logs with retention policy and review documentation",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.3.2, 5.3.4",
		},
	})

	return results
}

// Requirement 6: Secure Systems
func (c *AzurePCIChecks) CheckReq6_SecureSystems(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-6.2",
		Name:              "[PCI-DSS] Security Patching",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 6.2 requires critical security patches within 30 days",
		Remediation:       "Implement patch management process",
		RemediationDetail: "1. Use Azure Update Management for automated patching\n2. Implement automated patching where possible\n3. Document patch management procedures\n4. Track critical patches and ensure 30-day compliance",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Automation → Update Management → Show patch compliance status",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Automation/AutomationMenuBlade/updateManagement",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 6.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-6.3.2",
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
			"PCI-DSS": "Req 6.3.2, 6.5",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-6.4.3",
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
			"PCI-DSS": "Req 6.4.3",
		},
	})

	return results
}

// Requirement 9: Physical Access Controls
func (c *AzurePCIChecks) CheckReq9_PhysicalAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-9.1",
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
			"PCI-DSS": "Req 9.1, 9.1.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-9.2",
		Name:              "[PCI-DSS] Physical Access Procedures",
		Status:            "INFO",
		Evidence:          "MANUAL: Develop procedures to control physical access to facilities with systems that store, process, or transmit cardholder data",
		Remediation:       "Document physical access procedures for your facilities",
		RemediationDetail: "1. Implement badge/access card system for facility entry\n2. Establish visitor log procedures\n3. Differentiate badges for employees vs visitors\n4. Require escort for visitors in sensitive areas\n5. Document all procedures",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document physical access control procedures, visitor logs, and badge system",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.2, 9.3",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-9.4",
		Name:              "[PCI-DSS] Media Physical Security",
		Status:            "INFO",
		Evidence:          "MANUAL: Physically secure all media containing cardholder data (backups, portable devices)",
		Remediation:       "Implement physical controls for backup media and portable devices",
		RemediationDetail: "1. Store backup media in secure, locked location\n2. Maintain inventory of all media with cardholder data\n3. Review media inventory at least annually\n4. Securely destroy media when no longer needed (Req 9.8)",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Show backup media inventory, secure storage documentation, and destruction procedures",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.4, 9.5, 9.8",
		},
	})

	return results
}

// Requirement 11: Security Testing
func (c *AzurePCIChecks) CheckReq11_SecurityTesting(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-11.2.2",
		Name:              "[PCI-DSS] Quarterly Vulnerability Scans",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.2.2: PCI requires QUARTERLY vulnerability scans by Approved Scanning Vendor (ASV)",
		Remediation:       "Schedule quarterly ASV scans",
		RemediationDetail: "1. Engage PCI-approved ASV\n2. Schedule quarterly external scans\n3. Internal scans can use Defender for Cloud vulnerability assessment",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document ASV scan reports dated within last 90 days",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/22",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.2.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-11.3.1",
		Name:              "[PCI-DSS] Annual Penetration Testing",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.3.1: PCI requires ANNUAL penetration testing of CDE",
		Remediation:       "Schedule annual penetration test",
		RemediationDetail: "Annual external and internal penetration testing required",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document penetration test reports with dates and findings",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.3.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-11.5",
		Name:              "[PCI-DSS] File Integrity Monitoring",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.5: Deploy file integrity monitoring on critical systems",
		Remediation:       "Implement FIM solution",
		RemediationDetail: "Use Azure File Integrity Monitoring in Defender for Cloud or third-party FIM tools",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Defender for Cloud → File Integrity Monitoring → Show FIM enabled",
		ConsoleURL:        "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/18",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.5",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-11.5.1",
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
			"PCI-DSS": "Req 11.5.1",
		},
	})

	return results
}

// Requirement 12: Information Security Policy
func (c *AzurePCIChecks) CheckReq12_SecurityPolicy(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-12.1",
		Name:              "[PCI-DSS] Security Policy Establishment",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 12.1 requires establishing, publishing, maintaining, and disseminating a security policy",
		Remediation:       "Create and maintain comprehensive information security policy",
		RemediationDetail: "1. Establish security policy addressing PCI-DSS requirements\n2. Review policy at least annually\n3. Update when environment changes\n4. Communicate to all relevant personnel\n5. Document policy review and approval",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document current security policy, annual review dates, and communication records",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.1, 12.1.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.2",
		Name:              "[PCI-DSS] Risk Assessment Process",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement risk assessment process performed at least annually and upon significant changes",
		Remediation:       "Establish annual risk assessment process",
		RemediationDetail: "1. Perform formal risk assessment at least annually\n2. Identify critical assets and threats\n3. Assess likelihood and impact\n4. Document risk assessment results\n5. Update after significant infrastructure changes",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document risk assessments with dates, findings, and mitigation plans",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.3",
		Name:              "[PCI-DSS] Acceptable Use Policies",
		Status:            "INFO",
		Evidence:          "MANUAL: Develop usage policies for critical technologies (remote access, wireless, mobile devices, email, internet)",
		Remediation:       "Create and enforce acceptable use policies",
		RemediationDetail: "1. Define acceptable use for all critical technologies\n2. Require management approval for use of technologies\n3. Require authentication for use of technology\n4. Maintain list of authorized devices and personnel\n5. Document acceptable use policies",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document acceptable use policies, approval records, and technology inventory",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.3",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.5",
		Name:              "[PCI-DSS] Assign Security Responsibilities",
		Status:            "INFO",
		Evidence:          "MANUAL: Assign individual or team responsibility for information security management",
		Remediation:       "Document security responsibilities and assignments",
		RemediationDetail: "1. Formally assign information security responsibilities\n2. Define roles and responsibilities for PCI-DSS compliance\n3. Document organizational structure for security\n4. Ensure adequate resources allocated",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document organizational chart showing security responsibilities and role assignments",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.5, 12.5.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.6",
		Name:              "[PCI-DSS] Security Awareness Program",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement formal security awareness program for all personnel",
		Remediation:       "Establish security awareness and training program",
		RemediationDetail: "1. Provide security awareness training upon hire and at least annually\n2. Train personnel on their responsibilities for protecting cardholder data\n3. Require personnel acknowledge understanding\n4. Document training completion and acknowledgments",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document training program, completion records, and acknowledgment forms",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.6, 12.6.1, 12.6.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.8",
		Name:              "[PCI-DSS] Service Provider Management",
		Status:            "INFO",
		Evidence:          "MANUAL: Maintain and implement policies for service providers who handle cardholder data",
		Remediation:       "Implement service provider management procedures",
		RemediationDetail: "1. Maintain list of service providers\n2. Establish written agreement including PCI-DSS responsibilities\n3. Ensure service providers acknowledge responsibility\n4. Monitor service provider PCI-DSS compliance status at least annually",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document service provider list, contracts, and annual compliance verification",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.8, 12.8.1, 12.8.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.10",
		Name:              "[PCI-DSS] Incident Response Plan",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement an incident response plan for security incidents",
		Remediation:       "Create and test incident response plan",
		RemediationDetail: "1. Create incident response plan\n2. Assign roles and responsibilities\n3. Include specific incident response procedures\n4. Test plan at least annually\n5. Update plan based on test results and industry developments",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document incident response plan, test results, and update history",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.10, 12.10.1",
		},
	})

	return results
}
