package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/sqladmin/v1"
)

// GCPPCIChecks implements PCI-DSS v4.0.1 requirements for GCP
type GCPPCIChecks struct {
	storageClient  *storage.Client
	iamClient      *admin.IamClient
	computeService *compute.Service
	sqlService     *sqladmin.Service
	kmsClient      *kms.KeyManagementClient
	loggingClient  *logging.ConfigClient
	projectID      string
}

func NewGCPPCIChecks(
	storageClient *storage.Client,
	iamClient *admin.IamClient,
	computeService *compute.Service,
	sqlService *sqladmin.Service,
	kmsClient *kms.KeyManagementClient,
	loggingClient *logging.ConfigClient,
	projectID string,
) *GCPPCIChecks {
	return &GCPPCIChecks{
		storageClient:  storageClient,
		iamClient:      iamClient,
		computeService: computeService,
		sqlService:     sqlService,
		kmsClient:      kmsClient,
		loggingClient:  loggingClient,
		projectID:      projectID,
	}
}

func (c *GCPPCIChecks) Name() string {
	return "GCP PCI-DSS v4.0.1 Requirements"
}

func (c *GCPPCIChecks) Run(ctx context.Context) ([]CheckResult, error) {
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

	// Requirement 8: Authentication
	results = append(results, c.CheckReq8_Authentication(ctx)...)

	// Requirement 9: Physical Access Controls
	results = append(results, c.CheckReq9_PhysicalAccess(ctx)...)

	// v4.x requirements that became mandatory on 31 March 2025
	results = append(results, c.CheckFutureDated(ctx)...)

	// Requirement 10: Logging
	results = append(results, c.CheckReq10_Logging(ctx)...)

	// Requirement 11: Security Testing
	results = append(results, c.CheckReq11_SecurityTesting(ctx)...)

	// Requirement 12: Information Security Policy
	results = append(results, c.CheckReq12_SecurityPolicy(ctx)...)

	return results, nil
}

// Requirement 1: Network segmentation for CDE
func (c *GCPPCIChecks) CheckReq1_NetworkSegmentation(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Use NetworkChecks to verify firewall rules
	networkChecker := NewNetworkChecks(c.computeService, c.projectID)
	firewallResults := networkChecker.CheckFirewallRules(ctx)

	for _, result := range firewallResults {
		if result.Status == "FAIL" {
			// Re-label with PCI control ID
			result.Control = "PCI-1.2.1"
			result.Evidence = fmt.Sprintf("PCI-DSS 1.4.2 VIOLATION: %s", result.Evidence)
			results = append(results, result)
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:   "PCI-1.4.2",
			Name:      "[PCI-DSS] Network Segmentation",
			Status:    "PASS",
			Evidence:  "VPC firewall rules properly configured for network segmentation | Meets PCI DSS 1.4.2",
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
func (c *GCPPCIChecks) CheckReq3_StorageEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Use StorageChecks to verify encryption
	storageChecker := NewStorageChecks(c.storageClient, c.projectID)
	encryptionResults := storageChecker.CheckBucketEncryption(ctx)

	unencryptedCount := 0
	for _, result := range encryptionResults {
		if result.Status == "FAIL" {
			unencryptedCount++
		}
	}

	if unencryptedCount > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-3.5.1",
			Name:              "[PCI-DSS] Storage Encryption (Mandatory)",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS 3.5.1 VIOLATION: %d storage buckets without customer-managed encryption keys", unencryptedCount),
			Remediation:       "Enable customer-managed encryption keys (CMEK) immediately for cardholder data",
			RemediationDetail: "gcloud storage buckets update gs://BUCKET_NAME --default-encryption-key=KMS_KEY",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "Storage → Bucket → Encryption showing CMEK",
			Frameworks: map[string]string{
				"PCI-DSS": "3.4, 3.4.1",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-3.5.1",
			Name:      "[PCI-DSS] Storage Encryption",
			Status:    "PASS",
			Evidence:  "All storage buckets use encryption | Meets PCI DSS 3.5.1",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "3.5.1",
			},
		})
	}

	// Check KMS key rotation (PCI-DSS 3.7.4)
	kmsChecker := NewKMSChecks(c.kmsClient, c.projectID)
	keyResults := kmsChecker.CheckKMSKeyRotation(ctx)
	for _, result := range keyResults {
		if result.Status == "FAIL" {
			result.Control = "PCI-3.6.4"
			result.Evidence = fmt.Sprintf("PCI-DSS 3.7.4: %s", result.Evidence)
			results = append(results, result)
		}
	}

	return results
}

// Requirement 4: Encryption in transit
func (c *GCPPCIChecks) CheckReq4_TransitEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check SQL SSL enforcement
	sqlChecker := NewSQLChecks(c.sqlService, c.projectID)
	sslResults := sqlChecker.CheckSSLRequired(ctx)

	for _, result := range sslResults {
		if result.Status == "FAIL" {
			result.Control = "PCI-4.1"
			result.Evidence = fmt.Sprintf("PCI-DSS 4.2.1 VIOLATION: %s", result.Evidence)
			result.Severity = "CRITICAL"
			result.Priority = PriorityCritical
			results = append(results, result)
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:   "PCI-4.2.1",
			Name:      "[PCI-DSS] Encryption in Transit",
			Status:    "PASS",
			Evidence:  "SSL/TLS encryption enforced for all connections | Meets PCI DSS 4.2.1",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "4.2.1",
			},
		})
	}

	return results
}

// Requirement 7: Access control
func (c *GCPPCIChecks) CheckReq7_AccessControl(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for excessive privileged roles
	iamChecker := NewIAMChecks(c.iamClient, c.projectID)
	iamResults := iamChecker.CheckPrimitiveRoles(ctx)

	for _, result := range iamResults {
		if result.Status == "FAIL" && strings.Contains(result.Evidence, "primitive roles") {
			result.Control = "PCI-7.1"
			result.Evidence = fmt.Sprintf("PCI-DSS 7.2.1: %s", result.Evidence)
			result.Severity = "HIGH"
			results = append(results, result)
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:   "PCI-7.2.1",
			Name:      "[PCI-DSS] Least Privilege",
			Status:    "PASS",
			Evidence:  "IAM follows least privilege principle | Meets PCI DSS 7.2.1",
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
func (c *GCPPCIChecks) CheckReq8_Authentication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// MFA enforcement (PCI requires MFA for ALL access)
	results = append(results, CheckResult{
		Control:           "PCI-8.4.2",
		Name:              "[PCI-DSS] MFA for ALL Access",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.4.2: MANUAL CHECK - Verify MFA enabled for ALL users accessing the CDE (cloud portal, CLI and API all count as non-console access under 8.4.2)",
		Remediation:       "Enable MFA for every user accessing the cardholder data environment",
		RemediationDetail: "Google Workspace Admin → Security → 2-Step Verification → Enforce for all organizational units",
		ScreenshotGuide:   "Google Admin Console → Security → 2-Step Verification → Screenshot enforcement for all users",
		ConsoleURL:        "https://admin.google.com/ac/security/2sv",
		Priority:          PriorityCritical,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.4.2",
		},
	})

	// Service account key rotation (90-day requirement)
	iamChecker := NewIAMChecks(c.iamClient, c.projectID)
	keyResults := iamChecker.CheckServiceAccountKeys(ctx)

	for _, result := range keyResults {
		if result.Status == "FAIL" && strings.Contains(result.Evidence, "90 days") {
			result.Control = "PCI-8.2.4"
			result.Evidence = fmt.Sprintf("PCI-DSS 8.3.9: %s", result.Evidence)
			results = append(results, result)
		}
	}

	// Session timeout
	results = append(results, CheckResult{
		Control:           "PCI-8.2.8",
		Name:              "[PCI-DSS] 15-Minute Session Timeout",
		Status:            "INFO",
		Evidence:          "PCI-DSS 8.2.8: Configure 15-minute idle timeout for all sessions",
		Remediation:       "Set session timeout to 15 minutes via Identity-Aware Proxy or workspace settings",
		RemediationDetail: "Cloud Console → IAP → Configure session duration = 15 minutes",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.2.8",
		},
	})

	return results
}

// Requirement 10: Logging
func (c *GCPPCIChecks) CheckReq10_Logging(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Audit logging
	loggingChecker := NewLoggingChecks(c.loggingClient, c.projectID)
	loggingResults, _ := loggingChecker.Run(ctx)

	for _, result := range loggingResults {
		if result.Control == "CC7.2" {
			// Re-map to PCI control
			newResult := result
			newResult.Control = "PCI-10.1"
			newResult.Evidence = fmt.Sprintf("PCI-DSS 10.2.1.1: %s", result.Evidence)
			results = append(results, newResult)
		}
	}

	// 12-month retention requirement
	results = append(results, CheckResult{
		Control:           "PCI-10.5.1",
		Name:              "[PCI-DSS] 12-Month Log Retention",
		Status:            "INFO",
		Evidence:          "PCI-DSS 10.5.1: Logs must be retained for 12+ months (3 months readily available)",
		Remediation:       "Configure Cloud Storage lifecycle for 365+ day retention",
		RemediationDetail: "Storage bucket → Lifecycle management → Retain for 365+ days",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		ScreenshotGuide:   "Logging → Log Router → Sink → Storage bucket lifecycle policy showing 365+ day retention",
		Frameworks: map[string]string{
			"PCI-DSS": "10.5.1",
		},
	})

	return results
}

// Requirement 2: Default Passwords
func (c *GCPPCIChecks) CheckReq2_DefaultPasswords(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-2.2.2",
		Name:              "[PCI-DSS] Change Default Passwords",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS 2.2.4 requires changing vendor defaults before deploying systems",
		Remediation:       "Ensure all default passwords are changed",
		RemediationDetail: "1. Change default passwords on all GCP services and third-party systems\n2. Review Compute Engine instances for default SSH keys\n3. Change default database passwords\n4. Document password change procedures",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document password change procedures and verification checklist",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/compute/instances?project=%s", c.projectID),
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 2.2.2, 2.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-2.2.4",
		Name:              "[PCI-DSS] Disable Default Network Configurations",
		Status:            "INFO",
		Evidence:          "MANUAL: Review VPC default configurations and remove unnecessary default rules",
		Remediation:       "Disable or customize default network configurations",
		RemediationDetail: "Review VPC firewall rules for overly permissive default rules",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "VPC Network → Firewall → Show customized, restrictive rules",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/networking/firewalls/list?project=%s", c.projectID),
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 2.2.4",
		},
	})

	return results
}

// Requirement 5: Malware Protection
func (c *GCPPCIChecks) CheckReq5_MalwareProtection(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-5.2.1",
		Name:              "[PCI-DSS] Anti-Malware Protection",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 5.2.1 requires anti-malware on all systems commonly affected by malware",
		Remediation:       "Deploy and maintain anti-malware solution",
		RemediationDetail: "1. Deploy endpoint protection on Compute Engine instances\n2. Consider Google Chronicle or third-party solutions\n3. Ensure anti-malware is active and up-to-date\n4. Configure automatic updates and periodic scans",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Security Command Center → Show anti-malware deployed on all systems",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/security/command-center?project=%s", c.projectID),
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
		RemediationDetail: "Configure automatic signature updates and verify logs show active scanning",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Anti-malware console → Show automatic updates enabled and recent scan logs",
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
		RemediationDetail: "Enable logging for all anti-malware events and configure retention",
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
func (c *GCPPCIChecks) CheckReq6_SecureSystems(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-6.3.3",
		Name:              "[PCI-DSS] Security Patching",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 6.3.3 requires critical security patches within 30 days",
		Remediation:       "Implement patch management process",
		RemediationDetail: "1. Use OS Patch Management for Compute Engine\n2. Implement automated patching where possible\n3. Document patch management procedures\n4. Track critical patches and ensure 30-day compliance",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "VM Manager → Patch Management → Show patch compliance status",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/compute/osconfig?project=%s", c.projectID),
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
		RemediationDetail: "1. Implement code review process\n2. Conduct security testing before deployment\n3. Use Cloud Build for automated security scanning\n4. Document SDLC procedures",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document SDLC procedures and security review checkpoints",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/cloud-build?project=%s", c.projectID),
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
		Remediation:       "Implement Google Cloud Armor for web applications",
		RemediationDetail: "PCI requires WAF or regular code reviews for public-facing web apps",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Network Security → Cloud Armor → Show policies protecting web applications",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/net-security/securitypolicies/list?project=%s", c.projectID),
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 6.4.2",
		},
	})

	return results
}

// Requirement 9: Physical Access Controls
func (c *GCPPCIChecks) CheckReq9_PhysicalAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-9.1.1",
		Name:              "[PCI-DSS] Physical Access Controls",
		Status:            "INFO",
		Evidence:          "INFO: GCP data centers have physical security controls (inherited control). Review GCP compliance documentation.",
		Remediation:       "Document GCP physical security inheritance",
		RemediationDetail: "1. Review GCP PCI-DSS Attestation of Compliance (AOC)\n2. Download GCP PCI-DSS Responsibility Matrix\n3. Document inherited physical controls\n4. Focus on organizational physical security for offices with cardholder data access",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "GCP Compliance Reports → Download PCI-DSS AOC showing physical security controls",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/security/compliance?project=%s", c.projectID),
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
		RemediationDetail: "1. Implement badge/access card system\n2. Establish visitor log procedures\n3. Differentiate badges for employees vs visitors\n4. Require escort for visitors in sensitive areas",
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
		RemediationDetail: "1. Store backup media in secure location\n2. Maintain inventory of all media with cardholder data\n3. Review media inventory at least annually\n4. Securely destroy media when no longer needed",
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
func (c *GCPPCIChecks) CheckReq11_SecurityTesting(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-11.3.2",
		Name:              "[PCI-DSS] Quarterly Vulnerability Scans",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.3.2: PCI requires QUARTERLY vulnerability scans by Approved Scanning Vendor (ASV)",
		Remediation:       "Schedule quarterly ASV scans",
		RemediationDetail: "1. Engage PCI-approved ASV\n2. Schedule quarterly external scans\n3. Internal scans can use Security Command Center",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document ASV scan reports dated within last 90 days",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/security/command-center?project=%s", c.projectID),
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
		RemediationDetail: "Use Security Command Center or third-party FIM tools",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Show FIM configuration and monitoring for critical system files",
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
		RemediationDetail: "Use Security Command Center for configuration monitoring",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Security Command Center → Show change detection enabled",
		ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/security/command-center?project=%s", c.projectID),
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.5.2",
		},
	})

	return results
}

// Requirement 12: Information Security Policy
func (c *GCPPCIChecks) CheckReq12_SecurityPolicy(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	results = append(results, CheckResult{
		Control:           "PCI-12.1.1",
		Name:              "[PCI-DSS] Security Policy Establishment",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 12.1.1 requires establishing, publishing, maintaining, and disseminating a security policy",
		Remediation:       "Create and maintain comprehensive information security policy",
		RemediationDetail: "1. Establish security policy addressing PCI-DSS requirements\n2. Review policy at least annually\n3. Update when environment changes\n4. Communicate to all relevant personnel",
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
		RemediationDetail: "1. Perform formal risk assessment at least annually\n2. Identify critical assets and threats\n3. Assess likelihood and impact\n4. Document risk assessment results",
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
		RemediationDetail: "1. Define acceptable use for all critical technologies\n2. Require management approval\n3. Require authentication\n4. Maintain list of authorized devices and personnel",
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
		RemediationDetail: "1. Formally assign information security responsibilities\n2. Define roles and responsibilities for PCI-DSS compliance\n3. Document organizational structure",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document organizational chart showing security responsibilities",
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
		RemediationDetail: "1. Provide security awareness training upon hire and at least annually\n2. Train personnel on protecting cardholder data\n3. Require personnel acknowledgment\n4. Document training completion",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document training program, completion records, and acknowledgments",
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
		RemediationDetail: "1. Maintain list of service providers\n2. Establish written agreement including PCI-DSS responsibilities\n3. Monitor service provider PCI-DSS compliance status at least annually",
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
		RemediationDetail: "1. Create incident response plan\n2. Assign roles and responsibilities\n3. Test plan at least annually\n4. Update plan based on test results",
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
// 31 March 2025 and can be assessed from GCP configuration.
func (c *GCPPCIChecks) CheckFutureDated(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// 4.2.1.1 - inventory of trusted keys and certificates protecting PAN in
	// transit. Certificate Manager is not among this scanner's clients.
	results = append(results, CheckResult{
		Control:           "PCI-4.2.1.1",
		Name:              "[PCI-DSS] Trusted Key and Certificate Inventory",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 4.2.1.1 (mandatory since 31 Mar 2025): maintain an inventory of trusted keys and certificates used to protect PAN in transit",
		Remediation:       "Maintain a documented certificate inventory",
		RemediationDetail: "1. List certificates: gcloud certificate-manager certificates list\n2. Record issuer, expiry and the service each protects\n3. Review at least annually and on renewal",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Certificate Manager showing issued certificates, plus the maintained inventory document",
		ConsoleURL:        "https://console.cloud.google.com/security/ccm/list/lbCertificates",
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"PCI-DSS": "Req 4.2.1.1"},
	})

	// 8.6.1 and 8.6.3 - service accounts with user-managed keys are the GCP
	// equivalent of long-lived application credentials. System-managed keys are
	// rotated by Google and are not in scope here.
	withUserKeys := []string{}
	staleKeys := []string{}
	it := c.iamClient.ListServiceAccounts(ctx, &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", c.projectID),
	})
	iamErr := ""
	for {
		sa, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			iamErr = err.Error()
			break
		}
		keyResp, err := c.iamClient.ListServiceAccountKeys(ctx, &adminpb.ListServiceAccountKeysRequest{Name: sa.Name})
		if err != nil {
			continue
		}
		for _, key := range keyResp.Keys {
			if key.KeyType != adminpb.ListServiceAccountKeysRequest_USER_MANAGED {
				continue
			}
			if len(withUserKeys) == 0 || withUserKeys[len(withUserKeys)-1] != sa.Email {
				withUserKeys = append(withUserKeys, sa.Email)
			}
			if key.ValidAfterTime != nil {
				if days := int(time.Since(key.ValidAfterTime.AsTime()).Hours() / 24); days > 90 {
					staleKeys = append(staleKeys, fmt.Sprintf("%s (%d days)", sa.Email, days))
				}
			}
		}
	}

	if iamErr != "" {
		results = append(results, CheckResult{
			Control:    "PCI-8.6.1",
			Name:       "[PCI-DSS] Application Account Credential Management",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Unable to list service accounts: %s", iamErr),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"PCI-DSS": "Req 8.6.1"},
		})
	} else if len(withUserKeys) > 0 {
		shown := withUserKeys
		if len(shown) > 3 {
			shown = shown[:3]
		}
		results = append(results, CheckResult{
			Control:           "PCI-8.6.1",
			Name:              "[PCI-DSS] Application Account Credential Management",
			Status:            "FAIL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 8.6.1 (mandatory since 31 Mar 2025): %d service account(s) hold user-managed keys, which are long-lived credentials usable outside GCP: %s", len(withUserKeys), strings.Join(shown, ", ")),
			Remediation:       "Replace user-managed keys with workload identity",
			RemediationDetail: "1. Use Workload Identity Federation or attached service accounts instead of exported keys\n2. Delete the key: gcloud iam service-accounts keys delete KEY_ID --iam-account=EMAIL\n3. Where a key is unavoidable, document the exceptional circumstance",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "IAM service account showing no user-managed keys",
			ConsoleURL:        "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 8.6.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "PCI-8.6.1",
			Name:       "[PCI-DSS] Application Account Credential Management",
			Status:     "PASS",
			Evidence:   "PCI-DSS Req 8.6.1: no service account holds user-managed keys",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"PCI-DSS": "Req 8.6.1"},
		})
	}

	// 8.6.2 - credentials must not be hard coded. Not visible from configuration.
	results = append(results, CheckResult{
		Control:           "PCI-8.6.2",
		Name:              "[PCI-DSS] No Hardcoded Application Credentials",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 8.6.2 (mandatory since 31 Mar 2025): passwords for application and system accounts must not be hard coded in scripts, configuration files or source code",
		Remediation:       "Move credentials to Secret Manager",
		RemediationDetail: "1. Scan repositories for embedded service account keys\n2. Move secrets to Secret Manager\n3. Grant access via workload identity rather than exported keys",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Secret Manager inventory, plus evidence of secret scanning in CI",
		ConsoleURL:        "https://console.cloud.google.com/security/secret-manager",
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"PCI-DSS": "Req 8.6.2"},
	})

	if iamErr != "" {
		results = append(results, CheckResult{
			Control:    "PCI-8.6.3",
			Name:       "[PCI-DSS] Application Account Credential Rotation",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Service account enumeration failed (%s), so key ages could not be assessed", iamErr),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"PCI-DSS": "Req 8.6.3"},
		})
	} else if len(staleKeys) > 0 {
		shown := staleKeys
		if len(shown) > 3 {
			shown = shown[:3]
		}
		results = append(results, CheckResult{
			Control:           "PCI-8.6.3",
			Name:              "[PCI-DSS] Application Account Credential Rotation",
			Status:            "FAIL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 8.6.3 (mandatory since 31 Mar 2025): %d user-managed key(s) older than 90 days: %s", len(staleKeys), strings.Join(shown, ", ")),
			Remediation:       "Rotate or eliminate long-lived service account keys",
			RemediationDetail: "1. Prefer removing the key entirely in favour of workload identity\n2. Otherwise create a replacement, update consumers, then delete the old key\n3. Set the rotation frequency from your targeted risk analysis (Req 12.3.1)",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Service account key list showing ages within your defined rotation period",
			ConsoleURL:        "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 8.6.3"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "PCI-8.6.3",
			Name:       "[PCI-DSS] Application Account Credential Rotation",
			Status:     "PASS",
			Evidence:   "PCI-DSS Req 8.6.3: no user-managed service account key is older than 90 days",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"PCI-DSS": "Req 8.6.3"},
		})
	}

	// 10.4.1.1 - automated log review. A log sink exporting to BigQuery, Pub/Sub
	// or storage is the mechanism that makes automated review possible.
	sinks := []string{}
	sinkErr := ""
	sit := c.loggingClient.ListSinks(ctx, &loggingpb.ListSinksRequest{
		Parent: fmt.Sprintf("projects/%s", c.projectID),
	})
	for {
		sink, err := sit.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			// Treating a permission error the same as "no sinks" would report a
			// failure the project does not have.
			sinkErr = err.Error()
			break
		}
		// The _Default and _Required sinks exist in every project and are not
		// evidence that anyone configured automated review.
		if sink.Name == "_Default" || sink.Name == "_Required" {
			continue
		}
		sinks = append(sinks, sink.Name)
	}

	if sinkErr != "" {
		results = append(results, CheckResult{
			Control:    "PCI-10.4.1.1",
			Name:       "[PCI-DSS] Automated Audit Log Review",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Could not list log sinks (%s), so automated log review could not be assessed", sinkErr),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"PCI-DSS": "Req 10.4.1.1"},
		})
	} else if len(sinks) > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-10.4.1.1",
			Name:              "[PCI-DSS] Automated Audit Log Review",
			Status:            "PASS",
			Evidence:          fmt.Sprintf("PCI-DSS Req 10.4.1.1: %d log sink(s) configured: %s", len(sinks), strings.Join(sinks, ", ")),
			Remediation:       "Confirm alerting policies act on the exported logs",
			RemediationDetail: "Export alone is not review. Ensure log-based metrics and alerting policies exist for the events your risk analysis identifies.",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Log sinks plus the alerting policies defined on log-based metrics",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 10.4.1.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:           "PCI-10.4.1.1",
			Name:              "[PCI-DSS] Automated Audit Log Review",
			Status:            "FAIL",
			Evidence:          "PCI-DSS Req 10.4.1.1 (mandatory since 31 Mar 2025): no log sink is configured, so log review is not automated",
			Remediation:       "Export logs and alert on them",
			RemediationDetail: "1. gcloud logging sinks create NAME DESTINATION\n2. Create log-based metrics for the events your risk analysis identifies\n3. Attach alerting policies with a notification channel",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Logging sink configuration and the alerting policies defined on it",
			ConsoleURL:        "https://console.cloud.google.com/logs/router",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"PCI-DSS": "Req 10.4.1.1"},
		})
	}

	// 10.7.2 / 10.7.3 - detecting and responding to failures of critical security
	// control systems. Whether alerting exists on control failure is not visible
	// from the clients available here.
	results = append(results, CheckResult{
		Control:           "PCI-10.7.2",
		Name:              "[PCI-DSS] Security Control Failure Detection",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 10.7.2 (mandatory since 31 Mar 2025): failures of critical security control systems must be detected and alerted on, including logging, network controls and change detection",
		Remediation:       "Alert on the disabling of security controls",
		RemediationDetail: "1. Create log-based metrics for audit log configuration changes and sink deletion\n2. Attach alerting policies with a notification channel\n3. Include firewall and org policy changes",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Alerting policies covering logging configuration changes and sink deletion",
		ConsoleURL:        "https://console.cloud.google.com/monitoring/alerting",
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{"PCI-DSS": "Req 10.7.2"},
	})

	results = append(results, CheckResult{
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
	})

	return results
}
