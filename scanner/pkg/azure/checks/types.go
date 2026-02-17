package checks

import (
	"fmt"
	"context"
	"time"
)

// Framework constants - same as AWS
const (
	FrameworkSOC2     = "SOC2"
	FrameworkPCI      = "PCI-DSS"
	FrameworkHIPAA    = "HIPAA"
	FrameworkISO      = "ISO-27001"
	FrameworkCISAzure = "CIS-Azure"
)

// CheckResult - identical structure to AWS
type CheckResult struct {
	Control           string            `json:"control"`
	Name              string            `json:"name"`
	Status            string            `json:"status"` // PASS, FAIL, NOT_APPLICABLE, ERROR
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Severity          string            `json:"severity,omitempty"`
	Priority          Priority          `json:"priority"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

// Priority - NO EMOJIS
type Priority struct {
	Level     string `json:"level"`
	Impact    string `json:"impact"`
	TimeToFix string `json:"time_to_fix"`
	WillFail  bool   `json:"will_fail_audit"`
}

// Check interface - same as AWS
type Check interface {
	Run(ctx context.Context) ([]CheckResult, error)
	Name() string
}

// Azure-specific framework mappings with CIS Azure v3.0
var AzureFrameworkMappings = map[string]map[string]string{
	// Identity and Access Management (Section 1)
	"AAD_MFA": {
		FrameworkSOC2:     "CC6.6",
		FrameworkPCI:      "8.3.1",
		FrameworkHIPAA:    "164.312(a)(2)(i)",
		FrameworkISO:      "A.9.4.2",
		FrameworkCISAzure: "1.1, 1.2",
	},
	"AAD_PASSWORD_POLICY": {
		FrameworkSOC2:     "CC6.7",
		FrameworkPCI:      "8.2.3, 8.2.4, 8.2.5",
		FrameworkHIPAA:    "164.308(a)(5)(ii)(D)",
		FrameworkISO:      "A.9.4.3",
		FrameworkCISAzure: "1.3",
	},
	"AAD_PRIVILEGED_ROLES": {
		FrameworkSOC2:     "CC6.2",
		FrameworkPCI:      "7.1.2",
		FrameworkHIPAA:    "164.308(a)(3)(ii)(A)",
		FrameworkISO:      "A.9.2.3",
		FrameworkCISAzure: "1.4, 1.5, 1.6",
	},
	"AAD_GUEST_USERS": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "7.1.1",
		FrameworkHIPAA:    "164.308(a)(4)(ii)(C)",
		FrameworkISO:      "A.9.2.5",
		FrameworkCISAzure: "1.7, 1.8",
	},
	"AAD_CONDITIONAL_ACCESS": {
		FrameworkSOC2:     "CC6.6",
		FrameworkPCI:      "8.3.2",
		FrameworkHIPAA:    "164.312(a)(2)(i)",
		FrameworkISO:      "A.9.4.2",
		FrameworkCISAzure: "1.9, 1.10",
	},

	// Microsoft Defender for Cloud (Section 2) - ENHANCED with granular mappings
	"DEFENDER_ENABLED": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1, 2.2, 2.3",
	},
	"DEFENDER_SERVERS": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.1",
	},
	"DEFENDER_APPSERVICE": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.2",
	},
	"DEFENDER_DATABASES": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.3, 2.1.4, 2.1.5, 2.1.6",
	},
	"DEFENDER_SQL": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.3",
	},
	"DEFENDER_SQL_VM": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.4",
	},
	"DEFENDER_OPENSOURCE_DB": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.5",
	},
	"DEFENDER_COSMOSDB": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.6",
	},
	"DEFENDER_STORAGE": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.7",
	},
	"DEFENDER_CONTAINERS": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.8",
	},
	"DEFENDER_DNS": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.4",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.9",
	},
	"DEFENDER_KEYVAULT": {
		FrameworkSOC2:     "CC6.6",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.10",
	},
	"DEFENDER_API": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "6.5.10",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.11",
	},
	"DEFENDER_ARM": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.12",
	},
	"DEFENDER_AUTO_PROVISIONING": {
		FrameworkSOC2:     "CC7.3",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.17",
	},
	"DEFENDER_AUTOPROVISION": { // Alias
		FrameworkSOC2:     "CC7.3",
		FrameworkPCI:      "11.5.1",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "2.1.17",
	},
	"DEFENDER_CONTACT": {
		FrameworkSOC2:     "CC7.4",
		FrameworkPCI:      "12.10.1",
		FrameworkHIPAA:    "164.308(a)(6)(ii)",
		FrameworkISO:      "A.16.1.2",
		FrameworkCISAzure: "2.1.19",
	},
	"DEFENDER_CONTACTS": { // Alias
		FrameworkSOC2:     "CC7.4",
		FrameworkPCI:      "12.10.1",
		FrameworkHIPAA:    "164.308(a)(6)(ii)",
		FrameworkISO:      "A.16.1.2",
		FrameworkCISAzure: "2.1.19",
	},
	"DEFENDER_ALERTS": {
		FrameworkSOC2:     "CC7.4",
		FrameworkPCI:      "12.10.1",
		FrameworkHIPAA:    "164.308(a)(6)(ii)",
		FrameworkISO:      "A.16.1.2",
		FrameworkCISAzure: "2.1.20",
	},

	// Storage Accounts (Section 3) - ENHANCED with new checks
	"STORAGE_PUBLIC_ACCESS": {
		FrameworkSOC2:     "CC6.2",
		FrameworkPCI:      "1.2.1, 1.3.4",
		FrameworkHIPAA:    "164.312(a)(1)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "3.1, 3.2",
	},
	"STORAGE_ENCRYPTION": {
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4, 3.4.1",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.1",
		FrameworkCISAzure: "3.3, 3.4",
	},
	"STORAGE_INFRASTRUCTURE_ENCRYPTION": {
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4, 3.4.1",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.1",
		FrameworkCISAzure: "4.2",
	},
	"STORAGE_SECURE_TRANSFER": {
		FrameworkSOC2:     "CC6.7",
		FrameworkPCI:      "4.1",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "3.5, 4.15",
	},
	"STORAGE_SOFT_DELETE": {
		FrameworkSOC2:     "CC9.1",
		FrameworkPCI:      "3.1",
		FrameworkHIPAA:    "164.308(a)(7)(ii)(A)",
		FrameworkISO:      "A.12.3.1",
		FrameworkCISAzure: "3.6, 3.7",
	},
	"STORAGE_PUBLIC_NETWORK_ACCESS": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1, 1.3.4",
		FrameworkHIPAA:    "164.312(a)(1)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "4.6",
	},
	"STORAGE_NETWORK_RULES": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "3.8, 3.9, 4.7",
	},
	"STORAGE_BLOB_ANONYMOUS": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1, 1.3.4",
		FrameworkHIPAA:    "164.312(a)(1)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "4.17",
	},
	"STORAGE_CROSS_TENANT": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1",
		FrameworkHIPAA:    "164.312(a)(1)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "4.16",
	},

	// Database Services (Section 4/5) - ENHANCED
	"SQL_TDE": {
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.1",
		FrameworkCISAzure: "4.1, 4.2",
	},
	"SQL_AUDITING": {
		FrameworkSOC2:     "CC7.1",
		FrameworkPCI:      "10.2.1",
		FrameworkHIPAA:    "164.312(b)",
		FrameworkISO:      "A.12.4.1",
		FrameworkCISAzure: "4.3, 4.4",
	},
	"SQL_THREAT_DETECTION": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.4",
		FrameworkHIPAA:    "164.308(a)(1)(ii)(A)",
		FrameworkISO:      "A.12.6.1",
		FrameworkCISAzure: "4.5",
	},
	"SQL_FIREWALL": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "4.6",
	},
	"SQL_PUBLIC_ACCESS": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1, 1.3.4",
		FrameworkHIPAA:    "164.312(a)(1)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "5.1.2, 5.1.7",
	},
	"SQL_ENTRA_AUTH": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "8.2",
		FrameworkHIPAA:    "164.312(a)(2)(i)",
		FrameworkISO:      "A.9.4.2",
		FrameworkCISAzure: "5.1.4",
	},

	// Logging and Monitoring (Section 5)
	"ACTIVITY_LOG": {
		FrameworkSOC2:     "CC7.1",
		FrameworkPCI:      "10.1, 10.2.1",
		FrameworkHIPAA:    "164.312(b)",
		FrameworkISO:      "A.12.4.1",
		FrameworkCISAzure: "5.1, 5.2, 5.1.2, 5.1.3, 5.1.4",
	},
	"ACTIVITY_LOG_RETENTION": {
		FrameworkSOC2:     "CC7.1",
		FrameworkPCI:      "10.7",
		FrameworkHIPAA:    "164.312(b)",
		FrameworkISO:      "A.12.4.1",
		FrameworkCISAzure: "5.3",
	},
	"DIAGNOSTIC_SETTINGS": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "10.2.1",
		FrameworkHIPAA:    "164.312(b)",
		FrameworkISO:      "A.12.4.1",
		FrameworkCISAzure: "5.4, 5.5, 5.1.5, 5.1.6",
	},

	// Networking (Section 6/7) - ENHANCED with specific ports
	"NSG_RULES": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1, 1.3",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "6.1, 6.2, 6.3",
	},
	"NETWORK_RDP_RESTRICTED": {
		FrameworkSOC2:     "CC6.1, CC6.6",
		FrameworkPCI:      "1.2.1, 1.3, 2.2",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "7.1",
	},
	"NETWORK_SSH_RESTRICTED": {
		FrameworkSOC2:     "CC6.1, CC6.6",
		FrameworkPCI:      "1.2.1, 1.3, 2.2",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "7.2",
	},
	"NETWORK_UDP_RESTRICTED": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1, 1.3",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "7.3",
	},
	"NETWORK_HTTP_ACCESS": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "7.4",
	},
	"NSG_FLOW_LOGS": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "10.2.1",
		FrameworkHIPAA:    "164.312(b)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "6.4",
	},
	"NETWORK_WATCHER": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "11.4",
		FrameworkHIPAA:    "164.312(b)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "6.5",
	},

	// Virtual Machines (Section 7) - ENHANCED
	"DISK_ENCRYPTION": {
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4, 3.4.1",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.1",
		FrameworkCISAzure: "7.1, 7.2",
	},
	"VM_MANAGED_DISKS": {
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4.1",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.1",
		FrameworkCISAzure: "7.3",
	},
	"VM_ENDPOINT_PROTECTION": {
		FrameworkSOC2:     "CC7.2",
		FrameworkPCI:      "5.1",
		FrameworkHIPAA:    "164.308(a)(5)(ii)(B)",
		FrameworkISO:      "A.12.2.1",
		FrameworkCISAzure: "7.4, 7.5",
	},
	"VM_BACKUP": {
		FrameworkSOC2:     "CC9.1",
		FrameworkPCI:      "9.1",
		FrameworkHIPAA:    "164.308(a)(7)(ii)(A)",
		FrameworkISO:      "A.12.3.1",
		FrameworkCISAzure: "7.6",
	},
	"DISK_NETWORK_ACCESS": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1, 1.3.4",
		FrameworkHIPAA:    "164.312(a)(1)",
		FrameworkISO:      "A.13.1.1",
		FrameworkCISAzure: "8.5",
	},

	// Key Vault (Section 8) - ENHANCED
	"KEYVAULT_PURGE": {
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4.1",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.2",
		FrameworkCISAzure: "8.1, 8.2, 3.3.5",
	},
	"KEYVAULT_PURGE_PROTECTION": { // Alias
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4.1",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.2",
		FrameworkCISAzure: "3.3.5",
	},
	"KEYVAULT_SOFT_DELETE": {
		FrameworkSOC2:     "CC6.3",
		FrameworkPCI:      "3.4.1",
		FrameworkHIPAA:    "164.312(a)(2)(iv)",
		FrameworkISO:      "A.10.1.2",
		FrameworkCISAzure: "3.3.5",
	},
	"KEYVAULT_RBAC": {
		FrameworkSOC2:     "CC6.2",
		FrameworkPCI:      "7.1.2",
		FrameworkHIPAA:    "164.308(a)(3)(ii)(A)",
		FrameworkISO:      "A.9.2.3",
		FrameworkCISAzure: "3.3.6",
	},
	"KEYVAULT_PRIVATE_ENDPOINT": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "3.3.7",
	},
	"KEYVAULT_FIREWALL": {
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "8.3",
	},
	"KEYVAULT_NETWORK_RULES": { // Alias
		FrameworkSOC2:     "CC6.1",
		FrameworkPCI:      "1.2.1",
		FrameworkHIPAA:    "164.312(e)(1)",
		FrameworkISO:      "A.13.1.3",
		FrameworkCISAzure: "8.3",
	},
	"KEYVAULT_LOGGING": {
		FrameworkSOC2:     "CC7.1",
		FrameworkPCI:      "10.2.1",
		FrameworkHIPAA:    "164.312(b)",
		FrameworkISO:      "A.12.4.1",
		FrameworkCISAzure: "8.4, 8.5",
	},
}

// Helper function to get framework mappings for a control
func GetFrameworkMappings(controlType string) map[string]string {
	if mappings, exists := AzureFrameworkMappings[controlType]; exists {
		return mappings
	}
	return make(map[string]string)
}

// Helper to format framework requirements in evidence
func FormatFrameworkRequirements(frameworks map[string]string) string {
	if len(frameworks) == 0 {
		return ""
	}
	
	result := " | Requirements: "
	for fw, requirement := range frameworks {
		result += fmt.Sprintf("%s %s, ", fw, requirement)
	}
	// Remove trailing comma and space
	if len(result) > 2 {
		result = result[:len(result)-2]
	}
	return result
}

// Priority definitions - EXACTLY matching AWS, NO EMOJIS
var (
	PriorityCritical = Priority{
		Level:     "CRITICAL",
		Impact:    "AUDIT BLOCKER - Fix immediately or fail audit",
		TimeToFix: "Fix RIGHT NOW",
		WillFail:  true,
	}

	PriorityHigh = Priority{
		Level:     "HIGH",
		Impact:    "Major finding - Auditor will flag this",
		TimeToFix: "Fix this week",
		WillFail:  false,
	}

	PriorityMedium = Priority{
		Level:     "MEDIUM",
		Impact:    "Should fix - Makes audit smoother",
		TimeToFix: "Fix before audit",
		WillFail:  false,
	}

	PriorityLow = Priority{
		Level:     "LOW",
		Impact:    "Nice to have - Strengthens posture",
		TimeToFix: "When convenient",
		WillFail:  false,
	}

	PriorityInfo = Priority{
		Level:     "INFO",
		Impact:    "Good job, this passes",
		TimeToFix: "Already done",
		WillFail:  false,
	}
)

// Common evidence message prefixes without emojis
const (
	CriticalViolation = "CRITICAL:"
	HighRisk          = "HIGH RISK:"
	MediumRisk        = "MEDIUM RISK:"
	Compliant         = "COMPLIANT:"
	ManualReview      = "MANUAL REVIEW REQUIRED:"
	CheckError        = "ERROR:"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
