package checks

import (
	"context"
	"fmt"
	"time"
)

// CheckResult represents the result of a single compliance check
type CheckResult struct {
	Control           string            `json:"control"`
	Name              string            `json:"name"`
	Status            string            `json:"status"` // PASS, FAIL, INFO
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

// Priority levels for compliance findings
type Priority struct {
	Level     string `json:"level"`
	Impact    string `json:"impact"`
	TimeToFix string `json:"time_to_fix"`
	WillFail  bool   `json:"will_fail"`
}

// Priority definitions matching AWS/Azure
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
		TimeToFix: "Already compliant",
		WillFail:  false,
	}
)

// Check result statuses. Only StatusPass and StatusFail are scoreable; every
// other value is excluded from the compliance score rather than counted as a
// failed automated check.
//
// Three separate defects came from this field being an unconstrained string:
// MANUAL, then WARN, then ERROR each sat in the scoring denominator and could
// never pass. .github/scripts/check-statuses.sh rejects any value outside this
// set, so a fourth cannot ship.
const (
	StatusPass   = "PASS"   // the control was checked and satisfied
	StatusFail   = "FAIL"   // the control was checked and not satisfied
	StatusInfo   = "INFO"   // guidance only; nothing was evaluated
	StatusManual = "MANUAL" // requires human verification or documentation
	StatusError  = "ERROR"  // the check could not run, usually a missing permission
)

// ValidStatus reports whether s is one of the recognised statuses.
func ValidStatus(s string) bool {
	switch s {
	case StatusPass, StatusFail, StatusInfo, StatusManual, StatusError:
		return true
	}
	return false
}

// Framework constants
const (
	FrameworkSOC2  = "SOC2"
	FrameworkPCI   = "PCI-DSS"
	FrameworkCMMC  = "CMMC"
	FrameworkNIST  = "NIST-800-53"
	FrameworkHIPAA = "HIPAA"
	FrameworkCIS   = "CIS-GCP"
)

// Check interface that all GCP check implementations must satisfy
type Check interface {
	Run(ctx context.Context) ([]CheckResult, error)
}

// Framework mappings for GCP controls - UPDATED WITH CIS-GCP
var FrameworkMappings = map[string]map[string]string{
	// STORAGE CONTROLS
	"GCS_BUCKET_PUBLIC": {
		FrameworkSOC2:  "CC6.1, CC6.6",
		FrameworkPCI:   "1.4.2",
		FrameworkCMMC:  "AC.L1-3.1.1",
		FrameworkNIST:  "AC-3, AC-6",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "5.1, 5.2",
	},
	"GCS_BUCKET_ENCRYPTION": {
		FrameworkSOC2:  "CC6.1, CC6.7",
		FrameworkPCI:   "3.5.1",
		FrameworkCMMC:  "SC.L2-3.13.11",
		FrameworkNIST:  "SC-13, SC-28",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "5.2",
	},
	"GCS_BUCKET_VERSIONING": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5.1",
		FrameworkCMMC:  "SC.L2-3.13.6",
		FrameworkNIST:  "CP-9",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "5.1, 5.3",
	},
	"GCS_BUCKET_LOGGING": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.2.1.1",
		FrameworkCMMC:  "AU.L2-3.3.1",
		FrameworkNIST:  "AU-2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.3",
	},
	"GCS_UNIFORM_ACCESS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.2.2",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "5.2",
	},
	"GCS_RETENTION_POLICY": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "3.2.1",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "5.1",
	},

	// IAM CONTROLS
	"IAM_MFA_ENABLED": {
		FrameworkSOC2:  "CC6.1, CC6.2",
		FrameworkPCI:   "8.4.2",
		FrameworkCMMC:  "IA.L2-3.5.3",
		FrameworkNIST:  "IA-2(1)",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.1, 1.2",
	},
	"IAM_SERVICE_ACCOUNT_KEYS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "8.3.9",
		FrameworkCMMC:  "IA.L2-3.5.7",
		FrameworkNIST:  "IA-5",
		FrameworkHIPAA: "164.308(a)(4)(ii)(B)",
		FrameworkCIS:   "1.4, 1.5",
	},
	"IAM_PRIMITIVE_ROLES": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "7.2.2",
		FrameworkCMMC:  "AC.L2-3.1.5",
		FrameworkNIST:  "AC-6",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.5, 1.6, 1.7",
	},
	"IAM_API_KEYS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "8.2.1",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "1.12, 1.13, 1.14",
	},
	"IAM_SERVICE_ACCOUNT_ADMIN": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.4",
	},
	"IAM_CORPORATE_LOGIN": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "8.2.2",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.1",
	},
	"IAM_WORKLOAD_IDENTITY": {
		FrameworkSOC2:  "CC6.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.15",
	},
	"GCP_DEFAULT_SA": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.2.2",
		FrameworkCMMC:  "AC.L2-3.1.5",
		FrameworkNIST:  "AC-6",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.7",
	},

	// LOGGING & MONITORING
	"LOGGING_ENABLED": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.2.1.1, 10.3.1",
		FrameworkCMMC:  "AU.L2-3.3.1",
		FrameworkNIST:  "AU-2, AU-12",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "2.1, 2.2, 2.3",
	},
	"LOG_SINKS": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.5.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "2.2",
	},
	"LOG_RETENTION": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.5.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "2.3",
	},
	"LOG_METRIC_FILTERS": {
		FrameworkSOC2:  "CC7.3",
		FrameworkPCI:   "10.4.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.12",
	},
	"DNS_LOGGING": {
		FrameworkSOC2:  "CC7.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "2.13",
	},

	// NETWORK CONTROLS
	"VPC_FIREWALL_OPEN": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "1.4.2",
		FrameworkCMMC:  "SC.L1-3.13.1",
		FrameworkNIST:  "SC-7",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "3.6, 3.7",
	},
	"VPC_FLOW_LOGS": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.9",
	},
	"VPC_DEFAULT_NETWORK": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "3.1",
	},
	"VPC_PRIVATE_GOOGLE_ACCESS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "3.8",
	},
	"DNSSEC_ENABLED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "3.3",
	},
	"LOAD_BALANCER_LOGGING": {
		FrameworkSOC2:  "CC7.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.10",
	},

	// COMPUTE CONTROLS
	"COMPUTE_DISK_ENCRYPTION": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "3.5.1",
		FrameworkCMMC:  "SC.L2-3.13.11",
		FrameworkNIST:  "SC-28",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "4.1",
	},
	"COMPUTE_PUBLIC_IP": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "4.9",
	},
	"COMPUTE_OS_LOGIN": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "8.2.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "4.4",
	},
	"COMPUTE_SHIELDED_VM": {
		FrameworkSOC2:  "CC6.1",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "4.8",
	},
	"COMPUTE_SERIAL_PORT": {
		FrameworkSOC2:  "CC6.6",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "4.5",
	},
	"COMPUTE_IP_FORWARDING": {
		FrameworkSOC2:  "CC6.6",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "4.6",
	},
	"COMPUTE_PROJECT_SSH_KEYS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "4.3",
	},

	// SQL / DATABASE CONTROLS
	"SQL_PUBLIC_IP": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "1.4.2",
		FrameworkCMMC:  "SC.L1-3.13.1",
		FrameworkNIST:  "SC-7",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.1",
	},
	"SQL_BACKUP_ENABLED": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5.1",
		FrameworkCMMC:  "SC.L2-3.13.6",
		FrameworkNIST:  "CP-9",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "6.2",
	},
	"SQL_SSL_REQUIRED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "4.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.3",
	},
	"SQL_AUTO_BACKUPS": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5.1",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "6.7",
	},

	// KMS CONTROLS
	"KMS_ROTATION_ENABLED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "3.7.4",
		FrameworkCMMC:  "SC.L2-3.13.11",
		FrameworkNIST:  "SC-12",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "1.9, 1.10",
	},
	"KMS_SEPARATION_OF_DUTIES": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.9",
	},

	// BIGQUERY CONTROLS
	"BIGQUERY_PUBLIC_DATASETS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "7.1, 7.2",
	},
	"BIGQUERY_ENCRYPTION": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "7.3",
	},

	// GKE / KUBERNETES CONTROLS
	"GKE_BINARY_AUTHORIZATION": {
		FrameworkSOC2:  "CC8.1",
		FrameworkPCI:   "2.2.1",
		FrameworkCMMC:  "CM.L2-3.4.8",
		FrameworkNIST:  "CM-7",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "8.1",
	},
	"GKE_NETWORK_POLICY": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "1.4.2",
		FrameworkCMMC:  "SC.L1-3.13.1",
		FrameworkNIST:  "SC-7",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "8.2",
	},
	"GKE_DASHBOARD_DISABLED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "2.2.4",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "8.3",
	},
	"GKE_POD_SECURITY_POLICY": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "2.2.1",
		FrameworkCMMC:  "CM.L2-3.4.6",
		FrameworkNIST:  "CM-6",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "8.4",
	},
	"GKE_WORKLOAD_IDENTITY": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "8.2.2",
		FrameworkCMMC:  "IA.L2-3.5.3",
		FrameworkNIST:  "IA-3",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "8.5",
	},
}

// Helper function to get framework mappings for a control
func GetFrameworkMappings(controlType string) map[string]string {
	if mappings, exists := FrameworkMappings[controlType]; exists {
		return mappings
	}
	return make(map[string]string)
}

func FormatFrameworkRequirements(frameworks map[string]string) string {
	if len(frameworks) == 0 {
		return ""
	}

	result := " | Requirements: "
	for fw, requirement := range frameworks {
		result += fmt.Sprintf("%s %s, ", fw, requirement)
	}
	// Remove trailing comma and space
	return result[:len(result)-2]
}
