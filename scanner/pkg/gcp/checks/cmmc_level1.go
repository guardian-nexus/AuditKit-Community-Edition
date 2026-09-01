package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/storage"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
)

// GCPCMMCLevel1Checks implements CMMC Level 1 practices for GCP
// 17 foundational practices for Federal Contract Information (FCI)
type GCPCMMCLevel1Checks struct {
	storageClient  *storage.Client
	iamClient      *admin.IamClient
	computeService *compute.Service
	projectID      string
}

func NewGCPCMMCLevel1Checks(storageClient *storage.Client, iamClient *admin.IamClient, computeService *compute.Service, projectID string) *GCPCMMCLevel1Checks {
	return &GCPCMMCLevel1Checks{
		storageClient:  storageClient,
		iamClient:      iamClient,
		computeService: computeService,
		projectID:      projectID,
	}
}

func (c *GCPCMMCLevel1Checks) Name() string {
	return "GCP CMMC Level 1"
}

func (c *GCPCMMCLevel1Checks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// ACCESS CONTROL - 2 checks
	results = append(results, c.CheckAC_L1_001(ctx))
	results = append(results, c.CheckAC_L1_002(ctx))

	// IDENTIFICATION AND AUTHENTICATION - 2 checks
	results = append(results, c.CheckIA_L1_001(ctx))
	results = append(results, c.CheckIA_L1_002(ctx))

	// MEDIA PROTECTION - 1 INFO
	results = append(results, c.CheckMP_L1_001(ctx))

	// PHYSICAL PROTECTION - 6 INFO (Google inherited)
	results = append(results, c.CheckPE_L1_001_006(ctx)...)

	// PERSONNEL SECURITY - 2 INFO (organizational controls)
	results = append(results, c.CheckPS_L1_001_002(ctx)...)

	// SYSTEM AND COMMUNICATIONS PROTECTION - 2 checks
	results = append(results, c.CheckSC_L1_001(ctx))
	results = append(results, c.CheckSC_L1_002(ctx))

	// SYSTEM AND INFORMATION INTEGRITY - 2 INFO
	results = append(results, c.CheckSI_L1_001_003(ctx)...)

	return results, nil
}

// AC.L1-3.1.1 - Limit System Access
func (c *GCPCMMCLevel1Checks) CheckAC_L1_001(ctx context.Context) CheckResult {
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return CheckResult{
			Control:         "AC.L1-3.1.1",
			Name:            "[CMMC L1] Limit System Access",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Unable to verify IAM bindings: %v", err),
			Remediation:     "Enable GCP IAM and configure role bindings for authorized users",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → IAM & Admin → IAM → Screenshot role assignments",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
		}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return CheckResult{
			Control:     "AC.L1-3.1.1",
			Name:        "[CMMC L1] Limit System Access",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Remediation: "Configure GCP IAM with appropriate role assignments",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
		}
	}

	if len(policy.Bindings) == 0 {
		return CheckResult{
			Control:         "AC.L1-3.1.1",
			Name:            "[CMMC L1] Limit System Access",
			Status:          "FAIL",
			Evidence:        "No IAM bindings found - access control not configured",
			Remediation:     "Configure GCP IAM with appropriate role assignments for authorized users",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Add members → Screenshot",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
		}
	}

	return CheckResult{
		Control:         "AC.L1-3.1.1",
		Name:            "[CMMC L1] Limit System Access",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("GCP IAM configured with %d role bindings", len(policy.Bindings)),
		Remediation:     "Continue reviewing IAM bindings regularly for least privilege",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing role assignments",
		ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
		Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
	}
}

// AC.L1-3.1.2 - Limit System Access to Authorized Types
func (c *GCPCMMCLevel1Checks) CheckAC_L1_002(ctx context.Context) CheckResult {
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return CheckResult{
			Control:    "AC.L1-3.1.2",
			Name:       "[CMMC L1] Limit Access to Authorized Types",
			Status:     "FAIL",
			Evidence:   "Unable to verify role assignments",
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CMMC": "AC.L1-3.1.2", "NIST 800-171": "3.1.2"},
		}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return CheckResult{
			Control:    "AC.L1-3.1.2",
			Name:       "[CMMC L1] Limit Access to Authorized Types",
			Status:     "FAIL",
			Evidence:   "Unable to retrieve IAM policy",
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CMMC": "AC.L1-3.1.2", "NIST 800-171": "3.1.2"},
		}
	}

	ownerCount := 0
	for _, binding := range policy.Bindings {
		if strings.Contains(strings.ToLower(binding.Role), "owner") {
			ownerCount++
		}
	}

	if ownerCount > 3 {
		return CheckResult{
			Control:         "AC.L1-3.1.2",
			Name:            "[CMMC L1] Limit Access to Authorized Types",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Found %d Owner role assignments - may violate least privilege", ownerCount),
			Remediation:     "Review Owner assignments and use more restrictive roles where possible",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing limited Owner assignments",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.2", "NIST 800-171": "3.1.2"},
		}
	}

	return CheckResult{
		Control:    "AC.L1-3.1.2",
		Name:       "[CMMC L1] Limit Access to Authorized Types",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("IAM configured with appropriate role assignments (%d Owner roles)", ownerCount),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CMMC": "AC.L1-3.1.2", "NIST 800-171": "3.1.2"},
	}
}

// IA.L1-3.5.1 - Identify Users
func (c *GCPCMMCLevel1Checks) CheckIA_L1_001(ctx context.Context) CheckResult {
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return CheckResult{
			Control:    "IA.L1-3.5.1",
			Name:       "[CMMC L1] Identify Users",
			Status:     "FAIL",
			Evidence:   "Unable to verify user identities",
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CMMC": "IA.L1-3.5.1", "NIST 800-171": "3.5.1"},
		}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return CheckResult{
			Control:    "IA.L1-3.5.1",
			Name:       "[CMMC L1] Identify Users",
			Status:     "FAIL",
			Evidence:   "Unable to retrieve IAM policy",
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CMMC": "IA.L1-3.5.1", "NIST 800-171": "3.5.1"},
		}
	}

	userAccounts := []string{}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if strings.HasPrefix(member, "user:") {
				email := strings.TrimPrefix(member, "user:")
				// Use helper function from iam.go (no duplication)
				if !stringSliceContains(userAccounts, email) {
					userAccounts = append(userAccounts, email)
				}
			}
		}
	}

	if len(userAccounts) == 0 {
		return CheckResult{
			Control:    "IA.L1-3.5.1",
			Name:       "[CMMC L1] Identify Users",
			Status:     "INFO",
			Evidence:   "No user accounts found (only service accounts) - verify individual user identities exist",
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CMMC": "IA.L1-3.5.1", "NIST 800-171": "3.5.1"},
		}
	}

	return CheckResult{
		Control:    "IA.L1-3.5.1",
		Name:       "[CMMC L1] Identify Users",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("Found %d individual user accounts with unique identities", len(userAccounts)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CMMC": "IA.L1-3.5.1", "NIST 800-171": "3.5.1"},
	}
}

// IA.L1-3.5.2 - Authenticate Users
func (c *GCPCMMCLevel1Checks) CheckIA_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:           "IA.L1-3.5.2",
		Name:              "[CMMC L1] Authenticate Users",
		Status:            "INFO",
		Evidence:          "MANUAL: Verify 2-Step Verification is enabled for all users via Google Workspace admin console",
		Remediation:       "Enable 2-Step Verification for all users in Google Workspace",
		RemediationDetail: "admin.google.com → Security → 2-Step Verification → Enforce immediately",
		Priority:          PriorityCritical,
		Timestamp:         time.Now(),
		ScreenshotGuide:   "Google Admin Console → Security → 2-Step Verification → Screenshot enforcement status",
		ConsoleURL:        "https://admin.google.com/ac/security/2sv",
		Frameworks:        map[string]string{"CMMC": "IA.L1-3.5.2", "NIST 800-171": "3.5.2"},
	}
}

// MP.L1-3.8.3 - Sanitize Media
func (c *GCPCMMCLevel1Checks) CheckMP_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "MP.L1-3.8.3",
		Name:            "[CMMC L1] Sanitize Media",
		Status:          "INFO",
		Evidence:        "MANUAL: Document media sanitization procedures for Cloud Storage and compute resources",
		Remediation:     "Implement secure deletion using Cloud Storage lifecycle policies and disk encryption",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Documentation → Screenshot sanitization procedures | Storage → Lifecycle → Screenshot",
		ConsoleURL:      "https://console.cloud.google.com/storage/browser",
		Frameworks:      map[string]string{"CMMC": "MP.L1-3.8.3", "NIST 800-171": "3.8.3"},
	}
}

// PE.L1 - All 6 are INFO (Google inherited controls)
func (c *GCPCMMCLevel1Checks) CheckPE_L1_001_006(ctx context.Context) []CheckResult {
	baseMessage := "Google inherited: Google data centers %s (documented in SOC 2)"
	baseRemediation := "Review Google Trust Center for physical security controls documentation"
	baseURL := "https://cloud.google.com/security/compliance"

	practices := []struct {
		control string
		nist    string
		name    string
		action  string
	}{
		{"PE.L1-3.10.1", "3.10.1", "Limit Physical Access", "limit physical access"},
		{"PE.L1-3.10.2", "3.10.2", "Protect Physical Facility", "have physical protection"},
		{"PE.L1-3.10.3", "3.10.3", "Escort Visitors", "escort all visitors"},
		{"PE.L1-3.10.4", "3.10.4", "Physical Access Logs", "maintain physical access logs"},
		{"PE.L1-3.10.5", "3.10.5", "Control Access Devices", "control physical access devices"},
		{"PE.L1-3.10.6", "3.10.6", "Safeguard CUI", "enforce physical safeguards"},
	}

	results := []CheckResult{}
	for _, p := range practices {
		results = append(results, CheckResult{
			Control:         p.control,
			Name:            fmt.Sprintf("[CMMC L1] %s", p.name),
			Status:          "INFO",
			Evidence:        fmt.Sprintf(baseMessage, p.action),
			Remediation:     baseRemediation,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Trust Center → Screenshot physical security documentation",
			ConsoleURL:      baseURL,
			Frameworks:      map[string]string{"CMMC": p.control, "NIST 800-171": p.nist},
		})
	}

	return results
}

// PS.L1 - Personnel Security (organizational controls)
func (c *GCPCMMCLevel1Checks) CheckPS_L1_001_002(ctx context.Context) []CheckResult {
	return []CheckResult{
		{
			Control:         "PS.L1-3.9.1",
			Name:            "[CMMC L1] Screen Personnel",
			Status:          "INFO",
			Evidence:        "MANUAL: Document personnel screening procedures for CUI access",
			Remediation:     "Implement background checks for personnel with CUI access",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "HR Documentation → Screenshot showing personnel screening procedures and background check records",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CMMC": "PS.L1-3.9.1", "NIST 800-171": "3.9.1"},
		},
		{
			Control:         "PS.L1-3.9.2",
			Name:            "[CMMC L1] Ensure CUI Access Authorization",
			Status:          "INFO",
			Evidence:        "MANUAL: Document authorization process for CUI access",
			Remediation:     "Implement formal authorization process before granting CUI access",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Documentation → Screenshot showing CUI access authorization procedures and approval records",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CMMC": "PS.L1-3.9.2", "NIST 800-171": "3.9.2"},
		},
	}
}

// SC.L1-3.13.1 - Monitor Communications
func (c *GCPCMMCLevel1Checks) CheckSC_L1_001(ctx context.Context) CheckResult {
	firewallList, err := c.computeService.Firewalls.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return CheckResult{
			Control:     "SC.L1-3.13.1",
			Name:        "[CMMC L1] Monitor Communications",
			Status:      "FAIL",
			Evidence:    "Unable to verify VPC firewall rules",
			Remediation: "Configure VPC firewall rules",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CMMC": "SC.L1-3.13.1", "NIST 800-171": "3.13.1"},
		}
	}

	openRules := 0
	for _, rule := range firewallList.Items {
		if rule.Direction == "INGRESS" {
			for _, sourceRange := range rule.SourceRanges {
				if sourceRange == "0.0.0.0/0" {
					openRules++
					break
				}
			}
		}
	}

	if openRules > 0 {
		return CheckResult{
			Control:         "SC.L1-3.13.1",
			Name:            "[CMMC L1] Monitor Communications",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Found %d VPC firewall rules allowing unrestricted access", openRules),
			Remediation:     "Restrict firewall rules to specific IP ranges",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "VPC Network → Firewall → Screenshot restricted access",
			ConsoleURL:      "https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/list",
			Frameworks:      map[string]string{"CMMC": "SC.L1-3.13.1", "NIST 800-171": "3.13.1"},
		}
	}

	return CheckResult{
		Control:         "SC.L1-3.13.1",
		Name:            "[CMMC L1] Monitor Communications",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d VPC firewall rules have restricted access", len(firewallList.Items)),
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		ScreenshotGuide: "VPC Network → Firewall → Screenshot monitoring controls",
		ConsoleURL:      "https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/list",
		Frameworks:      map[string]string{"CMMC": "SC.L1-3.13.1", "NIST 800-171": "3.13.1"},
	}
}

// SC.L1-3.13.5 - Implement Subnetworks
func (c *GCPCMMCLevel1Checks) CheckSC_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "SC.L1-3.13.5",
		Name:            "[CMMC L1] Implement Subnetworks",
		Status:          "INFO",
		Evidence:        "MANUAL: Verify VPC subnets separate public and private systems",
		Remediation:     "Use separate subnets for public-facing and internal systems with firewall rules",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "VPC Network → VPC networks → Subnets → Screenshot subnet separation",
		ConsoleURL:      "https://console.cloud.google.com/networking/networks/list",
		Frameworks:      map[string]string{"CMMC": "SC.L1-3.13.5", "NIST 800-171": "3.13.5"},
	}
}

// SI.L1 - All 2 are INFO
func (c *GCPCMMCLevel1Checks) CheckSI_L1_001_003(ctx context.Context) []CheckResult {
	results := []CheckResult{
		{
			Control:         "SI.L1-3.14.1",
			Name:            "[CMMC L1] Identify Flaws",
			Status:          "INFO",
			Evidence:        "MANUAL: Verify Security Command Center identifies system flaws and vulnerabilities",
			Remediation:     "Enable Security Command Center with vulnerability scanning",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Security Command Center → Screenshot compliance and vulnerabilities",
			ConsoleURL:      "https://console.cloud.google.com/security/command-center",
			Frameworks:      map[string]string{"CMMC": "SI.L1-3.14.1", "NIST 800-171": "3.14.1"},
		},
		{
			Control:         "SI.L1-3.14.2",
			Name:            "[CMMC L1] Malicious Code Protection",
			Status:          "INFO",
			Evidence:        "MANUAL: Verify malicious code protection via Security Command Center",
			Remediation:     "Enable Security Command Center malware detection",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Security Command Center → Screenshot malware protection",
			ConsoleURL:      "https://console.cloud.google.com/security/command-center",
			Frameworks:      map[string]string{"CMMC": "SI.L1-3.14.2", "NIST 800-171": "3.14.2"},
		},
	}

	return results
}

// Helper function - renamed to avoid conflict with iam.go
func stringSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
