package checks

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/iam/admin/apiv1"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// CC1: Control Environment (5 criteria)
// CC2: Communication and Information (3 criteria)

type GCPCC1Checks struct {
	iamClient *admin.IamClient
	projectID string
}

func NewGCPCC1Checks(iamClient *admin.IamClient, projectID string) *GCPCC1Checks {
	return &GCPCC1Checks{
		iamClient: iamClient,
		projectID: projectID,
	}
}

func (c *GCPCC1Checks) Name() string {
	return "GCP SOC2 CC1 Control Environment"
}

func (c *GCPCC1Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC1.1: Integrity and Ethical Values
	results = append(results, CheckResult{
		Control:         "CC1.1",
		Name:            "Integrity and Ethical Values",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify code of conduct and ethics policies are documented",
		Severity:        "INFO",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Remediation:     "Document and publish organizational code of conduct",
		ScreenshotGuide: "Provide evidence of ethics policy documentation and training records",
		Frameworks: map[string]string{
			"SOC2": "CC1.1",
		},
	})

	// CC1.2: Board Oversight
	results = append(results, CheckResult{
		Control:         "CC1.2",
		Name:            "Board Oversight Responsibility",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify board oversight of security program",
		Severity:        "INFO",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Remediation:     "Document board meeting minutes discussing security oversight",
		ScreenshotGuide: "Provide board charter and meeting minutes related to security governance",
		Frameworks: map[string]string{
			"SOC2": "CC1.2",
		},
	})

	// CC1.3: Organizational Structure - Check GCP IAM
	results = append(results, c.CheckCC1_3_OrganizationalStructure(ctx))

	// CC1.4: Commitment to Competence
	results = append(results, CheckResult{
		Control:         "CC1.4",
		Name:            "Commitment to Competence",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify security training and competency programs",
		Severity:        "INFO",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Remediation:     "Implement security awareness training program",
		ScreenshotGuide: "Provide training records and certification documentation",
		Frameworks: map[string]string{
			"SOC2": "CC1.4",
		},
	})

	// CC1.5: Accountability
	results = append(results, c.CheckCC1_5_Accountability(ctx))

	return results, nil
}

func (c *GCPCC1Checks) CheckCC1_3_OrganizationalStructure(ctx context.Context) CheckResult {
	// Check for proper IAM roles (separation of duties)
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return CheckResult{
			Control:   "CC1.3",
			Name:      "Organizational Structure and Authority",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check IAM roles: %v", err),
			Severity:  "MEDIUM",
			Priority:  PriorityMedium,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2": "CC1.3",
			},
		}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return CheckResult{
			Control:   "CC1.3",
			Name:      "Organizational Structure and Authority",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Severity:  "MEDIUM",
			Priority:  PriorityMedium,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2": "CC1.3",
			},
		}
	}

	customRoles := 0
	builtInRoles := 0

	for _, binding := range policy.Bindings {
		if binding.Role != "" {
			if len(binding.Role) > 0 && binding.Role[0:12] == "organizations" {
				customRoles++
			} else {
				builtInRoles++
			}
		}
	}

	if customRoles > 0 || builtInRoles > 5 {
		return CheckResult{
			Control:         "CC1.3",
			Name:            "Organizational Structure and Authority",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("Found %d custom roles and %d built-in roles demonstrating defined structure", customRoles, builtInRoles),
			Severity:        "INFO",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → IAM & Admin → IAM → Screenshot showing role assignments",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks: map[string]string{
				"SOC2": "CC1.3",
			},
		}
	}

	return CheckResult{
		Control:     "CC1.3",
		Name:        "Organizational Structure and Authority",
		Status:      "INFO",
		Evidence:    "Review GCP IAM roles for proper separation of duties",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		Remediation: "Define custom roles for separation of duties",
		Frameworks: map[string]string{
			"SOC2": "CC1.3",
		},
	}
}

func (c *GCPCC1Checks) CheckCC1_5_Accountability(ctx context.Context) CheckResult {
	// Check for IAM bindings with proper accountability
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return CheckResult{
			Control:   "CC1.5",
			Name:      "Accountability Enforcement",
			Status:    "ERROR",
			Evidence:  "Unable to verify accountability controls",
			Severity:  "MEDIUM",
			Priority:  PriorityMedium,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2": "CC1.5",
			},
		}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return CheckResult{
			Control:   "CC1.5",
			Name:      "Accountability Enforcement",
			Status:    "ERROR",
			Evidence:  "Unable to verify accountability controls",
			Severity:  "MEDIUM",
			Priority:  PriorityMedium,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2": "CC1.5",
			},
		}
	}

	if len(policy.Bindings) > 0 {
		return CheckResult{
			Control:         "CC1.5",
			Name:            "Accountability Enforcement",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("Found %d IAM bindings with defined accountability", len(policy.Bindings)),
			Severity:        "INFO",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → Activity → Show accountability trail",
			Frameworks: map[string]string{
				"SOC2": "CC1.5",
			},
		}
	}

	return CheckResult{
		Control:   "CC1.5",
		Name:      "Accountability Enforcement",
		Status:    "INFO",
		Evidence:  "Manual review of accountability procedures required",
		Severity:  "INFO",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
		Frameworks: map[string]string{
			"SOC2": "CC1.5",
		},
	}
}

// CC2: Communication and Information
type GCPCC2Checks struct{}

func NewGCPCC2Checks() *GCPCC2Checks {
	return &GCPCC2Checks{}
}

func (c *GCPCC2Checks) Name() string {
	return "GCP SOC2 CC2 Communication and Information"
}

func (c *GCPCC2Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC2.1: Internal Communication
	results = append(results, CheckResult{
		Control:         "CC2.1",
		Name:            "Internal Communication",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify internal security communication channels",
		Severity:        "INFO",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Remediation:     "Establish security communication channels and incident reporting",
		ScreenshotGuide: "Document internal communication procedures and channels",
		Frameworks: map[string]string{
			"SOC2": "CC2.1",
		},
	})

	// CC2.2: External Communication
	results = append(results, CheckResult{
		Control:         "CC2.2",
		Name:            "External Communication",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify external security communication procedures",
		Severity:        "INFO",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Remediation:     "Document customer notification and external communication procedures",
		ScreenshotGuide: "Provide evidence of security contact information and SLAs",
		Frameworks: map[string]string{
			"SOC2": "CC2.2",
		},
	})

	// CC2.3: Communication Methods
	results = append(results, CheckResult{
		Control:     "CC2.3",
		Name:        "Communication Methods",
		Status:      "INFO",
		Evidence:    "Manual review required: Verify communication methods and channels",
		Severity:    "INFO",
		Priority:    PriorityInfo,
		Timestamp:   time.Now(),
		Remediation: "Document approved communication methods and security bulletin processes",
		Frameworks: map[string]string{
			"SOC2": "CC2.3",
		},
	})

	return results, nil
}
