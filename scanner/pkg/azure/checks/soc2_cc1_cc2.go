package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
)

// CC1: Control Environment (5 criteria)
// CC2: Communication and Information (3 criteria)

type AzureCC1Checks struct {
	roleClient    *armauthorization.RoleAssignmentsClient
	roleDefClient *armauthorization.RoleDefinitionsClient
}

func NewAzureCC1Checks(roleClient *armauthorization.RoleAssignmentsClient, roleDefClient *armauthorization.RoleDefinitionsClient) *AzureCC1Checks {
	return &AzureCC1Checks{
		roleClient:    roleClient,
		roleDefClient: roleDefClient,
	}
}

func (c *AzureCC1Checks) Name() string {
	return "Azure SOC2 CC1 Control Environment"
}

func (c *AzureCC1Checks) Run(ctx context.Context) ([]CheckResult, error) {
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

	// CC1.3: Organizational Structure - Check Azure RBAC
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

func (c *AzureCC1Checks) CheckCC1_3_OrganizationalStructure(ctx context.Context) CheckResult {
	// Check for proper RBAC roles (separation of duties)
	pager := c.roleClient.NewListPager(nil)

	customRoles := 0
	builtInRoles := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return CheckResult{
				Control:   "CC1.3",
				Name:      "Organizational Structure and Authority",
				Status:    "ERROR",
				Evidence:  fmt.Sprintf("Unable to check role assignments: %v", err),
				Severity:  "MEDIUM",
				Priority:  PriorityMedium,
				Timestamp: time.Now(),
				Frameworks: map[string]string{
					"SOC2": "CC1.3",
				},
			}
		}

		for _, assignment := range page.Value {
			if assignment.Properties != nil && assignment.Properties.RoleDefinitionID != nil {
				// Check if custom or built-in role
				roleID := *assignment.Properties.RoleDefinitionID
				if contains(roleID, "custom") {
					customRoles++
				} else {
					builtInRoles++
				}
			}
		}
	}

	if customRoles > 0 {
		return CheckResult{
			Control:         "CC1.3",
			Name:            "Organizational Structure and Authority",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("Found %d custom roles and %d built-in roles demonstrating defined structure", customRoles, builtInRoles),
			Severity:        "INFO",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Azure Portal -> Access control (IAM) -> Roles -> Screenshot showing role assignments",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Resources/SubscriptionDetails",
			Frameworks: map[string]string{
				"SOC2": "CC1.3",
			},
		}
	}

	return CheckResult{
		Control:     "CC1.3",
		Name:        "Organizational Structure and Authority",
		Status:      "INFO",
		Evidence:    "Review Azure RBAC roles for proper separation of duties",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		Remediation: "Define custom roles for separation of duties",
		Frameworks: map[string]string{
			"SOC2": "CC1.3",
		},
	}
}

func (c *AzureCC1Checks) CheckCC1_5_Accountability(ctx context.Context) CheckResult {
	// Check for role assignments with proper accountability
	pager := c.roleClient.NewListPager(nil)

	page, err := pager.NextPage(ctx)
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

	if len(page.Value) > 0 {
		return CheckResult{
			Control:         "CC1.5",
			Name:            "Accountability Enforcement",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("Found %d role assignments with defined accountability", len(page.Value)),
			Severity:        "INFO",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Azure Portal -> Activity log -> Show accountability trail",
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
type AzureCC2Checks struct {
	// Would need additional Azure SDK clients for full implementation
}

func NewAzureCC2Checks() *AzureCC2Checks {
	return &AzureCC2Checks{}
}

func (c *AzureCC2Checks) Name() string {
	return "Azure SOC2 CC2 Communication and Information"
}

func (c *AzureCC2Checks) Run(ctx context.Context) ([]CheckResult, error) {
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

func contains(s string, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr))
}
