package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// CC1: Control Environment (5 criteria)
// The foundation of internal control - governance, ethics, and organizational structure

type CC1Checks struct {
	iamClient *iam.Client
	orgClient *organizations.Client
	ssmClient *ssm.Client
}

func NewCC1Checks(iamClient *iam.Client, orgClient *organizations.Client, ssmClient *ssm.Client) *CC1Checks {
	return &CC1Checks{
		iamClient: iamClient,
		orgClient: orgClient,
		ssmClient: ssmClient,
	}
}

func (c *CC1Checks) Name() string {
	return "SOC2 CC1 Checks"
}

func (c *CC1Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC1.1: Demonstrates Commitment to Integrity and Ethical Values
	results = append(results, c.CheckCC1_1_IntegrityAndEthics(ctx)...)

	// CC1.2: Board Exercises Oversight Responsibility
	results = append(results, c.CheckCC1_2_BoardOversight(ctx)...)

	// CC1.3: Management Establishes Structure, Authority, and Responsibility
	results = append(results, c.CheckCC1_3_OrganizationalStructure(ctx)...)

	// CC1.4: Demonstrates Commitment to Competence
	results = append(results, c.CheckCC1_4_Competence(ctx)...)

	// CC1.5: Enforces Accountability
	results = append(results, c.CheckCC1_5_Accountability(ctx)...)

	return results, nil
}

func (c *CC1Checks) CheckCC1_1_IntegrityAndEthics(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check 1: AWS Organizations with SCPs for governance
	if c.orgClient != nil {
		org, err := c.orgClient.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
		if err != nil || org == nil || org.Organization == nil {
			results = append(results, CheckResult{
				Control:         "CC1.1",
				Name:            "Organizational Governance Structure",
				Status:          "FAIL",
				Severity:        "HIGH",
				Evidence:        "AWS Organizations not enabled - no centralized governance",
				Remediation:     "Enable AWS Organizations and implement Service Control Policies",
				ScreenshotGuide: "1. Go to AWS Organizations\n2. Screenshot the organization structure\n3. Document SCPs in place",
				ConsoleURL:      "https://console.aws.amazon.com/organizations/",
				Priority:        PriorityHigh,
				Timestamp:       time.Now(),
			})
		} else {
			// Check for Service Control Policies
			policies, _ := c.orgClient.ListPolicies(ctx, &organizations.ListPoliciesInput{
				Filter: "SERVICE_CONTROL_POLICY",
			})

			if policies != nil && policies.Policies != nil && len(policies.Policies) > 0 {
				results = append(results, CheckResult{
					Control:   "CC1.1",
					Name:      "Organizational Governance Structure",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("AWS Organizations enabled with %d SCPs for governance", len(policies.Policies)),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			} else {
				results = append(results, CheckResult{
					Control:     "CC1.1",
					Name:        "Organizational Governance - SCPs",
					Status:      "FAIL",
					Severity:    "MEDIUM",
					Evidence:    "Organizations enabled but no Service Control Policies defined",
					Remediation: "Implement SCPs to enforce organizational policies",
					Priority:    PriorityMedium,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return results
}

func (c *CC1Checks) CheckCC1_2_BoardOversight(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check 2: IAM roles for segregation of duties
	roles, _ := c.iamClient.ListRoles(ctx, &iam.ListRolesInput{})

	adminRoles := 0
	readOnlyRoles := 0

	if roles != nil && roles.Roles != nil {
		for _, role := range roles.Roles {
			roleName := strings.ToLower(aws.ToString(role.RoleName))
			if strings.Contains(roleName, "admin") || strings.Contains(roleName, "poweruser") {
				adminRoles++
			}
			if strings.Contains(roleName, "readonly") || strings.Contains(roleName, "audit") {
				readOnlyRoles++
			}
		}
	}

	if adminRoles > 0 && readOnlyRoles > 0 {
		results = append(results, CheckResult{
			Control:   "CC1.2",
			Name:      "Role-Based Access Segregation",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("Found %d admin roles and %d audit/readonly roles for oversight", adminRoles, readOnlyRoles),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:     "CC1.2",
			Name:        "Role-Based Access Segregation",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    "Insufficient role segregation for proper oversight",
			Remediation: "Create separate admin, operator, and audit roles",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
		})
	}

	return results
}

func (c *CC1Checks) CheckCC1_3_OrganizationalStructure(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check 3: SSM Parameter Store for configuration management
	if c.ssmClient != nil {
		params, _ := c.ssmClient.DescribeParameters(ctx, &ssm.DescribeParametersInput{})

		if params != nil && params.Parameters != nil && len(params.Parameters) > 0 {
			// Check for hierarchy in parameters (indicates structure)
			hierarchicalParams := 0
			for _, param := range params.Parameters {
				if param.Name != nil && strings.Contains(*param.Name, "/") {
					hierarchicalParams++
				}
			}

			if hierarchicalParams > 0 {
				results = append(results, CheckResult{
					Control:   "CC1.3",
					Name:      "Configuration Management Structure",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("%d hierarchical parameters showing organizational structure", hierarchicalParams),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			} else {
				results = append(results, CheckResult{
					Control:     "CC1.3",
					Name:        "Configuration Management Structure",
					Status:      "INFO",
					Evidence:    "Parameters exist but no hierarchical structure detected",
					Remediation: "Consider organizing parameters hierarchically (e.g., /prod/app/config)",
					Priority:    PriorityLow,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return results
}

func (c *CC1Checks) CheckCC1_4_Competence(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check 4: IAM users with MFA (demonstrates security competence)
	users, _ := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})

	if users != nil && users.Users != nil && len(users.Users) > 0 {
		mfaUsers := 0
		for _, user := range users.Users {
			mfaDevices, _ := c.iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: user.UserName,
			})
			if mfaDevices != nil && mfaDevices.MFADevices != nil && len(mfaDevices.MFADevices) > 0 {
				mfaUsers++
			}
		}

		mfaPercentage := float64(mfaUsers) / float64(len(users.Users)) * 100

		if mfaPercentage >= 90 {
			results = append(results, CheckResult{
				Control:   "CC1.4",
				Name:      "Security Competence - MFA Adoption",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%.0f%% of IAM users have MFA enabled", mfaPercentage),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:     "CC1.4",
				Name:        "Security Competence - MFA Adoption",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    fmt.Sprintf("Only %.0f%% of users have MFA enabled", mfaPercentage),
				Remediation: "Enforce MFA for all IAM users",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

func (c *CC1Checks) CheckCC1_5_Accountability(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check 5: IAM policies with explicit deny (shows accountability controls)
	policies, _ := c.iamClient.ListPolicies(ctx, &iam.ListPoliciesInput{
		Scope: "Local",
	})

	if policies != nil && policies.Policies != nil {
		restrictivePolicies := 0
		for _, policy := range policies.Policies {
			policyName := strings.ToLower(aws.ToString(policy.PolicyName))
			if strings.Contains(policyName, "deny") || strings.Contains(policyName, "restrict") || strings.Contains(policyName, "boundary") {
				restrictivePolicies++
			}
		}

		if restrictivePolicies > 0 {
			results = append(results, CheckResult{
				Control:   "CC1.5",
				Name:      "Accountability Controls",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%d restrictive policies enforcing accountability", restrictivePolicies),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:     "CC1.5",
				Name:        "Accountability Controls",
				Status:      "INFO",
				Evidence:    "No explicit deny policies found",
				Remediation: "Consider implementing permission boundaries and explicit deny policies",
				Priority:    PriorityLow,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

// CC2: Communication and Information (3 criteria)
// How information flows through the organization

type CC2Checks struct {
	snsClient *sns.Client
	ssmClient *ssm.Client
	iamClient *iam.Client
}

func NewCC2Checks(snsClient *sns.Client, ssmClient *ssm.Client, iamClient *iam.Client) *CC2Checks {
	return &CC2Checks{
		snsClient: snsClient,
		ssmClient: ssmClient,
		iamClient: iamClient,
	}
}

func (c *CC2Checks) Name() string {
	return "SOC2 CC2 Checks"
}

func (c *CC2Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC2.1: Obtains or Generates Relevant Information
	results = append(results, c.CheckCC2_1_InformationGeneration(ctx)...)

	// CC2.2: Communicates Internal Control Information
	results = append(results, c.CheckCC2_2_InternalCommunication(ctx)...)

	// CC2.3: Communicates with External Parties
	results = append(results, c.CheckCC2_3_ExternalCommunication(ctx)...)

	return results, nil
}

func (c *CC2Checks) CheckCC2_1_InformationGeneration(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check SSM Parameter Store for configuration information
	if c.ssmClient != nil {
		params, _ := c.ssmClient.DescribeParameters(ctx, &ssm.DescribeParametersInput{})

		if params != nil && params.Parameters != nil && len(params.Parameters) > 0 {
			// Check for encrypted parameters (sensitive info handling)
			encryptedCount := 0
			for _, param := range params.Parameters {
				if param.Type == "SecureString" {
					encryptedCount++
				}
			}

			if encryptedCount > 0 {
				results = append(results, CheckResult{
					Control:   "CC2.1",
					Name:      "Secure Information Storage",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("%d of %d parameters are encrypted", encryptedCount, len(params.Parameters)),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			} else if len(params.Parameters) > 0 {
				results = append(results, CheckResult{
					Control:     "CC2.1",
					Name:        "Configuration Information Management",
					Status:      "FAIL",
					Severity:    "MEDIUM",
					Evidence:    fmt.Sprintf("%d parameters but none encrypted - sensitive data at risk", len(params.Parameters)),
					Remediation: "Use SecureString type for sensitive parameters",
					Priority:    PriorityMedium,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return results
}

func (c *CC2Checks) CheckCC2_2_InternalCommunication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check SNS topics for internal alerting
	if c.snsClient != nil {
		topics, err := c.snsClient.ListTopics(ctx, &sns.ListTopicsInput{})

		if err != nil || topics == nil || topics.Topics == nil || len(topics.Topics) == 0 {
			results = append(results, CheckResult{
				Control:         "CC2.2",
				Name:            "Internal Alert Communication",
				Status:          "FAIL",
				Severity:        "HIGH",
				Evidence:        "No SNS topics configured - no security alerting mechanism",
				Remediation:     "Create SNS topics for security alerts and operational notifications",
				ScreenshotGuide: "1. Go to SNS Console\n2. Create topics for SecurityAlerts, OperationalAlerts\n3. Configure subscriptions",
				ConsoleURL:      "https://console.aws.amazon.com/sns/",
				Priority:        PriorityHigh,
				Timestamp:       time.Now(),
			})
		} else {
			// Check for security-related topics
			securityTopics := 0
			for _, topic := range topics.Topics {
				if topic.TopicArn != nil {
					topicName := strings.ToLower(*topic.TopicArn)
					if strings.Contains(topicName, "security") || strings.Contains(topicName, "alert") || strings.Contains(topicName, "alarm") {
						securityTopics++
					}
				}
			}

			if securityTopics > 0 {
				results = append(results, CheckResult{
					Control:   "CC2.2",
					Name:      "Security Alert Communication",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("%d security/alert topics configured for notifications", securityTopics),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			} else {
				results = append(results, CheckResult{
					Control:     "CC2.2",
					Name:        "Security Alert Communication",
					Status:      "FAIL",
					Severity:    "MEDIUM",
					Evidence:    fmt.Sprintf("%d SNS topics but none for security alerts", len(topics.Topics)),
					Remediation: "Create dedicated SNS topics for security notifications",
					Priority:    PriorityMedium,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return results
}

func (c *CC2Checks) CheckCC2_3_ExternalCommunication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for cross-account roles (external party communication)
	roles, _ := c.iamClient.ListRoles(ctx, &iam.ListRolesInput{})

	crossAccountRoles := 0
	if roles != nil && roles.Roles != nil {
		for _, role := range roles.Roles {
			if role.AssumeRolePolicyDocument != nil {
				// Check if the trust policy allows external accounts
				if strings.Contains(*role.AssumeRolePolicyDocument, "arn:aws:iam::") {
					// Look for external account patterns (not the same account)
					if !strings.Contains(*role.AssumeRolePolicyDocument, ":root") {
						crossAccountRoles++
					}
				}
			}
		}
	}

	if crossAccountRoles > 0 {
		results = append(results, CheckResult{
			Control:   "CC2.3",
			Name:      "External Party Integration",
			Status:    "INFO",
			Evidence:  fmt.Sprintf("%d cross-account roles configured - verify these are authorized", crossAccountRoles),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC2.3",
			Name:      "External Party Integration",
			Status:    "PASS",
			Evidence:  "No cross-account access detected - good isolation",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results
}
