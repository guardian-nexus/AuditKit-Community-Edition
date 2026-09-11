package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type IAMExtendedChecks struct {
	client *iam.Client
}

func NewIAMExtendedChecks(client *iam.Client) *IAMExtendedChecks {
	return &IAMExtendedChecks{client: client}
}

func (c *IAMExtendedChecks) Name() string {
	return "IAM Extended Security Configuration"
}

func (c *IAMExtendedChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckServiceLinkedRoles(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckPermissionBoundaries(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *IAMExtendedChecks) CheckServiceLinkedRoles(ctx context.Context) (CheckResult, error) {
	roles, err := c.client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "IAM Service-Linked Roles Configured",
			Status:     "ERROR",
			Evidence:   "Failed to list roles",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_SERVICE_LINKED_ROLES"),
		}, err
	}

	serviceLinkedRoles := 0
	for _, role := range roles.Roles {
		if role.Path != nil && *role.Path == "/aws-service-role/" {
			serviceLinkedRoles++
		}
	}

	if serviceLinkedRoles == 0 {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "IAM Service-Linked Roles Configured",
			Status:      "INFO",
			Evidence:    "No service-linked roles found - may not be using AWS services that require them",
			Remediation: "Service-linked roles are automatically created by AWS services when needed",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/iam/home#/roles",
			Frameworks:  GetFrameworkMappings("IAM_SERVICE_LINKED_ROLES"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "IAM Service-Linked Roles Configured",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("%d service-linked roles configured for AWS services", serviceLinkedRoles),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/roles",
		Frameworks: GetFrameworkMappings("IAM_SERVICE_LINKED_ROLES"),
	}, nil
}

func (c *IAMExtendedChecks) CheckPermissionBoundaries(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "IAM Permission Boundaries Configured",
			Status:     "ERROR",
			Evidence:   "Failed to list users",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_PERMISSION_BOUNDARIES"),
		}, err
	}

	roles, err := c.client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "IAM Permission Boundaries Configured",
			Status:     "ERROR",
			Evidence:   "Failed to list roles",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_PERMISSION_BOUNDARIES"),
		}, err
	}

	usersWithBoundaries := 0
	rolesWithBoundaries := 0

	for _, user := range users.Users {
		if user.PermissionsBoundary != nil {
			usersWithBoundaries++
		}
	}

	for _, role := range roles.Roles {
		if role.PermissionsBoundary != nil {
			rolesWithBoundaries++
		}
	}

	if usersWithBoundaries == 0 && rolesWithBoundaries == 0 {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "IAM Permission Boundaries Configured",
			Status:      "FAIL",
			Evidence:    "No permission boundaries configured - no delegation safeguards",
			Remediation: "Implement permission boundaries for delegated admin roles",
			RemediationDetail: `Permission boundaries prevent privilege escalation:
1. Create boundary policy limiting maximum permissions
2. Attach to roles that create other IAM resources
3. Ensures delegated admins can't grant more permissions than they have
4. Critical for multi-tenant or delegated administration`,
			Severity:        "MEDIUM",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM → Policies → Create permission boundary policy",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/policies",
			Frameworks:      GetFrameworkMappings("IAM_PERMISSION_BOUNDARIES"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "IAM Permission Boundaries Configured",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("Permission boundaries: %d users, %d roles", usersWithBoundaries, rolesWithBoundaries),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/roles",
		Frameworks: GetFrameworkMappings("IAM_PERMISSION_BOUNDARIES"),
	}, nil
}
