package checks

import (
	"context"
	"fmt"
	"time"

	//    "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type IAMAdvancedChecks struct {
	client *iam.Client
}

func NewIAMAdvancedChecks(client *iam.Client) *IAMAdvancedChecks {
	return &IAMAdvancedChecks{client: client}
}

func (c *IAMAdvancedChecks) Name() string {
	return "IAM Advanced Security"
}

func (c *IAMAdvancedChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckInactiveUsers(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckExcessivePermissions(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckServiceAccountMFA(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckRootAccountUsage(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *IAMAdvancedChecks) CheckInactiveUsers(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	inactiveUsers := []string{}
	zombieUsers := []string{} // Never logged in at all

	for _, user := range users.Users {
		// Check password last used
		if user.PasswordLastUsed == nil {
			// Never logged in with password
			zombieUsers = append(zombieUsers, *user.UserName)
		} else {
			lastActivity := time.Since(*user.PasswordLastUsed)
			days := int(lastActivity.Hours() / 24)

			if days > 90 {
				inactiveUsers = append(inactiveUsers, fmt.Sprintf("%s (%d days inactive)", *user.UserName, days))
			}
		}
	}

	if len(zombieUsers) > 0 {
		return CheckResult{
			Control:           "CC6.4",
			Name:              "Zombie IAM Users",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf(" %d users NEVER logged in - delete them!", len(zombieUsers)),
			Remediation:       fmt.Sprintf("Delete unused user: %s", zombieUsers[0]),
			RemediationDetail: fmt.Sprintf("aws iam delete-user --user-name %s", zombieUsers[0]),
			ScreenshotGuide:   "1. Go to IAM → Users\n2. Sort by 'Last activity'\n3. Screenshot users with 'Never' or >90 days\n4. Document why each inactive user exists",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	if len(inactiveUsers) > 0 {
		return CheckResult{
			Control:     "CC6.4",
			Name:        "Inactive IAM Users",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d users inactive >90 days", len(inactiveUsers)),
			Remediation: "Review and remove inactive users",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC6.4",
		Name:      "User Access Reviews",
		Status:    "PASS",
		Evidence:  "All users active within 90 days",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func (c *IAMAdvancedChecks) CheckExcessivePermissions(ctx context.Context) (CheckResult, error) {
	// Check for users with AdministratorAccess
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	adminUsers := []string{}

	for _, user := range users.Users {
		// Check attached policies
		policies, err := c.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: user.UserName,
		})

		if err == nil {
			for _, policy := range policies.AttachedPolicies {
				if *policy.PolicyName == "AdministratorAccess" {
					adminUsers = append(adminUsers, *user.UserName)
				}
			}
		}
	}

	if len(adminUsers) > 2 {
		return CheckResult{
			Control:           "CC6.5",
			Name:              "Excessive Admin Users",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf(" %d users have full admin (should be 1-2 max)", len(adminUsers)),
			Remediation:       "Apply principle of least privilege",
			RemediationDetail: "Remove AdministratorAccess policy and grant specific permissions only",
			ScreenshotGuide:   "1. Go to IAM → Users\n2. Click each admin user\n3. Screenshot 'Permissions' tab\n4. Document why they need admin",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC6.5",
		Name:      "Least Privilege Access",
		Status:    "PASS",
		Evidence:  "Admin access appropriately restricted",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func (c *IAMAdvancedChecks) CheckServiceAccountMFA(ctx context.Context) (CheckResult, error) {
	// Check for programmatic users without MFA
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	serviceAccountsNoMFA := []string{}

	for _, user := range users.Users {
		// Check if user has access keys (programmatic access)
		keys, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})

		if err == nil && len(keys.AccessKeyMetadata) > 0 {
			// Has access keys, check for MFA
			mfaDevices, err := c.client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: user.UserName,
			})

			if err == nil && len(mfaDevices.MFADevices) == 0 {
				// Service account without MFA
				serviceAccountsNoMFA = append(serviceAccountsNoMFA, *user.UserName)
			}
		}
	}

	if len(serviceAccountsNoMFA) > 0 {
		return CheckResult{
			Control:     "CC6.5",
			Name:        "Service Account Security",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d service accounts lack MFA protection", len(serviceAccountsNoMFA)),
			Remediation: "Enable MFA or use IAM roles instead",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC6.5",
		Name:      "Service Account Security",
		Status:    "PASS",
		Evidence:  "Service accounts properly secured",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func (c *IAMAdvancedChecks) CheckRootAccountUsage(ctx context.Context) (CheckResult, error) {
	// This would check CloudTrail for root account usage
	// For now, return a warning to check manually
	return CheckResult{
		Control:         "CC6.6",
		Name:            "Root Account Usage",
		Status:          "INFO",
		Severity:        "HIGH",
		Evidence:        "Check CloudTrail for root account usage (should be ZERO)",
		Remediation:     "Never use root account for daily operations",
		ScreenshotGuide: "1. Go to CloudTrail Event History\n2. Filter by 'User name' = 'root'\n3. Screenshot showing NO recent root usage\n4. If any usage, document why",
		ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/events",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
	}, nil
}
