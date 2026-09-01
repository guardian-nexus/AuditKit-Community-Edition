package checks

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type IAMChecks struct {
	client *iam.Client
}

func NewIAMChecks(client *iam.Client) *IAMChecks {
	return &IAMChecks{client: client}
}

func (c *IAMChecks) Name() string {
	return "IAM Security Configuration"
}

func (c *IAMChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Existing checks
	if result, err := c.CheckRootMFA(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckPasswordPolicy(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckAccessKeyRotation(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckUnusedCredentials(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS checks
	if result, err := c.CheckRootAccessKeys(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckIAMUsersMFA(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckCredentialsUnused90Days(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckOneActiveAccessKey(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckIAMPoliciesAttached(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckHardwareMFARoot(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckSupportRole(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckIAMInstanceRoles(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckIAMPoliciesOnGroupsOnly(ctx); err == nil {
		results = append(results, result)
	}

	// Additional CIS AWS controls for better coverage
	if result, err := c.CheckPasswordExpiration(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckPasswordReusePrevention(ctx); err == nil {
		results = append(results, result)
	}

	// CIS AWS 1.1, 1.2, 1.18, 1.22 - Final IAM controls for 100%
	results = append(results, c.CheckAccountContactDetails(ctx))
	results = append(results, c.CheckSecurityContactInfo(ctx))
	if result, err := c.CheckIAMRolesSeparation(ctx); err == nil {
		results = append(results, result)
	}
	results = append(results, c.CheckIAMUserAccessReview(ctx))

	// NEW CIS controls - v0.7.0 additions
	if result, err := c.CheckCredentialsUnused45Days(ctx); err == nil {
		results = append(results, result)
	}
	if result, err := c.CheckIAMPoliciesAttachedToUsers(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *IAMChecks) CheckRootMFA(ctx context.Context) (CheckResult, error) {
	summary, err := c.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.6",
			Name:       "Root Account MFA",
			Status:     "FAIL",
			Evidence:   "Unable to check root MFA status",
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ROOT_MFA"),
		}, err
	}

	if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val == 0 {
		return CheckResult{
			Control:           "CIS-1.5, CC6.6",
			Name:              "Root Account MFA",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "Root account has NO MFA protection | Violates CIS-1.5, PCI DSS 8.4.2 (MFA for all console access) & HIPAA 164.312(a)(2)(i)",
			Remediation:       "Enable MFA on root account immediately\nSee PDF for detailed steps",
			RemediationDetail: "1. Sign in as root user\n2. Go to Security Credentials\n3. Enable MFA immediately",
			ScreenshotGuide:   "1. Sign in to AWS as root user\n2. Click account name → 'Security credentials'\n3. Screenshot 'Multi-factor authentication (MFA)' section\n4. Must show at least one MFA device assigned\n5. For PCI DSS: Document MFA type (virtual/hardware)",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/security_credentials",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ROOT_MFA"),
		}, nil
	}

	return CheckResult{
		Control:         "CIS-1.5, CC6.6",
		Name:            "Root Account MFA",
		Status:          "PASS",
		Evidence:        "Root account has MFA enabled | Meets CIS-1.5, SOC2 CC6.6, PCI DSS 8.4.2, HIPAA 164.312(a)(2)(i)",
		Severity:        "INFO",
		ScreenshotGuide: "1. Go to IAM → Security credentials\n2. Screenshot MFA section showing device configured",
		ConsoleURL:      "https://console.aws.amazon.com/iam/home#/security_credentials",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("ROOT_MFA"),
	}, nil
}

func (c *IAMChecks) CheckPasswordPolicy(ctx context.Context) (CheckResult, error) {
	policy, err := c.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return CheckResult{
			Control:           "CC6.7",
			Name:              "Password Policy",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "No password policy configured | Violates PCI DSS 8.3.6-8.2.5 (password requirements)",
			Remediation:       "Run: aws iam update-account-password-policy\nSee PDF for required parameters",
			RemediationDetail: "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24",
			ScreenshotGuide:   "1. Go to IAM → Account settings\n2. Screenshot 'Password policy' section\n3. Must show all requirements enabled\n4. PCI DSS requires minimum 7 chars, we recommend 14+",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("PASSWORD_POLICY"),
		}, nil
	}

	minLength := aws.ToInt32(policy.PasswordPolicy.MinimumPasswordLength)
	requireSymbols := policy.PasswordPolicy.RequireSymbols
	requireNumbers := policy.PasswordPolicy.RequireNumbers
	requireUpper := policy.PasswordPolicy.RequireUppercaseCharacters
	requireLower := policy.PasswordPolicy.RequireLowercaseCharacters

	issues := []string{}
	// PCI DSS requires minimum 7 characters, but 14+ is recommended
	pciMinLength := 7
	recommendedLength := 14

	if minLength < int32(pciMinLength) {
		issues = append(issues, fmt.Sprintf("minimum length is %d (PCI DSS requires %d+, recommend %d+)", minLength, pciMinLength, recommendedLength))
	} else if minLength < int32(recommendedLength) {
		issues = append(issues, fmt.Sprintf("minimum length is %d (recommend %d+ for better security)", minLength, recommendedLength))
	}

	if !requireSymbols {
		issues = append(issues, "doesn't require symbols (PCI DSS 8.3.6)")
	}
	if !requireNumbers {
		issues = append(issues, "doesn't require numbers (PCI DSS 8.3.6)")
	}
	if !requireUpper || !requireLower {
		issues = append(issues, "doesn't require mixed case (PCI DSS 8.3.6)")
	}

	if len(issues) > 0 {
		return CheckResult{
			Control:           "CC6.7",
			Name:              "Password Policy",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("Password policy is weak: %s", issues[0]),
			Remediation:       "Update password policy (aws iam update-account-password-policy)",
			RemediationDetail: "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("PASSWORD_POLICY"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.7",
		Name:       "Password Policy",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("Password policy meets requirements (14+ chars, complexity) | Meets SOC2 CC6.7, PCI DSS 8.3.6-8.2.5, HIPAA 164.308(a)(5)(ii)(D)"),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("PASSWORD_POLICY"),
	}, nil
}

func (c *IAMChecks) CheckAccessKeyRotation(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	oldKeys := []string{}
	veryOldKeys := []string{}

	for _, user := range users.Users {
		keys, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}

		for _, key := range keys.AccessKeyMetadata {
			if key.Status != types.StatusTypeActive {
				continue
			}

			if key.CreateDate != nil {
				age := time.Since(*key.CreateDate)
				days := int(age.Hours() / 24)

				if days > 180 {
					veryOldKeys = append(veryOldKeys, fmt.Sprintf("%s (%d days old!)", *user.UserName, days))
				} else if days > 90 {
					oldKeys = append(oldKeys, fmt.Sprintf("%s (%d days)", *user.UserName, days))
				}
			}
		}
	}

	if len(veryOldKeys) > 0 {
		keyList := veryOldKeys[0]
		if len(veryOldKeys) > 1 {
			keyList += fmt.Sprintf(" +%d more", len(veryOldKeys)-1)
		}

		firstUser := ""
		if len(veryOldKeys) > 0 {
			// Extract just the username from "username (X days old!)"
			firstUser = veryOldKeys[0]
			if idx := fmt.Sprintf("%s", firstUser); len(idx) > 0 {
				if endIdx := len(firstUser); endIdx > 0 {
					for i, c := range firstUser {
						if c == ' ' {
							firstUser = firstUser[:i]
							break
						}
					}
				}
			}
		}

		return CheckResult{
			Control:           "CIS-1.14, CC6.8",
			Name:              "Access Key Rotation",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d access keys are 180+ days old: %s | Violates CIS-1.14, PCI DSS 8.3.9 (change every 90 days)", len(veryOldKeys), keyList),
			Remediation:       fmt.Sprintf("Rotate key for user: %s\nRun: aws iam create-access-key", firstUser),
			RemediationDetail: fmt.Sprintf("aws iam create-access-key --user-name %s && aws iam delete-access-key --access-key-id OLD_KEY_ID --user-name %s", firstUser, firstUser),
			ScreenshotGuide:   "1. Go to IAM → Users\n2. Click on each user\n3. Go to 'Security credentials' tab\n4. Screenshot 'Access keys' section showing creation dates\n5. For PCI DSS: Document rotation schedule",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ACCESS_KEY_ROTATION"),
		}, nil
	}

	if len(oldKeys) > 0 {
		return CheckResult{
			Control:     "CIS-1.14, CC6.8",
			Name:        "Access Key Rotation",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d access keys older than 90 days | CIS-1.14 and PCI DSS 8.3.9 requires rotation", len(oldKeys)),
			Remediation: "Rotate keys older than 90 days",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("ACCESS_KEY_ROTATION"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-1.14, CC6.8",
		Name:       "Access Key Rotation",
		Status:     "PASS",
		Evidence:   "All access keys rotated within 90 days | Meets CIS-1.14, SOC2 CC6.8, PCI DSS 8.3.9, HIPAA 164.308(a)(4)(ii)(B)",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ACCESS_KEY_ROTATION"),
	}, nil
}

func (c *IAMChecks) CheckUnusedCredentials(ctx context.Context) (CheckResult, error) {
	// Get credential report
	// Note: This may need to be generated first with GenerateCredentialReport
	report, err := c.client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		// If report doesn't exist, try to generate it
		_, genErr := c.client.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if genErr != nil {
			return CheckResult{
				Control:    "CC6.7",
				Name:       "Unused Credentials",
				Status:     "INFO",
				Evidence:   "Unable to generate credential report | Meets PCI DSS 8.2.6 (remove inactive accounts within 90 days)",
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("UNUSED_CREDENTIALS"),
			}, nil
		}

		return CheckResult{
			Control:    "CC6.7",
			Name:       "Unused Credentials",
			Status:     "INFO",
			Evidence:   "Credential report being generated, check again in 10 seconds",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("UNUSED_CREDENTIALS"),
		}, nil
	}

	// Parse the CSV report
	csvReader := csv.NewReader(strings.NewReader(string(report.Content)))
	records, err := csvReader.ReadAll()
	if err != nil {
		return CheckResult{
			Control:    "CC6.7",
			Name:       "Unused Credentials",
			Status:     "INFO",
			Evidence:   fmt.Sprintf("Unable to parse credential report: %v", err),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("UNUSED_CREDENTIALS"),
		}, nil
	}

	if len(records) < 2 {
		return CheckResult{
			Control:    "CC6.7",
			Name:       "Unused Credentials",
			Status:     StatusInfo,
			Evidence:   "No IAM users found in credential report",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("UNUSED_CREDENTIALS"),
		}, nil
	}

	// Parse header to find column indices
	header := records[0]
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[col] = i
	}

	unusedUsers := []string{}
	unusedPasswords := []string{}
	unusedKeys := []string{}
	now := time.Now()
	cutoffDate := now.AddDate(0, 0, -90) // 90 days ago

	// Skip header row
	for _, row := range records[1:] {
		if len(row) == 0 {
			continue
		}

		user := row[colIndex["user"]]
		if user == "<root_account>" {
			continue // Skip root account, handled separately
		}

		// Check password_last_used
		if pwIdx, ok := colIndex["password_last_used"]; ok && pwIdx < len(row) {
			pwLastUsed := row[pwIdx]
			if pwLastUsed != "N/A" && pwLastUsed != "no_information" && pwLastUsed != "" {
				if lastUsed, err := time.Parse(time.RFC3339, pwLastUsed); err == nil {
					if lastUsed.Before(cutoffDate) {
						unusedPasswords = append(unusedPasswords, user)
					}
				}
			}
		}

		// Check access_key_1_last_used_date
		if keyIdx, ok := colIndex["access_key_1_last_used_date"]; ok && keyIdx < len(row) {
			key1Active := ""
			if activeIdx, ok := colIndex["access_key_1_active"]; ok && activeIdx < len(row) {
				key1Active = row[activeIdx]
			}
			if key1Active == "true" {
				key1LastUsed := row[keyIdx]
				if key1LastUsed != "N/A" && key1LastUsed != "" {
					if lastUsed, err := time.Parse(time.RFC3339, key1LastUsed); err == nil {
						if lastUsed.Before(cutoffDate) {
							unusedKeys = append(unusedKeys, user+" (key1)")
						}
					}
				}
			}
		}

		// Check access_key_2_last_used_date
		if keyIdx, ok := colIndex["access_key_2_last_used_date"]; ok && keyIdx < len(row) {
			key2Active := ""
			if activeIdx, ok := colIndex["access_key_2_active"]; ok && activeIdx < len(row) {
				key2Active = row[activeIdx]
			}
			if key2Active == "true" {
				key2LastUsed := row[keyIdx]
				if key2LastUsed != "N/A" && key2LastUsed != "" {
					if lastUsed, err := time.Parse(time.RFC3339, key2LastUsed); err == nil {
						if lastUsed.Before(cutoffDate) {
							unusedKeys = append(unusedKeys, user+" (key2)")
						}
					}
				}
			}
		}
	}

	// Combine all unused credentials
	unusedUsers = append(unusedPasswords, unusedKeys...)

	if len(unusedUsers) > 0 {
		userList := strings.Join(unusedUsers, ", ")
		if len(unusedUsers) > 5 {
			userList = strings.Join(unusedUsers[:5], ", ") + fmt.Sprintf(" +%d more", len(unusedUsers)-5)
		}

		return CheckResult{
			Control:           "CC6.7",
			Name:              "Unused Credentials",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d credentials unused for 90+ days: %s | Violates PCI DSS 8.2.6 (remove/disable inactive accounts within 90 days)", len(unusedUsers), userList),
			Remediation:       "Disable or delete unused IAM credentials",
			RemediationDetail: "aws iam update-login-profile --user-name USERNAME --password-reset-required\naws iam delete-access-key --user-name USERNAME --access-key-id KEY_ID",
			ScreenshotGuide:   "1. Go to IAM → Users\n2. Sort by 'Last activity'\n3. Screenshot users with no recent activity\n4. For PCI DSS: Document review process for inactive accounts",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("UNUSED_CREDENTIALS"),
		}, nil
	}

	return CheckResult{
		Control:         "CC6.7",
		Name:            "Unused Credentials",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All credentials used within 90 days (checked %d users) | Meets PCI DSS 8.2.6, SOC2 CC6.7", len(records)-1),
		Severity:        "INFO",
		ScreenshotGuide: "1. Go to IAM → Credential Report\n2. Download report\n3. Screenshot showing recent activity for all users",
		ConsoleURL:      "https://console.aws.amazon.com/iam/home#/credential_report",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("UNUSED_CREDENTIALS"),
	}, nil
}

// NEW CIS-SPECIFIC CHECKS

// CIS 1.4 - Ensure no root user access keys exist
func (c *IAMChecks) CheckRootAccessKeys(ctx context.Context) (CheckResult, error) {
	summary, err := c.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return CheckResult{}, err
	}

	rootAccessKeysExist := false
	if val, ok := summary.SummaryMap["AccountAccessKeysPresent"]; ok && val > 0 {
		rootAccessKeysExist = true
	}

	if rootAccessKeysExist {
		return CheckResult{
			Control:           "CIS-1.11",
			Name:              "Root Account Access Keys",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "Root account has access keys | Violates CIS-1.11",
			Remediation:       "Delete root account access keys immediately",
			RemediationDetail: "1. Sign in as root\n2. Go to Security credentials\n3. Delete all access keys\n4. Use IAM users for programmatic access",
			ScreenshotGuide:   "AWS Console → Root account → Security credentials → Access keys section (must be empty)",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/security_credentials",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ROOT_ACCESS_KEYS"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-1.11",
		Name:       "Root Account Access Keys",
		Status:     "PASS",
		Evidence:   "No root account access keys exist | Meets CIS-1.11",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ROOT_ACCESS_KEYS"),
	}, nil
}

// CIS 1.6 - Ensure hardware MFA is enabled for root account
func (c *IAMChecks) CheckHardwareMFARoot(ctx context.Context) (CheckResult, error) {
	// This is an INFO check since we can't determine if it's hardware vs virtual MFA via API
	return CheckResult{
		Control:           "[CIS-1.6]",
		Name:              "Root Hardware MFA",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify root account uses hardware MFA (not virtual)",
		Remediation:       "Enable hardware MFA for root account for additional security",
		RemediationDetail: "1. Sign in as root\n2. Go to Security credentials\n3. Add hardware MFA device (not virtual authenticator app)\n4. Follow device setup instructions",
		ScreenshotGuide:   "AWS Console → Root Security credentials → MFA → Screenshot showing 'Hardware' MFA device type",
		ConsoleURL:        "https://console.aws.amazon.com/iam/home#/security_credentials",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("IAM_HARDWARE_MFA_ROOT"),
	}, nil
}

// CIS 1.10 - Ensure MFA is enabled for all IAM users with console access
func (c *IAMChecks) CheckIAMUsersMFA(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	usersWithoutMFA := []string{}
	for _, user := range users.Users {
		// Check if user has console access
		_, err := c.client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
			UserName: user.UserName,
		})
		if err != nil {
			// User doesn't have console access, skip
			continue
		}

		// Check MFA devices
		mfaDevices, err := c.client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: user.UserName,
		})
		if err != nil || len(mfaDevices.MFADevices) == 0 {
			usersWithoutMFA = append(usersWithoutMFA, *user.UserName)
		}
	}

	if len(usersWithoutMFA) > 0 {
		return CheckResult{
			Control:           "[CIS-1.10]",
			Name:              "MFA for IAM Users",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d IAM users without MFA: %v", len(usersWithoutMFA), usersWithoutMFA),
			Remediation:       "Enable MFA for all IAM users with console access",
			RemediationDetail: "For each user: IAM Console → Users → [Username] → Security credentials → Assign MFA device",
			ScreenshotGuide:   "IAM → Users → [each user] → Security credentials → Screenshot MFA section showing device assigned",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("IAM_USER_MFA"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.10]",
		Name:       "MFA for IAM Users",
		Status:     "PASS",
		Evidence:   "All IAM users with console access have MFA enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("IAM_USER_MFA"),
	}, nil
}

// CIS 1.12 - Ensure credentials unused for 90 days or greater are disabled
func (c *IAMChecks) CheckCredentialsUnused90Days(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "[CIS-1.12]",
		Name:              "Credentials Unused 90 Days",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Review IAM credential report for unused credentials",
		Remediation:       "Disable or remove IAM credentials not used in 90+ days",
		RemediationDetail: "1. Generate credential report: aws iam generate-credential-report\n2. Get report: aws iam get-credential-report\n3. Review password_last_used and access_key_last_used columns\n4. Disable unused credentials",
		ScreenshotGuide:   "IAM → Credential report → Screenshot showing users with password_last_used/access_key_last_used > 90 days",
		ConsoleURL:        "https://console.aws.amazon.com/iam/home#/credential_report",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("IAM_CREDENTIALS_UNUSED_90_DAYS"),
	}, nil
}

// CIS 1.13 - Ensure there is only one active access key per IAM user
func (c *IAMChecks) CheckOneActiveAccessKey(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	usersWithMultipleKeys := []string{}
	for _, user := range users.Users {
		keys, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})
		if err != nil {
			continue
		}

		activeKeyCount := 0
		for _, key := range keys.AccessKeyMetadata {
			if key.Status == types.StatusTypeActive {
				activeKeyCount++
			}
		}

		if activeKeyCount > 1 {
			usersWithMultipleKeys = append(usersWithMultipleKeys, fmt.Sprintf("%s (%d keys)", *user.UserName, activeKeyCount))
		}
	}

	if len(usersWithMultipleKeys) > 0 {
		return CheckResult{
			Control:           "[CIS-1.13]",
			Name:              "One Active Access Key Per User",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d users have multiple active access keys: %v", len(usersWithMultipleKeys), usersWithMultipleKeys),
			Remediation:       "Remove extra access keys, keep only one active per user",
			RemediationDetail: "For each user: aws iam delete-access-key --user-name [USERNAME] --access-key-id [KEY_ID]",
			ScreenshotGuide:   "IAM → Users → [user] → Security credentials → Screenshot showing single active access key",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("IAM_USER_UNUSED"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.13]",
		Name:       "One Active Access Key Per User",
		Status:     "PASS",
		Evidence:   "All IAM users have at most one active access key",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("IAM_USER_UNUSED"),
	}, nil
}

// CIS 1.15 - Ensure IAM users receive permissions only through groups
func (c *IAMChecks) CheckIAMPoliciesAttached(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	usersWithDirectPolicies := []string{}
	for _, user := range users.Users {
		// Check attached policies
		attached, err := c.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: user.UserName,
		})
		if err == nil && len(attached.AttachedPolicies) > 0 {
			usersWithDirectPolicies = append(usersWithDirectPolicies, *user.UserName)
			continue
		}

		// Check inline policies
		inline, err := c.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
			UserName: user.UserName,
		})
		if err == nil && len(inline.PolicyNames) > 0 {
			usersWithDirectPolicies = append(usersWithDirectPolicies, *user.UserName)
		}
	}

	if len(usersWithDirectPolicies) > 0 {
		return CheckResult{
			Control:           "[CIS-1.15]",
			Name:              "IAM Policies via Groups Only",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d users have policies attached directly: %v", len(usersWithDirectPolicies), usersWithDirectPolicies),
			Remediation:       "Attach policies to groups instead of users directly",
			RemediationDetail: "1. Create IAM groups with appropriate policies\n2. Add users to groups\n3. Remove direct policy attachments from users",
			ScreenshotGuide:   "IAM → Users → [user] → Permissions tab → Screenshot showing 'No permissions policies'",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("IAM_POLICIES_ATTACHED"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.15]",
		Name:       "IAM Policies via Groups Only",
		Status:     "PASS",
		Evidence:   "All IAM users receive permissions through groups",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("IAM_POLICIES_ATTACHED"),
	}, nil
}

// CIS 1.17 - Ensure a support role has been created for incident management
func (c *IAMChecks) CheckSupportRole(ctx context.Context) (CheckResult, error) {
	roles, err := c.client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	hasSupportRole := false
	for _, role := range roles.Roles {
		// Check if role has AWSSupportAccess policy
		attachedPolicies, err := c.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: role.RoleName,
		})
		if err == nil {
			for _, policy := range attachedPolicies.AttachedPolicies {
				if aws.ToString(policy.PolicyArn) == "arn:aws:iam::aws:policy/AWSSupportAccess" {
					hasSupportRole = true
					break
				}
			}
		}
		if hasSupportRole {
			break
		}
	}

	if !hasSupportRole {
		return CheckResult{
			Control:           "[CIS-1.17]",
			Name:              "IAM Support Role",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          "No IAM role with AWSSupportAccess policy exists",
			Remediation:       "Create IAM role with AWSSupportAccess for incident management",
			RemediationDetail: "1. Create IAM role\n2. Attach AWSSupportAccess policy: arn:aws:iam::aws:policy/AWSSupportAccess\n3. Document who can assume this role",
			ScreenshotGuide:   "IAM → Roles → Screenshot showing role with AWSSupportAccess policy attached",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/roles",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("IAM_SUPPORT_ROLE"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.17]",
		Name:       "IAM Support Role",
		Status:     "PASS",
		Evidence:   "IAM role with AWSSupportAccess policy exists",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("IAM_SUPPORT_ROLE"),
	}, nil
}

// CIS 1.19 - Ensure IAM instance roles are used for AWS resource access
func (c *IAMChecks) CheckIAMInstanceRoles(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "[CIS-1.19]",
		Name:              "IAM Instance Roles",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify EC2 instances use IAM roles instead of access keys",
		Remediation:       "Attach IAM roles to EC2 instances for AWS resource access",
		RemediationDetail: "1. Create IAM role with required permissions\n2. Attach role to EC2 instance\n3. Remove any embedded access keys from instance\n4. Update application code to use instance role credentials",
		ScreenshotGuide:   "EC2 Console → Instances → Instance details → Screenshot showing IAM role attached",
		ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#Instances",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("IAM_INSTANCE_ROLES"),
	}, nil
}

// CIS 1.22 - Ensure IAM policies are attached only to groups or roles
func (c *IAMChecks) CheckIAMPoliciesOnGroupsOnly(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{
			Control:    "[CIS-1.22]",
			Name:       "IAM Policies Attached to Groups Only",
			Status:     "FAIL",
			Evidence:   "Unable to check IAM user policies",
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "1.22", "SOC2": "CC6.3"},
		}, err
	}

	usersWithPolicies := []string{}

	for _, user := range users.Users {
		// Check for attached managed policies
		managedPolicies, err := c.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: user.UserName,
		})
		if err == nil && len(managedPolicies.AttachedPolicies) > 0 {
			usersWithPolicies = append(usersWithPolicies, fmt.Sprintf("%s (%d policies)", aws.ToString(user.UserName), len(managedPolicies.AttachedPolicies)))
		}

		// Check for inline policies
		inlinePolicies, err := c.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
			UserName: user.UserName,
		})
		if err == nil && len(inlinePolicies.PolicyNames) > 0 {
			// Only add if not already added for managed policies
			alreadyAdded := false
			userName := aws.ToString(user.UserName)
			for _, existing := range usersWithPolicies {
				if len(existing) > len(userName) && existing[:len(userName)] == userName {
					alreadyAdded = true
					break
				}
			}
			if !alreadyAdded {
				usersWithPolicies = append(usersWithPolicies, fmt.Sprintf("%s (%d inline)", userName, len(inlinePolicies.PolicyNames)))
			}
		}
	}

	if len(usersWithPolicies) > 0 {
		displayUsers := usersWithPolicies
		if len(usersWithPolicies) > 3 {
			displayUsers = usersWithPolicies[:3]
		}

		firstUser := ""
		if len(usersWithPolicies) > 0 {
			firstUser = usersWithPolicies[0]
			for i, c := range firstUser {
				if c == ' ' {
					firstUser = firstUser[:i]
					break
				}
			}
		}

		return CheckResult{
			Control:     "[CIS-1.22]",
			Name:        "IAM Policies Attached to Groups Only",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d users have policies attached directly (violates CIS 1.22): %v | Should use groups/roles instead", len(usersWithPolicies), displayUsers),
			Remediation: fmt.Sprintf("Remove policies from user '%s' and attach to groups instead", firstUser),
			RemediationDetail: fmt.Sprintf(`# Create or use existing IAM group
aws iam create-group --group-name Developers

# Attach policy to group
aws iam attach-group-policy --group-name Developers --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Add user to group
aws iam add-user-to-group --group-name Developers --user-name %s

# Remove direct policy from user
aws iam detach-user-policy --user-name %s --policy-arn POLICY_ARN
aws iam delete-user-policy --user-name %s --policy-name INLINE_POLICY_NAME`, firstUser, firstUser, firstUser),
			ScreenshotGuide: "IAM Console → Users → Click user → Permissions tab → Screenshot showing NO attached policies (policies should be via groups)",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "1.22", "SOC2": "CC6.3", "PCI-DSS": "7.2.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.22]",
		Name:       "IAM Policies Attached to Groups Only",
		Status:     "PASS",
		Evidence:   "No IAM policies attached directly to users | Meets CIS 1.22 (centralized permissions via groups/roles)",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "1.22", "SOC2": "CC6.3", "PCI-DSS": "7.2.2"},
	}, nil
}

// CheckPasswordExpiration verifies password expiration is 90 days or less (CIS 1.20)
func (c *IAMChecks) CheckPasswordExpiration(ctx context.Context) (CheckResult, error) {
	policy, err := c.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return CheckResult{
			Control:           "[CIS-1.20]",
			Name:              "Password Expiration Policy",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          "No password policy configured | Violates CIS 1.20 (password expiration required)",
			Remediation:       "Configure password policy with max age of 90 days or less",
			RemediationDetail: "aws iam update-account-password-policy --max-password-age 90 --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24",
			ScreenshotGuide:   "IAM → Account settings → Password policy → Screenshot showing 'Password expiration period' set to 90 days or less",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "1.20", "SOC2": "CC6.1", "PCI-DSS": "8.3.9"},
		}, nil
	}

	maxAge := aws.ToInt32(policy.PasswordPolicy.MaxPasswordAge)

	if maxAge == 0 {
		return CheckResult{
			Control:           "[CIS-1.20]",
			Name:              "Password Expiration Policy",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          "Password expiration is not enabled | Violates CIS 1.20 (passwords never expire)",
			Remediation:       "Set password max age to 90 days or less",
			RemediationDetail: "aws iam update-account-password-policy --max-password-age 90",
			ScreenshotGuide:   "IAM → Account settings → Password policy → Screenshot showing 'Password expiration period' enabled and ≤ 90 days",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "1.20", "SOC2": "CC6.1", "PCI-DSS": "8.3.9"},
		}, nil
	}

	if maxAge > 90 {
		return CheckResult{
			Control:           "[CIS-1.20]",
			Name:              "Password Expiration Policy",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("Password max age is %d days (exceeds 90 days) | Violates CIS 1.20", maxAge),
			Remediation:       "Reduce password max age to 90 days or less",
			RemediationDetail: "aws iam update-account-password-policy --max-password-age 90",
			ScreenshotGuide:   "IAM → Account settings → Password policy → Screenshot showing 'Password expiration period' ≤ 90 days",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "1.20", "SOC2": "CC6.1", "PCI-DSS": "8.3.9"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.20]",
		Name:       "Password Expiration Policy",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("Password max age is %d days (≤ 90) | Meets CIS 1.20", maxAge),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "1.20", "SOC2": "CC6.1", "PCI-DSS": "8.3.9"},
	}, nil
}

// CheckPasswordReusePrevention verifies password reuse prevention is configured (CIS 1.21)
func (c *IAMChecks) CheckPasswordReusePrevention(ctx context.Context) (CheckResult, error) {
	policy, err := c.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return CheckResult{
			Control:           "[CIS-1.21]",
			Name:              "Password Reuse Prevention",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          "No password policy configured | Violates CIS 1.21 (password reuse prevention required)",
			Remediation:       "Configure password policy to prevent reuse of last 24 passwords",
			RemediationDetail: "aws iam update-account-password-policy --password-reuse-prevention 24 --max-password-age 90 --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters",
			ScreenshotGuide:   "IAM → Account settings → Password policy → Screenshot showing 'Password reuse prevention' set to 24",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "1.21", "SOC2": "CC6.1", "PCI-DSS": "8.3.7"},
		}, nil
	}

	reusePrevent := aws.ToInt32(policy.PasswordPolicy.PasswordReusePrevention)

	if reusePrevent == 0 {
		return CheckResult{
			Control:           "[CIS-1.21]",
			Name:              "Password Reuse Prevention",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          "Password reuse prevention is not enabled | Violates CIS 1.21 (users can reuse old passwords)",
			Remediation:       "Enable password reuse prevention for last 24 passwords",
			RemediationDetail: "aws iam update-account-password-policy --password-reuse-prevention 24",
			ScreenshotGuide:   "IAM → Account settings → Password policy → Screenshot showing 'Password reuse prevention' = 24",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "1.21", "SOC2": "CC6.1", "PCI-DSS": "8.3.7"},
		}, nil
	}

	if reusePrevent < 24 {
		return CheckResult{
			Control:           "[CIS-1.21]",
			Name:              "Password Reuse Prevention",
			Status:            "FAIL",
			Severity:          "LOW",
			Evidence:          fmt.Sprintf("Password reuse prevention is %d (CIS recommends 24) | Partially meets CIS 1.21", reusePrevent),
			Remediation:       "Increase password reuse prevention to 24 passwords",
			RemediationDetail: "aws iam update-account-password-policy --password-reuse-prevention 24",
			ScreenshotGuide:   "IAM → Account settings → Password policy → Screenshot showing 'Password reuse prevention' = 24",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Priority:          PriorityLow,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "1.21", "SOC2": "CC6.1", "PCI-DSS": "8.3.7"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.21]",
		Name:       "Password Reuse Prevention",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("Password reuse prevention is %d (≥ 24) | Meets CIS 1.21", reusePrevent),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "1.21", "SOC2": "CC6.1", "PCI-DSS": "8.3.7"},
	}, nil
}

// CIS 1.1 - Maintain current contact details
func (c *IAMChecks) CheckAccountContactDetails(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "[CIS-1.1]",
		Name:        "Account Contact Details",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Verify account contact details are current and monitored",
		Remediation: "Update account contact details in AWS Console",
		RemediationDetail: `1. Sign in as root user
2. Navigate to "My Account" page
3. Update contact information including:
   - Full Name
   - Address
   - Phone Number
   - Email (ensure it's monitored)
4. Screenshot showing current contact details`,
		ScreenshotGuide: "AWS Console → Account (top right) → My Account → Contact Information → Screenshot",
		ConsoleURL:      "https://console.aws.amazon.com/billing/home#/account",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-AWS": "1.1"},
	}
}

// CIS 1.2 - Ensure security contact information is registered
func (c *IAMChecks) CheckSecurityContactInfo(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "[CIS-1.2]",
		Name:        "Security Contact Information",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Verify security contact information is registered and monitored",
		Remediation: "Register security contact information",
		RemediationDetail: `1. Sign in as root user
2. Navigate to "My Account" page
3. Scroll to "Alternate Contacts" section
4. Add "Security" contact with:
   - Name
   - Email (monitored 24/7)
   - Phone number
5. Screenshot showing security contact configured`,
		ScreenshotGuide: "AWS Console → Account → My Account → Alternate Contacts → Security contact → Screenshot",
		ConsoleURL:      "https://console.aws.amazon.com/billing/home#/account",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-AWS": "1.2", "SOC2": "CC6.1"},
	}
}

// CIS 1.18 - Ensure IAM Master and IAM Manager roles are in use
func (c *IAMChecks) CheckIAMRolesSeparation(ctx context.Context) (CheckResult, error) {
	// List all roles
	rolesOutput, err := c.client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	hasIAMAdminRole := false
	hasIAMLimitedRole := false

	for _, role := range rolesOutput.Roles {
		roleName := aws.ToString(role.RoleName)

		// Check for IAM management roles (various naming conventions)
		if contains(roleName, "IAMAdmin") || contains(roleName, "IAMMaster") || contains(roleName, "IAMFullAccess") {
			hasIAMAdminRole = true
		}
		if contains(roleName, "IAMManager") || contains(roleName, "IAMLimited") || contains(roleName, "IAMReadOnly") {
			hasIAMLimitedRole = true
		}
	}

	if !hasIAMAdminRole || !hasIAMLimitedRole {
		return CheckResult{
			Control:     "[CIS-1.18]",
			Name:        "IAM Master and Manager Roles",
			Status:      "INFO",
			Severity:    "MEDIUM",
			Evidence:    "MANUAL CHECK: Verify IAM Master (full admin) and IAM Manager (limited) roles exist for separation of duties | CIS 1.18",
			Remediation: "Create separate IAM roles for full IAM administration vs limited IAM management",
			RemediationDetail: `# Create IAM Master role (full IAM admin)
aws iam create-role --role-name IAMMasterRole --assume-role-policy-document file://trust-policy.json
aws iam attach-role-policy --role-name IAMMasterRole --policy-arn arn:aws:iam::aws:policy/IAMFullAccess

# Create IAM Manager role (limited IAM management)
aws iam create-role --role-name IAMManagerRole --assume-role-policy-document file://trust-policy.json
aws iam put-role-policy --role-name IAMManagerRole --policy-name IAMLimitedAccess --policy-document file://limited-iam-policy.json

# Best practice: Separate who can create/delete IAM resources vs who can assign permissions`,
			ScreenshotGuide: "IAM → Roles → Screenshot showing IAMMasterRole and IAMManagerRole with appropriate policies",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/roles",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "1.18", "SOC2": "CC6.3"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.18]",
		Name:       "IAM Master and Manager Roles",
		Status:     "PASS",
		Evidence:   "IAM management roles detected | Meets CIS 1.18",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "1.18", "SOC2": "CC6.3"},
	}, nil
}

// CIS 1.22 - Ensure IAM user access is reviewed periodically
func (c *IAMChecks) CheckIAMUserAccessReview(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "[CIS-1.22]",
		Name:        "IAM User Access Review",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Verify IAM user access is reviewed at least every 90 days",
		Remediation: "Establish periodic IAM access review process",
		RemediationDetail: `1. Generate credential report:
   aws iam generate-credential-report
   aws iam get-credential-report --output text --query Content | base64 -d > credentials.csv

2. Review the report for:
   - Users with access keys not rotated in 90+ days
   - Users who haven't logged in for 90+ days
   - Users with unnecessary permissions

3. Document the review process:
   - Who performed the review
   - Date of review
   - Actions taken (revoked access, etc.)

4. Automate with AWS Config rules or Lambda

5. Screenshot showing documented review process`,
		ScreenshotGuide: "IAM → Credential Report → Screenshot showing recent review date + documented process",
		ConsoleURL:      "https://console.aws.amazon.com/iam/home#/credential_report",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-AWS": "1.22", "SOC2": "CC6.2", "PCI-DSS": "8.2.6"},
	}
}

// CIS-1.3 - Ensure credentials unused for 45 days or greater are disabled
func (c *IAMChecks) CheckCredentialsUnused45Days(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unusedCredentials := []string{}

	for _, user := range users.Users {
		// Check password last used
		if user.PasswordLastUsed != nil {
			daysSinceUsed := int(time.Since(*user.PasswordLastUsed).Hours() / 24)
			if daysSinceUsed > 45 {
				unusedCredentials = append(unusedCredentials, fmt.Sprintf("%s (password unused %d days)", *user.UserName, daysSinceUsed))
			}
		}

		// Check access keys last used
		keys, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})
		if err == nil {
			for _, key := range keys.AccessKeyMetadata {
				if key.Status == types.StatusTypeActive && key.CreateDate != nil {
					keyAge := int(time.Since(*key.CreateDate).Hours() / 24)
					if keyAge > 45 {
						// Check if key has been used recently
						accessKeyLastUsed, err := c.client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
							AccessKeyId: key.AccessKeyId,
						})
						if err == nil && accessKeyLastUsed.AccessKeyLastUsed != nil && accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate != nil {
							daysSinceKeyUsed := int(time.Since(*accessKeyLastUsed.AccessKeyLastUsed.LastUsedDate).Hours() / 24)
							if daysSinceKeyUsed > 45 {
								unusedCredentials = append(unusedCredentials, fmt.Sprintf("%s (access key unused %d days)", *user.UserName, daysSinceKeyUsed))
							}
						}
					}
				}
			}
		}
	}

	if len(unusedCredentials) > 0 {
		return CheckResult{
			Control:           "CIS-1.3",
			Name:              "Credentials Unused 45+ Days",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d credentials unused for 45+ days: %v | Violates CIS-1.3", len(unusedCredentials), unusedCredentials),
			Remediation:       "Disable or remove unused credentials",
			RemediationDetail: "aws iam update-access-key --access-key-id KEY_ID --status Inactive --user-name USERNAME",
			ScreenshotGuide:   "IAM → Users → Security credentials → Screenshot showing all credentials used within 45 days",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("UNUSED_CREDENTIALS_45"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-1.3",
		Name:       "Credentials Unused 45+ Days",
		Status:     "PASS",
		Evidence:   "No credentials unused for 45+ days | Meets CIS-1.3",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("UNUSED_CREDENTIALS_45"),
	}, nil
}

// CIS-1.16 - Ensure IAM policies are attached only to groups or roles
func (c *IAMChecks) CheckIAMPoliciesAttachedToUsers(ctx context.Context) (CheckResult, error) {
	users, err := c.client.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	usersWithDirectPolicies := []string{}

	for _, user := range users.Users {
		// Check for attached managed policies
		attachedPolicies, err := c.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: user.UserName,
		})
		if err == nil && len(attachedPolicies.AttachedPolicies) > 0 {
			usersWithDirectPolicies = append(usersWithDirectPolicies, fmt.Sprintf("%s (%d policies)", *user.UserName, len(attachedPolicies.AttachedPolicies)))
		}

		// Check for inline policies
		inlinePolicies, err := c.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
			UserName: user.UserName,
		})
		if err == nil && len(inlinePolicies.PolicyNames) > 0 {
			usersWithDirectPolicies = append(usersWithDirectPolicies, fmt.Sprintf("%s (%d inline)", *user.UserName, len(inlinePolicies.PolicyNames)))
		}
	}

	if len(usersWithDirectPolicies) > 0 {
		return CheckResult{
			Control:           "CIS-1.16",
			Name:              "IAM Policies on Groups/Roles Only",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d users have policies attached directly (should use groups): %v | Violates CIS-1.16", len(usersWithDirectPolicies), usersWithDirectPolicies),
			Remediation:       "Attach policies to groups/roles, not users",
			RemediationDetail: "1. Create IAM group\n2. Attach policies to group\n3. Add users to group\n4. Remove direct policy attachments from users",
			ScreenshotGuide:   "IAM → Users → Permissions tab → Screenshot showing no directly attached policies (should inherit from groups)",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("IAM_POLICIES_GROUPS_ONLY"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-1.16",
		Name:       "IAM Policies on Groups/Roles Only",
		Status:     "PASS",
		Evidence:   "All IAM policies attached to groups/roles (not users) | Meets CIS-1.16",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("IAM_POLICIES_GROUPS_ONLY"),
	}, nil
}
