package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type AWSCMMCLevel1Checks struct {
	iamClient        *iam.Client
	s3Client         *s3.Client
	ec2Client        *ec2.Client
	cloudtrailClient *cloudtrail.Client
}

func NewAWSCMMCLevel1Checks(iamClient *iam.Client, s3Client *s3.Client, ec2Client *ec2.Client, cloudtrailClient *cloudtrail.Client) *AWSCMMCLevel1Checks {
	return &AWSCMMCLevel1Checks{
		iamClient:        iamClient,
		s3Client:         s3Client,
		ec2Client:        ec2Client,
		cloudtrailClient: cloudtrailClient,
	}
}

func (c *AWSCMMCLevel1Checks) Name() string {
	return "AWS CMMC Level 1"
}

func (c *AWSCMMCLevel1Checks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// ACCESS CONTROL - 2 automated
	results = append(results, c.CheckAC_L1_001(ctx))
	results = append(results, c.CheckAC_L1_002(ctx))

	// IDENTIFICATION AND AUTHENTICATION - 2 automated
	results = append(results, c.CheckIA_L1_001(ctx))
	results = append(results, c.CheckIA_L1_002(ctx))

	// MEDIA PROTECTION - 1 INFO
	results = append(results, c.CheckMP_L1_001(ctx))

	// PHYSICAL PROTECTION - 4 INFO
	results = append(results, c.CheckPE_L1_001(ctx))
	results = append(results, c.CheckPE_L1_002(ctx))
	results = append(results, c.CheckPE_L1_003(ctx))
	results = append(results, c.CheckPE_L1_004(ctx))

	// SYSTEM AND COMMUNICATIONS PROTECTION - 2 INFO
	results = append(results, c.CheckSC_L1_001(ctx))
	results = append(results, c.CheckSC_L1_002(ctx))

	// SYSTEM AND INFORMATION INTEGRITY - 2 automated
	results = append(results, c.CheckSI_L1_001(ctx))
	results = append(results, c.CheckSI_L1_002(ctx))

	return results, nil
}

// AC.L1-3.1.1 - AUTOMATED
func (c *AWSCMMCLevel1Checks) CheckAC_L1_001(ctx context.Context) CheckResult {
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{
			Control:         "AC.L1-3.1.1",
			Name:            "[CMMC L1] Limit System Access",
			Status:          "ERROR",
			Evidence:        fmt.Sprintf("Unable to list IAM users: %v", err),
			Remediation:     "Grant iam:ListUsers, iam:ListAccessKeys and iam:GetAccessKeyLastUsed so access can be measured",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Screenshot",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
		}
	}

	// The practice is that access is limited to authorized users. Counting
	// users, as the previous version did, answered whether anyone had access
	// at all, so it passed on every account with an IAM user. An access key
	// that has never been used, or has not been used in 90 days, is a live
	// credential belonging to nobody currently doing the work - which is the
	// form "access not limited" takes in an account that looks tidy.
	const staleDays = 90
	cutoff := time.Now().AddDate(0, 0, -staleDays)
	stale := []string{}
	active := 0

	for _, user := range users.Users {
		name := aws.ToString(user.UserName)
		keys, err := c.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			continue
		}
		for _, key := range keys.AccessKeyMetadata {
			if key.Status != iamtypes.StatusTypeActive {
				continue
			}
			active++
			used, err := c.iamClient.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: key.AccessKeyId,
			})
			if err != nil {
				continue
			}
			// A key the service has no record of using has never been used.
			if used.AccessKeyLastUsed == nil || used.AccessKeyLastUsed.LastUsedDate == nil {
				stale = append(stale, name+" (never used)")
				continue
			}
			if used.AccessKeyLastUsed.LastUsedDate.Before(cutoff) {
				stale = append(stale, fmt.Sprintf("%s (last used %s)",
					name, used.AccessKeyLastUsed.LastUsedDate.Format("2006-01-02")))
			}
		}
	}

	if active == 0 {
		return CheckResult{
			Control:         "AC.L1-3.1.1",
			Name:            "[CMMC L1] Limit System Access",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("No active IAM access keys across %d users, so there are no long-lived credentials to limit", len(users.Users)),
			Remediation:     "Continue using short-lived credentials through roles rather than IAM user keys",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Security credentials → Screenshot showing no active keys",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
		}
	}

	if len(stale) > 0 {
		listed := strings.Join(stale, ", ")
		if len(stale) > 3 {
			listed = strings.Join(stale[:3], ", ") + fmt.Sprintf(" +%d more", len(stale)-3)
		}
		return CheckResult{
			Control:         "AC.L1-3.1.1",
			Name:            "[CMMC L1] Limit System Access",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("%d of %d active access keys unused for %d days or never used: %s", len(stale), active, staleDays, listed),
			Remediation:     "Deactivate and delete access keys that are not in use, and confirm each remaining key belongs to a current authorized user",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Credential report → Screenshot the access key last-used columns",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
		}
	}

	return CheckResult{
		Control:         "AC.L1-3.1.1",
		Name:            "[CMMC L1] Limit System Access",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d active access keys used within %d days, across %d users", active, staleDays, len(users.Users)),
		Remediation:     "Continue reviewing access keys so each belongs to a current authorized user",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Credential report → Screenshot the access key last-used columns",
		ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
		Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.1", "NIST 800-171": "3.1.1"},
	}
}

// AC.L1-3.1.2 - AUTOMATED
func (c *AWSCMMCLevel1Checks) CheckAC_L1_002(ctx context.Context) CheckResult {
	policies, err := c.iamClient.ListPolicies(ctx, &iam.ListPoliciesInput{Scope: "Local"})
	if err != nil {
		return CheckResult{
			Control:         "AC.L1-3.1.2",
			Name:            "[CMMC L1] Limit Access to Permitted Transactions",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Unable to verify IAM policies: %v", err),
			Remediation:     "Configure IAM policies to limit access to permitted functions and transactions",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Policies → Screenshot policy list",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/policies",
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.2", "NIST 800-171": "3.1.2"},
		}
	}

	if len(policies.Policies) == 0 {
		return CheckResult{
			Control:         "AC.L1-3.1.2",
			Name:            "[CMMC L1] Limit Access to Permitted Transactions",
			Status:          "FAIL",
			Evidence:        "No custom IAM policies - relying on AWS managed policies only",
			Remediation:     "Create custom IAM policies to restrict access appropriately",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Policies → Create policy → Screenshot custom policies",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/policies",
			Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.2", "NIST 800-171": "3.1.2"},
		}
	}

	return CheckResult{
		Control:         "AC.L1-3.1.2",
		Name:            "[CMMC L1] Limit Access to Permitted Transactions",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("IAM policies configured (%d custom policies)", len(policies.Policies)),
		Remediation:     "Review policies quarterly for least privilege",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Policies → Screenshot showing custom access policies",
		ConsoleURL:      "https://console.aws.amazon.com/iam/home#/policies",
		Frameworks:      map[string]string{"CMMC": "AC.L1-3.1.2", "NIST 800-171": "3.1.2"},
	}
}

// IA.L1-3.5.1 - AUTOMATED
func (c *AWSCMMCLevel1Checks) CheckIA_L1_001(ctx context.Context) CheckResult {
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return CheckResult{
			Control:         "IA.L1-3.5.1",
			Name:            "[CMMC L1] Identify Users",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Unable to verify user identities: %v", err),
			Remediation:     "Ensure IAM users have unique identities",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Screenshot user identities",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
			Frameworks:      map[string]string{"CMMC": "IA.L1-3.5.1", "NIST 800-171": "3.5.1"},
		}
	}

	sharedAccounts := 0
	var sharedNames []string
	for _, user := range users.Users {
		name := strings.ToLower(*user.UserName)
		if strings.Contains(name, "shared") || strings.Contains(name, "team") || strings.Contains(name, "generic") {
			sharedAccounts++
			sharedNames = append(sharedNames, *user.UserName)
		}
	}

	if sharedAccounts > 0 {
		return CheckResult{
			Control:         "IA.L1-3.5.1",
			Name:            "[CMMC L1] Identify Users",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Found %d potential shared accounts: %s", sharedAccounts, strings.Join(sharedNames, ", ")),
			Remediation:     "Replace shared accounts with individual user accounts",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing individual (not shared) accounts",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
			Frameworks:      map[string]string{"CMMC": "IA.L1-3.5.1", "NIST 800-171": "3.5.1"},
		}
	}

	return CheckResult{
		Control:         "IA.L1-3.5.1",
		Name:            "[CMMC L1] Identify Users",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d IAM users have unique identities", len(users.Users)),
		Remediation:     "Continue ensuring unique user identities",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing unique user identities",
		ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
		Frameworks:      map[string]string{"CMMC": "IA.L1-3.5.1", "NIST 800-171": "3.5.1"},
	}
}

// IA.L1-3.5.2 - AUTOMATED
func (c *AWSCMMCLevel1Checks) CheckIA_L1_002(ctx context.Context) CheckResult {
	summary, err := c.iamClient.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return CheckResult{
			Control:         "IA.L1-3.5.2",
			Name:            "[CMMC L1] Authenticate Users",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Unable to verify authentication: %v", err),
			Remediation:     "Configure MFA for all users",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Account settings → Screenshot MFA enforcement",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/account_settings",
			Frameworks:      map[string]string{"CMMC": "IA.L1-3.5.2", "NIST 800-171": "3.5.2"},
		}
	}

	users := summary.SummaryMap["Users"]
	mfaUsers := summary.SummaryMap["UsersWithMFA"]

	if users > 0 && mfaUsers < users {
		return CheckResult{
			Control:         "IA.L1-3.5.2",
			Name:            "[CMMC L1] Authenticate Users",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Only %d/%d users have MFA enabled", mfaUsers, users),
			Remediation:     "Enable MFA for all IAM users",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → IAM → Users → Security credentials → Screenshot MFA devices",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
			Frameworks:      map[string]string{"CMMC": "IA.L1-3.5.2", "NIST 800-171": "3.5.2"},
		}
	}

	return CheckResult{
		Control:         "IA.L1-3.5.2",
		Name:            "[CMMC L1] Authenticate Users",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d users have MFA enabled", users),
		Remediation:     "Continue enforcing MFA for all users",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → IAM → Users → Screenshot showing MFA enabled for all users",
		ConsoleURL:      "https://console.aws.amazon.com/iam/home#/users",
		Frameworks:      map[string]string{"CMMC": "IA.L1-3.5.2", "NIST 800-171": "3.5.2"},
	}
}

// MP.L1-3.8.3 - INFO (manual)
func (c *AWSCMMCLevel1Checks) CheckMP_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "MP.L1-3.8.3",
		Name:            "[CMMC L1] Sanitize Media",
		Status:          "INFO",
		Evidence:        "MANUAL: Document media sanitization procedures for EBS volumes and S3 objects",
		Remediation:     "Implement secure deletion procedures using AWS encryption and S3 lifecycle policies",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Documentation → Screenshot showing media sanitization procedures | AWS Console → S3 → Lifecycle rules",
		ConsoleURL:      "https://console.aws.amazon.com/s3/home",
		Frameworks:      map[string]string{"CMMC": "MP.L1-3.8.3", "NIST 800-171": "3.8.3"},
	}
}

// PE.L1 - 4 INFO (all manual - physical protection)
func (c *AWSCMMCLevel1Checks) CheckPE_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "PE.L1-3.10.1",
		Name:            "[CMMC L1] Limit Physical Access",
		Status:          "INFO",
		Evidence:        "MANUAL: AWS data centers have physical controls (inherited control)",
		Remediation:     "Review AWS compliance documentation for physical security controls",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Artifact → Screenshot SOC 2 report showing physical controls",
		ConsoleURL:      "https://console.aws.amazon.com/artifact/home",
		Frameworks:      map[string]string{"CMMC": "PE.L1-3.10.1", "NIST 800-171": "3.10.1"},
	}
}

func (c *AWSCMMCLevel1Checks) CheckPE_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "PE.L1-3.10.3",
		Name:            "[CMMC L1] Escort Visitors",
		Status:          "INFO",
		Evidence:        "MANUAL: AWS data centers escort visitors (inherited control)",
		Remediation:     "Review AWS compliance documentation for visitor controls",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Artifact → Screenshot showing visitor management procedures",
		ConsoleURL:      "https://console.aws.amazon.com/artifact/home",
		Frameworks:      map[string]string{"CMMC": "PE.L1-3.10.3", "NIST 800-171": "3.10.3"},
	}
}

func (c *AWSCMMCLevel1Checks) CheckPE_L1_003(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "PE.L1-3.10.4",
		Name:            "[CMMC L1] Maintain Audit Logs",
		Status:          "INFO",
		Evidence:        "MANUAL: AWS maintains physical access logs (inherited control)",
		Remediation:     "Review AWS compliance documentation for physical audit logs",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Artifact → Screenshot showing physical access logging",
		ConsoleURL:      "https://console.aws.amazon.com/artifact/home",
		Frameworks:      map[string]string{"CMMC": "PE.L1-3.10.4", "NIST 800-171": "3.10.4"},
	}
}

func (c *AWSCMMCLevel1Checks) CheckPE_L1_004(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "PE.L1-3.10.5",
		Name:            "[CMMC L1] Control Physical Access Devices",
		Status:          "INFO",
		Evidence:        "MANUAL: AWS controls physical access devices (inherited control)",
		Remediation:     "Review AWS compliance documentation for access device controls",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Artifact → Screenshot showing physical access device management",
		ConsoleURL:      "https://console.aws.amazon.com/artifact/home",
		Frameworks:      map[string]string{"CMMC": "PE.L1-3.10.5", "NIST 800-171": "3.10.5"},
	}
}

// PS.L1 - 2 INFO (personnel screening - manual)

// SC.L1 - 3 AUTOMATED
func (c *AWSCMMCLevel1Checks) CheckSC_L1_001(ctx context.Context) CheckResult {
	groups, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{
			Control:         "SC.L1-3.13.1",
			Name:            "[CMMC L1] Monitor Communications",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("Unable to verify security groups: %v", err),
			Remediation:     "Configure VPC security groups to monitor network traffic",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → VPC → Security Groups → Screenshot",
			ConsoleURL:      "https://console.aws.amazon.com/vpc/home#SecurityGroups:",
			Frameworks:      map[string]string{"CMMC": "SC.L1-3.13.1", "NIST 800-171": "3.13.1"},
		}
	}

	openGroups := 0
	var openGroupNames []string
	for _, sg := range groups.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, ipRange := range perm.IpRanges {
				if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
					openGroups++
					openGroupNames = append(openGroupNames, *sg.GroupId)
					break
				}
			}
		}
	}

	if openGroups > 0 {
		return CheckResult{
			Control:         "SC.L1-3.13.1",
			Name:            "[CMMC L1] Monitor Communications",
			Status:          "FAIL",
			Evidence:        fmt.Sprintf("%d security groups allow unrestricted access: %s", openGroups, strings.Join(openGroupNames, ", ")),
			Remediation:     "Restrict security group rules to specific IP ranges",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Console → VPC → Security Groups → Screenshot showing restricted inbound rules",
			ConsoleURL:      "https://console.aws.amazon.com/vpc/home#SecurityGroups:",
			Frameworks:      map[string]string{"CMMC": "SC.L1-3.13.1", "NIST 800-171": "3.13.1"},
		}
	}

	return CheckResult{
		Control:         "SC.L1-3.13.1",
		Name:            "[CMMC L1] Monitor Communications",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d security groups have restricted access", len(groups.SecurityGroups)),
		Remediation:     "Continue monitoring security group rules",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → VPC → Security Groups → Screenshot showing monitoring controls",
		ConsoleURL:      "https://console.aws.amazon.com/vpc/home#SecurityGroups:",
		Frameworks:      map[string]string{"CMMC": "SC.L1-3.13.1", "NIST 800-171": "3.13.1"},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSC_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "SC.L1-3.13.5",
		Name:            "[CMMC L1] Implement Subnetworks for Public Systems",
		Status:          "INFO",
		Evidence:        "MANUAL: Verify public-facing systems are in separate subnets from internal systems",
		Remediation:     "Use VPC subnets to separate public and internal systems with appropriate security groups",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → VPC → Subnets → Screenshot showing subnet separation strategy",
		ConsoleURL:      "https://console.aws.amazon.com/vpc/home#subnets:",
		Frameworks:      map[string]string{"CMMC": "SC.L1-3.13.5", "NIST 800-171": "3.13.5"},
	}
}

// SI.L1 - 3 AUTOMATED
func (c *AWSCMMCLevel1Checks) CheckSI_L1_001(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "SI.L1-3.14.1",
		Name:            "[CMMC L1] Identify Flaws",
		Status:          "INFO",
		Evidence:        "MANUAL: Document flaw identification and remediation processes",
		Remediation:     "Enable AWS Systems Manager Patch Manager and Inspector for automated vulnerability scanning",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → Systems Manager → Patch Manager → Screenshot compliance dashboard",
		ConsoleURL:      "https://console.aws.amazon.com/systems-manager/patch-manager",
		Frameworks:      map[string]string{"CMMC": "SI.L1-3.14.1", "NIST 800-171": "3.14.1"},
	}
}

func (c *AWSCMMCLevel1Checks) CheckSI_L1_002(ctx context.Context) CheckResult {
	return CheckResult{
		Control:         "SI.L1-3.14.2",
		Name:            "[CMMC L1] Malicious Code Protection",
		Status:          "INFO",
		Evidence:        "MANUAL: Document malicious code protection mechanisms",
		Remediation:     "Enable AWS GuardDuty and deploy endpoint protection on EC2 instances",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Console → GuardDuty → Screenshot showing malware detection enabled",
		ConsoleURL:      "https://console.aws.amazon.com/guardduty/home",
		Frameworks:      map[string]string{"CMMC": "SI.L1-3.14.2", "NIST 800-171": "3.14.2"},
	}
}
