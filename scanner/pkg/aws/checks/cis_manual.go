package checks

import (
	"context"
	"time"
)

// CISManualChecks returns manual guidance for non-automatable CIS controls
type CISManualChecks struct{}

func NewCISManualChecks() *CISManualChecks {
	return &CISManualChecks{}
}

func (c *CISManualChecks) Name() string {
	return "CIS Manual Controls"
}

func (c *CISManualChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Section 4 - Monitoring (CloudWatch Metric Filters & Alarms)
	// These require manual configuration and cannot be fully automated

	results = append(results, CheckResult{
		Control:     "CIS-5.1",
		Name:        "Metric Filter - Unauthorized API Calls",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for unauthorized API calls",
		Remediation: "Create CloudWatch metric filter for pattern: { ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }",
		RemediationDetail: `1. Open CloudWatch console
2. Navigate to Log groups
3. Select CloudTrail log group
4. Create metric filter with pattern: { ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }
5. Create alarm for this metric
6. Screenshot showing filter and alarm configured`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for unauthorized API calls",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_UNAUTHORIZED_API"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.2",
		Name:        "Metric Filter - Console Sign-in Without MFA",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for console sign-in without MFA",
		Remediation: "Create CloudWatch metric filter for pattern: { ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter with pattern for console login without MFA
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for console login without MFA",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_CONSOLE_NO_MFA"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.3",
		Name:        "Metric Filter - Root Account Usage",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for root account usage",
		Remediation: "Create CloudWatch metric filter for pattern: { $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for root account usage
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for root account usage",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_ROOT_USAGE"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.4",
		Name:        "Metric Filter - IAM Policy Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for IAM policy changes",
		Remediation: "Create CloudWatch metric filter for IAM policy change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for IAM policy changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for IAM changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_IAM_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.5",
		Name:        "Metric Filter - CloudTrail Configuration Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for CloudTrail configuration changes",
		Remediation: "Create CloudWatch metric filter for CloudTrail configuration change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for CloudTrail changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for CloudTrail changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_CLOUDTRAIL_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.6",
		Name:        "Metric Filter - Console Authentication Failures",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for console authentication failures",
		Remediation: "Create CloudWatch metric filter for failed console authentication attempts",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for failed console logins
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for auth failures",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_CONSOLE_AUTH_FAIL"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.7",
		Name:        "Metric Filter - KMS Key Disable/Delete",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for disabling or scheduled deletion of KMS keys",
		Remediation: "Create CloudWatch metric filter for KMS key disable/delete events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for KMS key changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for KMS changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_CMK_DISABLE"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.8",
		Name:        "Metric Filter - S3 Bucket Policy Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for S3 bucket policy changes",
		Remediation: "Create CloudWatch metric filter for S3 bucket policy change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for S3 policy changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for S3 changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_S3_POLICY_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.9",
		Name:        "Metric Filter - AWS Config Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for AWS Config configuration changes",
		Remediation: "Create CloudWatch metric filter for AWS Config change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for Config changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for Config changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_CONFIG_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.10",
		Name:        "Metric Filter - Security Group Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for security group changes",
		Remediation: "Create CloudWatch metric filter for security group change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for security group changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for SG changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_SECURITY_GROUP_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.11",
		Name:        "Metric Filter - NACL Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for Network ACL changes",
		Remediation: "Create CloudWatch metric filter for NACL change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for NACL changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for NACL changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_NACL_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.12",
		Name:        "Metric Filter - Network Gateway Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for network gateway changes",
		Remediation: "Create CloudWatch metric filter for gateway change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for gateway changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for gateway changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_GATEWAY_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.13",
		Name:        "Metric Filter - Route Table Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for route table changes",
		Remediation: "Create CloudWatch metric filter for route table change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for route table changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for route changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_ROUTE_TABLE_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.14",
		Name:        "Metric Filter - VPC Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for VPC changes",
		Remediation: "Create CloudWatch metric filter for VPC change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for VPC changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for VPC changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_VPC_CHANGES"),
	})

	results = append(results, CheckResult{
		Control:     "CIS-5.15",
		Name:        "Metric Filter - AWS Organizations Changes",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Ensure metric filter and alarm exist for AWS Organizations changes",
		Remediation: "Create CloudWatch metric filter for Organizations change events",
		RemediationDetail: `1. Open CloudWatch console
2. Create metric filter for Organizations changes
3. Create alarm for this metric
4. Screenshot showing filter and alarm configured`,
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "CloudWatch → Log groups → CloudTrail logs → Metric filters → Screenshot showing filter for Org changes",
		ConsoleURL:      "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups",
		Frameworks:      GetFrameworkMappings("METRIC_FILTER_ORGANIZATIONS_CHANGES"),
	})

	results = append(results, c.foundationsManualControls()...)

	return results, nil
}

// foundationsManualControls covers the Foundations recommendations that are
// marked Manual in the benchmark and had no result at all, so a user reading an
// AuditKit report could not tell they were part of the standard.
//
// The wording is ours. CIS's terms require contacting their legal team before
// reproducing portions of recommendations in third-party documentation, so each
// requirement is described here rather than quoted.
func (c *CISManualChecks) foundationsManualControls() []CheckResult {
	return []CheckResult{
		{
			Control:     "CIS-2.1.1",
			Name:        "Centralized Root Access for Member Accounts",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm member-account root credentials are centrally managed through AWS Organizations rather than held per account",
			Remediation: "Enable centralized root access in Organizations, then remove the root credentials and MFA devices held by member accounts",
			RemediationDetail: `1. Open the AWS Organizations console from the management account
2. Enable the centralized root access feature
3. For each member account, remove standalone root credentials and MFA devices
4. Screenshot the Organizations setting and one member account showing no root credentials`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Organizations -> Settings -> Screenshot centralized root access enabled | IAM in a member account -> Screenshot no root access keys",
			ConsoleURL:      "https://console.aws.amazon.com/organizations/v2/home/settings",
			Frameworks:      map[string]string{"CIS-AWS": "2.1.1", "SOC2": "CC6.1"},
		},
		{
			Control:     "CIS-2.1.3",
			Name:        "Management Account Not Used for Workloads",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm the Organizations management account runs no production workloads and holds no application data",
			Remediation: "Move any workloads out of the management account into member accounts; keep it for governance only",
			RemediationDetail: `1. Inventory the resources in the management account
2. Move application workloads and data stores into member accounts
3. Leave only Organizations, billing and governance functions in place
4. Screenshot the management account resource inventory showing no workloads`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Resource Groups -> Tag Editor in the management account -> Screenshot the resource list | Organizations -> Screenshot the account list",
			ConsoleURL:      "https://console.aws.amazon.com/resource-groups/tag-editor/find-resources",
			Frameworks:      map[string]string{"CIS-AWS": "2.1.3", "SOC2": "CC6.1"},
		},
		{
			Control:     "CIS-2.1.4",
			Name:        "Organizational Units Structured by Environment and Sensitivity",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm organizational units separate accounts by environment and by data sensitivity, so policy can be applied per tier",
			Remediation: "Restructure the organizational units so production, non-production and sensitive-data accounts sit in separate OUs with their own policies",
			RemediationDetail: `1. Open Organizations and review the OU tree
2. Group accounts so environment and data sensitivity each map to an OU
3. Attach the policies each tier needs at the OU rather than the account
4. Screenshot the OU structure and the policies attached to each`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Organizations -> AWS accounts -> Screenshot the organizational unit tree | Screenshot the policies on each OU",
			ConsoleURL:      "https://console.aws.amazon.com/organizations/v2/home/accounts",
			Frameworks:      map[string]string{"CIS-AWS": "2.1.4", "SOC2": "CC5.2"},
		},
		{
			Control:     "CIS-2.1.5",
			Name:        "Delegated Administrator Manages Organization Policies",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm organization policies are administered by a delegated account rather than from the management account directly",
			Remediation: "Register a delegated administrator for Organizations policy management and administer policies from there",
			RemediationDetail: `1. Choose a member account to act as the delegated policy administrator
2. Register it with a delegation policy scoped to policy management
3. Administer service control and other organization policies from that account
4. Screenshot the delegation policy and the registered administrator`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Organizations -> Settings -> Delegated administrator -> Screenshot the registered account and its delegation policy",
			ConsoleURL:      "https://console.aws.amazon.com/organizations/v2/home/settings",
			Frameworks:      map[string]string{"CIS-AWS": "2.1.5", "SOC2": "CC6.3"},
		},
		{
			Control:     "CIS-2.1.6",
			Name:        "Delegated Administrators for Organization-Integrated Services",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm each service integrated with Organizations has a delegated administrator account rather than being run from the management account",
			Remediation: "Register delegated administrators for the services integrated with Organizations, such as Security Hub, GuardDuty, Config and IAM Access Analyzer",
			RemediationDetail: `1. Open Organizations and list the services with trusted access enabled
2. For each, register a delegated administrator account
3. Operate that service from the delegated account
4. Screenshot the trusted-access list and the delegated administrator for each service`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Organizations -> Services -> Screenshot each integrated service and its delegated administrator",
			ConsoleURL:      "https://console.aws.amazon.com/organizations/v2/home/services",
			Frameworks:      map[string]string{"CIS-AWS": "2.1.6", "SOC2": "CC6.3"},
		},
		{
			Control:     "CIS-2.19",
			Name:        "IAM Identities Managed Centrally",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: In a multi-account environment, confirm human access comes from one identity source through federation or IAM Identity Center rather than per-account IAM users",
			Remediation: "Move human access to IAM Identity Center or an external identity provider, and remove per-account IAM users",
			RemediationDetail: `1. Enable IAM Identity Center, or federate an existing identity provider
2. Map permission sets to the accounts and roles people need
3. Remove the IAM users that duplicated those identities
4. Screenshot the identity source and the permission set assignments`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM Identity Center -> Settings -> Screenshot the identity source | Screenshot permission set assignments",
			ConsoleURL:      "https://console.aws.amazon.com/singlesignon/home",
			Frameworks:      map[string]string{"CIS-AWS": "2.19", "SOC2": "CC6.1"},
		},
		{
			Control:     "CIS-2.20",
			Name:        "CloudShell Full Access Restricted",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm the managed policy granting full CloudShell access is attached only to identities that need file upload and download through CloudShell",
			Remediation: "Detach AWSCloudShellFullAccess from general users and grant the narrower CloudShell permissions instead",
			RemediationDetail: `1. Open IAM and list the entities attached to AWSCloudShellFullAccess
2. Detach it from any identity that does not need CloudShell file transfer
3. Grant a scoped policy covering only the CloudShell actions required
4. Screenshot the policy's attached entities after the change`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM -> Policies -> AWSCloudShellFullAccess -> Entities attached -> Screenshot the remaining list",
			ConsoleURL:      "https://console.aws.amazon.com/iam/home#/policies",
			Frameworks:      map[string]string{"CIS-AWS": "2.20", "SOC2": "CC6.3"},
		},
		{
			Control:     "CIS-2.21",
			Name:        "Resource Policies Do Not Grant Unrestricted Principals",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm no resource policy grants access to every principal without a condition narrowing who may use it",
			Remediation: "Replace an unrestricted principal in each resource policy with named principals, or add conditions that bound it to your accounts or organization",
			RemediationDetail: `1. Run IAM Access Analyzer and review the external-access findings
2. For each resource policy granting every principal, name the principals or add a condition such as the organization id
3. Re-run the analyzer and confirm the finding clears
4. Screenshot the analyzer findings before and after`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM -> Access Analyzer -> Findings -> Screenshot the external access findings, then the cleared state",
			ConsoleURL:      "https://console.aws.amazon.com/access-analyzer/home",
			Frameworks:      map[string]string{"CIS-AWS": "2.21", "SOC2": "CC6.1"},
		},
		{
			Control:     "CIS-3.1.3",
			Name:        "S3 Data Discovered and Classified",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm the data held in S3 has been discovered and classified, and that anything sensitive is protected accordingly",
			Remediation: "Run a discovery and classification job across the buckets, then apply the controls each classification calls for",
			RemediationDetail: `1. Enable Amazon Macie, or use an equivalent classification tool, across the account's buckets
2. Review the findings and record a classification for each bucket
3. Apply the encryption, access and retention controls the classification requires
4. Screenshot the classification results and the resulting bucket settings`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Macie -> Findings by bucket -> Screenshot the classification results | S3 -> Screenshot the settings on a sensitive bucket",
			ConsoleURL:      "https://console.aws.amazon.com/macie/home",
			Frameworks:      map[string]string{"CIS-AWS": "3.1.3", "SOC2": "CC6.1"},
		},
		{
			Control:     "CIS-4.10",
			Name:        "Access Logging on AWS-Managed Web Front Ends",
			Status:      "MANUAL",
			Evidence:    "MANUAL CHECK: Confirm the AWS-managed services fronting web traffic write access logs, covering load balancers, CloudFront distributions and API Gateway stages",
			Remediation: "Turn on access logging for each web-facing service and send the logs to a retained destination",
			RemediationDetail: `1. Enable access logs on each Application and Network Load Balancer
2. Enable standard logging on each CloudFront distribution
3. Enable access logging on each API Gateway stage
4. Confirm the destination bucket or log group has the retention the audit needs
5. Screenshot the logging setting for one of each service type`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "EC2 -> Load Balancers -> Attributes -> Screenshot access logs enabled | CloudFront -> Distribution -> Screenshot standard logging | API Gateway -> Stage -> Screenshot access logging",
			ConsoleURL:      "https://console.aws.amazon.com/ec2/home#LoadBalancers:",
			Frameworks:      map[string]string{"CIS-AWS": "4.10", "SOC2": "CC7.2"},
		},
	}
}
