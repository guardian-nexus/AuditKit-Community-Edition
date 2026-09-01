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
		Control:     "CIS-4.1",
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
		Control:     "CIS-4.2",
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
		Control:     "CIS-4.3",
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
		Control:     "CIS-4.4",
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
		Control:     "CIS-4.5",
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
		Control:     "CIS-4.6",
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
		Control:     "CIS-4.7",
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
		Control:     "CIS-4.8",
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
		Control:     "CIS-4.9",
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
		Control:     "CIS-4.10",
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
		Control:     "CIS-4.11",
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
		Control:     "CIS-4.12",
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
		Control:     "CIS-4.13",
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
		Control:     "CIS-4.14",
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
		Control:     "CIS-4.15",
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

	return results, nil
}
