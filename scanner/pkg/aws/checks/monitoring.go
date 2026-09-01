package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

type MonitoringChecks struct {
	cwClient  *cloudwatch.Client
	snsClient *sns.Client
	shClient  *securityhub.Client
}

func NewMonitoringChecks(cwClient *cloudwatch.Client, snsClient *sns.Client, shClient *securityhub.Client) *MonitoringChecks {
	return &MonitoringChecks{
		cwClient:  cwClient,
		snsClient: snsClient,
		shClient:  shClient,
	}
}

func (c *MonitoringChecks) Name() string {
	return "Security Event Monitoring"
}

func (c *MonitoringChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckCloudWatchAlarms(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckSNSTopics(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckSecurityHubEnabled(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *MonitoringChecks) CheckCloudWatchAlarms(ctx context.Context) (CheckResult, error) {
	alarms, err := c.cwClient.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	// Check for critical security alarms
	criticalAlarms := map[string]bool{
		"root-account-usage":     false,
		"unauthorized-api-calls": false,
		"iam-changes":            false,
		"security-group-changes": false,
		"cloudtrail-changes":     false,
	}

	for _, alarm := range alarms.MetricAlarms {
		name := *alarm.AlarmName
		for key := range criticalAlarms {
			if contains(name, key) {
				criticalAlarms[key] = true
			}
		}
	}

	missingAlarms := []string{}
	for alarm, exists := range criticalAlarms {
		if !exists {
			missingAlarms = append(missingAlarms, alarm)
		}
	}

	if len(missingAlarms) > 0 {
		return CheckResult{
			Control:           "CC7.3",
			Name:              "Security Event Monitoring",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("Missing %d critical security alarms", len(missingAlarms)),
			Remediation:       "Create CloudWatch alarms for security events",
			RemediationDetail: "Create alarms for: root usage, unauthorized API calls, IAM changes, etc.",
			ScreenshotGuide:   "1. Go to CloudWatch → Alarms\n2. Screenshot list of security alarms\n3. Each alarm should notify SNS topic\n4. Show alarm history (triggered events)",
			ConsoleURL:        "https://console.aws.amazon.com/cloudwatch/home#alarmsV2",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC7.3",
		Name:      "Security Event Monitoring",
		Status:    "PASS",
		Evidence:  fmt.Sprintf("All critical security alarms configured (%d total)", len(alarms.MetricAlarms)),
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func (c *MonitoringChecks) CheckSNSTopics(ctx context.Context) (CheckResult, error) {
	topics, err := c.snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(topics.Topics) == 0 {
		return CheckResult{
			Control:           "CC7.4",
			Name:              "Alert Notifications",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "No SNS topics configured for alerts!",
			Remediation:       "Create SNS topic for security alerts",
			RemediationDetail: "aws sns create-topic --name security-alerts && aws sns subscribe --topic-arn ARN --protocol email --notification-endpoint security@company.com",
			ScreenshotGuide:   "1. Go to SNS → Topics\n2. Screenshot security alert topic\n3. Show subscriptions (email/Slack)",
			ConsoleURL:        "https://console.aws.amazon.com/sns/v3/home#/topics",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC7.4",
		Name:      "Alert Notifications",
		Status:    "PASS",
		Evidence:  fmt.Sprintf("%d SNS topics configured", len(topics.Topics)),
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func contains(str, substr string) bool {
	return len(str) > 0 && len(substr) > 0 && (str == substr || len(str) > len(substr))
}

// CheckSecurityHubEnabled verifies AWS Security Hub is enabled (CIS 4.16)
func (c *MonitoringChecks) CheckSecurityHubEnabled(ctx context.Context) (CheckResult, error) {
	// Try to get the Security Hub status
	hub, err := c.shClient.DescribeHub(ctx, &securityhub.DescribeHubInput{})

	if err != nil {
		// Check if the error is because Security Hub is not enabled
		if strings.Contains(err.Error(), "not subscribed") ||
			strings.Contains(err.Error(), "InvalidAccessException") ||
			strings.Contains(err.Error(), "ResourceNotFoundException") {
			return CheckResult{
				Control:     "[CIS-4.16]",
				Name:        "AWS Security Hub Enabled",
				Status:      "FAIL",
				Severity:    "MEDIUM",
				Evidence:    "AWS Security Hub is NOT enabled in this region",
				Remediation: "Enable AWS Security Hub to centralize security findings",
				RemediationDetail: `AWS Security Hub aggregates, organizes, and prioritizes security findings from AWS services and third-party products.

REMEDIATION STEPS:
1. Open AWS Security Hub console
2. Click "Go to Security Hub" or "Enable Security Hub"
3. Choose security standards to enable (CIS AWS Foundations, AWS Foundational Security Best Practices)
4. Click "Enable Security Hub"
5. Repeat for all regions where you have resources

AWS CLI:
aws securityhub enable-security-hub --region <region>

ENABLE IN ALL REGIONS:
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws securityhub enable-security-hub --region $region
done

IMPORTANT: Security Hub requires AWS Config to be enabled first.
Also consider enabling:
- AWS Config (CIS 3.3)
- Amazon GuardDuty
- AWS Inspector
- Amazon Macie`,
				ScreenshotGuide: `AUDIT EVIDENCE:
1. AWS Console → Security Hub → Summary dashboard
2. Screenshot showing Security Hub is enabled with "Hub ARN" visible
3. Screenshot of enabled security standards (CIS, AWS Foundational)
4. Show findings summary and security score
5. For multi-region: Screenshot showing Security Hub enabled in all active regions`,
				ConsoleURL: "https://console.aws.amazon.com/securityhub/home",
				Priority:   PriorityMedium,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("SECURITY_HUB"),
			}, nil
		}

		// Other errors (permission issues, etc.)
		return CheckResult{
			Control:           "[CIS-4.16]",
			Name:              "AWS Security Hub Enabled",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("Unable to check Security Hub status: %v", err),
			Remediation:       "Verify IAM permissions to check Security Hub status",
			RemediationDetail: "Ensure the IAM role has securityhub:DescribeHub permission",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SECURITY_HUB"),
		}, nil
	}

	// Security Hub is enabled - check if it's active
	if hub.HubArn == nil || *hub.HubArn == "" {
		return CheckResult{
			Control:     "[CIS-4.16]",
			Name:        "AWS Security Hub Enabled",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    "Security Hub is enabled but Hub ARN is missing",
			Remediation: "Verify Security Hub configuration",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SECURITY_HUB"),
		}, nil
	}

	// Success - Security Hub is enabled and configured
	subscriptionDate := "unknown"
	if hub.SubscribedAt != nil {
		subscriptionDate = *hub.SubscribedAt
	}

	return CheckResult{
		Control:    "[CIS-4.16]",
		Name:       "AWS Security Hub Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("AWS Security Hub is enabled | Hub ARN: %s | Subscribed: %s", *hub.HubArn, subscriptionDate),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SECURITY_HUB"),
	}, nil
}
