package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

type SecurityServicesChecks struct {
	guarddutyClient   *guardduty.Client
	macieClient       *macie2.Client
	securityHubClient *securityhub.Client
	inspectorClient   *inspector2.Client
}

func NewSecurityServicesChecks(guardduty *guardduty.Client, macie *macie2.Client, securityHub *securityhub.Client, inspector *inspector2.Client) *SecurityServicesChecks {
	return &SecurityServicesChecks{
		guarddutyClient:   guardduty,
		macieClient:       macie,
		securityHubClient: securityHub,
		inspectorClient:   inspector,
	}
}

func (c *SecurityServicesChecks) Name() string {
	return "AWS Security Services"
}

func (c *SecurityServicesChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// GuardDuty checks
	if result, err := c.CheckGuardDutyEnabled(ctx); err == nil {
		results = append(results, result)
	}

	// Macie checks
	if result, err := c.CheckMacieEnabled(ctx); err == nil {
		results = append(results, result)
	}

	// Security Hub checks
	if result, err := c.CheckSecurityHubEnabled(ctx); err == nil {
		results = append(results, result)
	}

	// Inspector checks
	if result, err := c.CheckInspectorEnabled(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CIS 9.1 - Ensure GuardDuty is enabled
func (c *SecurityServicesChecks) CheckGuardDutyEnabled(ctx context.Context) (CheckResult, error) {
	detectors, err := c.guarddutyClient.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return CheckResult{
			Control:           "[CIS-9.1]",
			Name:              "GuardDuty Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("Unable to check GuardDuty status: %v | CIS 9.1", err),
			Remediation:       "Enable GuardDuty",
			RemediationDetail: "aws guardduty create-detector --enable",
			ScreenshotGuide:   "GuardDuty Console → Getting started → Screenshot showing detector enabled",
			ConsoleURL:        "https://console.aws.amazon.com/guardduty/home",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.1", "SOC2": "CC7.2"},
		}, nil
	}

	if len(detectors.DetectorIds) == 0 {
		return CheckResult{
			Control:           "[CIS-9.1]",
			Name:              "GuardDuty Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "GuardDuty is not enabled in this region | CIS 9.1 | Intelligent threat detection not active",
			Remediation:       "Enable GuardDuty to detect threats",
			RemediationDetail: `aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES`,
			ScreenshotGuide:   "GuardDuty Console → Dashboard → Screenshot showing detector enabled with findings",
			ConsoleURL:        "https://console.aws.amazon.com/guardduty/home",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.1", "SOC2": "CC7.2", "PCI-DSS": "11.4"},
		}, nil
	}

	// Check if detector is enabled
	detectorId := detectors.DetectorIds[0]
	detector, err := c.guarddutyClient.GetDetector(ctx, &guardduty.GetDetectorInput{
		DetectorId: &detectorId,
	})
	if err != nil {
		return CheckResult{}, err
	}

	if detector.Status != "ENABLED" {
		return CheckResult{
			Control:           "[CIS-9.1]",
			Name:              "GuardDuty Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("GuardDuty detector exists but is %s | CIS 9.1", detector.Status),
			Remediation:       "Enable GuardDuty detector",
			RemediationDetail: fmt.Sprintf("aws guardduty update-detector --detector-id %s --enable", detectorId),
			ScreenshotGuide:   "GuardDuty Console → Settings → Screenshot showing detector enabled",
			ConsoleURL:        "https://console.aws.amazon.com/guardduty/home",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.1"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-9.1]",
		Name:       "GuardDuty Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("GuardDuty is enabled (Detector: %s) | Meets CIS 9.1", detectorId),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "9.1"},
	}, nil
}

// CIS 9.2 - Ensure Amazon Macie is enabled
func (c *SecurityServicesChecks) CheckMacieEnabled(ctx context.Context) (CheckResult, error) {
	session, err := c.macieClient.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
	if err != nil {
		return CheckResult{
			Control:           "[CIS-9.2]",
			Name:              "Macie Enabled",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "Macie is not enabled in this region | CIS 9.2 | Sensitive data discovery not active",
			Remediation:       "Enable Amazon Macie",
			RemediationDetail: `aws macie2 enable-macie`,
			ScreenshotGuide:   "Macie Console → Dashboard → Screenshot showing Macie enabled",
			ConsoleURL:        "https://console.aws.amazon.com/macie/home",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.2", "SOC2": "CC6.7", "PCI-DSS": "3.4"},
		}, nil
	}

	if session.Status != "ENABLED" {
		return CheckResult{
			Control:           "[CIS-9.2]",
			Name:              "Macie Enabled",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("Macie exists but is %s | CIS 9.2", session.Status),
			Remediation:       "Enable Amazon Macie",
			RemediationDetail: "aws macie2 enable-macie",
			ScreenshotGuide:   "Macie Console → Settings → Screenshot showing Macie status enabled",
			ConsoleURL:        "https://console.aws.amazon.com/macie/home",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-9.2]",
		Name:       "Macie Enabled",
		Status:     "PASS",
		Evidence:   "Amazon Macie is enabled for sensitive data discovery | Meets CIS 9.2",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "9.2"},
	}, nil
}

// CIS 9.3 - Ensure Security Hub is enabled
func (c *SecurityServicesChecks) CheckSecurityHubEnabled(ctx context.Context) (CheckResult, error) {
	hub, err := c.securityHubClient.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		return CheckResult{
			Control:           "[CIS-9.3]",
			Name:              "Security Hub Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "AWS Security Hub is not enabled | CIS 9.3 | Centralized security findings not available",
			Remediation:       "Enable AWS Security Hub",
			RemediationDetail: `aws securityhub enable-security-hub --enable-default-standards`,
			ScreenshotGuide:   "Security Hub Console → Summary → Screenshot showing Security Hub enabled with standards",
			ConsoleURL:        "https://console.aws.amazon.com/securityhub/home",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.3", "SOC2": "CC7.1, CC7.2", "PCI-DSS": "10.6, 11.4"},
		}, nil
	}

	if hub.HubArn == nil {
		return CheckResult{
			Control:           "[CIS-9.3]",
			Name:              "Security Hub Enabled",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "Security Hub exists but is not properly configured | CIS 9.3",
			Remediation:       "Enable Security Hub",
			RemediationDetail: "aws securityhub enable-security-hub",
			ScreenshotGuide:   "Security Hub Console → Screenshot showing enabled",
			ConsoleURL:        "https://console.aws.amazon.com/securityhub/home",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.3"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-9.3]",
		Name:       "Security Hub Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("AWS Security Hub is enabled | Meets CIS 9.3"),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "9.3"},
	}, nil
}

// CIS 9.4 - Ensure Amazon Inspector is enabled
func (c *SecurityServicesChecks) CheckInspectorEnabled(ctx context.Context) (CheckResult, error) {
	status, err := c.inspectorClient.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		return CheckResult{
			Control:           "[CIS-9.4]",
			Name:              "Inspector Enabled",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "Amazon Inspector is not enabled | CIS 9.4 | Vulnerability scanning not active",
			Remediation:       "Enable Amazon Inspector",
			RemediationDetail: `aws inspector2 enable --resource-types EC2 ECR LAMBDA`,
			ScreenshotGuide:   "Inspector Console → Dashboard → Screenshot showing Inspector enabled",
			ConsoleURL:        "https://console.aws.amazon.com/inspector/v2/home",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.4", "SOC2": "CC8.1", "PCI-DSS": "6.2, 11.2.2"},
		}, nil
	}

	if len(status.Accounts) == 0 {
		return CheckResult{
			Control:           "[CIS-9.4]",
			Name:              "Inspector Enabled",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "Amazon Inspector has no enabled accounts | CIS 9.4",
			Remediation:       "Enable Amazon Inspector for vulnerability scanning",
			RemediationDetail: "aws inspector2 enable --resource-types EC2 ECR LAMBDA",
			ScreenshotGuide:   "Inspector Console → Account management → Screenshot showing account enabled",
			ConsoleURL:        "https://console.aws.amazon.com/inspector/v2/home",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.4"},
		}, nil
	}

	account := status.Accounts[0]
	if account.State.Status != "ENABLED" {
		return CheckResult{
			Control:           "[CIS-9.4]",
			Name:              "Inspector Enabled",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("Amazon Inspector status is %s | CIS 9.4", account.State.Status),
			Remediation:       "Enable Amazon Inspector",
			RemediationDetail: "aws inspector2 enable --resource-types EC2 ECR LAMBDA",
			ScreenshotGuide:   "Inspector Console → Settings → Screenshot showing status enabled",
			ConsoleURL:        "https://console.aws.amazon.com/inspector/v2/home",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "9.4"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-9.4]",
		Name:       "Inspector Enabled",
		Status:     "PASS",
		Evidence:   "Amazon Inspector is enabled for vulnerability scanning | Meets CIS 9.4",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "9.4"},
	}, nil
}
