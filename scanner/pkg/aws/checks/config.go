package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

// ConfigChecks for AWS Config
type ConfigChecks struct {
	client *configservice.Client
}

func NewConfigChecks(client *configservice.Client) *ConfigChecks {
	return &ConfigChecks{client: client}
}

func (c *ConfigChecks) Name() string {
	return "AWS Config Compliance"
}

func (c *ConfigChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Existing check
	if result, err := c.CheckConfigEnabled(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS check
	if result, err := c.CheckConfigRecording(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *ConfigChecks) CheckConfigEnabled(ctx context.Context) (CheckResult, error) {
	recorders, err := c.client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "AWS Config Recording",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "Unable to check AWS Config status",
			Remediation:       "Enable AWS Config to track configuration changes",
			RemediationDetail: "1. Create S3 bucket for Config\n2. Create IAM role for Config\n3. Enable Config: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=ROLE_ARN",
			ScreenshotGuide:   "AWS Config Console → Screenshot showing Configuration recorder: On",
			ConsoleURL:        "https://console.aws.amazon.com/config/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("CONFIG_ENABLED"),
		}, err
	}

	if len(recorders.ConfigurationRecorders) == 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "AWS Config Recording",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "AWS Config NOT enabled! Cannot track configuration changes!",
			Remediation:       "Enable AWS Config to record all resource configurations",
			RemediationDetail: "1. Go to AWS Config Console\n2. Click 'Get started'\n3. Select 'Record all resources'\n4. Create/select S3 bucket\n5. Create/select IAM role\n6. Click 'Confirm'",
			ScreenshotGuide:   "1. Go to AWS Config Console\n2. Click 'Get started'\n3. Enable recording for all resources\n4. Screenshot showing 'Recorder is ON'",
			ConsoleURL:        "https://console.aws.amazon.com/config/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("CONFIG_ENABLED"),
		}, nil
	}

	return CheckResult{
		Control:         "CC7.1",
		Name:            "AWS Config Recording",
		Status:          "PASS",
		Evidence:        "AWS Config is recording configuration changes",
		ScreenshotGuide: "AWS Config Console → Screenshot showing active configuration recording",
		ConsoleURL:      "https://console.aws.amazon.com/config/",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("CONFIG_ENABLED"),
	}, nil
}

// CIS 4.3 - Ensure AWS Config is enabled in all regions
func (c *ConfigChecks) CheckConfigRecording(ctx context.Context) (CheckResult, error) {
	recorders, err := c.client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil || len(recorders.ConfigurationRecorders) == 0 {
		return CheckResult{
			Control:           "CIS-4.3",
			Name:              "AWS Config Recording Status",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "AWS Config not configured",
			Remediation:       "Enable AWS Config in all regions",
			RemediationDetail: "1. Enable Config in each region\n2. Set to record all resources\n3. Configure S3 bucket for logs\n4. Enable SNS notifications (optional)",
			ScreenshotGuide:   "AWS Config → Settings → Screenshot showing 'Recording is on' for all resource types",
			ConsoleURL:        "https://console.aws.amazon.com/config/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("CONFIG_ENABLED"),
		}, nil
	}

	// Check if recorder is actually recording
	recorderStatus, err := c.client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return CheckResult{}, err
	}

	notRecording := []string{}
	for _, status := range recorderStatus.ConfigurationRecordersStatus {
		if !status.Recording {
			notRecording = append(notRecording, *status.Name)
		}
	}

	if len(notRecording) > 0 {
		return CheckResult{
			Control:           "CIS-4.3",
			Name:              "AWS Config Recording Status",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("AWS Config recorder exists but not recording: %v", notRecording),
			Remediation:       "Start AWS Config recording",
			RemediationDetail: fmt.Sprintf("aws configservice start-configuration-recorder --configuration-recorder-name %s", notRecording[0]),
			ScreenshotGuide:   "AWS Config → Dashboard → Screenshot showing 'Recording: On'",
			ConsoleURL:        "https://console.aws.amazon.com/config/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("CONFIG_ENABLED"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-4.3",
		Name:       "AWS Config Recording Status",
		Status:     "PASS",
		Evidence:   "AWS Config is actively recording configuration changes",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CONFIG_ENABLED"),
	}, nil
}

// GuardDuty checks
type GuardDutyChecks struct {
	client *guardduty.Client
}

func NewGuardDutyChecks(client *guardduty.Client) *GuardDutyChecks {
	return &GuardDutyChecks{client: client}
}

func (c *GuardDutyChecks) Name() string {
	return "GuardDuty Threat Detection"
}

func (c *GuardDutyChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	detectors, err := c.client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil || len(detectors.DetectorIds) == 0 {
		results = append(results, CheckResult{
			Control:         "CC7.2",
			Name:            "GuardDuty Threat Detection",
			Status:          "FAIL",
			Severity:        "HIGH",
			Evidence:        "GuardDuty NOT enabled - missing threat detection!",
			Remediation:     "Enable GuardDuty for automated threat detection",
			ScreenshotGuide: "1. Go to GuardDuty Console\n2. Click 'Get Started'\n3. Enable GuardDuty\n4. Screenshot showing 'GuardDuty is ENABLED'",
			ConsoleURL:      "https://console.aws.amazon.com/guardduty/",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC7.2",
			Name:      "GuardDuty Threat Detection",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("GuardDuty enabled with %d detector(s)", len(detectors.DetectorIds)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results, nil
}
