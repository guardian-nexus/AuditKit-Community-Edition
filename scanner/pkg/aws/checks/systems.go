package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type SystemsChecks struct {
	ssmClient *ssm.Client
	asClient  *autoscaling.Client
}

func NewSystemsChecks(ssmClient *ssm.Client, asClient *autoscaling.Client) *SystemsChecks {
	return &SystemsChecks{
		ssmClient: ssmClient,
		asClient:  asClient,
	}
}

func (c *SystemsChecks) Name() string {
	return "System Availability & Patching"
}

func (c *SystemsChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckPatchCompliance(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckAutoScaling(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *SystemsChecks) CheckPatchCompliance(ctx context.Context) (CheckResult, error) {
	// Check if Systems Manager is being used for patching
	patches, err := c.ssmClient.DescribePatchBaselines(ctx, &ssm.DescribePatchBaselinesInput{})

	if err != nil || len(patches.BaselineIdentities) == 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "Patch Management",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "CRITICAL: No patch baselines configured - systems vulnerable!",
			Remediation:       "Configure Systems Manager Patch Manager",
			RemediationDetail: "Enable Systems Manager and create patch baselines for automated patching",
			ScreenshotGuide:   "1. Go to Systems Manager → Patch Manager\n2. Screenshot patch baselines\n3. Show compliance dashboard\n4. Document patching schedule",
			ConsoleURL:        "https://console.aws.amazon.com/systems-manager/patch-manager",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "CC7.1",
		Name:      "Patch Management",
		Status:    "PASS",
		Evidence:  fmt.Sprintf("%d patch baselines configured", len(patches.BaselineIdentities)),
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}

func (c *SystemsChecks) CheckAutoScaling(ctx context.Context) (CheckResult, error) {
	groups, err := c.asClient.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{})

	if err != nil || len(groups.AutoScalingGroups) == 0 {
		return CheckResult{
			Control:         "A1.1",
			Name:            "Processing Capacity Management",
			Status:          "FAIL",
			Severity:        "MEDIUM",
			Evidence:        "No auto-scaling configured - single points of failure exist",
			Remediation:     "Implement auto-scaling for critical services",
			ScreenshotGuide: "1. Go to EC2 → Auto Scaling Groups\n2. Document HA architecture\n3. Show multi-AZ deployments",
			ConsoleURL:      "https://console.aws.amazon.com/ec2/v2/home#AutoScalingGroups",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
		}, nil
	}

	return CheckResult{
		Control:   "A1.1",
		Name:      "High Availability",
		Status:    "PASS",
		Evidence:  fmt.Sprintf("%d auto-scaling groups configured", len(groups.AutoScalingGroups)),
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	}, nil
}
