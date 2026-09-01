package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
)

type CloudFormationChecks struct {
	client *cloudformation.Client
}

func NewCloudFormationChecks(client *cloudformation.Client) *CloudFormationChecks {
	return &CloudFormationChecks{client: client}
}

func (c *CloudFormationChecks) Name() string {
	return "CloudFormation Security Configuration"
}

func (c *CloudFormationChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckStackPolicy(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckDriftDetection(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *CloudFormationChecks) CheckStackPolicy(ctx context.Context) (CheckResult, error) {
	stacks, err := c.client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{})
	if err != nil {
		return CheckResult{
			Control:    "CIS-15.1",
			Name:       "CloudFormation Stack Policy Configured",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Failed to list stacks: %v", err),
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("CFN_STACK_POLICY"),
		}, err
	}

	if len(stacks.Stacks) == 0 {
		return CheckResult{
			Control:    "CIS-15.1",
			Name:       "CloudFormation Stack Policy Configured",
			Status:     "INFO",
			Evidence:   "No CloudFormation stacks found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("CFN_STACK_POLICY"),
		}, nil
	}

	without := []string{}
	with := 0

	for _, stack := range stacks.Stacks {
		policy, err := c.client.GetStackPolicy(ctx, &cloudformation.GetStackPolicyInput{
			StackName: stack.StackName,
		})
		if err != nil || policy.StackPolicyBody == nil {
			without = append(without, *stack.StackName)
		} else {
			with++
		}
	}

	if len(without) > 0 {
		return CheckResult{
			Control:     "CIS-15.1",
			Name:        "CloudFormation Stack Policy Configured",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d stacks lack stack policies: %v", len(without), len(stacks.Stacks), without),
			Remediation: "Configure stack policies to protect critical resources",
			Severity:    "MEDIUM",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/cloudformation/home#/stacks",
			Frameworks:  GetFrameworkMappings("CFN_STACK_POLICY"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-15.1",
		Name:       "CloudFormation Stack Policy Configured",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d stacks have stack policies configured", with),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/cloudformation/home#/stacks",
		Frameworks: GetFrameworkMappings("CFN_STACK_POLICY"),
	}, nil
}

func (c *CloudFormationChecks) CheckDriftDetection(ctx context.Context) (CheckResult, error) {
	stacks, err := c.client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{})
	if err != nil {
		return CheckResult{
			Control:    "CIS-15.2",
			Name:       "CloudFormation Drift Detection",
			Status:     "ERROR",
			Evidence:   "Failed to list stacks",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("CFN_DRIFT_DETECTION"),
		}, err
	}

	if len(stacks.Stacks) == 0 {
		return CheckResult{
			Control:    "CIS-15.2",
			Name:       "CloudFormation Drift Detection",
			Status:     "INFO",
			Evidence:   "No CloudFormation stacks found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("CFN_DRIFT_DETECTION"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-15.2",
		Name:        "CloudFormation Drift Detection",
		Status:      "MANUAL",
		Evidence:    fmt.Sprintf("MANUAL CHECK: Run drift detection on %d stacks regularly", len(stacks.Stacks)),
		Remediation: "Run drift detection monthly to detect manual changes",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/cloudformation/home#/stacks",
		Frameworks:  GetFrameworkMappings("CFN_DRIFT_DETECTION"),
	}, nil
}
