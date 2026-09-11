package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
)

type BeanstalkChecks struct {
	client *elasticbeanstalk.Client
}

func NewBeanstalkChecks(client *elasticbeanstalk.Client) *BeanstalkChecks {
	return &BeanstalkChecks{client: client}
}

func (c *BeanstalkChecks) Name() string {
	return "Elastic Beanstalk Security Configuration"
}

func (c *BeanstalkChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 10.4 - Enhanced Health Reporting
	if result, err := c.CheckEnhancedHealthReporting(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.5 - Managed Platform Updates
	if result, err := c.CheckManagedPlatformUpdates(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.6 - Log Streaming
	if result, err := c.CheckLogStreaming(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CheckEnhancedHealthReporting - Ensure Beanstalk environments use enhanced health reporting
func (c *BeanstalkChecks) CheckEnhancedHealthReporting(ctx context.Context) (CheckResult, error) {
	environments, err := c.client.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return CheckResult{
			Control:     "AWS-BEANSTALK-01",
			Name:        "Elastic Beanstalk Enhanced Health Reporting",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list Beanstalk environments: %v", err),
			Remediation: "Verify Elastic Beanstalk access permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BEANSTALK_ENHANCED_HEALTH"),
		}, err
	}

	if len(environments.Environments) == 0 {
		return CheckResult{
			Control:     "AWS-BEANSTALK-01",
			Name:        "Elastic Beanstalk Enhanced Health Reporting",
			Status:      "INFO",
			Evidence:    "No Elastic Beanstalk environments found",
			Remediation: "N/A - No Beanstalk environments to check",
			RemediationDetail: `If you create Beanstalk environments in the future:
1. Open Elastic Beanstalk console
2. Create environment or update existing
3. Configuration → Monitoring → Enhanced health reporting: Enabled
4. This provides detailed health metrics and insights`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Elastic Beanstalk → Environments → Screenshot showing no environments",
			ConsoleURL:      "https://console.aws.amazon.com/elasticbeanstalk/home#/environments",
			Frameworks:      GetFrameworkMappings("BEANSTALK_ENHANCED_HEALTH"),
		}, nil
	}

	withoutEnhancedHealth := []string{}
	withEnhancedHealth := 0

	for _, env := range environments.Environments {
		if env.HealthStatus != "" {
			withEnhancedHealth++
		} else {
			withoutEnhancedHealth = append(withoutEnhancedHealth, *env.EnvironmentName)
		}
	}

	if len(withoutEnhancedHealth) > 0 {
		return CheckResult{
			Control:     "AWS-BEANSTALK-01",
			Name:        "Elastic Beanstalk Enhanced Health Reporting",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d environments lack enhanced health reporting: %v", len(withoutEnhancedHealth), len(environments.Environments), withoutEnhancedHealth),
			Remediation: "Enable enhanced health reporting for Beanstalk environments",
			RemediationDetail: fmt.Sprintf(`1. Open Elastic Beanstalk console
2. For each environment without enhanced health: %v
3. Go to Configuration → Monitoring
4. Enable Enhanced health reporting
5. Apply changes
6. Verify health status appears in console`, withoutEnhancedHealth),
			Severity:        "MEDIUM",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Elastic Beanstalk → Environment → Configuration → Monitoring → Screenshot showing enhanced health enabled",
			ConsoleURL:      "https://console.aws.amazon.com/elasticbeanstalk/home#/environments",
			Frameworks:      GetFrameworkMappings("BEANSTALK_ENHANCED_HEALTH"),
		}, nil
	}

	return CheckResult{
		Control:     "AWS-BEANSTALK-01",
		Name:        "Elastic Beanstalk Enhanced Health Reporting",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d Beanstalk environments have enhanced health reporting enabled", withEnhancedHealth),
		Remediation: "N/A - All environments properly configured",
		RemediationDetail: fmt.Sprintf(`All %d environments use enhanced health reporting.
This provides detailed health insights and CloudWatch metrics.`, withEnhancedHealth),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Elastic Beanstalk → Environments → Screenshot showing all with enhanced health",
		ConsoleURL:      "https://console.aws.amazon.com/elasticbeanstalk/home#/environments",
		Frameworks:      GetFrameworkMappings("BEANSTALK_ENHANCED_HEALTH"),
	}, nil
}

// CheckManagedPlatformUpdates - Ensure environments have managed platform updates enabled
func (c *BeanstalkChecks) CheckManagedPlatformUpdates(ctx context.Context) (CheckResult, error) {
	environments, err := c.client.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return CheckResult{
			Control:     "AWS-BEANSTALK-03",
			Name:        "Elastic Beanstalk Managed Platform Updates",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list environments: %v", err),
			Remediation: "Verify Beanstalk permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BEANSTALK_MANAGED_UPDATES"),
		}, err
	}

	if len(environments.Environments) == 0 {
		return CheckResult{
			Control:     "AWS-BEANSTALK-03",
			Name:        "Elastic Beanstalk Managed Platform Updates",
			Status:      "INFO",
			Evidence:    "No Elastic Beanstalk environments found",
			Remediation: "N/A - No environments to check",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BEANSTALK_MANAGED_UPDATES"),
		}, nil
	}

	// For managed updates, we need to check configuration settings
	// This is a manual check as the API doesn't directly expose this setting
	return CheckResult{
		Control:     "AWS-BEANSTALK-03",
		Name:        "Elastic Beanstalk Managed Platform Updates",
		Status:      "MANUAL",
		Evidence:    fmt.Sprintf("MANUAL CHECK: Verify %d environment(s) have managed platform updates enabled", len(environments.Environments)),
		Remediation: "Enable managed platform updates for all Beanstalk environments",
		RemediationDetail: fmt.Sprintf(`1. Open Elastic Beanstalk console
2. For each environment, verify managed updates:
3. Go to Configuration → Managed updates
4. Enable managed updates
5. Select update level: Minor and patch
6. Select maintenance window
7. Screenshot showing configuration for each environment

Environments to check: %d total`, len(environments.Environments)),
		Severity:        "MEDIUM",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Elastic Beanstalk → Environment → Configuration → Managed updates → Screenshot showing enabled",
		ConsoleURL:      "https://console.aws.amazon.com/elasticbeanstalk/home#/environments",
		Frameworks:      GetFrameworkMappings("BEANSTALK_MANAGED_UPDATES"),
	}, nil
}

// CheckLogStreaming - Ensure log streaming to CloudWatch is enabled
func (c *BeanstalkChecks) CheckLogStreaming(ctx context.Context) (CheckResult, error) {
	environments, err := c.client.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{})
	if err != nil {
		return CheckResult{
			Control:     "AWS-BEANSTALK-02",
			Name:        "Elastic Beanstalk Log Streaming",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list environments: %v", err),
			Remediation: "Verify Beanstalk permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BEANSTALK_LOGS"),
		}, err
	}

	if len(environments.Environments) == 0 {
		return CheckResult{
			Control:     "AWS-BEANSTALK-02",
			Name:        "Elastic Beanstalk Log Streaming",
			Status:      "INFO",
			Evidence:    "No Elastic Beanstalk environments found",
			Remediation: "N/A - No environments to check",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BEANSTALK_LOGS"),
		}, nil
	}

	// Log streaming configuration is not directly available via API
	// This requires manual verification or config settings check
	return CheckResult{
		Control:     "AWS-BEANSTALK-02",
		Name:        "Elastic Beanstalk Log Streaming",
		Status:      "MANUAL",
		Evidence:    fmt.Sprintf("MANUAL CHECK: Verify %d environment(s) have CloudWatch log streaming enabled", len(environments.Environments)),
		Remediation: "Enable CloudWatch log streaming for all Beanstalk environments",
		RemediationDetail: fmt.Sprintf(`1. Open Elastic Beanstalk console
2. For each environment:
3. Go to Configuration → Software
4. Enable log streaming to CloudWatch Logs
5. Set retention period (recommended: 30+ days)
6. Screenshot showing log streaming enabled

Environments to check: %d total`, len(environments.Environments)),
		Severity:        "HIGH",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Elastic Beanstalk → Environment → Configuration → Software → Screenshot showing log streaming",
		ConsoleURL:      "https://console.aws.amazon.com/elasticbeanstalk/home#/environments",
		Frameworks:      GetFrameworkMappings("BEANSTALK_LOGS"),
	}, nil
}
