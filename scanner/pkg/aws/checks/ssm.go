package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type SSMChecks struct {
	client *ssm.Client
}

func NewSSMChecks(client *ssm.Client) *SSMChecks {
	return &SSMChecks{client: client}
}

func (c *SSMChecks) Name() string {
	return "Systems Manager Security Configuration"
}

func (c *SSMChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 10.1 - SSM Parameter Store Encryption
	if result, err := c.CheckParameterEncryption(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.2 - SSM Session Manager Logging
	if result, err := c.CheckSessionManagerLogging(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.3 - SSM Patch Compliance
	if result, err := c.CheckPatchCompliance(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CheckParameterEncryption - Ensure SSM Parameter Store uses encryption
func (c *SSMChecks) CheckParameterEncryption(ctx context.Context) (CheckResult, error) {
	// List all parameters
	params, err := c.client.DescribeParameters(ctx, &ssm.DescribeParametersInput{})
	if err != nil {
		return CheckResult{
			Control:           "CIS-10.1",
			Name:              "SSM Parameter Store Encryption",
			Status:            "ERROR",
			Evidence:          fmt.Sprintf("Failed to list SSM parameters: %v", err),
			Remediation:       "Ensure AWS Systems Manager Parameter Store access is enabled",
			RemediationDetail: "Verify IAM permissions for SSM access",
			Priority:          PriorityLow,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SSM_PARAMETER_ENCRYPTION"),
		}, err
	}

	if len(params.Parameters) == 0 {
		return CheckResult{
			Control:     "CIS-10.1",
			Name:        "SSM Parameter Store Encryption",
			Status:      "INFO",
			Evidence:    "No SSM parameters found",
			Remediation: "Create encrypted parameters when storing sensitive configuration data",
			RemediationDetail: `1. Open Systems Manager console
2. Navigate to Parameter Store
3. Create parameters with Type=SecureString
4. Use default KMS key or custom KMS key for encryption`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Systems Manager → Parameter Store → Create parameter → Type: SecureString",
			ConsoleURL:      "https://console.aws.amazon.com/systems-manager/parameters",
			Frameworks:      GetFrameworkMappings("SSM_PARAMETER_ENCRYPTION"),
		}, nil
	}

	unencryptedParams := []string{}
	encryptedCount := 0

	for _, param := range params.Parameters {
		if param.Type == types.ParameterTypeSecureString {
			encryptedCount++
		} else {
			unencryptedParams = append(unencryptedParams, *param.Name)
		}
	}

	if len(unencryptedParams) > 0 {
		return CheckResult{
			Control:     "CIS-10.1",
			Name:        "SSM Parameter Store Encryption",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d parameters not encrypted (using String/StringList instead of SecureString): %v", len(unencryptedParams), len(params.Parameters), unencryptedParams),
			Remediation: "Migrate unencrypted parameters to SecureString type",
			RemediationDetail: fmt.Sprintf(`1. Open Systems Manager console
2. Navigate to Parameter Store
3. For each unencrypted parameter:
   - Create new SecureString parameter with same value
   - Update applications to use new parameter name
   - Delete old unencrypted parameter
4. Unencrypted parameters: %v`, unencryptedParams),
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Systems Manager → Parameter Store → Screenshot showing unencrypted parameters",
			ConsoleURL:      "https://console.aws.amazon.com/systems-manager/parameters",
			Frameworks:      GetFrameworkMappings("SSM_PARAMETER_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-10.1",
		Name:        "SSM Parameter Store Encryption",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d SSM parameters use encryption (SecureString type)", encryptedCount),
		Remediation: "N/A - All parameters encrypted",
		RemediationDetail: fmt.Sprintf(`All %d parameters properly use SecureString type for encryption at rest.
Continue this practice for all new parameters.`, encryptedCount),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Systems Manager → Parameter Store → Screenshot showing all SecureString parameters",
		ConsoleURL:      "https://console.aws.amazon.com/systems-manager/parameters",
		Frameworks:      GetFrameworkMappings("SSM_PARAMETER_ENCRYPTION"),
	}, nil
}

// CheckSessionManagerLogging - Ensure Session Manager logs sessions
func (c *SSMChecks) CheckSessionManagerLogging(ctx context.Context) (CheckResult, error) {
	// Check Session Manager preferences for logging configuration
	docName := "SSM-SessionManagerRunShell"
	prefs, err := c.client.GetDocument(ctx, &ssm.GetDocumentInput{
		Name: &docName,
	})

	if err != nil {
		// Document might not exist or access denied
		return CheckResult{
			Control:     "CIS-10.2",
			Name:        "SSM Session Manager Logging",
			Status:      "FAIL",
			Evidence:    "Session Manager logging configuration not found or not accessible",
			Remediation: "Configure Session Manager to log session activity to CloudWatch Logs or S3",
			RemediationDetail: `1. Open Systems Manager console
2. Navigate to Session Manager → Preferences
3. Enable CloudWatch logging
4. Optionally enable S3 logging for audit trail
5. Click Save`,
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Systems Manager → Session Manager → Preferences → Screenshot showing CloudWatch logging enabled",
			ConsoleURL:      "https://console.aws.amazon.com/systems-manager/session-manager/preferences",
			Frameworks:      GetFrameworkMappings("SSM_SESSION_LOGGING"),
		}, nil
	}

	// If document exists, check for logging configuration
	_ = prefs // Document content would need parsing

	// For now, return INFO status since we can't easily determine logging config via API
	return CheckResult{
		Control:     "CIS-10.2",
		Name:        "SSM Session Manager Logging",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Verify Session Manager logging is configured",
		Remediation: "Manually verify Session Manager preferences include CloudWatch or S3 logging",
		RemediationDetail: `1. Open Systems Manager console
2. Navigate to Session Manager → Preferences
3. Verify CloudWatch logging is enabled
4. Verify S3 logging is enabled (recommended)
5. Screenshot showing both logging destinations configured`,
		Severity:        "MEDIUM",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Systems Manager → Session Manager → Preferences → Screenshot showing logging configuration",
		ConsoleURL:      "https://console.aws.amazon.com/systems-manager/session-manager/preferences",
		Frameworks:      GetFrameworkMappings("SSM_SESSION_LOGGING"),
	}, nil
}

// CheckPatchCompliance - Ensure EC2 instances are patch compliant
func (c *SSMChecks) CheckPatchCompliance(ctx context.Context) (CheckResult, error) {
	// List managed instances
	instances, err := c.client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{})
	if err != nil {
		return CheckResult{
			Control:     "CIS-10.3",
			Name:        "SSM Patch Compliance",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list managed instances: %v", err),
			Remediation: "Verify Systems Manager access permissions",
			RemediationDetail: `Check IAM permissions for Systems Manager.
Required permissions:
- ssm:DescribeInstanceInformation
- ssm:DescribeInstancePatchStates`,
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SSM_PATCH_COMPLIANCE"),
		}, err
	}

	if len(instances.InstanceInformationList) == 0 {
		return CheckResult{
			Control:     "CIS-10.3",
			Name:        "SSM Patch Compliance",
			Status:      "INFO",
			Evidence:    "No EC2 instances managed by Systems Manager",
			Remediation: "Install SSM Agent on EC2 instances for patch management",
			RemediationDetail: `1. Install SSM Agent on EC2 instances
2. Attach IAM role with SSM permissions to instances
3. Create Patch Baselines in Systems Manager
4. Create Maintenance Windows for patching
5. Monitor patch compliance in Systems Manager console`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Systems Manager → Fleet Manager → Screenshot showing no managed instances",
			ConsoleURL:      "https://console.aws.amazon.com/systems-manager/managed-instances",
			Frameworks:      GetFrameworkMappings("SSM_PATCH_COMPLIANCE"),
		}, nil
	}

	// Check patch compliance for managed instances
	patchStates, err := c.client.DescribeInstancePatchStates(ctx, &ssm.DescribeInstancePatchStatesInput{
		InstanceIds: getInstanceIds(instances.InstanceInformationList),
	})

	if err != nil {
		return CheckResult{
			Control:     "CIS-10.3",
			Name:        "SSM Patch Compliance",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to get patch compliance status: %v", err),
			Remediation: "Verify patch compliance permissions",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SSM_PATCH_COMPLIANCE"),
		}, nil
	}

	compliantInstances := 0
	nonCompliantInstances := []string{}

	for _, state := range patchStates.InstancePatchStates {
		if state.FailedCount > 0 || state.MissingCount > 0 || state.NotApplicableCount > 0 {
			nonCompliantInstances = append(nonCompliantInstances, *state.InstanceId)
		} else {
			compliantInstances++
		}
	}

	if len(nonCompliantInstances) > 0 {
		return CheckResult{
			Control:     "CIS-10.3",
			Name:        "SSM Patch Compliance",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d instances are not patch compliant: %v", len(nonCompliantInstances), len(patchStates.InstancePatchStates), nonCompliantInstances),
			Remediation: "Apply missing patches to non-compliant instances",
			RemediationDetail: fmt.Sprintf(`1. Open Systems Manager console
2. Navigate to Patch Manager
3. Review non-compliant instances: %v
4. Create Maintenance Window to apply patches
5. Run Patch Now or schedule patching during maintenance window
6. Verify compliance after patching`, nonCompliantInstances),
			Severity:        "HIGH",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Systems Manager → Patch Manager → Compliance → Screenshot showing non-compliant instances",
			ConsoleURL:      "https://console.aws.amazon.com/systems-manager/patch-manager/compliance",
			Frameworks:      GetFrameworkMappings("SSM_PATCH_COMPLIANCE"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-10.3",
		Name:        "SSM Patch Compliance",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d managed instances are patch compliant", compliantInstances),
		Remediation: "N/A - All instances patched",
		RemediationDetail: fmt.Sprintf(`All %d managed instances have required patches applied.
Continue monitoring patch compliance and apply patches regularly.`, compliantInstances),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Systems Manager → Patch Manager → Compliance → Screenshot showing all compliant",
		ConsoleURL:      "https://console.aws.amazon.com/systems-manager/patch-manager/compliance",
		Frameworks:      GetFrameworkMappings("SSM_PATCH_COMPLIANCE"),
	}, nil
}

// Helper functions
func getInstanceIds(instances []types.InstanceInformation) []string {
	ids := make([]string, len(instances))
	for i, inst := range instances {
		ids[i] = *inst.InstanceId
	}
	return ids
}
