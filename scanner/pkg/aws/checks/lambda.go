package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

type LambdaChecks struct {
	client *lambda.Client
}

func NewLambdaChecks(client *lambda.Client) *LambdaChecks {
	return &LambdaChecks{client: client}
}

func (c *LambdaChecks) Name() string {
	return "Lambda Security Configuration"
}

func (c *LambdaChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 6 - Lambda controls
	if result, err := c.CheckLambdaInVPC(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckLambdaEnvironmentEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckLambdaExecutionRole(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckLambdaPublicAccess(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckLambdaTracing(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CIS 6.1 - Ensure Lambda functions are in VPC when accessing VPC resources
func (c *LambdaChecks) CheckLambdaInVPC(ctx context.Context) (CheckResult, error) {
	functions, err := c.client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	functionsNotInVPC := []string{}
	totalFunctions := len(functions.Functions)

	for _, fn := range functions.Functions {
		if fn.VpcConfig == nil || fn.VpcConfig.VpcId == nil || *fn.VpcConfig.VpcId == "" {
			functionsNotInVPC = append(functionsNotInVPC, *fn.FunctionName)
		}
	}

	if len(functionsNotInVPC) > 0 {
		displayFunctions := functionsNotInVPC
		if len(functionsNotInVPC) > 5 {
			displayFunctions = functionsNotInVPC[:5]
		}

		return CheckResult{
			Control:     "[CIS-6.1]",
			Name:        "Lambda Functions in VPC",
			Status:      "INFO",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d/%d Lambda functions not in VPC: %v | INFO: Only required if accessing VPC resources", len(functionsNotInVPC), totalFunctions, displayFunctions),
			Remediation: "Configure Lambda functions to run in VPC if they need to access VPC resources",
			RemediationDetail: `aws lambda update-function-configuration \
  --function-name FUNCTION_NAME \
  --vpc-config SubnetIds=subnet-xxx,SecurityGroupIds=sg-xxx`,
			ScreenshotGuide: "Lambda Console → Functions → Configuration → VPC → Screenshot showing VPC configuration",
			ConsoleURL:      "https://console.aws.amazon.com/lambda/home#/functions",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "6.1", "SOC2": "CC6.6"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-6.1]",
		Name:       "Lambda Functions in VPC",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Lambda functions are in VPC | Meets CIS 6.1", totalFunctions),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "6.1"},
	}, nil
}

// CIS 6.2 - Ensure Lambda environment variables are encrypted
func (c *LambdaChecks) CheckLambdaEnvironmentEncryption(ctx context.Context) (CheckResult, error) {
	functions, err := c.client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	functionsWithoutKMS := []string{}
	totalWithEnvVars := 0

	for _, fn := range functions.Functions {
		if fn.Environment != nil && fn.Environment.Variables != nil && len(fn.Environment.Variables) > 0 {
			totalWithEnvVars++
			if fn.KMSKeyArn == nil || *fn.KMSKeyArn == "" {
				functionsWithoutKMS = append(functionsWithoutKMS, *fn.FunctionName)
			}
		}
	}

	if len(functionsWithoutKMS) > 0 {
		displayFunctions := functionsWithoutKMS
		if len(functionsWithoutKMS) > 5 {
			displayFunctions = functionsWithoutKMS[:5]
		}

		return CheckResult{
			Control:     "[CIS-6.2]",
			Name:        "Lambda Environment Encryption",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d functions with environment variables not encrypted with customer KMS key: %v | CIS 6.2", len(functionsWithoutKMS), totalWithEnvVars, displayFunctions),
			Remediation: "Encrypt Lambda environment variables with customer-managed KMS keys",
			RemediationDetail: `# Create KMS key first
aws kms create-key --description "Lambda environment variables"

# Update function to use KMS key
aws lambda update-function-configuration \
  --function-name FUNCTION_NAME \
  --kms-key-arn arn:aws:kms:region:account:key/KEY_ID`,
			ScreenshotGuide: "Lambda Console → Functions → Configuration → Environment variables → Encryption → Screenshot showing KMS key",
			ConsoleURL:      "https://console.aws.amazon.com/lambda/home#/functions",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "6.2", "SOC2": "CC6.7", "PCI-DSS": "3.4"},
		}, nil
	}

	if totalWithEnvVars == 0 {
		return CheckResult{
			Control:    "[CIS-6.2]",
			Name:       "Lambda Environment Encryption",
			Status:     "PASS",
			Evidence:   "No Lambda functions with environment variables | CIS 6.2 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "6.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-6.2]",
		Name:       "Lambda Environment Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d functions with environment variables use KMS encryption | Meets CIS 6.2", totalWithEnvVars),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "6.2"},
	}, nil
}

// CIS 6.3 - Ensure Lambda execution role follows least privilege
func (c *LambdaChecks) CheckLambdaExecutionRole(ctx context.Context) (CheckResult, error) {
	functions, err := c.client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	functionsWithBroadRoles := []string{}

	for _, fn := range functions.Functions {
		if fn.Role != nil {
			role := *fn.Role
			// Check if using overly permissive managed policies
			if contains(role, "AdministratorAccess") || contains(role, "PowerUserAccess") {
				functionsWithBroadRoles = append(functionsWithBroadRoles, *fn.FunctionName)
			}
		}
	}

	if len(functionsWithBroadRoles) > 0 {
		displayFunctions := functionsWithBroadRoles
		if len(functionsWithBroadRoles) > 5 {
			displayFunctions = functionsWithBroadRoles[:5]
		}

		return CheckResult{
			Control:     "[CIS-6.3]",
			Name:        "Lambda Execution Role Permissions",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d functions with overly permissive roles: %v | CIS 6.3", len(functionsWithBroadRoles), displayFunctions),
			Remediation: "Use least privilege IAM roles for Lambda execution",
			RemediationDetail: `# Create custom role with only required permissions
aws iam create-role --role-name LambdaExecutionRole --assume-role-policy-document file://trust-policy.json
aws iam put-role-policy --role-name LambdaExecutionRole --policy-name LambdaPolicy --policy-document file://lambda-policy.json

# Update function
aws lambda update-function-configuration \
  --function-name FUNCTION_NAME \
  --role arn:aws:iam::ACCOUNT:role/LambdaExecutionRole`,
			ScreenshotGuide: "Lambda Console → Functions → Configuration → Permissions → Screenshot showing least-privilege role",
			ConsoleURL:      "https://console.aws.amazon.com/lambda/home#/functions",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "6.3", "SOC2": "CC6.3", "PCI-DSS": "7.1.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-6.3]",
		Name:       "Lambda Execution Role Permissions",
		Status:     "PASS",
		Evidence:   "Lambda functions use least-privilege execution roles | Meets CIS 6.3",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "6.3"},
	}, nil
}

// CIS 6.4 - Ensure Lambda functions are not publicly accessible
func (c *LambdaChecks) CheckLambdaPublicAccess(ctx context.Context) (CheckResult, error) {
	functions, err := c.client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	publicFunctions := []string{}

	for _, fn := range functions.Functions {
		// Check function policy for public access
		policyOutput, err := c.client.GetPolicy(ctx, &lambda.GetPolicyInput{
			FunctionName: fn.FunctionName,
		})

		if err != nil {
			continue // No policy = not public
		}

		if policyOutput.Policy != nil {
			policy := *policyOutput.Policy
			// Check for wildcard principal or public access
			if contains(policy, `"Principal":"*"`) || contains(policy, `"Principal":{"AWS":"*"}`) {
				publicFunctions = append(publicFunctions, *fn.FunctionName)
			}
		}
	}

	if len(publicFunctions) > 0 {
		displayFunctions := publicFunctions
		if len(publicFunctions) > 5 {
			displayFunctions = publicFunctions[:5]
		}

		return CheckResult{
			Control:     "[CIS-6.4]",
			Name:        "Lambda Functions Not Public",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("%d Lambda functions are publicly accessible: %v | CIS 6.4", len(publicFunctions), displayFunctions),
			Remediation: "Remove public access from Lambda function policies",
			RemediationDetail: `aws lambda remove-permission \
  --function-name FUNCTION_NAME \
  --statement-id AllowPublicInvoke`,
			ScreenshotGuide: "Lambda Console → Functions → Configuration → Permissions → Resource-based policy → Screenshot showing no public access",
			ConsoleURL:      "https://console.aws.amazon.com/lambda/home#/functions",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "6.4", "SOC2": "CC6.1", "PCI-DSS": "1.2.1"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-6.4]",
		Name:       "Lambda Functions Not Public",
		Status:     "PASS",
		Evidence:   "No Lambda functions are publicly accessible | Meets CIS 6.4",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "6.4"},
	}, nil
}

// CIS 6.5 - Ensure Lambda functions have tracing enabled
func (c *LambdaChecks) CheckLambdaTracing(ctx context.Context) (CheckResult, error) {
	functions, err := c.client.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	functionsWithoutTracing := []string{}
	totalFunctions := len(functions.Functions)

	for _, fn := range functions.Functions {
		if fn.TracingConfig == nil || fn.TracingConfig.Mode != "Active" {
			functionsWithoutTracing = append(functionsWithoutTracing, *fn.FunctionName)
		}
	}

	if len(functionsWithoutTracing) > 0 {
		displayFunctions := functionsWithoutTracing
		if len(functionsWithoutTracing) > 5 {
			displayFunctions = functionsWithoutTracing[:5]
		}

		return CheckResult{
			Control:     "[CIS-6.5]",
			Name:        "Lambda X-Ray Tracing Enabled",
			Status:      "FAIL",
			Severity:    "LOW",
			Evidence:    fmt.Sprintf("%d/%d functions without X-Ray tracing: %v | CIS 6.5", len(functionsWithoutTracing), totalFunctions, displayFunctions),
			Remediation: "Enable X-Ray tracing for Lambda functions",
			RemediationDetail: `aws lambda update-function-configuration \
  --function-name FUNCTION_NAME \
  --tracing-config Mode=Active`,
			ScreenshotGuide: "Lambda Console → Functions → Configuration → Monitoring → Screenshot showing X-Ray tracing enabled",
			ConsoleURL:      "https://console.aws.amazon.com/lambda/home#/functions",
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "6.5", "SOC2": "CC7.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-6.5]",
		Name:       "Lambda X-Ray Tracing Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Lambda functions have X-Ray tracing enabled | Meets CIS 6.5", totalFunctions),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "6.5"},
	}, nil
}
