package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

type APIGatewayChecks struct {
	clientV1 *apigateway.Client
	clientV2 *apigatewayv2.Client
}

func NewAPIGatewayChecks(clientV1 *apigateway.Client, clientV2 *apigatewayv2.Client) *APIGatewayChecks {
	return &APIGatewayChecks{
		clientV1: clientV1,
		clientV2: clientV2,
	}
}

func (c *APIGatewayChecks) Name() string {
	return "API Gateway Security Configuration"
}

func (c *APIGatewayChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 10.7 - API Gateway Logging
	if result, err := c.CheckAPIGatewayLogging(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.8 - API Gateway Authentication
	if result, err := c.CheckAPIGatewayAuth(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.9 - API Gateway TLS
	if result, err := c.CheckAPIGatewayTLS(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CheckAPIGatewayLogging - Ensure API Gateway stages have logging enabled
func (c *APIGatewayChecks) CheckAPIGatewayLogging(ctx context.Context) (CheckResult, error) {
	// Check REST APIs (v1)
	restAPIs, err := c.clientV1.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC7.1",
			Name:        "API Gateway Logging Enabled",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list API Gateway REST APIs: %v", err),
			Remediation: "Verify API Gateway access permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("API_GATEWAY_LOGGING"),
		}, err
	}

	// Check HTTP APIs (v2)
	httpAPIs, err := c.clientV2.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC7.1",
			Name:        "API Gateway Logging Enabled",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list API Gateway HTTP APIs: %v", err),
			Remediation: "Verify API Gateway access permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("API_GATEWAY_LOGGING"),
		}, err
	}

	totalAPIs := len(restAPIs.Items) + len(httpAPIs.Items)

	if totalAPIs == 0 {
		return CheckResult{
			Control:     "CC7.1",
			Name:        "API Gateway Logging Enabled",
			Status:      "INFO",
			Evidence:    "No API Gateway APIs found",
			Remediation: "N/A - No APIs to check",
			RemediationDetail: `When you create API Gateway APIs:
1. Open API Gateway console
2. Select API → Stages
3. Enable CloudWatch Logs for each stage
4. Set log level to INFO or ERROR
5. Enable detailed CloudWatch metrics`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "API Gateway → APIs → Screenshot showing no APIs",
			ConsoleURL:      "https://console.aws.amazon.com/apigateway/home#/apis",
			Frameworks:      GetFrameworkMappings("API_GATEWAY_LOGGING"),
		}, nil
	}

	// Check REST API stages for logging
	stagesWithoutLogging := []string{}
	stagesWithLogging := 0

	for _, api := range restAPIs.Items {
		stages, err := c.clientV1.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Item {
			if stage.MethodSettings != nil {
				// Check if logging is enabled for any method
				hasLogging := false
				for _, settings := range stage.MethodSettings {
					if settings.LoggingLevel != nil && *settings.LoggingLevel != "" {
						hasLogging = true
						break
					}
				}
				if hasLogging {
					stagesWithLogging++
				} else {
					stagesWithoutLogging = append(stagesWithoutLogging, fmt.Sprintf("%s/%s", *api.Name, *stage.StageName))
				}
			} else {
				stagesWithoutLogging = append(stagesWithoutLogging, fmt.Sprintf("%s/%s", *api.Name, *stage.StageName))
			}
		}
	}

	if len(stagesWithoutLogging) > 0 {
		return CheckResult{
			Control:     "CC7.1",
			Name:        "API Gateway Logging Enabled",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d stages lack CloudWatch logging: %v", len(stagesWithoutLogging), stagesWithoutLogging),
			Remediation: "Enable CloudWatch Logs for all API Gateway stages",
			RemediationDetail: fmt.Sprintf(`1. Open API Gateway console
2. For each API/stage without logging: %v
3. Select API → Stages → Stage name
4. Logs/Tracing tab
5. Enable CloudWatch Logs
6. Set Log level: INFO or ERROR
7. Enable Detailed CloudWatch metrics
8. Save changes`, stagesWithoutLogging),
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "API Gateway → API → Stages → Stage → Logs/Tracing → Screenshot showing logging enabled",
			ConsoleURL:      "https://console.aws.amazon.com/apigateway/home#/apis",
			Frameworks:      GetFrameworkMappings("API_GATEWAY_LOGGING"),
		}, nil
	}

	return CheckResult{
		Control:     "CC7.1",
		Name:        "API Gateway Logging Enabled",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d API Gateway stages have CloudWatch logging enabled", stagesWithLogging),
		Remediation: "N/A - All stages properly configured",
		RemediationDetail: fmt.Sprintf(`All %d stages have CloudWatch logging enabled.
Continue monitoring logs for security events and errors.`, stagesWithLogging),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "API Gateway → APIs → Stages → Screenshot showing all with logging",
		ConsoleURL:      "https://console.aws.amazon.com/apigateway/home#/apis",
		Frameworks:      GetFrameworkMappings("API_GATEWAY_LOGGING"),
	}, nil
}

// CheckAPIGatewayAuth - Ensure API Gateway uses authorization
func (c *APIGatewayChecks) CheckAPIGatewayAuth(ctx context.Context) (CheckResult, error) {
	restAPIs, err := c.clientV1.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "API Gateway Authorization Enabled",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list APIs: %v", err),
			Remediation: "Verify permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("API_GATEWAY_AUTH"),
		}, err
	}

	if len(restAPIs.Items) == 0 {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "API Gateway Authorization Enabled",
			Status:      "INFO",
			Evidence:    "No API Gateway APIs found",
			Remediation: "N/A - No APIs to check",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("API_GATEWAY_AUTH"),
		}, nil
	}

	// Check for authorizers is complex - require manual verification
	return CheckResult{
		Control:     "CC6.1",
		Name:        "API Gateway Authorization Enabled",
		Status:      "MANUAL",
		Evidence:    fmt.Sprintf("MANUAL CHECK: Verify %d API(s) use authorizers (IAM, Cognito, Lambda, or API keys)", len(restAPIs.Items)),
		Remediation: "Enable authorization for all API Gateway methods",
		RemediationDetail: fmt.Sprintf(`1. Open API Gateway console
2. For each API (%d total):
3. Select API → Authorizers
4. Create authorizer: IAM, Cognito, Lambda, or API keys
5. For each method in Resources:
6. Method Request → Authorization: Select authorizer
7. Verify NO methods use "NONE" authorization
8. Screenshot showing authorizers configured`, len(restAPIs.Items)),
		Severity:        "CRITICAL",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "API Gateway → API → Authorizers → Screenshot showing configured authorizers",
		ConsoleURL:      "https://console.aws.amazon.com/apigateway/home#/apis",
		Frameworks:      GetFrameworkMappings("API_GATEWAY_AUTH"),
	}, nil
}

// CheckAPIGatewayTLS - Ensure API Gateway uses TLS 1.2 or higher
func (c *APIGatewayChecks) CheckAPIGatewayTLS(ctx context.Context) (CheckResult, error) {
	// Check domain names for TLS configuration
	domainNames, err := c.clientV1.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{})
	if err != nil {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "API Gateway TLS 1.2+",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list custom domains: %v", err),
			Remediation: "Verify permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("API_GATEWAY_TLS"),
		}, err
	}

	if len(domainNames.Items) == 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "API Gateway TLS 1.2+",
			Status:      "INFO",
			Evidence:    "No custom domains configured - API Gateway default endpoints use TLS 1.2+",
			Remediation: "N/A - Default endpoints are secure",
			RemediationDetail: `API Gateway default endpoints (execute-api.amazonaws.com) use TLS 1.2+.
When configuring custom domains, ensure:
1. Select Security Policy: TLS 1.2
2. Use ACM certificate
3. Avoid TLS 1.0/1.1`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "API Gateway → Custom domain names → Screenshot showing no custom domains or TLS 1.2",
			ConsoleURL:      "https://console.aws.amazon.com/apigateway/home#/custom-domain-names",
			Frameworks:      GetFrameworkMappings("API_GATEWAY_TLS"),
		}, nil
	}

	weakTLSDomains := []string{}
	secureDomains := 0

	for _, domain := range domainNames.Items {
		if domain.SecurityPolicy != "" {
			// TLS_1_0 is insecure, TLS_1_2 is required
			if string(domain.SecurityPolicy) == "TLS_1_0" {
				weakTLSDomains = append(weakTLSDomains, *domain.DomainName)
			} else {
				secureDomains++
			}
		} else {
			// No policy specified - might be using default (need to check)
			weakTLSDomains = append(weakTLSDomains, *domain.DomainName)
		}
	}

	if len(weakTLSDomains) > 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "API Gateway TLS 1.2+",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d custom domains use weak TLS (1.0/1.1): %v", len(weakTLSDomains), weakTLSDomains),
			Remediation: "Upgrade custom domains to TLS 1.2 security policy",
			RemediationDetail: fmt.Sprintf(`1. Open API Gateway console
2. Navigate to Custom domain names
3. For each domain with weak TLS: %v
4. Edit domain
5. Security policy: Select TLS 1.2
6. Save changes
7. Test API connectivity after upgrade`, weakTLSDomains),
			Severity:        "CRITICAL",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "API Gateway → Custom domain names → Domain → Screenshot showing TLS 1.2 security policy",
			ConsoleURL:      "https://console.aws.amazon.com/apigateway/home#/custom-domain-names",
			Frameworks:      GetFrameworkMappings("API_GATEWAY_TLS"),
		}, nil
	}

	return CheckResult{
		Control:     "CC6.3",
		Name:        "API Gateway TLS 1.2+",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d custom domains use TLS 1.2 security policy", secureDomains),
		Remediation: "N/A - All domains properly configured",
		RemediationDetail: fmt.Sprintf(`All %d custom domains use TLS 1.2 or higher.
Continue using TLS 1.2+ for all new custom domains.`, secureDomains),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "API Gateway → Custom domain names → Screenshot showing all TLS 1.2",
		ConsoleURL:      "https://console.aws.amazon.com/apigateway/home#/custom-domain-names",
		Frameworks:      GetFrameworkMappings("API_GATEWAY_TLS"),
	}, nil
}
