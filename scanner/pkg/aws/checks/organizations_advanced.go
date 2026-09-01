package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

type OrganizationsAdvancedChecks struct {
	orgClient *organizations.Client
	ctClient  *cloudtrail.Client
}

func NewOrganizationsAdvancedChecks(orgClient *organizations.Client, ctClient *cloudtrail.Client) *OrganizationsAdvancedChecks {
	return &OrganizationsAdvancedChecks{
		orgClient: orgClient,
		ctClient:  ctClient,
	}
}

func (c *OrganizationsAdvancedChecks) Name() string {
	return "AWS Organizations Advanced Configuration"
}

func (c *OrganizationsAdvancedChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS 11.1 - SCPs enabled
	if result, err := c.CheckSCPsEnabled(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 11.2 - Multi-account structure
	if result, err := c.CheckMultiAccountStructure(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 11.3 - Organization CloudTrail
	if result, err := c.CheckOrganizationTrail(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 11.4 - Service Control Policies configured
	if result, err := c.CheckSCPsConfigured(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *OrganizationsAdvancedChecks) CheckSCPsEnabled(ctx context.Context) (CheckResult, error) {
	org, err := c.orgClient.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return CheckResult{
			Control:     "CIS-11.1",
			Name:        "AWS Organizations SCPs Enabled",
			Status:      "INFO",
			Evidence:    "Not using AWS Organizations (single account) or no permissions",
			Remediation: "Enable AWS Organizations for multi-account governance",
			RemediationDetail: `1. Open Organizations console
2. Create organization
3. Enable all features (not just consolidated billing)
4. SCPs are automatically enabled with all features`,
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ORGANIZATIONS_SCPS_ENABLED"),
		}, nil
	}

	if len(org.Organization.AvailablePolicyTypes) == 0 {
		return CheckResult{
			Control:     "CIS-11.1",
			Name:        "AWS Organizations SCPs Enabled",
			Status:      "FAIL",
			Evidence:    "Organization exists but Service Control Policies (SCPs) are not enabled",
			Remediation: "Enable all features in AWS Organizations to use SCPs",
			RemediationDetail: `1. Open Organizations console
2. Settings → Enable all features
3. Accept invitation in all member accounts
4. SCPs will become available for governance`,
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			ConsoleURL: "https://console.aws.amazon.com/organizations/v2/home",
			Frameworks: GetFrameworkMappings("ORGANIZATIONS_SCPS_ENABLED"),
		}, nil
	}

	// Check if SCP policy type is enabled
	scpEnabled := false
	for _, policyType := range org.Organization.AvailablePolicyTypes {
		if policyType.Type == "SERVICE_CONTROL_POLICY" {
			scpEnabled = true
			break
		}
	}

	if !scpEnabled {
		return CheckResult{
			Control:     "CIS-11.1",
			Name:        "AWS Organizations SCPs Enabled",
			Status:      "FAIL",
			Evidence:    "AWS Organizations enabled but SCPs are not available",
			Remediation: "Enable Service Control Policies in Organizations",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("ORGANIZATIONS_SCPS_ENABLED"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-11.1",
		Name:        "AWS Organizations SCPs Enabled",
		Status:      "PASS",
		Evidence:    "AWS Organizations is enabled with Service Control Policies (SCPs) available",
		Remediation: "N/A - SCPs enabled",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/organizations/v2/home/policies/service-control-policy",
		Frameworks:  GetFrameworkMappings("ORGANIZATIONS_SCPS_ENABLED"),
	}, nil
}

func (c *OrganizationsAdvancedChecks) CheckMultiAccountStructure(ctx context.Context) (CheckResult, error) {
	accounts, err := c.orgClient.ListAccounts(ctx, &organizations.ListAccountsInput{})
	if err != nil {
		return CheckResult{
			Control:     "CIS-11.2",
			Name:        "Multi-Account Structure",
			Status:      "INFO",
			Evidence:    "Not using AWS Organizations or no permissions",
			Remediation: "Consider multi-account strategy for workload isolation",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("ORGANIZATIONS_MULTI_ACCOUNT"),
		}, nil
	}

	accountCount := len(accounts.Accounts)

	if accountCount <= 1 {
		return CheckResult{
			Control:     "CIS-11.2",
			Name:        "Multi-Account Structure",
			Status:      "FAIL",
			Evidence:    "Using single AWS account - no workload isolation",
			Remediation: "Implement multi-account structure for security and compliance",
			RemediationDetail: `Recommended account structure:
1. Management account (Organizations only)
2. Security account (logging, monitoring)
3. Development account
4. Staging account
5. Production account
6. Shared services account

Benefits:
- Blast radius containment
- Separate billing
- Clear compliance boundaries
- Different security controls per environment`,
			Severity:        "MEDIUM",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Organizations → Accounts → Screenshot showing multi-account structure",
			ConsoleURL:      "https://console.aws.amazon.com/organizations/v2/home/accounts",
			Frameworks:      GetFrameworkMappings("ORGANIZATIONS_MULTI_ACCOUNT"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-11.2",
		Name:        "Multi-Account Structure",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("Using multi-account structure with %d accounts for workload isolation", accountCount),
		Remediation: "N/A - Multi-account structure implemented",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/organizations/v2/home/accounts",
		Frameworks:  GetFrameworkMappings("ORGANIZATIONS_MULTI_ACCOUNT"),
	}, nil
}

func (c *OrganizationsAdvancedChecks) CheckOrganizationTrail(ctx context.Context) (CheckResult, error) {
	trails, err := c.ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return CheckResult{
			Control:     "CIS-11.3",
			Name:        "Organization-wide CloudTrail",
			Status:      "ERROR",
			Evidence:    "Cannot check CloudTrail configuration",
			Remediation: "Verify CloudTrail permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("ORGANIZATIONS_TRAIL"),
		}, nil
	}

	hasOrgTrail := false
	for _, trail := range trails.TrailList {
		if trail.IsOrganizationTrail != nil && *trail.IsOrganizationTrail {
			hasOrgTrail = true
			break
		}
	}

	if !hasOrgTrail {
		return CheckResult{
			Control:     "CIS-11.3",
			Name:        "Organization-wide CloudTrail",
			Status:      "FAIL",
			Evidence:    "No organization-wide CloudTrail configured - member accounts may not be logged",
			Remediation: "Create organization trail to log all accounts",
			RemediationDetail: `1. Open CloudTrail console in management account
2. Create trail
3. Enable "Enable for all accounts in my organization"
4. Configure S3 bucket in security/logging account
5. Enable log file validation
6. All member accounts automatically inherit this trail`,
			Severity:        "CRITICAL",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "CloudTrail → Trails → Create trail → Screenshot showing organization trail enabled",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Frameworks:      GetFrameworkMappings("ORGANIZATIONS_TRAIL"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-11.3",
		Name:        "Organization-wide CloudTrail",
		Status:      "PASS",
		Evidence:    "Organization-wide CloudTrail is configured - all accounts are logged",
		Remediation: "N/A - Organization trail configured",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/cloudtrail/home#/trails",
		Frameworks:  GetFrameworkMappings("ORGANIZATIONS_TRAIL"),
	}, nil
}

func (c *OrganizationsAdvancedChecks) CheckSCPsConfigured(ctx context.Context) (CheckResult, error) {
	policies, err := c.orgClient.ListPolicies(ctx, &organizations.ListPoliciesInput{
		Filter: "SERVICE_CONTROL_POLICY",
	})
	if err != nil {
		return CheckResult{
			Control:     "CIS-11.4",
			Name:        "Service Control Policies Configured",
			Status:      "INFO",
			Evidence:    "Cannot list SCPs - not using Organizations or no permissions",
			Remediation: "N/A",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("ORGANIZATIONS_SCPS_CONFIGURED"),
		}, nil
	}

	// Default FullAWSAccess policy doesn't count as configured
	customPolicies := 0
	for _, policy := range policies.Policies {
		if policy.Name != nil && *policy.Name != "FullAWSAccess" {
			customPolicies++
		}
	}

	if customPolicies == 0 {
		return CheckResult{
			Control:     "CIS-11.4",
			Name:        "Service Control Policies Configured",
			Status:      "FAIL",
			Evidence:    "No custom SCPs configured - using default FullAWSAccess only",
			Remediation: "Create SCPs to enforce security boundaries",
			RemediationDetail: `Recommended SCPs:
1. Deny leaving organization
2. Deny disabling CloudTrail
3. Deny disabling Config
4. Deny changing security baseline
5. Region restrictions
6. Service restrictions per OU

Example deny policy:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": ["cloudtrail:DeleteTrail", "cloudtrail:StopLogging"],
    "Resource": "*"
  }]
}`,
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Organizations → Policies → Service control policies → Screenshot showing custom policies",
			ConsoleURL:      "https://console.aws.amazon.com/organizations/v2/home/policies/service-control-policy",
			Frameworks:      GetFrameworkMappings("ORGANIZATIONS_SCPS_CONFIGURED"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-11.4",
		Name:        "Service Control Policies Configured",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("%d custom SCPs configured for security boundaries", customPolicies),
		Remediation: "N/A - SCPs configured",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/organizations/v2/home/policies/service-control-policy",
		Frameworks:  GetFrameworkMappings("ORGANIZATIONS_SCPS_CONFIGURED"),
	}, nil
}
