package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

type AccessAnalyzerChecks struct {
	client *accessanalyzer.Client
	region string
}

func NewAccessAnalyzerChecks(client *accessanalyzer.Client, region string) *AccessAnalyzerChecks {
	return &AccessAnalyzerChecks{
		client: client,
		region: region,
	}
}

func (c *AccessAnalyzerChecks) Name() string {
	return "IAM Access Analyzer"
}

func (c *AccessAnalyzerChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckAccessAnalyzerEnabled(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CheckAccessAnalyzerEnabled verifies IAM Access Analyzer is enabled
// CIS AWS Foundations Benchmark 1.8
func (c *AccessAnalyzerChecks) CheckAccessAnalyzerEnabled(ctx context.Context) (CheckResult, error) {
	// List all analyzers in this region
	resp, err := c.client.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		return CheckResult{
			Control:    "CIS-1.8",
			Name:       "IAM Access Analyzer Enabled",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check IAM Access Analyzer: %v", err),
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_ACCESS_ANALYZER"),
		}, err
	}

	if len(resp.Analyzers) == 0 {
		return CheckResult{
			Control:     "CIS-1.8",
			Name:        "IAM Access Analyzer Enabled",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("No IAM Access Analyzer found in region %s | Violates CIS AWS 1.8 (external access detection)", c.region),
			Remediation: "Enable IAM Access Analyzer in this region",
			RemediationDetail: fmt.Sprintf(`# Create IAM Access Analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name "ConsoleAnalyzer-$(uuidgen | cut -d'-' -f1)" \
  --type ACCOUNT \
  --region %s

# Alternative: Use Console
1. Open IAM Console: https://console.aws.amazon.com/iam/
2. Click 'Access analyzer' in left navigation
3. Click 'Create analyzer'
4. Choose:
   - Name: ConsoleAnalyzer (or custom name)
   - Zone of trust: Current account
5. Click 'Create analyzer'
6. Review findings regularly`, c.region),
			ScreenshotGuide: fmt.Sprintf(`IAM Access Analyzer Evidence:
1. Open IAM Console: https://console.aws.amazon.com/iam/
2. Click 'Access analyzer' in left navigation
3. Screenshot showing:
   - At least one analyzer in 'Active' status
   - Analyzer name and creation date
   - Zone of trust: Current account
   - Region: %s
4. Click on analyzer name
5. Screenshot of 'Findings' tab (can be empty if no findings)`, c.region),
			ConsoleURL: "https://console.aws.amazon.com/iamv2/home#/access_analyzer",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_ACCESS_ANALYZER"),
		}, nil
	}

	// Check if at least one analyzer is active
	activeAnalyzers := 0
	analyzerNames := []string{}

	for _, analyzer := range resp.Analyzers {
		if analyzer.Status == types.AnalyzerStatusActive {
			activeAnalyzers++
			analyzerNames = append(analyzerNames, *analyzer.Name)
		}
	}

	if activeAnalyzers == 0 {
		return CheckResult{
			Control:     "CIS-1.8",
			Name:        "IAM Access Analyzer Enabled",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Found %d analyzer(s) but none are active in region %s | Violates CIS AWS 1.8", len(resp.Analyzers), c.region),
			Remediation: "Activate IAM Access Analyzer or create a new one",
			RemediationDetail: fmt.Sprintf(`# Check analyzer status
aws accessanalyzer list-analyzers --region %s

# Create new analyzer if needed
aws accessanalyzer create-analyzer \
  --analyzer-name "ConsoleAnalyzer-$(uuidgen | cut -d'-' -f1)" \
  --type ACCOUNT \
  --region %s`, c.region, c.region),
			ScreenshotGuide: "IAM Console → Access analyzer → Screenshot showing no active analyzers",
			ConsoleURL:      "https://console.aws.amazon.com/iamv2/home#/access_analyzer",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("IAM_ACCESS_ANALYZER"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-1.8",
		Name:       "IAM Access Analyzer Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("IAM Access Analyzer is active in region %s (%d active analyzer(s): %v) | Meets CIS AWS 1.8 (external access monitoring)", c.region, activeAnalyzers, analyzerNames),
		Severity:   "INFO",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("IAM_ACCESS_ANALYZER"),
	}, nil
}
