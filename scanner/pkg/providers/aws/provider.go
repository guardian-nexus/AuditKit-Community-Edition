package aws

import (
	"context"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/aws"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/core"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/providers"
)

// AWSProvider implements the Provider interface for AWS
type AWSProvider struct {
	*providers.BaseProvider
	scanner *aws.AWSScanner
}

// NewProvider creates a new AWS provider
func NewProvider() *AWSProvider {
	return &AWSProvider{
		BaseProvider: providers.NewBaseProvider("aws"),
	}
}

// Initialize sets up AWS credentials and creates the scanner
func (p *AWSProvider) Initialize(profile string) error {
	scanner, err := aws.NewScanner(profile)
	if err != nil {
		return err
	}

	p.scanner = scanner

	// Get and cache account ID
	ctx := context.Background()
	accountID := scanner.GetAccountID(ctx)
	p.SetAccountID(accountID)

	return nil
}

// Scan executes compliance checks
func (p *AWSProvider) Scan(ctx context.Context, services []string, framework string, verbose bool) ([]core.ScanResult, error) {
	if p.scanner == nil {
		return nil, nil
	}

	// Call existing AWS scanner
	awsResults, err := p.scanner.ScanServices(ctx, services, verbose, framework)
	if err != nil {
		return nil, err
	}

	// Convert AWS results to core.ScanResult
	results := make([]core.ScanResult, len(awsResults))
	for i, r := range awsResults {
		results[i] = core.ScanResult{
			Control:           r.Control,
			Name:              getControlName(r.Control),
			Category:          getControlCategory(r.Control),
			Status:            r.Status,
			Severity:          r.Severity,
			Evidence:          r.Evidence,
			Remediation:       r.Remediation,
			RemediationDetail: r.RemediationDetail,
			ScreenshotGuide:   r.ScreenshotGuide,
			ConsoleURL:        r.ConsoleURL,
			Priority:          getPriority(r.Severity, r.Status),
			Frameworks:        r.Frameworks,
		}
	}

	return results, nil
}

// Helper functions to match main.go logic
func getControlName(controlID string) string {
	// Simple implementation - could be moved to shared package
	return controlID
}

func getControlCategory(controlID string) string {
	// Simple implementation - could be moved to shared package
	return "Security"
}

func getPriority(severity, status string) string {
	if status == "PASS" {
		return "PASSED"
	}
	return severity
}
