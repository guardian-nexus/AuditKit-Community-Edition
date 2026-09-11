package azure

import (
	"context"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/azure"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/core"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/providers"
)

// AzureProvider implements the Provider interface for Azure
type AzureProvider struct {
	*providers.BaseProvider
	scanner *azure.AzureScanner
}

// NewProvider creates a new Azure provider
func NewProvider() *AzureProvider {
	return &AzureProvider{
		BaseProvider: providers.NewBaseProvider("azure"),
	}
}

// Initialize sets up Azure credentials and creates the scanner
func (p *AzureProvider) Initialize(subscriptionID string) error {
	scanner, err := azure.NewScanner(subscriptionID)
	if err != nil {
		return err
	}

	p.scanner = scanner

	// Get and cache subscription ID
	ctx := context.Background()
	accountID := scanner.GetAccountID(ctx)
	p.SetAccountID(accountID)

	return nil
}

// Scan executes compliance checks
func (p *AzureProvider) Scan(ctx context.Context, services []string, framework string, verbose bool) ([]core.ScanResult, error) {
	if p.scanner == nil {
		return nil, nil
	}

	// Call existing Azure scanner
	azureResults, err := p.scanner.ScanServices(ctx, services, verbose, framework)
	if err != nil {
		return nil, err
	}

	// Convert Azure results to core.ScanResult
	results := make([]core.ScanResult, len(azureResults))
	for i, r := range azureResults {
		results[i] = core.ScanResult{
			Control:           r.Control,
			Name:              r.Control,
			Category:          "Security",
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

func getPriority(severity, status string) string {
	if status == "PASS" {
		return "PASSED"
	}
	return severity
}
