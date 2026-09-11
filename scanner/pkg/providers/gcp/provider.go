package gcp

import (
	"context"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/core"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/gcp"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/providers"
)

// GCPProvider implements the Provider interface for GCP
type GCPProvider struct {
	*providers.BaseProvider
	scanner *gcp.GCPScanner
}

// NewProvider creates a new GCP provider
func NewProvider() *GCPProvider {
	return &GCPProvider{
		BaseProvider: providers.NewBaseProvider("gcp"),
	}
}

// Initialize sets up GCP credentials and creates the scanner
func (p *GCPProvider) Initialize(projectID string) error {
	scanner, err := gcp.NewScanner(projectID)
	if err != nil {
		return err
	}

	p.scanner = scanner

	// Get and cache project ID
	ctx := context.Background()
	accountID := scanner.GetAccountID(ctx)
	p.SetAccountID(accountID)

	return nil
}

// Scan executes compliance checks
func (p *GCPProvider) Scan(ctx context.Context, services []string, framework string, verbose bool) ([]core.ScanResult, error) {
	if p.scanner == nil {
		return nil, nil
	}

	// Call existing GCP scanner
	gcpResults, err := p.scanner.ScanServices(ctx, services, verbose, framework)
	if err != nil {
		return nil, err
	}

	// Convert GCP results to core.ScanResult
	results := make([]core.ScanResult, len(gcpResults))
	for i, r := range gcpResults {
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

// Close cleans up the GCP scanner
func (p *GCPProvider) Close() error {
	if p.scanner != nil {
		return p.scanner.Close()
	}
	return nil
}

func getPriority(severity, status string) string {
	if status == "PASS" {
		return "PASSED"
	}
	return severity
}
