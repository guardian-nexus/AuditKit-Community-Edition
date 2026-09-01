package prowler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations"
)

// ProwlerOutput represents the top-level Prowler JSON output (v3+)
type ProwlerOutput struct {
	AssessmentStartTime string          `json:"AssessmentStartTime"`
	FindingsCount       FindingsCount   `json:"FindingsCount"`
	Findings            []ProwlerResult `json:"Findings"`
}

type FindingsCount struct {
	Total  int `json:"Total"`
	Pass   int `json:"Pass"`
	Fail   int `json:"Fail"`
	Info   int `json:"Info"`
	Manual int `json:"Manual"`
}

// ProwlerResult represents a single Prowler finding
type ProwlerResult struct {
	CheckID        string              `json:"CheckID"`
	CheckTitle     string              `json:"CheckTitle"`
	CheckType      []string            `json:"CheckType"`
	ServiceName    string              `json:"ServiceName"`
	SubServiceName string              `json:"SubServiceName"`
	Status         string              `json:"Status"`
	StatusExtended string              `json:"StatusExtended"`
	Severity       string              `json:"Severity"`
	Region         string              `json:"Region"`
	ResourceID     string              `json:"ResourceId"`
	ResourceArn    string              `json:"ResourceArn"`
	ResourceTags   map[string]string   `json:"ResourceTags"`
	Description    string              `json:"Description"`
	Risk           string              `json:"Risk"`
	Notes          string              `json:"Notes"`
	Remediation    ProwlerRemediation  `json:"Remediation"`
	Compliance     map[string][]string `json:"Compliance"`
	AccountID      string              `json:"AccountId"`
	Provider       string              `json:"Provider"`
}

type ProwlerRemediation struct {
	Recommendation RecommendationInfo `json:"Recommendation"`
	Code           RemediationCode    `json:"Code"`
}

type RecommendationInfo struct {
	Text string `json:"Text"`
	URL  string `json:"Url"`
}

type RemediationCode struct {
	CLI       string `json:"CLI"`
	NativeIaC string `json:"NativeIaC"`
	Terraform string `json:"Terraform"`
	Other     string `json:"Other"`
}

// ProwlerIntegration handles parsing of Prowler AWS/Azure/GCP compliance results
type ProwlerIntegration struct{}

// NewProwlerIntegration creates a new Prowler parser
func NewProwlerIntegration() *ProwlerIntegration {
	return &ProwlerIntegration{}
}

func (p *ProwlerIntegration) Name() string {
	return "Prowler Security Scanner Integration"
}

func (p *ProwlerIntegration) SupportedFrameworks() []string {
	return []string{"SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-800-53", "CIS", "CMMC", "GDPR", "FedRAMP"}
}

// ParseFile parses Prowler JSON output and converts to AuditKit format
func (p *ProwlerIntegration) ParseFile(ctx context.Context, filePath string) ([]integrations.IntegrationResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Prowler file: %v", err)
	}

	// Try parsing as full output first (with Findings array)
	var prowlerOutput ProwlerOutput
	if err := json.Unmarshal(data, &prowlerOutput); err == nil && len(prowlerOutput.Findings) > 0 {
		return p.convertToAuditKitResults(prowlerOutput.Findings), nil
	}

	// Try parsing as array of findings (JSONL or bare array)
	var findings []ProwlerResult
	if err := json.Unmarshal(data, &findings); err == nil && len(findings) > 0 {
		return p.convertToAuditKitResults(findings), nil
	}

	// Try parsing as JSONL (newline-delimited JSON)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var finding ProwlerResult
		if err := json.Unmarshal([]byte(line), &finding); err == nil {
			findings = append(findings, finding)
		}
	}

	if len(findings) == 0 {
		return nil, fmt.Errorf("no valid Prowler findings found in file")
	}

	return p.convertToAuditKitResults(findings), nil
}

func (p *ProwlerIntegration) convertToAuditKitResults(findings []ProwlerResult) []integrations.IntegrationResult {
	var results []integrations.IntegrationResult

	for _, finding := range findings {
		result := integrations.IntegrationResult{
			Source:          "prowler",
			RuleID:          finding.CheckID,
			Product:         p.formatProduct(finding),
			Title:           finding.CheckTitle,
			Status:          p.normalizeStatus(finding.Status),
			Evidence:        p.formatEvidence(finding),
			Remediation:     p.formatRemediation(finding),
			ScreenshotGuide: p.generateScreenshotGuide(finding),
			ConsoleURL:      p.getConsoleURL(finding),
			Frameworks:      p.convertCompliance(finding.Compliance),
			Timestamp:       time.Now(),
		}

		results = append(results, result)
	}

	return results
}

func (p *ProwlerIntegration) formatProduct(finding ProwlerResult) string {
	provider := strings.ToUpper(finding.Provider)
	if provider == "" {
		provider = "AWS" // Default to AWS if not specified
	}

	service := finding.ServiceName
	if finding.SubServiceName != "" {
		service = fmt.Sprintf("%s/%s", finding.ServiceName, finding.SubServiceName)
	}

	return fmt.Sprintf("%s %s", provider, service)
}

func (p *ProwlerIntegration) normalizeStatus(status string) string {
	switch strings.ToUpper(status) {
	case "PASS":
		return "PASS"
	case "FAIL":
		return "FAIL"
	case "INFO":
		return "INFO"
	case "MANUAL":
		return "MANUAL"
	default:
		return "INFO"
	}
}

func (p *ProwlerIntegration) formatEvidence(finding ProwlerResult) string {
	var evidence strings.Builder

	// Status and title
	evidence.WriteString(fmt.Sprintf("[%s] %s\n\n", finding.Status, finding.CheckTitle))

	// Description
	if finding.Description != "" {
		evidence.WriteString(fmt.Sprintf("Description: %s\n\n", finding.Description))
	}

	// Resource info
	if finding.ResourceArn != "" {
		evidence.WriteString(fmt.Sprintf("Resource ARN: %s\n", finding.ResourceArn))
	} else if finding.ResourceID != "" {
		evidence.WriteString(fmt.Sprintf("Resource ID: %s\n", finding.ResourceID))
	}

	if finding.Region != "" {
		evidence.WriteString(fmt.Sprintf("Region: %s\n", finding.Region))
	}

	if finding.AccountID != "" {
		evidence.WriteString(fmt.Sprintf("Account: %s\n", finding.AccountID))
	}

	// Status details
	if finding.StatusExtended != "" {
		evidence.WriteString(fmt.Sprintf("\nDetails: %s\n", finding.StatusExtended))
	}

	// Risk assessment
	if finding.Risk != "" {
		evidence.WriteString(fmt.Sprintf("\nRisk: %s\n", finding.Risk))
	}

	return evidence.String()
}

func (p *ProwlerIntegration) formatRemediation(finding ProwlerResult) string {
	var remediation strings.Builder

	// Recommendation text
	if finding.Remediation.Recommendation.Text != "" {
		remediation.WriteString(fmt.Sprintf("Recommendation:\n%s\n", finding.Remediation.Recommendation.Text))
	}

	// CLI command
	if finding.Remediation.Code.CLI != "" {
		remediation.WriteString(fmt.Sprintf("\nCLI Command:\n%s\n", finding.Remediation.Code.CLI))
	}

	// Terraform
	if finding.Remediation.Code.Terraform != "" {
		remediation.WriteString(fmt.Sprintf("\nTerraform:\n%s\n", finding.Remediation.Code.Terraform))
	}

	// Reference URL
	if finding.Remediation.Recommendation.URL != "" {
		remediation.WriteString(fmt.Sprintf("\nReference: %s\n", finding.Remediation.Recommendation.URL))
	}

	if remediation.Len() == 0 {
		return "See Prowler documentation for remediation guidance."
	}

	return remediation.String()
}

func (p *ProwlerIntegration) generateScreenshotGuide(finding ProwlerResult) string {
	var guide strings.Builder

	guide.WriteString(fmt.Sprintf("Evidence Collection for: %s\n\n", finding.CheckTitle))

	provider := strings.ToUpper(finding.Provider)
	if provider == "" {
		provider = "AWS"
	}

	switch provider {
	case "AWS":
		guide.WriteString("1. Log into AWS Console\n")
		guide.WriteString(fmt.Sprintf("2. Navigate to %s service\n", finding.ServiceName))
		if finding.Region != "" {
			guide.WriteString(fmt.Sprintf("3. Select region: %s\n", finding.Region))
		}
		if finding.ResourceID != "" {
			guide.WriteString(fmt.Sprintf("4. Locate resource: %s\n", finding.ResourceID))
		}
		guide.WriteString("5. Screenshot the relevant configuration\n")
	case "AZURE":
		guide.WriteString("1. Log into Azure Portal\n")
		guide.WriteString(fmt.Sprintf("2. Navigate to %s service\n", finding.ServiceName))
		if finding.ResourceID != "" {
			guide.WriteString(fmt.Sprintf("3. Locate resource: %s\n", finding.ResourceID))
		}
		guide.WriteString("4. Screenshot the relevant configuration\n")
	case "GCP":
		guide.WriteString("1. Log into GCP Console\n")
		guide.WriteString(fmt.Sprintf("2. Navigate to %s service\n", finding.ServiceName))
		if finding.ResourceID != "" {
			guide.WriteString(fmt.Sprintf("3. Locate resource: %s\n", finding.ResourceID))
		}
		guide.WriteString("4. Screenshot the relevant configuration\n")
	}

	if finding.Remediation.Recommendation.URL != "" {
		guide.WriteString(fmt.Sprintf("\nDocumentation: %s\n", finding.Remediation.Recommendation.URL))
	}

	return guide.String()
}

func (p *ProwlerIntegration) getConsoleURL(finding ProwlerResult) string {
	// If Prowler provides a URL, use it
	if finding.Remediation.Recommendation.URL != "" {
		return finding.Remediation.Recommendation.URL
	}

	// Generate console URL based on provider and service
	provider := strings.ToUpper(finding.Provider)
	if provider == "" {
		provider = "AWS"
	}

	region := finding.Region
	if region == "" {
		region = "us-east-1"
	}

	switch provider {
	case "AWS":
		return fmt.Sprintf("https://%s.console.aws.amazon.com/%s/", region, finding.ServiceName)
	case "AZURE":
		return "https://portal.azure.com/"
	case "GCP":
		return "https://console.cloud.google.com/"
	default:
		return ""
	}
}

func (p *ProwlerIntegration) convertCompliance(compliance map[string][]string) map[string]string {
	result := make(map[string]string)

	// Map Prowler compliance keys to AuditKit framework names
	frameworkMap := map[string]string{
		"SOC2":                 "SOC2",
		"PCI-DSS":              "PCI-DSS",
		"PCI":                  "PCI-DSS",
		"HIPAA":                "HIPAA",
		"ISO27001":             "ISO27001",
		"ISO-27001":            "ISO27001",
		"NIST-800-53":          "NIST-800-53",
		"NIST800-53":           "NIST-800-53",
		"CIS":                  "CIS",
		"CIS-AWS":              "CIS-AWS",
		"CIS-Azure":            "CIS-Azure",
		"CIS-GCP":              "CIS-GCP",
		"CMMC":                 "CMMC",
		"GDPR":                 "GDPR",
		"FedRAMP":              "FedRAMP",
		"FedRAMP-Moderate":     "FedRAMP",
		"FedRAMP-Low":          "FedRAMP",
		"AWS-Well-Architected": "AWS-WAF",
	}

	for prowlerKey, controls := range compliance {
		// Normalize framework name
		normalizedKey := prowlerKey
		if mapped, exists := frameworkMap[prowlerKey]; exists {
			normalizedKey = mapped
		}

		// Join multiple controls with comma
		if len(controls) > 0 {
			result[normalizedKey] = strings.Join(controls, ", ")
		}
	}

	return result
}
