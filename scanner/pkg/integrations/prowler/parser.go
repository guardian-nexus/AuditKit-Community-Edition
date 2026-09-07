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

// ParseFile parses Prowler JSON output and converts to AuditKit format.
// Supports Prowler 4.x/5.x OCSF (json-ocsf) and the legacy Prowler 3 native JSON.
func (p *ProwlerIntegration) ParseFile(ctx context.Context, filePath string) ([]integrations.IntegrationResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Prowler file: %v", err)
	}

	// Prowler 4/5 OCSF: a bare array of OCSF finding objects.
	var ocsf []ocsfFinding
	if err := json.Unmarshal(data, &ocsf); err == nil && isOCSF(ocsf) {
		findings := make([]ProwlerResult, 0, len(ocsf))
		for _, f := range ocsf {
			findings = append(findings, f.toProwlerResult())
		}
		return p.convertToAuditKitResults(findings), nil
	}

	// Legacy Prowler 3: full output object with a Findings array.
	var prowlerOutput ProwlerOutput
	if err := json.Unmarshal(data, &prowlerOutput); err == nil && hasUsableFindings(prowlerOutput.Findings) {
		return p.convertToAuditKitResults(prowlerOutput.Findings), nil
	}

	// Legacy Prowler 3: bare array of findings.
	var findings []ProwlerResult
	if err := json.Unmarshal(data, &findings); err == nil && hasUsableFindings(findings) {
		return p.convertToAuditKitResults(findings), nil
	}

	// JSONL (newline-delimited JSON), either format.
	var jsonl []ProwlerResult
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ","))
		if line == "" || line == "[" || line == "]" {
			continue
		}
		var of ocsfFinding
		if err := json.Unmarshal([]byte(line), &of); err == nil && (of.StatusCode != "" || of.Metadata.EventCode != "") {
			jsonl = append(jsonl, of.toProwlerResult())
			continue
		}
		var finding ProwlerResult
		// "null" and "{}" unmarshal without error into a zero value; appending
		// those inflated the control count with blank findings.
		if err := json.Unmarshal([]byte(line), &finding); err == nil && finding.CheckID != "" {
			jsonl = append(jsonl, finding)
		}
	}
	if hasUsableFindings(jsonl) {
		return p.convertToAuditKitResults(jsonl), nil
	}

	// Fail loudly rather than reporting a file we could not read as a scan in
	// which nothing passed. json-asff and sarif land here.
	return nil, fmt.Errorf("no usable Prowler findings in %s: unrecognised format. "+
		"Re-run Prowler with -M json-ocsf (Prowler 4/5) or use Prowler 3 native JSON", filePath)
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
	// Only reuse Prowler's URL when it actually points at a cloud console. OCSF
	// remediation references are documentation links (hub.prowler.com), and
	// returning those here replaced every console link in the report.
	if isCloudConsoleURL(finding.Remediation.Recommendation.URL) {
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

// ---------------------------------------------------------------------------
// OCSF (Prowler 4.x / 5.x)
//
// Prowler 3 emitted PascalCase "native" JSON. Prowler 4 removed it; modern
// versions emit csv, json-ocsf, json-asff, html and sarif only. The structs
// above still describe the v3 shape, so an OCSF file unmarshalled into them
// produced findings with every field empty - which scored as "0 of N passed"
// instead of failing loudly. These types map OCSF onto the same internal shape.
// ---------------------------------------------------------------------------

type ocsfFinding struct {
	Message      string `json:"message"`
	StatusCode   string `json:"status_code"`
	StatusDetail string `json:"status_detail"`
	Severity     string `json:"severity"`
	RiskDetails  string `json:"risk_details"`
	Metadata     struct {
		EventCode string `json:"event_code"`
	} `json:"metadata"`
	FindingInfo struct {
		Title string `json:"title"`
		Desc  string `json:"desc"`
		UID   string `json:"uid"`
	} `json:"finding_info"`
	Resources []struct {
		UID    string `json:"uid"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Region string `json:"region"`
		Group  struct {
			Name string `json:"name"`
		} `json:"group"`
	} `json:"resources"`
	Remediation struct {
		Desc       string   `json:"desc"`
		References []string `json:"references"`
	} `json:"remediation"`
	Cloud struct {
		Provider string `json:"provider"`
		Account  struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
	Unmapped struct {
		Provider    string              `json:"provider"`
		ProviderUID string              `json:"provider_uid"`
		Compliance  map[string][]string `json:"compliance"`
	} `json:"unmapped"`
}

// isOCSF reports whether the decoded findings look like OCSF rather than v3.
func isOCSF(findings []ocsfFinding) bool {
	for _, f := range findings {
		if f.StatusCode != "" || f.Metadata.EventCode != "" {
			return true
		}
	}
	return false
}

// toProwlerResult maps an OCSF finding onto the internal v3-shaped struct so the
// rest of the conversion pipeline is shared between both formats.
func (f ocsfFinding) toProwlerResult() ProwlerResult {
	r := ProwlerResult{
		CheckID:        f.Metadata.EventCode,
		CheckTitle:     f.FindingInfo.Title,
		Status:         f.StatusCode,
		StatusExtended: f.StatusDetail,
		Severity:       f.Severity,
		Description:    f.FindingInfo.Desc,
		Risk:           f.RiskDetails,
		Compliance:     f.Unmapped.Compliance,
		Provider:       f.Unmapped.Provider,
		AccountID:      f.Unmapped.ProviderUID,
	}
	if r.StatusExtended == "" {
		r.StatusExtended = f.Message
	}
	if r.Provider == "" {
		r.Provider = f.Cloud.Provider
	}
	if r.AccountID == "" {
		r.AccountID = f.Cloud.Account.UID
	}
	if len(f.Resources) > 0 {
		res := f.Resources[0]
		r.Region = res.Region
		r.ResourceID = res.Name
		r.ResourceArn = res.UID
		r.ServiceName = res.Group.Name
	}
	r.Remediation.Recommendation.Text = f.Remediation.Desc
	if len(f.Remediation.References) > 0 {
		r.Remediation.Recommendation.URL = f.Remediation.References[0]
	}
	return r
}

// hasUsableFindings guards against a file that decodes structurally but carries
// none of the fields we need - the exact failure that made an unsupported format
// look like a scan where nothing passed.
func hasUsableFindings(findings []ProwlerResult) bool {
	for _, f := range findings {
		// CheckID only, deliberately. Go matches JSON field names
		// case-insensitively, so an OCSF file's top-level "status":"New" binds to
		// .Status and would otherwise satisfy this guard, letting an OCSF file be
		// reported as a legacy scan in which nothing passed.
		if f.CheckID != "" {
			return true
		}
	}
	return false
}

// isCloudConsoleURL reports whether a URL points at a cloud provider console.
func isCloudConsoleURL(url string) bool {
	if url == "" {
		return false
	}
	for _, host := range []string{"console.aws.amazon.com", "portal.azure.com", "console.cloud.google.com"} {
		if strings.Contains(url, host) {
			return true
		}
	}
	return false
}
