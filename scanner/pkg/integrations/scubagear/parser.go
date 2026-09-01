package scubagear

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations"
)

// Contributor's Entra mapping structure
type EntraMappingFile struct {
	Source  string      `json:"source"`
	Domain  string      `json:"domain"`
	Version string      `json:"version"`
	Rules   []EntraRule `json:"rules"`
}

type EntraRule struct {
	RuleID           string                        `json:"rule_id"`
	Product          string                        `json:"product"`
	Title            string                        `json:"title"`
	Mappings         map[string][]FrameworkMapping `json:"mappings"`
	Severity         string                        `json:"severity"`
	RemediationSteps []string                      `json:"remediation_steps"`
	EvidenceGuidance []string                      `json:"evidence_guidance"`
	ConsoleURL       string                        `json:"console_url"`
	FallbackNotes    string                        `json:"fallback_notes"`
	References       []string                      `json:"references"`
}

type FrameworkMapping struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// ScubaGear JSON output structure
type ScubaGearResults struct {
	ReportSummary struct {
		Date        string   `json:"Date"`
		Tenant      string   `json:"Tenant"`
		ProductsRun []string `json:"ProductsRun"`
	} `json:"ReportSummary"`
	Results map[string][]ScubaFinding `json:"Results"`
}

type ScubaFinding struct {
	RuleID      string `json:"Requirement"`
	Result      bool   `json:"Result"`
	Details     string `json:"Details"`
	PolicyName  string `json:"PolicyName"`
	ProductName string `json:"ProductName"`
}

// ScubaGearIntegration handles parsing of CISA ScubaGear M365 compliance results
type ScubaGearIntegration struct {
	mappingsDir string
	mappings    map[string]map[string]*EntraRule // domain -> rule_id -> rule
}

// NewScubaGearIntegration creates a new ScubaGear parser
func NewScubaGearIntegration(mappingsDir string) *ScubaGearIntegration {
	return &ScubaGearIntegration{
		mappingsDir: mappingsDir,
		mappings:    make(map[string]map[string]*EntraRule),
	}
}

func (s *ScubaGearIntegration) Name() string {
	return "CISA ScubaGear M365 Integration"
}

func (s *ScubaGearIntegration) SupportedFrameworks() []string {
	return []string{"SOC2", "PCI", "HIPAA", "ISO27001", "NIST", "CMMC"}
}

// LoadMappings loads contributor's entra.json mapping file
func (s *ScubaGearIntegration) LoadMappings() error {
	if s.mappingsDir == "" {
		return fmt.Errorf("mappings directory not set")
	}

	mappingFiles, err := filepath.Glob(filepath.Join(s.mappingsDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to find mapping files: %v", err)
	}

	if len(mappingFiles) == 0 {
		return fmt.Errorf("no mapping files found in %s", s.mappingsDir)
	}

	for _, file := range mappingFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip problematic files
		}

		var entraMappings EntraMappingFile
		if err := json.Unmarshal(data, &entraMappings); err != nil {
			continue // Skip invalid JSON
		}

		// Convert to internal format
		domain := entraMappings.Domain
		if _, exists := s.mappings[domain]; !exists {
			s.mappings[domain] = make(map[string]*EntraRule)
		}

		for i := range entraMappings.Rules {
			rule := &entraMappings.Rules[i]
			s.mappings[domain][rule.RuleID] = rule
		}
	}

	if len(s.mappings) == 0 {
		return fmt.Errorf("no valid mappings loaded from %s", s.mappingsDir)
	}

	return nil
}

// ParseFile parses ScubaGear JSON output and converts to AuditKit format
func (s *ScubaGearIntegration) ParseFile(ctx context.Context, filePath string) ([]integrations.IntegrationResult, error) {
	// Load mappings if not already loaded
	if len(s.mappings) == 0 {
		if err := s.LoadMappings(); err != nil {
			return nil, fmt.Errorf("failed to load mappings: %v", err)
		}
	}

	// Parse ScubaGear output
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ScubaGear file: %v", err)
	}

	var scubaResults ScubaGearResults
	if err := json.Unmarshal(data, &scubaResults); err != nil {
		return nil, fmt.Errorf("failed to parse ScubaGear JSON: %v", err)
	}

	return s.convertToAuditKitResults(scubaResults), nil
}

// Convert ScubaGear findings to AuditKit format using contributor's mappings
func (s *ScubaGearIntegration) convertToAuditKitResults(scubaResults ScubaGearResults) []integrations.IntegrationResult {
	var results []integrations.IntegrationResult

	// Process each domain (AAD, SharePoint, etc.)
	for domain, findings := range scubaResults.Results {
		domainMappings, exists := s.mappings[strings.ToLower(domain)]
		if !exists {
			continue // Skip domains we don't have mappings for
		}

		// Process each finding in the domain
		for _, finding := range findings {
			// Find the corresponding rule mapping
			rule, exists := domainMappings[finding.RuleID]
			if !exists {
				continue
			}

			result := integrations.IntegrationResult{
				Source:          "scubagear",
				RuleID:          finding.RuleID,
				Product:         rule.Product,
				Title:           rule.Title,
				Status:          s.convertStatus(finding.Result, rule.Severity),
				Evidence:        s.formatEvidence(finding, rule),
				Remediation:     s.generateRemediation(rule),
				ScreenshotGuide: s.generateScreenshotGuide(rule),
				ConsoleURL:      rule.ConsoleURL,
				Frameworks:      s.convertFrameworks(rule.Mappings),
				Timestamp:       time.Now(),
			}

			results = append(results, result)
		}
	}

	return results
}

func (s *ScubaGearIntegration) convertStatus(passed bool, severity string) string {
	if passed {
		return "PASS"
	}
	// Failed check - use severity from contributor's mapping
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "FAIL"
	case "HIGH":
		return "FAIL"
	case "MEDIUM":
		return "FAIL"
	default:
		return "FAIL"
	}
}

func (s *ScubaGearIntegration) formatEvidence(finding ScubaFinding, rule *EntraRule) string {
	var evidence strings.Builder

	if finding.Result {
		evidence.WriteString(fmt.Sprintf("[PASS] %s: ", rule.Title))
	} else {
		evidence.WriteString(fmt.Sprintf("[FAIL] %s: ", rule.Title))
	}

	if finding.Details != "" {
		evidence.WriteString(finding.Details)
	} else {
		evidence.WriteString(fmt.Sprintf("Checked %s configuration in %s", finding.PolicyName, finding.ProductName))
	}

	// Add evidence guidance if available
	if len(rule.EvidenceGuidance) > 0 {
		evidence.WriteString("\n\nEvidence Requirements:\n")
		for _, guidance := range rule.EvidenceGuidance {
			evidence.WriteString(fmt.Sprintf("- %s\n", guidance))
		}
	}

	return evidence.String()
}

func (s *ScubaGearIntegration) generateRemediation(rule *EntraRule) string {
	var remediation strings.Builder

	if len(rule.RemediationSteps) > 0 {
		remediation.WriteString("Remediation Steps:\n")
		for i, step := range rule.RemediationSteps {
			remediation.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
	}

	// Add fallback notes if available
	if rule.FallbackNotes != "" {
		remediation.WriteString(fmt.Sprintf("\nNote: %s\n", rule.FallbackNotes))
	}

	// Add references
	if len(rule.References) > 0 {
		remediation.WriteString("\nReferences:\n")
		for _, ref := range rule.References {
			remediation.WriteString(fmt.Sprintf("- %s\n", ref))
		}
	}

	return remediation.String()
}

func (s *ScubaGearIntegration) generateScreenshotGuide(rule *EntraRule) string {
	if len(rule.EvidenceGuidance) == 0 {
		return "No screenshot guidance available"
	}

	var guide strings.Builder
	guide.WriteString("Screenshot Evidence Guide:\n")
	for i, guidance := range rule.EvidenceGuidance {
		guide.WriteString(fmt.Sprintf("%d. %s\n", i+1, guidance))
	}

	if rule.ConsoleURL != "" {
		guide.WriteString(fmt.Sprintf("\nDirect Link: %s\n", rule.ConsoleURL))
	}

	if rule.FallbackNotes != "" {
		guide.WriteString(fmt.Sprintf("\nFallback: %s\n", rule.FallbackNotes))
	}

	return guide.String()
}

func (s *ScubaGearIntegration) convertFrameworks(mappings map[string][]FrameworkMapping) map[string]string {
	result := make(map[string]string)

	for framework, controls := range mappings {
		// Combine all control IDs for this framework
		var controlIDs []string
		for _, control := range controls {
			controlIDs = append(controlIDs, control.ID)
		}

		// Store as comma-separated list matching AuditKit format
		result[strings.ToUpper(framework)] = strings.Join(controlIDs, ", ")
	}

	return result
}
