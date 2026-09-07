package scubagear

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations"
)

// The mappings ship inside the binary. They used to be read from a
// mappings/scubagear directory beside the working directory, which exists in a
// checkout but not in a release archive, so `integrate -source scubagear`
// failed for everyone who installed from a release rather than the repo.
//
//go:embed mappings/*.json
var embeddedMappings embed.FS

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
	// Results is keyed by baseline name, and each value is an array of *groups*
	// ("Conditional Access", "Guest User Access"...), each carrying a Controls
	// array. Modelling it as a flat array of findings parsed without error and
	// yielded nothing, because every element had only GroupName/Controls and
	// none of the finding fields.
	Results map[string][]ScubaGroup `json:"Results"`
}

// ScubaGroup is one baseline group in a product's results.
//
// It also accepts a bare control row in the same position: ScubaGear's own
// output is always grouped, but hand-assembled files and the raw Rego provider
// output are flat, and accepting both costs nothing.
type ScubaGroup struct {
	GroupName         string         `json:"GroupName"`
	GroupNumber       string         `json:"GroupNumber"`
	GroupReferenceURL string         `json:"GroupReferenceURL"`
	Controls          []ScubaFinding `json:"Controls"`

	ScubaFinding
}

// findings returns the control rows this element carries, in either shape.
func (g ScubaGroup) findings() []ScubaFinding {
	if len(g.Controls) > 0 {
		return g.Controls
	}
	if g.ruleID() != "" {
		return []ScubaFinding{g.ScubaFinding}
	}
	return nil
}

// ScubaFinding is one row of a ScubaGear report.
//
// The field names come from the pscustomobject ScubaGear's CreateReport module
// builds: the policy identifier is "Control ID" (with a space) and "Requirement"
// holds the prose, which is the opposite of what this parser assumed for a long
// time. "Result" is one of Pass, Fail, Warning, Error, Omitted or
// "Incorrect result" - a string, not a boolean.
//
// PolicyId and RequirementMet are the raw Rego field names, kept so that
// provider output fed in directly still parses.
type ScubaFinding struct {
	ControlID   string `json:"Control ID"`
	PolicyID    string `json:"PolicyId"`
	Requirement string `json:"Requirement"`
	Result      string `json:"Result"`
	Met         *bool  `json:"RequirementMet"`
	Criticality string `json:"Criticality"`
	Details     string `json:"Details"`
	PolicyName  string `json:"PolicyName"`
	ProductName string `json:"ProductName"`
}

// ruleID returns the identifier to look up in the mappings.
//
// ScubaGear writes the policy id with a baseline-version suffix
// ("MS.AAD.1.1v1"); the mapping files key on the unsuffixed id, so the suffix is
// trimmed. "Requirement" is the last resort because older AuditKit
// documentation told people to put the id there.
func (f ScubaFinding) ruleID() string {
	id := f.ControlID
	if id == "" {
		id = f.PolicyID
	}
	if id == "" {
		id = f.Requirement
	}
	return trimBaselineVersion(strings.TrimSpace(id))
}

// trimBaselineVersion strips a trailing "v<digits>" from a policy id.
func trimBaselineVersion(id string) string {
	i := strings.LastIndexByte(id, 'v')
	if i <= 0 || i == len(id)-1 {
		return id
	}
	for _, r := range id[i+1:] {
		if r < '0' || r > '9' {
			return id
		}
	}
	// Only a version suffix, never part of the identifier itself, which is
	// always digits and dots after the product segment.
	if id[i-1] < '0' || id[i-1] > '9' {
		return id
	}
	return id[:i]
}

// passed reports whether the policy was met.
func (f ScubaFinding) passed() bool {
	if f.Met != nil {
		return *f.Met
	}
	return strings.EqualFold(strings.TrimSpace(f.Result), "Pass")
}

// scoreable reports whether the row should count towards a score at all.
// ScubaGear reports policies it could not evaluate, and ones the operator chose
// to omit; counting those as failures would understate a tenant's posture.
func (f ScubaFinding) scoreable() bool {
	if f.Met != nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(f.Result)) {
	case "omitted", "error", "n/a", "not applicable", "":
		return false
	}
	return true
}

// scubaDomainAliases maps the product keys ScubaGear writes in its Results
// object to the domain names the mapping files declare. Without this, AAD and
// SharePoint findings - 38 of the 134 mapped rules - match nothing.
var scubaDomainAliases = map[string]string{
	"aad":           "entra",
	"azuread":       "entra",
	"entraid":       "entra",
	"sharepoint":    "spo",
	"onedrive":      "spo",
	"securitysuite": "defender",
	"defenderxdr":   "defender",
}

// resolveDomain returns the mapping domain for a ScubaGear product key.
func resolveDomain(product string) string {
	d := strings.ToLower(strings.TrimSpace(product))
	if alias, ok := scubaDomainAliases[d]; ok {
		return alias
	}
	return d
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

// LoadMappings loads the rule mappings. The embedded copy is the default; a
// directory passed to NewScubaGearIntegration overrides it, so a contributor
// can test an edited mapping without rebuilding.
func (s *ScubaGearIntegration) LoadMappings() error {
	if s.mappingsDir != "" {
		if err := s.loadFromDir(s.mappingsDir); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		// The directory is absent, which is the normal case for an installed
		// binary. Fall through to the embedded mappings.
	}
	return s.loadEmbedded()
}

func (s *ScubaGearIntegration) loadFromDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return err
	}

	mappingFiles, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to find mapping files: %v", err)
	}

	if len(mappingFiles) == 0 {
		return fmt.Errorf("no mapping files found in %s", dir)
	}

	for _, file := range mappingFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip problematic files
		}
		s.addMappingFile(data)
	}

	if len(s.mappings) == 0 {
		return fmt.Errorf("no valid mappings loaded from %s", dir)
	}

	return nil
}

func (s *ScubaGearIntegration) loadEmbedded() error {
	entries, err := fs.Glob(embeddedMappings, "mappings/*.json")
	if err != nil {
		return fmt.Errorf("failed to read embedded mappings: %v", err)
	}

	for _, name := range entries {
		data, err := embeddedMappings.ReadFile(name)
		if err != nil {
			continue
		}
		s.addMappingFile(data)
	}

	if len(s.mappings) == 0 {
		return fmt.Errorf("no valid embedded mappings")
	}

	return nil
}

func (s *ScubaGearIntegration) addMappingFile(data []byte) {
	var entraMappings EntraMappingFile
	if err := json.Unmarshal(data, &entraMappings); err != nil {
		return // Skip invalid JSON
	}

	domain := entraMappings.Domain
	if _, exists := s.mappings[domain]; !exists {
		s.mappings[domain] = make(map[string]*EntraRule)
	}

	for i := range entraMappings.Rules {
		rule := &entraMappings.Rules[i]
		s.mappings[domain][rule.RuleID] = rule
	}
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

	return s.Parse(ctx, data)
}

// Parse converts ScubaGear JSON already held in memory. The Desktop receives an
// upload rather than a path, and previously carried its own copy of this
// parsing, which read Results as an array when ScubaGear writes an object keyed
// by product, and compared Result against the string "Pass" when it is a bool.
// Every real ScubaResults.json imported as an empty scan.
func (s *ScubaGearIntegration) Parse(ctx context.Context, data []byte) ([]integrations.IntegrationResult, error) {
	if len(s.mappings) == 0 {
		if err := s.LoadMappings(); err != nil {
			return nil, fmt.Errorf("failed to load mappings: %v", err)
		}
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

	// Process each product. ScubaGear keys its Results object by baseline name
	// ("AAD", "SharePoint", "EXO"), which is not the domain the mapping files
	// declare, so the key is resolved through an alias table first.
	for domain, findings := range scubaResults.Results {
		domainMappings, exists := s.mappings[resolveDomain(domain)]
		if !exists {
			continue // Skip domains we don't have mappings for
		}

		// Flatten the groups into their control rows.
		var rows []ScubaFinding
		for _, g := range findings {
			rows = append(rows, g.findings()...)
		}

		// Process each finding in the domain
		for _, finding := range rows {
			// Find the corresponding rule mapping
			ruleID := finding.ruleID()
			rule, exists := domainMappings[ruleID]
			if !exists {
				continue
			}

			result := integrations.IntegrationResult{
				Source:          "scubagear",
				RuleID:          ruleID,
				Product:         rule.Product,
				Title:           rule.Title,
				Status:          s.convertStatus(finding),
				Severity:        rule.Severity,
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

// convertStatus maps a ScubaGear result onto an AuditKit status. Only PASS and
// FAIL are scoreable; a policy ScubaGear could not evaluate, or that the
// operator omitted, becomes MANUAL so it is reported without being counted as a
// failure.
func (s *ScubaGearIntegration) convertStatus(finding ScubaFinding) string {
	if !finding.scoreable() {
		if strings.EqualFold(strings.TrimSpace(finding.Result), "Error") {
			return "ERROR"
		}
		return "MANUAL"
	}
	if finding.passed() {
		return "PASS"
	}
	return "FAIL"
}

func (s *ScubaGearIntegration) formatEvidence(finding ScubaFinding, rule *EntraRule) string {
	var evidence strings.Builder

	evidence.WriteString(fmt.Sprintf("[%s] %s: ", s.convertStatus(finding), rule.Title))

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
