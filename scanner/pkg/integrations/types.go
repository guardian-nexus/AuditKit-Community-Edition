package integrations

import (
	"context"
	"time"
)

// Integration interface for external compliance tools
type Integration interface {
	Name() string
	ParseFile(ctx context.Context, filePath string) ([]IntegrationResult, error)
	SupportedFrameworks() []string
}

// IntegrationResult represents a compliance finding from an external tool
type IntegrationResult struct {
	Source          string            `json:"source"`           // "scubagear", "prowler", etc.
	RuleID          string            `json:"rule_id"`          // External tool's rule ID
	Product         string            `json:"product"`          // M365 service (AAD, SharePoint, etc.)
	Title           string            `json:"title"`            // Human readable control name
	Status          string            `json:"status"`           // PASS, FAIL, INFO, MANUAL
	Evidence        string            `json:"evidence"`         // What was found/checked
	Remediation     string            `json:"remediation"`      // How to fix
	ScreenshotGuide string            `json:"screenshot_guide"` // Evidence collection guidance
	ConsoleURL      string            `json:"console_url"`      // Direct link to fix location
	Frameworks      map[string]string `json:"frameworks"`       // SOC2: "CC6.1", PCI: "8.2.3", etc.
	Timestamp       time.Time         `json:"timestamp"`
}

// MappingFile represents contributor's framework mappings
type MappingFile struct {
	Version     string                 `json:"version"`
	Domain      string                 `json:"domain"` // "aad", "sharepoint", etc.
	LastUpdated time.Time              `json:"last_updated"`
	Rules       map[string]MappingRule `json:"rules"` // Rule ID -> mapping info
}

// MappingRule maps external tool rules to compliance frameworks
type MappingRule struct {
	Product         string            `json:"product"`          // "Azure AD", "SharePoint", etc.
	Title           string            `json:"title"`            // Control description
	Mappings        map[string]string `json:"mappings"`         // Framework -> Control ID
	RemediationHint string            `json:"remediation_hint"` // Generic fix guidance
	ScreenshotHint  string            `json:"screenshot_hint"`  // Evidence guidance
	ConsoleURL      string            `json:"console_url"`      // Direct link to setting
}
