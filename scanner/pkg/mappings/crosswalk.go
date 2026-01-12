// Framework Crosswalk - Derives NIST 800-53 mappings from existing frameworks
// This allows 800-53 scanning without modifying individual check files

package mappings

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Crosswalk holds mappings between frameworks and NIST 800-53
type Crosswalk struct {
	SOC2ToCIS     map[string][]string `yaml:"soc2_to_800_53"`
	PCIToCIS      map[string][]string `yaml:"pci_to_800_53"`
	CMMCToCIS     map[string][]string `yaml:"cmmc_to_800_53"`
	HIPAAToCIS    map[string][]string `yaml:"hipaa_to_800_53"`
	ISO27001ToCIS map[string][]string `yaml:"iso27001_to_800_53"`
	GDPRToCIS     map[string][]string `yaml:"gdpr_to_800_53"`
	NISTCSFToCIS  map[string][]string `yaml:"nist_csf_to_800_53"`
}

// FedRAMPBaselines holds FedRAMP baseline control lists
type FedRAMPBaselines struct {
	Low      []string `yaml:"fedramp_low"`
	Moderate []string `yaml:"fedramp_moderate"`
	High     []string `yaml:"fedramp_high"`
}

var globalCrosswalk *Crosswalk
var globalFedRAMPBaselines *FedRAMPBaselines

// LoadCrosswalk loads the framework crosswalk from YAML
func LoadCrosswalk(filepath string) (*Crosswalk, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read crosswalk file: %w", err)
	}

	var crosswalk Crosswalk
	if err := yaml.Unmarshal(data, &crosswalk); err != nil {
		return nil, fmt.Errorf("failed to parse crosswalk YAML: %w", err)
	}

	globalCrosswalk = &crosswalk
	return &crosswalk, nil
}

// GetCrosswalk returns the global crosswalk (loads if not already loaded)
func GetCrosswalk() (*Crosswalk, error) {
	if globalCrosswalk != nil {
		return globalCrosswalk, nil
	}

	// Try to load from default location
	filepath := "pkg/mappings/framework-crosswalk.yaml"
	return LoadCrosswalk(filepath)
}

// Get800_53Controls returns NIST 800-53 control IDs for a given control across all frameworks
func (c *Crosswalk) Get800_53Controls(frameworks map[string]string) []string {
	if frameworks == nil {
		return nil
	}

	controlSet := make(map[string]bool)

	// Check SOC2 mappings
	if soc2ID, exists := frameworks["SOC2"]; exists {
		if controls, found := c.SOC2ToCIS[soc2ID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Check PCI mappings
	if pciID, exists := frameworks["PCI-DSS"]; exists {
		// PCI IDs might be comma-separated (e.g., "1.2.1, 1.3.4")
		pciIDs := strings.Split(pciID, ",")
		for _, id := range pciIDs {
			id = strings.TrimSpace(id)
			if controls, found := c.PCIToCIS[fmt.Sprintf("PCI-%s", id)]; found {
				for _, ctrl := range controls {
					controlSet[ctrl] = true
				}
			}
		}
	}

	// Check CMMC mappings
	if cmmcID, exists := frameworks["CMMC"]; exists {
		if controls, found := c.CMMCToCIS[cmmcID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Check HIPAA mappings
	if hipaaID, exists := frameworks["HIPAA"]; exists {
		if controls, found := c.HIPAAToCIS[hipaaID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Check ISO 27001 mappings
	if iso27001ID, exists := frameworks["ISO27001"]; exists {
		if controls, found := c.ISO27001ToCIS[iso27001ID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Check GDPR mappings
	if gdprID, exists := frameworks["GDPR"]; exists {
		if controls, found := c.GDPRToCIS[gdprID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Check NIST CSF mappings
	if csfID, exists := frameworks["NIST-CSF"]; exists {
		if controls, found := c.NISTCSFToCIS[csfID]; found {
			for _, ctrl := range controls {
				controlSet[ctrl] = true
			}
		}
	}

	// Convert set to slice
	var result []string
	for ctrl := range controlSet {
		result = append(result, ctrl)
	}

	return result
}

// Get800_53ByControlID looks up 800-53 mappings directly by control ID (e.g., "CC3.2", "PCI-1.2.1")
// This is a fallback for controls that don't have Frameworks map populated
func (c *Crosswalk) Get800_53ByControlID(controlID string) []string {
	// Try SOC2 mapping first (most common: CC1.1, CC6.2, etc.)
	if controls, found := c.SOC2ToCIS[controlID]; found {
		return controls
	}
	
	// Try PCI mapping (e.g., "PCI-1.2.1" or "1.2.1")
	if strings.HasPrefix(controlID, "PCI-") {
		if controls, found := c.PCIToCIS[controlID]; found {
			return controls
		}
	} else {
		// Try adding PCI- prefix
		if controls, found := c.PCIToCIS[fmt.Sprintf("PCI-%s", controlID)]; found {
			return controls
		}
	}
	
	// Try CMMC mapping
	if controls, found := c.CMMCToCIS[controlID]; found {
		return controls
	}
	
	// Try HIPAA mapping
	if controls, found := c.HIPAAToCIS[controlID]; found {
		return controls
	}

	// Try ISO 27001 mapping (e.g., "A.8.1", "A.8.24")
	if controls, found := c.ISO27001ToCIS[controlID]; found {
		return controls
	}

	// Try GDPR mapping (e.g., "Art32-1a", "Art5-1f")
	if controls, found := c.GDPRToCIS[controlID]; found {
		return controls
	}

	// Try NIST CSF mapping (e.g., "PR.AC-1", "DE.CM-1")
	if controls, found := c.NISTCSFToCIS[controlID]; found {
		return controls
	}

	return nil
}

// Get800_53StringByControlID returns comma-separated 800-53 IDs by control ID
func (c *Crosswalk) Get800_53StringByControlID(controlID string) string {
	controls := c.Get800_53ByControlID(controlID)
	if len(controls) == 0 {
		return ""
	}
	return strings.Join(controls, ", ")
}

// ControlHas800_53 checks if a control maps to any 800-53 controls
// First tries using the Frameworks map, then falls back to control ID lookup
func (c *Crosswalk) ControlHas800_53(frameworks map[string]string, controlID string) bool {
	// Try using Frameworks map first (if populated)
	if len(c.Get800_53Controls(frameworks)) > 0 {
		return true
	}
	
	// Fallback: try direct control ID lookup
	if len(c.Get800_53ByControlID(controlID)) > 0 {
		return true
	}
	
	return false
}

// Get800_53String returns comma-separated 800-53 control IDs
// First tries using the Frameworks map, then falls back to control ID lookup
func (c *Crosswalk) Get800_53String(frameworks map[string]string, controlID string) string {
	// Try using Frameworks map first (if populated)
	controls := c.Get800_53Controls(frameworks)
	if len(controls) > 0 {
		return strings.Join(controls, ", ")
	}

	// Fallback: try direct control ID lookup
	return c.Get800_53StringByControlID(controlID)
}

// LoadFedRAMPBaselines loads FedRAMP baseline definitions from YAML
func LoadFedRAMPBaselines(filepath string) (*FedRAMPBaselines, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read FedRAMP baselines file: %w", err)
	}

	var baselines FedRAMPBaselines
	if err := yaml.Unmarshal(data, &baselines); err != nil {
		return nil, fmt.Errorf("failed to parse FedRAMP baselines YAML: %w", err)
	}

	globalFedRAMPBaselines = &baselines
	return &baselines, nil
}

// GetFedRAMPBaselines returns the global FedRAMP baselines (loads if not already loaded)
func GetFedRAMPBaselines() (*FedRAMPBaselines, error) {
	if globalFedRAMPBaselines != nil {
		return globalFedRAMPBaselines, nil
	}

	// Try to load from default location
	filepath := "pkg/mappings/fedramp-baselines.yaml"
	return LoadFedRAMPBaselines(filepath)
}

// IsInFedRAMPBaseline checks if an 800-53 control is in the specified FedRAMP baseline
func (f *FedRAMPBaselines) IsInFedRAMPBaseline(control800_53 string, baseline string) bool {
	var baselineControls []string

	switch strings.ToLower(baseline) {
	case "low", "fedramp-low":
		baselineControls = f.Low
	case "moderate", "fedramp-moderate":
		baselineControls = f.Moderate
	case "high", "fedramp-high":
		baselineControls = f.High
	default:
		return false
	}

	// Normalize control ID (e.g., "AC-2" or "AC-2(1)")
	control800_53 = strings.TrimSpace(control800_53)

	for _, ctrl := range baselineControls {
		if ctrl == control800_53 {
			return true
		}
	}

	return false
}

// GetBaselineControls returns all controls for a given FedRAMP baseline
func (f *FedRAMPBaselines) GetBaselineControls(baseline string) []string {
	switch strings.ToLower(baseline) {
	case "low", "fedramp-low":
		return f.Low
	case "moderate", "fedramp-moderate":
		return f.Moderate
	case "high", "fedramp-high":
		return f.High
	default:
		return nil
	}
}
