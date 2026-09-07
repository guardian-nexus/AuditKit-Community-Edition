package mappings

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Framework control catalogs. Every supported framework ships its full control
// list so a scan can report on every control, marking as MANUAL the ones with no
// automated signal. Before this existed a framework silently omitted anything it
// could not check, so the denominator - and therefore the score - was wrong.
//
// Sources:
//
//	nist800-53, fedramp-*  NIST OSCAL SP 800-53 Rev5 catalog and baselines
//	nist-csf               NIST Cybersecurity Framework 2.0 core
//	hipaa                  45 CFR Part 164 Subpart C (eCFR)
//	cmmc                   NIST SP 800-171 Rev2, the 110 CMMC Level 2 practices
//	soc2                   AICPA Trust Services Criteria
//	iso27001               ISO/IEC 27001:2022 Annex A identifiers
//	pci-dss                partial - see PartialCatalogs
//
//go:embed catalogs/*.json
var catalogFS embed.FS

// PartialCatalogs names frameworks whose shipped catalog is known to be smaller
// than the published standard, so callers can say so rather than imply coverage.
var PartialCatalogs = map[string]string{
	"fedramp-low":      "derived from the NIST 800-53 Rev5 Low baseline; FedRAMP-specific additions are not included",
	"fedramp-moderate": "derived from the NIST 800-53 Rev5 Moderate baseline; FedRAMP-specific additions are not included",
	"fedramp-high":     "derived from the NIST 800-53 Rev5 High baseline; FedRAMP-specific additions are not included",
}

var catalogFiles = map[string]string{
	"soc2":             "soc2",
	"pci":              "pci-dss",
	"pci-dss":          "pci-dss",
	"cmmc":             "cmmc",
	"hipaa":            "hipaa",
	"800-53":           "nist800-53",
	"nist800-53":       "nist800-53",
	"nist-800-53":      "nist800-53",
	"nist-csf":         "nist-csf",
	"csf":              "nist-csf",
	"iso27001":         "iso27001",
	"iso-27001":        "iso27001",
	"fedramp-low":      "fedramp-low",
	"fedramp-moderate": "fedramp-moderate",
	"fedramp-high":     "fedramp-high",
}

// CatalogFor returns the full control catalog for a framework, keyed by control
// ID. It returns nil when the framework has no catalog (for example "cis", whose
// benchmarks are provider-specific and already fully enumerated by the checks).
var (
	catalogMu    sync.Mutex
	catalogCache = map[string]map[string]string{}
)

// CatalogFor is called once per unmatched scan result, so the parsed catalog is
// cached; re-reading and re-unmarshalling the 1196-entry 800-53 file on every
// call dominated a large scan.
func CatalogFor(framework string) map[string]string {
	name, ok := catalogFiles[strings.ToLower(strings.TrimSpace(framework))]
	if !ok {
		return nil
	}

	catalogMu.Lock()
	defer catalogMu.Unlock()
	if cached, hit := catalogCache[name]; hit {
		return cached
	}

	data, err := catalogFS.ReadFile(fmt.Sprintf("catalogs/%s.json", name))
	if err != nil {
		return nil
	}

	catalog := make(map[string]string)
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil
	}

	catalogCache[name] = catalog

	return catalog
}

var nistControl = regexp.MustCompile(`^([A-Z]{2}-\d+(?:\(\d+\))?)`)

// NormalizeControlID maps a scan result's control ID onto the catalog's key
// space. CMMC results are labelled "AC.L2-3.1.3" while the catalog is keyed by
// the underlying 800-171 requirement "3.1.3", and 800-53 results may carry
// trailing text.
func NormalizeControlID(framework, id string) string {
	id = strings.TrimSpace(strings.Trim(id, "[]"))

	switch strings.ToLower(framework) {
	case "cmmc":
		// The catalog is keyed by practice id, so results and catalog share one
		// identifier and a filled-in control reads the same as a checked one.
		return id
	case "800-53", "nist800-53", "nist-800-53", "fedramp-low", "fedramp-moderate", "fedramp-high":
		if m := nistControl.FindStringSubmatch(id); m != nil {
			return m[1]
		}
	}

	return id
}

// MissingControls returns the catalog entries a scan did not report on, so the
// caller can emit them as MANUAL and keep the framework's denominator complete.
func MissingControls(framework string, reported []string) map[string]string {
	catalog := CatalogFor(framework)
	if catalog == nil {
		return nil
	}

	seen := make(map[string]bool, len(reported))
	for _, id := range reported {
		seen[NormalizeControlID(framework, id)] = true
	}

	missing := make(map[string]string)
	for id, title := range catalog {
		if seen[id] {
			continue
		}
		// Every catalog entry the scan did not report is listed. HIPAA
		// implementation specifications are each separately Required or
		// Addressable, so reporting only the parent standard would hide them.
		missing[id] = title
	}

	return missing
}

// PartialCatalogNote returns the caveat for a framework whose shipped catalog is
// smaller than the published standard, resolving the same aliases CatalogFor
// accepts ("pci" and "pci-dss" name one catalog).
func PartialCatalogNote(framework string) (string, bool) {
	name, ok := catalogFiles[strings.ToLower(strings.TrimSpace(framework))]
	if !ok {
		return "", false
	}
	note, partial := PartialCatalogs[name]
	return note, partial
}
