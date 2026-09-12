package mappings

import "testing"

// Every framework -framework accepts must resolve to a catalog, or the scan
// silently omits whatever it did not assess instead of reporting it.
func TestEveryAcceptedFrameworkResolvesToACatalog(t *testing.T) {
	accepted := []string{"soc2", "pci", "pci-dss", "cmmc", "hipaa", "iso27001",
		"nist-csf", "csf", "800-53", "nist800-53", "fedramp-low",
		"fedramp-moderate", "fedramp-high", "gdpr",
		"cis-aws", "cis-azure", "cis-gcp", "cis-aks", "cis-gke"}
	for _, framework := range accepted {
		c := CatalogFor(framework)
		if c == nil {
			t.Errorf("%s resolves to no catalog", framework)
			continue
		}
		if len(c) == 0 {
			t.Errorf("%s resolves to an empty catalog", framework)
		}
		t.Logf("%-18s %4d entries", framework, len(c))
	}
}
