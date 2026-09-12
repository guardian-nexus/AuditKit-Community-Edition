package mappings

import "testing"

// The line drawn here is deliberate, so it is pinned: a framework an assessor
// works through lists every control it could not evaluate, because that list
// is their worklist. 800-53 does not, because 1,045 rows bury the findings.
func TestSummariseUncoveredCoversTheLargeCatalogsOnly(t *testing.T) {
	for _, framework := range []string{"800-53", "nist800-53", "nist-800-53",
		"fedramp-low", "fedramp-moderate", "fedramp-high"} {
		if !ShouldSummariseUncovered(framework) {
			t.Errorf("%s should report its uncovered set as a count", framework)
		}
	}
	// PCI's 235 and CMMC's manual practices are the assessor's worklist.
	for _, framework := range []string{"pci", "pci-dss", "cmmc", "hipaa",
		"iso27001", "soc2", "nist-csf"} {
		if ShouldSummariseUncovered(framework) {
			t.Errorf("%s should list its uncovered controls individually", framework)
		}
	}
}

func TestShouldSummariseUncoveredResolvesAliases(t *testing.T) {
	if !ShouldSummariseUncovered("  NIST800-53  ") {
		t.Fatal("must resolve case and surrounding space, as CatalogFor does")
	}
	if ShouldSummariseUncovered("") {
		t.Fatal("an empty framework summarises nothing")
	}
}

// If a name in SummariseUncovered stopped resolving to a catalog the rule
// would silently stop applying, so the two are checked against each other.
func TestEverySummarisedFrameworkHasACatalog(t *testing.T) {
	for framework := range SummariseUncovered {
		if CatalogFor(framework) == nil {
			t.Errorf("%s is marked for summarising but resolves to no catalog", framework)
		}
	}
}
