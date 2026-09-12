package azure

import (
	"context"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/azure/checks"
)

// A framework path must run the shared suite list exactly once. Each path used
// to construct some suites itself and then call runSuites, whose allSuites
// carries the same suites, so every row those suites produced appeared twice
// and every FAIL counted twice; the CIS path built its own eleven and never
// called runSuites, so the CIS Azure v6.0.0 suites never ran on a cis-azure
// scan.
//
// runSuites is cached per scan, so seeding the cache stands in for the suites
// having run. The paths' own extras run for real against nil clients, which
// the vulnerability collector reads as no data rather than dereferencing.
func TestFrameworkPathsRunTheSuitesOnce(t *testing.T) {
	suiteRows := []ScanResult{
		{Control: "CC6.1", Status: "FAIL", Evidence: "storage account allows public access"},
		{Control: "PCI-1.3.1", Status: "FAIL", Evidence: "NSG allows any inbound",
			Frameworks: map[string]string{"PCI-DSS": "1.3.1"}},
		{Control: "AC.L1-3.1.1", Status: "PASS", Evidence: "role assignments scoped",
			Frameworks: map[string]string{"CMMC": "AC.L1-3.1.1"}},
		{Control: "CIS-5.1.3", Status: "FAIL", Evidence: "MFA not enforced",
			Frameworks: map[string]string{"CIS-Azure": "5.1.3"}},
	}
	paths := []struct {
		name string
		run  func(*AzureScanner, context.Context, bool) []ScanResult
	}{
		{"soc2", (*AzureScanner).runSOC2Checks},
		{"pci", (*AzureScanner).runPCIChecks},
		{"cmmc", (*AzureScanner).runCMMCChecks},
		{"cis", (*AzureScanner).runCISChecks},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			// Spare capacity behind the cache, so a path that appended onto
			// the cached slice itself leaves its rows where the test can see.
			s := &AzureScanner{suiteCached: true}
			s.suiteCache = append(make([]ScanResult, 0, 2*len(suiteRows)), suiteRows...)

			got := p.run(s, context.Background(), false)

			for _, want := range suiteRows {
				if n := countRow(got, want); n != 1 {
					t.Errorf("suite row %s appears %d times, want once", want.Control, n)
				}
			}
			for i, r := range s.suiteCache[len(s.suiteCache):cap(s.suiteCache)] {
				if r.Control != "" || r.Status != "" {
					t.Errorf("wrote %s into the cache's spare capacity at %d; the next path would overwrite it", r.Control, i)
					break
				}
			}
			if p.name != "cmmc" {
				return
			}
			// The practice report runs after the suites, so a practice a suite
			// answered must not come back a second time as unanswered.
			n := 0
			for _, r := range got {
				if r.Control == "AC.L1-3.1.1" {
					n++
				}
			}
			if n != 1 {
				t.Errorf("AC.L1-3.1.1 reported %d times; a suite answered it, so the practice report must not", n)
			}
		})
	}
}

// Every suite a framework path needs is in allSuites, and each once. A suite
// missing from the list is the one thing that tempts a path to construct it
// itself, which is how the rows came to be doubled.
func TestAllSuitesCarriesEachSuiteOnce(t *testing.T) {
	seen := map[string]int{}
	for _, c := range (&AzureScanner{}).allSuites() {
		seen[c.Name()]++
	}
	for _, want := range []string{
		checks.NewAzurePCIChecks(nil, nil, nil, nil, nil, nil, nil, "").Name(),
		checks.NewAzureCMMCLevel1Checks(nil, nil, nil, nil, "").Name(),
	} {
		if seen[want] == 0 {
			t.Errorf("%q is not in allSuites", want)
		}
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("%q is constructed %d times in allSuites", name, n)
		}
	}
}

func rowKey(r ScanResult) string { return r.Control + "\x00" + r.Status + "\x00" + r.Evidence }

func countRow(rows []ScanResult, want ScanResult) int {
	n := 0
	for _, r := range rows {
		if rowKey(r) == rowKey(want) {
			n++
		}
	}
	return n
}
