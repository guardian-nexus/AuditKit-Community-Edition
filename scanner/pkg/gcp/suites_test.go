package gcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/gcp/checks"
)

// Every suite is listed once. The framework paths used to construct some of
// them a second time and then call runSuites as well, so a CMMC or CIS scan
// ran those suites twice and reported every row twice; the aggregate PCI
// checker was the other way round, constructed by the PCI path and listed
// nowhere. Both ends of that are pinned here: the list is the only place a
// suite is constructed, and no suite is in it twice.
func TestAllSuitesListsEachSuiteOnce(t *testing.T) {
	s := &GCPScanner{projectID: "test-project"}
	seen := map[string]int{}
	for _, c := range s.allSuites() {
		seen[fmt.Sprintf("%T", c)]++
	}
	for typ, n := range seen {
		if n > 1 {
			t.Errorf("%s is in allSuites %d times", typ, n)
		}
	}
	for _, want := range []string{
		fmt.Sprintf("%T", &checks.GCPPCIChecks{}),
		fmt.Sprintf("%T", &checks.GCPCMMCLevel1Checks{}),
	} {
		if seen[want] == 0 {
			t.Errorf("%s is not in allSuites; a framework path must not construct it itself", want)
		}
	}
}

// The paths append their own rows to what runSuites returns. The cache is
// built by append and so has spare capacity, and appending onto the cached
// slice itself would write into the backing array the next path's rows start
// from - so each caller has to get its own copy.
func TestRunSuitesHandsEachCallerItsOwnRows(t *testing.T) {
	cache := make([]ScanResult, 0, 8)
	cache = append(cache, ScanResult{Control: "CC6.1", Status: "PASS"})
	s := &GCPScanner{suiteCache: cache, suiteCached: true}
	ctx := context.Background()

	first := append(s.runSuites(ctx, false, "PCI-DSS"), ScanResult{Control: "PCI-11.3.1"})
	second := append(s.runSuites(ctx, false, "CMMC"), ScanResult{Control: "RA.L2-3.11.2"})

	if got := first[len(first)-1].Control; got != "PCI-11.3.1" {
		t.Errorf("the first path's extra row became %q after the second path appended its own", got)
	}
	if got := second[len(second)-1].Control; got != "RA.L2-3.11.2" {
		t.Errorf("the second path's extra row is %q", got)
	}
	if len(s.suiteCache) != 1 || s.suiteCache[0].Control != "CC6.1" {
		t.Errorf("the cache changed under the callers: %+v", s.suiteCache)
	}
}
