package azure

import (
	"context"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/azure/checks"
)

// The suites fill either Severity or Priority.Level; the framework paths
// that used to run a suite directly read the other field, and a blank
// here drops a HIGH finding to LOW at the report layer.
func TestSeverityOfFallsBackToTheOtherField(t *testing.T) {
	if got := severityOf(checks.CheckResult{Severity: "HIGH"}); got != "HIGH" {
		t.Fatalf("Severity set: got %q", got)
	}
	if got := severityOf(checks.CheckResult{Priority: checks.Priority{Level: "MEDIUM"}}); got != "MEDIUM" {
		t.Fatalf("Priority.Level set: got %q", got)
	}
	if got := severityOf(checks.CheckResult{}); got != "" {
		t.Fatalf("neither set: got %q", got)
	}
}

// runSuites hands each caller its own rows. The cache is built by append and
// has spare capacity, so two framework paths appending onto the same backing
// array overwrote each other's rows.
func TestRunSuitesHandsEachCallerItsOwnRows(t *testing.T) {
	s := &AzureScanner{}
	s.suiteCache = append(make([]ScanResult, 0, 8), ScanResult{Control: "CC6.1", Status: "PASS", Evidence: "seed"})
	s.suiteCached = true
	a := append(s.runSuites(context.Background(), false), ScanResult{Control: "A-1"})
	b := append(s.runSuites(context.Background(), false), ScanResult{Control: "B-1"})
	if a[1].Control != "A-1" || b[1].Control != "B-1" {
		t.Fatalf("callers clobbered each other: %v / %v", a[1].Control, b[1].Control)
	}
	if len(s.suiteCache) != 1 {
		t.Fatalf("the cache itself grew to %d", len(s.suiteCache))
	}
}
