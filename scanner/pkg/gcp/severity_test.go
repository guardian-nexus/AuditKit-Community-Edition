package gcp

import (
	"context"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/gcp/checks"
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
