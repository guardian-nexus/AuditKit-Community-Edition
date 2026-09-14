package main

import (
	"strings"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/tracker"
)

func TestEvidenceTrackerHTMLSeeding(t *testing.T) {
	controls := []tracker.ControlResult{
		{Control: "CC6.1", Status: "FAIL"},
		{Control: "CC6.6", Status: "PASS"},
	}
	seed := `{"CC6.1":{"collected":true,"notes":"IAM screenshot"}}`

	html := generateEvidenceTrackerHTML(controls, "123456789012", seed)

	if strings.Contains(html, "%!s(MISSING)") || strings.Contains(html, "%!(EXTRA") {
		t.Fatalf("format verb/argument mismatch in the template")
	}
	if !strings.Contains(html, "const SEEDED = "+seed) {
		t.Errorf("seed was not injected")
	}
	if !strings.Contains(html, "applySeeded()") {
		t.Errorf("applySeeded is never called")
	}
	if !strings.Contains(html, "auditkit_evidence_123456789012") {
		t.Errorf("storage key lost the account id")
	}
	if !strings.Contains(html, `data-control="CC6.1"`) {
		t.Errorf("controls were not rendered")
	}
}
