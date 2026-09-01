package report

import (
	"strings"
	"testing"
)

// The disclaimer block is built with Sprintf and its argument order was wrong:
// the errored-checks note and the assessor line rendered in each other's slots.
func TestDisclaimerArgumentOrder(t *testing.T) {
	res := ComplianceResult{
		Framework: "soc2",
		Controls: []ControlResult{
			{ID: "CC6.1", Status: "PASS"},
			{ID: "CC6.2", Status: "FAIL"},
			{ID: "CC6.3", Status: "INFO"},
			{ID: "CC6.4", Status: "ERROR"},
		},
	}
	html := GenerateHTML(res)

	if strings.Contains(html, "<li><li>") || strings.Contains(html, "<li></li>") {
		t.Errorf("malformed list item: the two %%s slots are swapped")
	}
	if !strings.Contains(html, "could not be evaluated") {
		t.Errorf("errored note missing despite an ERROR control")
	}
	if strings.Contains(html, "%!s(MISSING)") || strings.Contains(html, "%!(EXTRA") {
		t.Errorf("format verb/argument mismatch")
	}
}

// ERROR must stay out of the denominator; it means the check could not run.
func TestErroredExcludedFromScore(t *testing.T) {
	res := ComplianceResult{
		Framework: "soc2",
		Controls: []ControlResult{
			{ID: "A", Status: "PASS"},
			{ID: "B", Status: "ERROR"},
			{ID: "C", Status: "ERROR"},
		},
	}
	html := GenerateHTML(res)
	// 1 of 1 scoreable control passed, so the automated score is 100%.
	if !strings.Contains(html, "100") {
		t.Errorf("errored checks appear to be dragging the score down")
	}
}
