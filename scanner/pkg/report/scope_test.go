package report

import (
	"strings"
	"testing"
)

// A GDPR or FedRAMP report must say its catalog is a subset and that it is
// not legal advice; a SOC2 report, whose catalog is complete, must not.
func TestScopeNoteOnlyForPartialCatalogs(t *testing.T) {
	got := scopeNote("gdpr")
	if !strings.Contains(got, "not legal advice") || !strings.Contains(got, "GDPR") {
		t.Fatalf("gdpr scope note is missing: %q", got)
	}
	if scopeNote("soc2") != "" {
		t.Fatal("soc2's catalog is complete; no scope note")
	}
}
