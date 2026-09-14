package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/integrations"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
)

// Every report labelled with a framework carries the framework's whole
// catalog: what the scan reached, and a MANUAL row for everything it did not.
func TestCompleteFrameworkFillsTheCatalog(t *testing.T) {
	got := completeFramework([]ControlResult{{ID: "AC.L1-3.1.1", Status: "FAIL",
		Frameworks: map[string]string{"CMMC": "AC.L1-3.1.1"}}}, "cmmc")
	if want := len(mappings.CatalogFor("cmmc")); len(got) != want {
		t.Fatalf("cmmc: %d rows, want the %d-practice catalog", len(got), want)
	}
	n := 0
	for _, c := range got {
		if c.ID == "AC.L1-3.1.1" {
			n++
			if c.Status != "FAIL" {
				t.Fatalf("the assessed practice must keep its verdict, got %s", c.Status)
			}
		}
	}
	if n != 1 {
		t.Fatalf("AC.L1-3.1.1 appears %d times; an assessed practice must not also be filled", n)
	}
}

// 800-53 and the FedRAMP baselines summarise the uncovered set in one row, and
// its arithmetic is the catalog's. Counting rows put INFO and ERROR rows, and
// every row of a control reported more than once, into the assessed figure
// and pushed the total past the catalog: "129 of 1189" against 1,196.
func TestCompleteFrameworkSummarisesTheLargeCatalogsExactly(t *testing.T) {
	controls := []ControlResult{
		{ID: "AC-2", Status: "PASS"},
		{ID: "AC-2", Status: "INFO"},
		{ID: "AC-3", Status: "ERROR"},
	}
	got := completeFramework(controls, "800-53")
	if len(got) != 4 {
		t.Fatalf("expected the 3 rows plus one summary row, got %d", len(got))
	}
	last := got[3]
	if last.ID != "800-53-UNCOVERED" || last.Status != "MANUAL" {
		t.Fatalf("summary row missing: %+v", last)
	}
	want := fmt.Sprintf("2 of %d controls were assessed", len(mappings.CatalogFor("800-53")))
	if !strings.Contains(last.Evidence, want) {
		t.Fatalf("evidence %q must say %q", last.Evidence, want)
	}
}

func TestCompleteFrameworkLeavesAnAllScanAlone(t *testing.T) {
	if got := completeFramework([]ControlResult{{ID: "CC6.1", Status: "PASS"}}, "all"); len(got) != 1 {
		t.Fatalf("an all-framework scan has no single catalog to fill, got %d rows", len(got))
	}
}

// An imported ScubaGear or Prowler run is labelled with a framework too, and
// its denominator was the handful of findings the mapping file knew.
func TestImportedRunReportsTheWholeFramework(t *testing.T) {
	got := convertIntegrationResults([]integrations.IntegrationResult{
		{RuleID: "MS.AAD.1.1", Title: "Legacy authentication blocked", Status: "FAIL", Severity: "HIGH",
			Frameworks: map[string]string{"SOC2": "CC6.1"}},
	}, "M365", "soc2")
	if want := len(mappings.CatalogFor("soc2")); got.TotalControls != want {
		t.Fatalf("import: total %d, want the %d-criterion catalog", got.TotalControls, want)
	}
}

// isPracticeID decides whether a CMMC report may file a tagged row under
// the practice; a tag that names a level ("L2") or a SOC2 id names nothing.
func TestIsPracticeIDAndPracticeIDs(t *testing.T) {
	for _, ok := range []string{"AC.L1-3.1.1", "SC.L2-3.13.11", "RA.L2-3.11.2"} {
		if !isPracticeID(ok) {
			t.Errorf("%s is a practice id", ok)
		}
	}
	for _, bad := range []string{"CC6.1", "L2", "CIS-AWS-2.10", "AC.L3-3.1.1", "AC.L1-4.1.1", ""} {
		if isPracticeID(bad) {
			t.Errorf("%s is not a practice id", bad)
		}
	}
	got := practiceIDs("IR.L2-3.6.1, L2, CC9.1, SI.L2-3.14.6")
	if len(got) != 2 || got[0] != "IR.L2-3.6.1" || got[1] != "SI.L2-3.14.6" {
		t.Fatalf("practiceIDs kept %v", got)
	}
}

// A SOC2 row re-filed under IR.L2-3.6.1 arrived beside the practice's own
// row, so a CMMC report carried three rows for one practice.
func TestCompleteFrameworkKeepsOneRowPerPractice(t *testing.T) {
	in := []ControlResult{
		{ID: "IR.L2-3.6.1", Name: "Incident handling", Status: "PASS", Evidence: "plan present"},
		{ID: "IR.L2-3.6.1", Name: "Risk assessment cadence (via CC9.1, CMMC)", Status: "FAIL", Evidence: "no cadence"},
		{ID: "CC6.1", Status: "PASS"},
	}
	got := completeFramework(in, "cmmc")
	n := 0
	for _, c := range got {
		if c.ID == "IR.L2-3.6.1" {
			n++
			if c.Status != "FAIL" || !strings.Contains(c.Evidence, "no cadence") || !strings.Contains(c.Evidence, "plan present") {
				t.Fatalf("the surviving row must carry the FAIL and both evidences: %+v", c)
			}
		}
	}
	if n != 1 {
		t.Fatalf("IR.L2-3.6.1 appears %d times", n)
	}
}
