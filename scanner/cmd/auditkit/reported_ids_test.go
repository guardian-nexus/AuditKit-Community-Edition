package main

import (
	"reflect"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
)

// The CIS catalogs are keyed by bare recommendation number, and only the
// check's framework tag carries that shape once the CIS branch has rewritten
// the control id to CIS-<PROVIDER>-<n>. The Azure checks tag with "CIS-Azure",
// so an exact lookup of the upper-cased framework name matched "CIS-AWS" and
// "CIS-GCP" by coincidence and re-listed every assessed Azure recommendation
// as an unassessed fill: 162 rows for a 127-entry catalog.
func TestReportedControlIDsReadsFrameworkTagCaseInsensitively(t *testing.T) {
	got := reportedControlIDs("cis-azure", []ControlResult{
		{ID: "CIS-AZURE-5.1.1", Frameworks: map[string]string{"CIS-Azure": "5.1.1", "SOC2": "CC6.1"}},
		{ID: "CIS-AZURE-9.3.2.2", Frameworks: map[string]string{"CIS-Azure": "9.3.2.2, 9.3.8"}},
	})
	want := []string{"CIS-AZURE-5.1.1", "5.1.1", "CIS-AZURE-9.3.2.2", "9.3.2.2", "9.3.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reportedControlIDs = %v, want %v", got, want)
	}
}

func TestAssessedCISRecommendationsAreNotFilledAsUnassessed(t *testing.T) {
	cases := []struct {
		framework string
		control   ControlResult
		answered  []string
		stillOpen string
	}{
		{
			framework: "cis-azure",
			control:   ControlResult{ID: "CIS-AZURE-5.1.1", Frameworks: map[string]string{"CIS-Azure": "5.1.1", "SOC2": "CC6.1"}},
			answered:  []string{"5.1.1"},
			stillOpen: "7.1",
		},
		{
			framework: "cis-azure",
			control:   ControlResult{ID: "CIS-AZURE-9.3.2.2, CIS-AZURE-9.3.8", Frameworks: map[string]string{"CIS-Azure": "9.3.2.2, 9.3.8"}},
			answered:  []string{"9.3.2.2", "9.3.8"},
			stillOpen: "5.1.1",
		},
		{
			framework: "cis-aws",
			control:   ControlResult{ID: "CIS-AWS-5.16", Frameworks: map[string]string{"CIS-AWS": "5.16"}},
			answered:  []string{"5.16"},
			stillOpen: "2.1.1",
		},
		{
			framework: "cis-gcp",
			control:   ControlResult{ID: "CIS-GCP-1.13", Frameworks: map[string]string{"CIS-GCP": "1.13"}},
			answered:  []string{"1.13"},
			stillOpen: "4.2",
		},
	}

	for _, tc := range cases {
		missing := mappings.MissingControls(tc.framework, reportedControlIDs(tc.framework, []ControlResult{tc.control}))
		if missing == nil {
			t.Fatalf("%s: no catalog registered", tc.framework)
		}
		for _, id := range tc.answered {
			if _, filled := missing[id]; filled {
				t.Errorf("%s: %s is assessed by %q but is still filled as unassessed", tc.framework, id, tc.control.ID)
			}
		}
		if _, open := missing[tc.stillOpen]; !open {
			t.Errorf("%s: %s was not assessed but is no longer filled", tc.framework, tc.stillOpen)
		}
	}
}

// A recommendation number from another CIS benchmark must not answer the
// requested one: the numbers overlap, and an AKS tag says nothing about the
// Azure foundations catalog.
func TestOtherBenchmarkTagDoesNotAnswerRequestedCatalog(t *testing.T) {
	missing := mappings.MissingControls("cis-azure", reportedControlIDs("cis-azure", []ControlResult{
		{ID: "CIS-AKS-5.1.1", Frameworks: map[string]string{"CIS-AKS": "5.1.1"}},
	}))
	if _, open := missing["5.1.1"]; !open {
		t.Errorf("CIS-Azure 5.1.1 was marked assessed by a CIS-AKS tag")
	}
}
