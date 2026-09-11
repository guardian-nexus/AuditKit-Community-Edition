package checks

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
)

// A CMMC report must carry all 110 requirements of NIST SP 800-171 Rev 2.
// The count came from the catalog rather than being trusted as a constant,
// because the constant is the thing most likely to drift.
func TestPracticeTableMatchesTheCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../mappings/catalogs/cmmc.json")
	if err != nil {
		t.Skipf("no catalog to compare against: %v", err)
	}
	var catalog map[string]string
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("catalog is not readable: %v", err)
	}
	want := map[string]bool{}
	for id := range catalog {
		if !strings.HasPrefix(id, "_") {
			want[id] = true
		}
	}
	if len(want) != mappings.CMMCPracticeCount {
		t.Errorf("catalog holds %d practices, CMMCPracticeCount says %d",
			len(want), mappings.CMMCPracticeCount)
	}
	got := map[string]bool{}
	for _, p := range mappings.CMMCPractices() {
		if got[p.ID] {
			t.Errorf("%s appears twice in the practice table", p.ID)
		}
		got[p.ID] = true
		if p.Name == "" || p.Evidence == "" || p.Remedy == "" {
			t.Errorf("%s has an empty field; a practice reported with no guidance is noise", p.ID)
		}
	}
	for id := range want {
		if !got[id] {
			t.Errorf("%s is in the catalog but not the practice table", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("%s is in the practice table but not the catalog", id)
		}
	}
}

// The whole point of computing the covered set from real results: a practice
// an automated check already answered must not also be reported as an
// unanswered question.
func TestCoveredPracticesAreNotReportedAgain(t *testing.T) {
	all, err := NewCMMCPracticeReport(nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != mappings.CMMCPracticeCount {
		t.Fatalf("with nothing covered the report holds %d practices, want %d",
			len(all), mappings.CMMCPracticeCount)
	}

	covered := map[string]bool{"AC.L1-3.1.1": true, "SI.L1-3.14.2": true}
	some, err := NewCMMCPracticeReport(covered).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(some) != mappings.CMMCPracticeCount-len(covered) {
		t.Errorf("with %d covered the report holds %d, want %d",
			len(covered), len(some), mappings.CMMCPracticeCount-len(covered))
	}
	for _, r := range some {
		if covered[r.Control] {
			t.Errorf("%s was already answered by a real check and must not be asked again", r.Control)
		}
	}
}

// These rows are questions, not verdicts. Scoring them would let an estate
// improve its compliance score by having more unanswered requirements.
func TestReportedPracticesAreNeverScored(t *testing.T) {
	rows, err := NewCMMCPracticeReport(nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Status != StatusManual {
			t.Errorf("%s reported %s; only MANUAL is honest for a practice nothing measured", r.Control, r.Status)
		}
		if r.Frameworks["CMMC"] != r.Control {
			t.Errorf("%s carries CMMC tag %q; without the tag the framework filter drops it",
				r.Control, r.Frameworks["CMMC"])
		}
		if r.Evidence == "" || r.ScreenshotGuide == "" {
			t.Errorf("%s gives the reader nothing to collect", r.Control)
		}
	}
}
