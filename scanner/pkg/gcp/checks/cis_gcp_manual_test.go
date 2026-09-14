package checks

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// A CIS GCP report must carry all 93 recommendations of Foundation v5.0.0.
// The automated checks reach most of them; this asserts the union does, and
// that the catalog is the thing being compared against rather than a constant.
func TestEveryV5RecommendationIsReachable(t *testing.T) {
	raw, err := os.ReadFile("../../mappings/catalogs/cis-gcp.json")
	if err != nil {
		t.Skipf("no catalog to compare against: %v", err)
	}
	var doc struct {
		Recommendations map[string]string `json:"recommendations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("catalog is not readable: %v", err)
	}

	// Everything the source claims, by any of the routes a claim travels.
	claimed := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			continue
		}
		for _, id := range cisGCPLiterals(string(src)) {
			claimed[id] = true
		}
	}
	var missing []string
	for id := range doc.Recommendations {
		if !claimed[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d of %d recommendation(s) are claimed by nothing: %v",
			len(missing), len(doc.Recommendations), missing)
	}
}

// The fill-in must not repeat a recommendation an automated check answered:
// two rows for one recommendation is the report disagreeing with itself.
func TestManualReportSkipsWhatWasMeasured(t *testing.T) {
	all, err := NewCISGCPManualReport(nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("with nothing covered the report is empty")
	}
	covered := map[string]bool{}
	for _, r := range all[:2] {
		covered[strings.TrimPrefix(r.Control, "CIS-GCP-")] = true
	}
	some, err := NewCISGCPManualReport(covered).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(some) != len(all)-2 {
		t.Errorf("with 2 covered the report holds %d, want %d", len(some), len(all)-2)
	}
	for _, r := range some {
		if covered[strings.TrimPrefix(r.Control, "CIS-GCP-")] {
			t.Errorf("%s was measured by a real check and must not be asked again", r.Control)
		}
	}
}

// These rows are questions, not verdicts. Scoring them would let a project
// improve its score by having more unexamined recommendations.
func TestManualRowsAreNeverScored(t *testing.T) {
	rows, err := NewCISGCPManualReport(nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Status != "MANUAL" {
			t.Errorf("%s reported %s; only MANUAL is honest for something nothing measured", r.Control, r.Status)
		}
		if !strings.HasPrefix(r.Control, "CIS-GCP-") {
			t.Errorf("%s does not carry the provider prefix, so the tooling cannot see it", r.Control)
		}
		if r.Frameworks["CIS-GCP"] == "" || r.Evidence == "" || r.Remediation == "" {
			t.Errorf("%s gives the reader nothing to act on", r.Control)
		}
		if seen[r.Control] {
			t.Errorf("%s appears twice in the table", r.Control)
		}
		seen[r.Control] = true
	}
}

// cisGCPLiterals finds the Foundation identifiers a source file claims. Both
// spellings are read: "CIS-GCP-6.2.1" as a control id, and the bare number in
// a "CIS-GCP" framework tag.
var (
	cisGCPControl = regexp.MustCompile(`"CIS-GCP-([0-9][0-9.]*)"`)
	cisGCPTag     = regexp.MustCompile(`"CIS-GCP":\s*"([^"]+)"`)
	cisGCPTable   = regexp.MustCompile(`FrameworkCIS\w*:\s*"([^"]+)"`)
)

func cisGCPLiterals(src string) []string {
	var out []string
	for _, m := range cisGCPControl.FindAllStringSubmatch(src, -1) {
		out = append(out, m[1])
	}
	for _, re := range []*regexp.Regexp{cisGCPTag, cisGCPTable} {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			for _, part := range splitList(m[1]) {
				out = append(out, part)
			}
		}
	}
	return out
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
