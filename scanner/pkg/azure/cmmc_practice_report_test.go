package azure

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/guardian-nexus/auditkit/scanner/pkg/mappings"
)

// The hook, not the table. A CMMC scan must end up with all 110 practices
// reported exactly once, whatever the automated suites happened to produce.
//
// This is what the CLI has always promised - "all 110 practices reported" -
// and what the scanner did not do: it reported only the practices its own
// checks named, so a reader could not tell an absent practice from a
// satisfied one.
func TestEveryCMMCPracticeIsReportedExactlyOnce(t *testing.T) {
	s := &AzureScanner{}
	cases := []struct {
		name     string
		reported []ScanResult
	}{
		{"nothing automated", nil},
		{
			name: "practices named in the Control field",
			reported: []ScanResult{
				{Control: "AC.L1-3.1.1", Status: "PASS"},
				{Control: "IA.L1-3.5.2", Status: "FAIL"},
			},
		},
		{
			name: "practices named only in a framework tag",
			reported: []ScanResult{
				{Control: "CC6.1", Status: "PASS", Frameworks: map[string]string{"CMMC": "SC.L1-3.13.1"}},
			},
		},
		{
			name: "a tag naming several practices",
			reported: []ScanResult{
				{Control: "CC6.6", Status: "PASS",
					Frameworks: map[string]string{"CMMC": "AC.L2-3.1.12, AC.L2-3.1.5"}},
			},
		},
		{
			name: "the same practice reported by two suites",
			reported: []ScanResult{
				{Control: "SI.L1-3.14.2", Status: "PASS"},
				{Control: "SI.L1-3.14.2", Status: "FAIL"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			all := append(append([]ScanResult{}, tc.reported...),
				s.reportRemainingCMMCPractices(context.Background(), tc.reported)...)

			seen := map[string]int{}
			for _, r := range all {
				if isCMMCPractice(r.Control) {
					seen[r.Control]++
				}
				for _, id := range splitCMMCTag(r.Frameworks["CMMC"]) {
					if id != r.Control {
						seen[id]++
					}
				}
			}
			for _, p := range mappings.CMMCPractices() {
				switch n := seen[p.ID]; {
				case n == 0:
					t.Errorf("%s is not reported at all", p.ID)
				case n > 1 && !alreadyDuplicated(tc.reported, p.ID):
					t.Errorf("%s is reported %d times; the practice report duplicated a real check", p.ID, n)
				}
			}
			if len(seen) != mappings.CMMCPracticeCount {
				t.Errorf("%d distinct practices reported, want %d", len(seen), mappings.CMMCPracticeCount)
			}
		})
	}
}

var cmmcPracticeID = regexp.MustCompile(`^[A-Z]{2}\.L[12]-3\.\d+\.\d+$`)

func isCMMCPractice(s string) bool { return cmmcPracticeID.MatchString(s) }

func splitCMMCTag(tag string) []string {
	var out []string
	for _, part := range strings.Split(tag, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// A practice the automated suites themselves report twice is a pre-existing
// duplicate, not one this report introduced, and is not what this test is for.
func alreadyDuplicated(reported []ScanResult, id string) bool {
	n := 0
	for _, r := range reported {
		if r.Control == id {
			n++
		}
	}
	return n > 1
}
