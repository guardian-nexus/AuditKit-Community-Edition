package checks

import (
	"context"
	"strings"
	"testing"
)

// These recommendations were the last the scanner knew about and never
// mentioned - not as a finding, not as a manual item, not as a denominator.
func TestAKSCoverageAccountsForEveryRecommendation(t *testing.T) {
	rows, err := NewCISAKSReport(map[string]bool{}).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one summary row, got %d", len(rows))
	}
	row := rows[0]
	if row.Status != StatusManual {
		t.Errorf("a coverage statement is manual, got %q", row.Status)
	}
	// With nothing assessed the row must account for all 51: 30 the benchmark
	// marks Manual, 21 it marks Automated but which need node access.
	for _, want := range []string{"0 of 51", "30 are marked Manual", "21 are marked Automated"} {
		if !strings.Contains(row.Evidence, want) {
			t.Errorf("evidence missing %q:\n  %s", want, row.Evidence)
		}
	}
}

// Answering a recommendation must remove it from the gap rather than leaving
// it counted in both places.
func TestAKSCoverageShrinksAsRecommendationsAreAnswered(t *testing.T) {
	rows, _ := NewCISAKSReport(map[string]bool{"5.1.1": true, "5.4.1": true}).Run(context.Background())
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	if !strings.Contains(rows[0].Evidence, "2 of 51") {
		t.Errorf("expected the assessed count to rise to 2:\n  %s", rows[0].Evidence)
	}
}

// A fully answered benchmark has no gap to report, so the row disappears
// rather than claiming "51 of 51 assessed, 0 remaining".
func TestAKSCoverageSilentWhenNothingIsMissing(t *testing.T) {
	all := map[string]bool{}
	for id := range aksCatalogForTest(t) {
		all[id] = true
	}
	rows, _ := NewCISAKSReport(all).Run(context.Background())
	if len(rows) != 0 {
		t.Fatalf("expected no row when every recommendation is assessed, got %d", len(rows))
	}
}

func aksCatalogForTest(t *testing.T) map[string]string {
	t.Helper()
	c := aksCatalog()
	if c == nil {
		t.Fatal("the cis-aks catalog must resolve; it went a year unregistered in catalogFiles")
	}
	return c
}
