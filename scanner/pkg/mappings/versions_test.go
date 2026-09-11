package mappings

import (
	"strings"
	"testing"
	"time"
)

func TestADocumentAndAVerificationDateComeTogether(t *testing.T) {
	// One without the other is a contradiction: a document nobody dated, or a
	// date with nothing behind it. Either way the row cannot be trusted.
	for _, e := range Editions() {
		if (e.Document == "") != (e.Verified == "") {
			t.Errorf("%s: Document=%q Verified=%q - a row is either checked or it is not",
				e.Framework, e.Document, e.Verified)
		}
		if e.Verified != "" {
			if _, err := time.Parse("2006-01-02", e.Verified); err != nil {
				t.Errorf("%s: Verified %q is not YYYY-MM-DD", e.Framework, e.Verified)
			}
		}
	}
}

func TestEveryRowSaysSomethingUsable(t *testing.T) {
	for _, e := range Editions() {
		if e.Framework == "" || e.Name == "" {
			t.Errorf("row %+v has no framework or name", e)
		}
		// A row with no version must explain itself, or a reader is left to
		// guess whether it is unreconciled or simply unversioned.
		if e.Version == "" && e.Note == "" {
			t.Errorf("%s claims no version and gives no reason", e.Framework)
		}
		// An unverified row must say so; silence reads as assurance.
		if !e.Checked() && e.Note == "" {
			t.Errorf("%s was never checked against a document and does not say so", e.Framework)
		}
	}
}

// The CIS rows exist because all three benchmarks were restructured away from
// the identifiers we implement. Writing a version into them is exactly the
// mistake this registry is here to prevent, so it is pinned: the reconciliation
// has to happen first, and doing it means editing this test deliberately.
func TestTheCISRowsStayUnreconciledUntilTheWorkIsDone(t *testing.T) {
	for _, key := range []string{"CIS-AWS", "CIS-Azure", "CIS-GCP"} {
		e, ok := EditionFor(key)
		if !ok {
			t.Fatalf("%s has no row", key)
		}
		if e.Version != "" {
			t.Errorf("%s claims version %q - the identifiers were never reconciled against "+
				"the benchmark, so this is a claim the code cannot support", key, e.Version)
		}
		if !e.Checked() {
			t.Errorf("%s: the benchmark was read, so Document and Verified belong on the row", key)
		}
		if !strings.Contains(strings.ToLower(e.Note), "reconcil") {
			t.Errorf("%s: the note must say the identifiers are unreconciled, got %q", key, e.Note)
		}
	}
}

func TestDescribeNeverInventsAVersion(t *testing.T) {
	unreconciled, _ := EditionFor("CIS-AWS")
	got := unreconciled.Describe()
	if strings.Contains(got, "v7") || strings.Contains(got, "7.0.0") {
		t.Errorf("Describe must not print the benchmark version we have not reconciled to: %q", got)
	}
	if !strings.Contains(got, "not yet reconciled") {
		t.Errorf("Describe should say the edition is unsettled: %q", got)
	}

	known, _ := EditionFor("PCI-DSS")
	if known.Describe() != "Payment Card Industry Data Security Standard 4.0.1" {
		t.Errorf("a settled edition prints plainly, got %q", known.Describe())
	}
}

func TestProvenanceSeparatesCheckedFromAsserted(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)

	pci, _ := EditionFor("PCI-DSS")
	got := pci.Provenance(now)
	if !strings.Contains(got, "verified against") || !strings.Contains(got, "10 days ago") {
		t.Errorf("a checked row states the document and how long ago: %q", got)
	}

	soc2, _ := EditionFor("SOC2")
	if got := soc2.Provenance(now); !strings.Contains(got, "asserted, not verified") {
		t.Errorf("an unchecked row must not read like a verification: %q", got)
	}
	if soc2.AgeDays(now) != -1 {
		t.Errorf("never-verified has no age, got %d", soc2.AgeDays(now))
	}
}

func TestEditionsAreOrderedAndLookupWorks(t *testing.T) {
	all := Editions()
	if len(all) < 10 {
		t.Fatalf("expected the full framework set, got %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Framework > all[i].Framework {
			t.Errorf("not ordered at %d: %s then %s", i, all[i-1].Framework, all[i].Framework)
		}
	}
	if _, ok := EditionFor("NOT-A-FRAMEWORK"); ok {
		t.Error("unknown framework must not resolve")
	}
}

// Reading a standard and reconciling our identifiers against it are two claims.
// Collapsing them is how "we read v7.0.0" would become "we implement v7.0.0".
func TestProvenanceDoesNotClaimAReconciliationThatDidNotHappen(t *testing.T) {
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	e, _ := EditionFor("CIS-AWS")
	got := e.Provenance(now)
	if strings.Contains(got, "verified against") {
		t.Errorf("the document was read, not conformed to: %q", got)
	}
	for _, want := range []string{"read on", "not", "reconciled"} {
		if !strings.Contains(got, want) {
			t.Errorf("provenance should say the identifiers are unreconciled, missing %q: %q", want, got)
		}
	}
	if !strings.Contains(got, "1 day ago") {
		t.Errorf("one day is singular: %q", got)
	}
}

func TestGDPRReadsAsASentence(t *testing.T) {
	e, _ := EditionFor("GDPR")
	if got := e.Describe(); got != "General Data Protection Regulation (EU) 2016/679" {
		t.Errorf("got %q", got)
	}
}
