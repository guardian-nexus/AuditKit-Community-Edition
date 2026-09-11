package gcp

import "testing"

// The framework paths share one suite list, so a scan that runs several of them
// receives the same finding once per path. Deduping keys on control, status and
// evidence rather than the control alone, because several resources failing one
// criterion are distinct findings that legitimately share an id.
func TestDedupeKeepsDistinctFindingsSharingAControl(t *testing.T) {
	in := []ScanResult{
		{Control: "CIS-GCP-4.9", Status: "FAIL", Evidence: "instance-a has a public IP"},
		{Control: "CIS-GCP-4.9", Status: "FAIL", Evidence: "instance-a has a public IP"},
		{Control: "CIS-GCP-4.9", Status: "FAIL", Evidence: "instance-b has a public IP"},
		{Control: "CIS-GCP-4.9", Status: "PASS", Evidence: "instance-c has no public IP"},
	}
	out := dedupeIdenticalResults(in)
	if len(out) != 3 {
		t.Fatalf("got %d results, want 3: the exact repeat should go and the rest stay", len(out))
	}
	for _, want := range []string{"instance-a has a public IP", "instance-b has a public IP",
		"instance-c has no public IP"} {
		found := false
		for _, r := range out {
			if r.Evidence == want {
				found = true
			}
		}
		if !found {
			t.Errorf("dedupe dropped a distinct finding: %q", want)
		}
	}
}

func TestDedupeHandlesEmptyInput(t *testing.T) {
	if got := dedupeIdenticalResults(nil); len(got) != 0 {
		t.Errorf("got %d results from no input", len(got))
	}
}
