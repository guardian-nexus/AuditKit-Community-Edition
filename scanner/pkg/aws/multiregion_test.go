package aws

import (
	"strings"
	"testing"
)

func row(control, status, evidence string) ScanResult {
	return ScanResult{Control: control, Name: "n-" + control, Status: status, Evidence: evidence, Severity: "HIGH"}
}

func TestMergeRegionsKeepsUniformRowsAndMergesTheRest(t *testing.T) {
	per := map[string][]ScanResult{
		"us-east-1":  {row("IAM-1", "PASS", "all users have MFA"), row("GD-1", "PASS", "GuardDuty enabled"), row("CT-1", "INFO", "no trails to evaluate")},
		"eu-west-1":  {row("GD-1", "FAIL", "GuardDuty NOT enabled"), row("CT-1", "PASS", "1 trail logging")},
		"ap-south-1": {row("GD-1", "PASS", "GuardDuty enabled"), row("CT-1", "ERROR", "Could not run this check: AccessDenied")},
	}
	out := mergeRegions(per, []string{"us-east-1", "eu-west-1", "ap-south-1"})
	byControl := map[string]ScanResult{}
	for _, r := range out {
		byControl[r.Control] = r
	}
	if len(out) != 3 {
		t.Fatalf("want 3 merged rows, got %d: %+v", len(out), out)
	}
	// Global suite row: present in one region only, kept as it is.
	if r := byControl["IAM-1"]; r.Status != "PASS" || r.Evidence != "all users have MFA" {
		t.Errorf("global row changed: %+v", r)
	}
	// A failure in any region is the control's verdict, and the evidence says where.
	if r := byControl["GD-1"]; r.Status != "FAIL" || !strings.HasPrefix(r.Evidence, "FAIL in eu-west-1: GuardDuty NOT enabled") || !strings.Contains(r.Evidence, "PASS in us-east-1, ap-south-1") {
		t.Errorf("regional failure not merged correctly: %+v", r)
	}
	// A region that could not be read beats a pass.
	if r := byControl["CT-1"]; r.Status != "ERROR" || !strings.HasPrefix(r.Evidence, "ERROR in ap-south-1") {
		t.Errorf("unreadable region did not win over a pass: %+v", r)
	}
}

func TestMergeRegionsLeavesPerResourceRowsSeparate(t *testing.T) {
	per := map[string][]ScanResult{
		"us-east-1": {row("SNS-1", "FAIL", "topic a unencrypted"), row("SNS-1", "FAIL", "topic b unencrypted")},
		"eu-west-1": {row("SNS-1", "PASS", "all topics encrypted")},
	}
	out := mergeRegions(per, []string{"us-east-1", "eu-west-1"})
	if len(out) != 3 {
		t.Fatalf("per-resource rows must not be folded: got %d", len(out))
	}
	for _, r := range out {
		if !strings.HasPrefix(r.Evidence, "us-east-1: ") && !strings.HasPrefix(r.Evidence, "eu-west-1: ") {
			t.Errorf("row lost its region: %q", r.Evidence)
		}
	}
}
