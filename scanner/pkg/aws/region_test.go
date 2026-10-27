package aws

import (
	"strings"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/aws/checks"
)

// A PASS saying GuardDuty or Security Hub is enabled was true of the one region
// the scan read, and read as account-wide.
func TestNoteRegionNamesTheScannedRegion(t *testing.T) {
	pass := checks.CheckResult{Status: checks.StatusPass, Evidence: "GuardDuty is enabled (Detector: abc)"}
	if got := noteRegion(pass, "eu-west-2"); !strings.Contains(got, "eu-west-2") {
		t.Fatalf("regional PASS evidence does not name the region: %q", got)
	}
	for _, cr := range []checks.CheckResult{
		{Status: checks.StatusFail, Evidence: "GuardDuty is not enabled"},
		{Status: checks.StatusPass, Evidence: "IAM Access Analyzer is active in region us-east-1"},
		{Status: checks.StatusPass, Evidence: "All IAM users have MFA"},
	} {
		if got := noteRegion(cr, "eu-west-2"); got != cr.Evidence {
			t.Errorf("evidence changed when it should not be: %q -> %q", cr.Evidence, got)
		}
	}
}

func TestScannerReportsItsRegion(t *testing.T) {
	if got := deniedScanner(t).Region(); got != "us-east-1" {
		t.Fatalf("Region() = %q", got)
	}
}
