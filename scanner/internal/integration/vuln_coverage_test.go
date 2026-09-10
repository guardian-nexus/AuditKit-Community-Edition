package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	awschecks "github.com/guardian-nexus/auditkit/scanner/pkg/aws/checks"
	gcpchecks "github.com/guardian-nexus/auditkit/scanner/pkg/gcp/checks"
	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/awsinspector"
	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/gcposconfig"
	osconfig "google.golang.org/api/osconfig/v1"
)

func run(t *testing.T, c awsinspector.Clients, emit awschecks.Emit) []awschecks.CheckResult {
	t.Helper()
	res, err := awschecks.NewVulnCoverageChecks(c, "111122223333", emit).Run(context.Background())
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return res
}

func byControl(res []awschecks.CheckResult) map[string]awschecks.CheckResult {
	out := map[string]awschecks.CheckResult{}
	for _, r := range res {
		out[r.Control] = r
	}
	return out
}

// Coverage gap detection is the free tier's whole job: telling a contractor
// that nothing is scanning half the estate is what creates the urgency, and
// removing it to build a moat would be worse than having no moat.
func TestCommunityFindsTheCoverageGap(t *testing.T) {
	now := time.Now()
	clients := awsinspector.Clients{
		Inspector: &fakeInspector{coverage: []inspectortypes.CoveredResource{
			covered("i-scanned", "AWS_EC2_INSTANCE", "ACTIVE", "SUCCESSFUL", now.Add(-2*time.Hour)),
		}},
		EC2:    fakeEC2{ids: []string{"i-scanned", "i-unknown"}},
		Lambda: fakeLambda{},
		ECR:    fakeECR{},
	}
	got := byControl(run(t, clients, awschecks.EmitCMMC))

	if got["RA.L2-3.11.2"].Status != "FAIL" {
		t.Errorf("an unscanned in-scope instance must FAIL, got %s (%s)",
			got["RA.L2-3.11.2"].Status, got["RA.L2-3.11.2"].Evidence)
	}
	// Evidence is the summary line; the actionable list of which assets are
	// uncovered belongs in RemediationDetail. "Community finds the gaps" means
	// naming them, so this is the assertion that the pitch is true.
	if !strings.Contains(got["RA.L2-3.11.2"].RemediationDetail, "i-unknown") {
		t.Errorf("the free tier must name the gap it found:\nevidence: %q\ndetail: %q",
			got["RA.L2-3.11.2"].Evidence, got["RA.L2-3.11.2"].RemediationDetail)
	}
	if !strings.Contains(got["RA.L2-3.11.2"].Evidence, "1 of 2") {
		t.Errorf("and must state the count: %q", got["RA.L2-3.11.2"].Evidence)
	}
	if got["PCI-11.3.1"].Control != "" {
		t.Error("the CMMC pass must not also emit the PCI control")
	}
	if pci := byControl(run(t, clients, awschecks.EmitPCI)); pci["PCI-11.3.1"].Status != "FAIL" {
		t.Errorf("PCI 11.3.1 reads the same coverage, got %s", pci["PCI-11.3.1"].Status)
	}
}

// The runtime half of the edition split. check-edition-split.py reads the
// source for these; this runs the adapter and looks at the output, because a
// capability that leaks back in through a different code path would satisfy the
// source check and still give the paid feature away.
func TestCommunityDoesNotEmitThePaidControlOrAgeAnything(t *testing.T) {
	now := time.Now()
	insp := &fakeInspector{
		coverage: []inspectortypes.CoveredResource{
			covered("i-scanned", "AWS_EC2_INSTANCE", "ACTIVE", "SUCCESSFUL", now.Add(-2*time.Hour)),
		},
		// Long overdue against any window. If ageing ever reaches this edition,
		// something here will report it.
		findings: []inspectortypes.Finding{
			awsFinding("CVE-2024-3094", "i-scanned", "CRITICAL", now.AddDate(0, 0, -400)),
		},
	}
	clients := awsinspector.Clients{
		Inspector: insp,
		EC2:       fakeEC2{ids: []string{"i-scanned"}},
		Lambda:    fakeLambda{},
		ECR:       fakeECR{},
	}

	for _, emit := range []awschecks.Emit{awschecks.EmitCMMC, awschecks.EmitPCI} {
		res := run(t, clients, emit)
		for _, r := range res {
			if r.Control == "RA.L2-3.11.3" {
				t.Errorf("RA.L2-3.11.3 is a paid control and must not be emitted here: %+v", r)
			}
			// Remediation ageing language must not appear in free evidence.
			for _, word := range []string{"overdue", "remediation window", "past the"} {
				if strings.Contains(strings.ToLower(r.Evidence), word) {
					t.Errorf("%s evidence reads like remediation ageing: %q", r.Control, r.Evidence)
				}
			}
		}
	}
	// Not fetching the findings is also what keeps the free tier's scan cheap.
	if insp.findCalls != 0 {
		t.Errorf("this edition must not walk Inspector findings; called %d times", insp.findCalls)
	}
}

// A denied call is ERROR, never PASS. Asserting compliance from a call that
// never returned is how two earlier GCP defects shipped, and the test pinning
// it belongs in both editions.
func TestCommunityDeniedCallIsNeverAPass(t *testing.T) {
	clients := awsinspector.Clients{
		Inspector: &fakeInspector{covErr: errors.New("AccessDeniedException: not authorized")},
		EC2:       fakeEC2{ids: []string{"i-a"}},
		Lambda:    fakeLambda{},
		ECR:       fakeECR{},
	}
	for _, emit := range []awschecks.Emit{awschecks.EmitCMMC, awschecks.EmitPCI} {
		for _, r := range run(t, clients, emit) {
			if r.Status != "ERROR" {
				t.Errorf("%s must be ERROR when coverage could not be read, got %s (%s)",
					r.Control, r.Status, r.Evidence)
			}
		}
	}
}

// Inspector switched off must not read as a clean account.
func TestCommunityScannerOffIsNotClean(t *testing.T) {
	clients := awsinspector.Clients{
		Inspector: &fakeInspector{status: inspectortypes.StatusDisabled},
		EC2:       fakeEC2{ids: []string{"i-a", "i-b"}},
		Lambda:    fakeLambda{},
		ECR:       fakeECR{},
	}
	for _, emit := range []awschecks.Emit{awschecks.EmitCMMC, awschecks.EmitPCI} {
		for _, r := range run(t, clients, emit) {
			if r.Status == "PASS" {
				t.Errorf("%s must not PASS with the scanner off: %s", r.Control, r.Evidence)
			}
		}
	}
}

// VM Manager switched off is the finding this feature exists to report, so it
// must FAIL and be counted. The score is passed/(passed+failed), so an ERROR
// lands in neither half and the control disappears - which let a GCP project
// with no vulnerability scanning at all score better than an AWS account in
// the identical state.
func TestGCPServiceDisabledIsScoredNotSkipped(t *testing.T) {
	for _, tc := range []struct {
		name, err, want string
	}{
		{"api not enabled",
			"googleapi: Error 403: OS Config API has not been used in project proj-1", "FAIL"},
		{"permission denied, which proves nothing",
			"googleapi: Error 403: Permission denied on resource project proj-1", "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clients := gcposconfig.Clients{Reports: fakeReports{err: errors.New(tc.err)}}
			res, err := gcpchecks.NewVulnCoverageChecksWithClients(clients, "proj-1", gcpchecks.EmitCMMC).
				Run(context.Background())
			if err != nil {
				t.Fatalf("gcp adapter: %v", err)
			}
			if len(res) != 1 {
				t.Fatalf("want one control, got %+v", res)
			}
			if res[0].Status != tc.want {
				t.Errorf("want %s, got %s (%s)", tc.want, res[0].Status, res[0].Evidence)
			}
			scoreable := res[0].Status == "PASS" || res[0].Status == "FAIL"
			if tc.want == "FAIL" && !scoreable {
				t.Error("a FAIL is scoreable; an ERROR would drop out of the denominator")
			}
			if tc.want == "ERROR" && scoreable {
				t.Error("an ERROR must not be scored - nothing was measured")
			}
		})
	}
}

type fakeReports struct{ err error }

func (f fakeReports) List(_ context.Context, _ string, _ string) (*osconfig.ListVulnerabilityReportsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &osconfig.ListVulnerabilityReportsResponse{}, nil
}
