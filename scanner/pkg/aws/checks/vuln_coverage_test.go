package checks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/awsinspector"
)

type stubInspector struct {
	enabled   bool
	resources []inspectortypes.CoveredResource
	findings  []inspectortypes.Finding
	err       error
}

func (s stubInspector) BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput, ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	st := inspectortypes.StatusDisabled
	on := inspectortypes.StatusDisabled
	if s.enabled {
		st, on = inspectortypes.StatusEnabled, inspectortypes.StatusEnabled
	}
	id := "111122223333"
	return &inspector2.BatchGetAccountStatusOutput{
		Accounts: []inspectortypes.AccountState{{
			AccountId: &id,
			State:     &inspectortypes.State{Status: st},
			ResourceState: &inspectortypes.ResourceState{
				Ec2:    &inspectortypes.State{Status: on},
				Ecr:    &inspectortypes.State{Status: on},
				Lambda: &inspectortypes.State{Status: on},
			},
		}},
	}, nil
}

func (s stubInspector) ListCoverage(context.Context, *inspector2.ListCoverageInput, ...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &inspector2.ListCoverageOutput{CoveredResources: s.resources}, nil
}

func (s stubInspector) ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &inspector2.ListFindingsOutput{Findings: s.findings}, nil
}

type stubEC2 struct{ ids []string }

func (s stubEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	var out []ec2types.Instance
	for i := range s.ids {
		id := s.ids[i]
		out = append(out, ec2types.Instance{InstanceId: &id,
			State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}})
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: out}}}, nil
}

func coveredResource(id string, reason inspectortypes.ScanStatusReason, scanned *time.Time) inspectortypes.CoveredResource {
	return inspectortypes.CoveredResource{
		ResourceId: &id, ResourceType: inspectortypes.CoverageResourceTypeAwsEc2Instance,
		LastScannedAt: scanned, ScanStatus: &inspectortypes.ScanStatus{Reason: reason},
	}
}

func runAWS(t *testing.T, c awsinspector.Clients, emit Emit) []CheckResult {
	t.Helper()
	res, err := NewVulnCoverageChecks(c, "111122223333", emit).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	return res
}

// The two passes must not report each other's control, or a scan of every
// framework counts the same control twice in the score.
func TestAWSEmitSelectsDisjointControls(t *testing.T) {
	now := time.Now()
	c := awsinspector.Clients{
		Inspector: stubInspector{enabled: true, resources: []inspectortypes.CoveredResource{
			coveredResource("i-1", "SUCCESSFUL", &now)}},
		EC2: stubEC2{ids: []string{"i-1"}},
	}
	cmmc, pci := map[string]bool{}, map[string]bool{}
	for _, r := range runAWS(t, c, EmitCMMC) {
		cmmc[r.Control] = true
	}
	for _, r := range runAWS(t, c, EmitPCI) {
		pci[r.Control] = true
	}
	if !cmmc["RA.L2-3.11.2"] || !cmmc["RA.L2-3.11.3"] {
		t.Errorf("the CMMC pass answers both risk-assessment practices, got %v", cmmc)
	}
	if !pci["PCI-11.3.1"] {
		t.Errorf("the PCI pass answers PCI-11.3.1, got %v", pci)
	}
	for ctrl := range cmmc {
		if pci[ctrl] {
			t.Errorf("%s is reported by both passes and would be double-counted", ctrl)
		}
	}
}

func TestAWSEveryResultIsUsable(t *testing.T) {
	c := awsinspector.Clients{Inspector: stubInspector{enabled: true}, EC2: stubEC2{ids: []string{"i-1"}}}
	for _, emit := range []Emit{EmitCMMC, EmitPCI} {
		for _, r := range runAWS(t, c, emit) {
			if r.Control == "" || r.Name == "" || len(r.Frameworks) == 0 {
				t.Errorf("a result needs an id, a name and a framework tag: %+v", r)
			}
			if !ValidStatus(r.Status) {
				t.Errorf("%s has an unrecognised status %q", r.Control, r.Status)
			}
			if r.Status == StatusFail && (r.Remediation == "" || r.ConsoleURL == "") {
				t.Errorf("%s fails without telling the reader what to do", r.Control)
			}
		}
	}
}

func TestAWSUncoveredInstanceFailsBothControls(t *testing.T) {
	c := awsinspector.Clients{
		Inspector: stubInspector{enabled: true}, // Inspector on, no coverage records
		EC2:       stubEC2{ids: []string{"i-orphan"}},
	}
	for _, emit := range []Emit{EmitCMMC, EmitPCI} {
		for _, r := range runAWS(t, c, emit) {
			if r.Control == "RA.L2-3.11.3" {
				continue // remediation, not coverage
			}
			if r.Status != StatusFail {
				t.Errorf("%s should fail with an uncovered instance, got %s: %s",
					r.Control, r.Status, r.Evidence)
			}
		}
	}
}

func TestAWSScannerOffFailsRatherThanErrors(t *testing.T) {
	c := awsinspector.Clients{Inspector: stubInspector{enabled: false}, EC2: stubEC2{ids: []string{"i-1"}}}
	for _, r := range runAWS(t, c, EmitCMMC) {
		if r.Status != StatusFail {
			t.Errorf("%s: Inspector being off is a failure, not an error, got %s", r.Control, r.Status)
		}
	}
}

// A read that did not complete must never produce a pass.
func TestAWSCollectionFailureIsAnError(t *testing.T) {
	c := awsinspector.Clients{Inspector: stubInspector{err: errors.New("AccessDeniedException")}}
	for _, emit := range []Emit{EmitCMMC, EmitPCI} {
		for _, r := range runAWS(t, c, emit) {
			if r.Status != StatusError {
				t.Errorf("%s should be ERROR when the read failed, got %s", r.Control, r.Status)
			}
		}
	}
}

// RA.L2-3.11.3 must be absent rather than passing when findings were not
// fetched, which is what the PCI pass does.
func TestAWSRemediationOnlyReportedWhenFindingsWereCollected(t *testing.T) {
	now := time.Now()
	c := awsinspector.Clients{
		Inspector: stubInspector{enabled: true, resources: []inspectortypes.CoveredResource{
			coveredResource("i-1", "SUCCESSFUL", &now)}},
		EC2: stubEC2{ids: []string{"i-1"}},
	}
	for _, r := range runAWS(t, c, EmitPCI) {
		if r.Control == "RA.L2-3.11.3" {
			t.Error("the PCI pass does not fetch findings, so it must not report remediation")
		}
	}
}
