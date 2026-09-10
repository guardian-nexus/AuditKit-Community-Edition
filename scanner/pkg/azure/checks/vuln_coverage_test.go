package checks

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/azuredefender"
)

const testSub = "00000000-1111-2222-3333-444444444444"

type stubPricing struct {
	standard map[string]bool
	err      error
}

func (s stubPricing) Get(_ context.Context, _ string, name string, _ *armsecurity.PricingsClientGetOptions) (armsecurity.PricingsClientGetResponse, error) {
	if s.err != nil {
		return armsecurity.PricingsClientGetResponse{}, s.err
	}
	tier := armsecurity.PricingTierFree
	if s.standard[name] {
		tier = armsecurity.PricingTierStandard
	}
	cs := armsecurity.ResourcesCoverageStatusFullyCovered
	return armsecurity.PricingsClientGetResponse{Pricing: armsecurity.Pricing{
		Properties: &armsecurity.PricingProperties{PricingTier: &tier, ResourcesCoverageStatus: &cs},
	}}, nil
}

func stubPager[T any](page T) *runtime.Pager[T] {
	return runtime.NewPager(runtime.PagingHandler[T]{
		More:    func(T) bool { return false },
		Fetcher: func(context.Context, *T) (T, error) { return page, nil },
	})
}

type stubVMs struct{ ids []string }

func (s stubVMs) NewListAllPager(*armcompute.VirtualMachinesClientListAllOptions) *runtime.Pager[armcompute.VirtualMachinesClientListAllResponse] {
	var vms []*armcompute.VirtualMachine
	for i := range s.ids {
		id := s.ids[i]
		vms = append(vms, &armcompute.VirtualMachine{ID: &id})
	}
	return stubPager(armcompute.VirtualMachinesClientListAllResponse{
		VirtualMachineListResult: armcompute.VirtualMachineListResult{Value: vms},
	})
}

type stubSubAssess struct{}

func (stubSubAssess) NewListAllPager(string, *armsecurity.SubAssessmentsClientListAllOptions) *runtime.Pager[armsecurity.SubAssessmentsClientListAllResponse] {
	return stubPager(armsecurity.SubAssessmentsClientListAllResponse{})
}

func runAzure(t *testing.T, c azuredefender.Clients, emit Emit) []CheckResult {
	t.Helper()
	res, err := NewVulnCoverageChecks(c, testSub, emit).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	return res
}

func TestAzureEmitSelectsDisjointControls(t *testing.T) {
	c := azuredefender.Clients{
		Pricing:        stubPricing{standard: map[string]bool{"VirtualMachines": true}},
		SubAssessments: stubSubAssess{},
		VMs:            stubVMs{ids: []string{"/vm/1"}},
	}
	cmmc, pci := map[string]bool{}, map[string]bool{}
	for _, r := range runAzure(t, c, EmitCMMC) {
		cmmc[r.Control] = true
	}
	for _, r := range runAzure(t, c, EmitPCI) {
		pci[r.Control] = true
	}
	if !cmmc["RA.L2-3.11.2"] {
		t.Errorf("the CMMC pass answers RA.L2-3.11.2, got %v", cmmc)
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

func TestAzureEveryResultIsUsable(t *testing.T) {
	c := azuredefender.Clients{
		Pricing: stubPricing{standard: map[string]bool{"VirtualMachines": true}},
		VMs:     stubVMs{ids: []string{"/vm/1"}},
	}
	for _, emit := range []Emit{EmitCMMC, EmitPCI} {
		for _, r := range runAzure(t, c, emit) {
			if r.Control == "" || r.Name == "" || len(r.Frameworks) == 0 {
				t.Errorf("a result needs an id, a name and a framework tag: %+v", r)
			}
			if !ValidStatus(r.Status) {
				t.Errorf("%s has an unrecognised status %q", r.Control, r.Status)
			}
		}
	}
}

// Defender gives no scan timestamps, so the cadence is unproven. That must not
// demote a proven coverage result to INFO and drop it out of the score.
func TestAzureUnknownCadenceStillPassesTheScanningPractice(t *testing.T) {
	c := azuredefender.Clients{
		Pricing: stubPricing{standard: map[string]bool{"VirtualMachines": true}},
		VMs:     stubVMs{ids: []string{"/vm/1"}},
	}
	var scanning CheckResult
	for _, r := range runAzure(t, c, EmitCMMC) {
		if r.Control == "RA.L2-3.11.2" {
			scanning = r
		}
	}
	if scanning.Status != StatusPass {
		t.Fatalf("full coverage with an unproven cadence still satisfies RA.L2-3.11.2; got %s: %s",
			scanning.Status, scanning.Evidence)
	}
	// but the caveat must be visible
	if scanning.Evidence == "" {
		t.Error("the freshness caveat should reach the evidence")
	}
}

// PCI-DSS 11.3.1 names a quarterly cadence, so an unproven cadence cannot pass
// there even though it can for RA.L2-3.11.2.
func TestAzureUnknownCadenceDoesNotPassPCI(t *testing.T) {
	c := azuredefender.Clients{
		Pricing: stubPricing{standard: map[string]bool{"VirtualMachines": true}},
		VMs:     stubVMs{ids: []string{"/vm/1"}},
	}
	for _, r := range runAzure(t, c, EmitPCI) {
		if r.Status == StatusPass {
			t.Fatalf("11.3.1 requires a demonstrable cadence; got PASS: %s", r.Evidence)
		}
		if r.Status != StatusInfo {
			t.Fatalf("an unproven cadence is INFO, not a failure; got %s", r.Status)
		}
	}
}

func TestAzureDefenderOffFails(t *testing.T) {
	c := azuredefender.Clients{Pricing: stubPricing{}, VMs: stubVMs{ids: []string{"/vm/1"}}}
	for _, r := range runAzure(t, c, EmitCMMC) {
		if r.Status != StatusFail {
			t.Errorf("%s: Defender being off is a failure, got %s", r.Control, r.Status)
		}
	}
}

func TestAzureCollectionFailureIsAnError(t *testing.T) {
	c := azuredefender.Clients{Pricing: stubPricing{err: errors.New("AuthorizationFailed")}}
	for _, emit := range []Emit{EmitCMMC, EmitPCI} {
		for _, r := range runAzure(t, c, emit) {
			if r.Status != StatusError {
				t.Errorf("%s should be ERROR when the read failed, got %s", r.Control, r.Status)
			}
		}
	}
}
