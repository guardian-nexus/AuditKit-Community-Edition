package azuredefender

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

const sub = "00000000-1111-2222-3333-444444444444"

// ---- fakes -----------------------------------------------------------------

type fakePricing struct {
	tiers    map[string]armsecurity.PricingTier
	coverage map[string]armsecurity.ResourcesCoverageStatus
	err      map[string]error
}

func (f fakePricing) Get(_ context.Context, _ string, name string, _ *armsecurity.PricingsClientGetOptions) (armsecurity.PricingsClientGetResponse, error) {
	if e, ok := f.err[name]; ok {
		return armsecurity.PricingsClientGetResponse{}, e
	}
	tier, ok := f.tiers[name]
	if !ok {
		tier = armsecurity.PricingTierFree
	}
	props := &armsecurity.PricingProperties{PricingTier: &tier}
	if cs, ok := f.coverage[name]; ok {
		props.ResourcesCoverageStatus = &cs
	}
	return armsecurity.PricingsClientGetResponse{
		Pricing: armsecurity.Pricing{Properties: props},
	}, nil
}

// onePage builds a pager that yields exactly one page, which is all these
// tests need and keeps the fakes honest about the real interface.
func onePage[T any](page T) *runtime.Pager[T] {
	served := false
	return runtime.NewPager(runtime.PagingHandler[T]{
		More: func(T) bool { return false },
		Fetcher: func(context.Context, *T) (T, error) {
			served = true
			_ = served
			return page, nil
		},
	})
}

func errPager[T any](err error) *runtime.Pager[T] {
	return runtime.NewPager(runtime.PagingHandler[T]{
		More:    func(T) bool { return false },
		Fetcher: func(context.Context, *T) (T, error) { var z T; return z, err },
	})
}

type fakeVMs struct {
	vms []*armcompute.VirtualMachine
	err error
}

func (f fakeVMs) NewListAllPager(*armcompute.VirtualMachinesClientListAllOptions) *runtime.Pager[armcompute.VirtualMachinesClientListAllResponse] {
	if f.err != nil {
		return errPager[armcompute.VirtualMachinesClientListAllResponse](f.err)
	}
	return onePage(armcompute.VirtualMachinesClientListAllResponse{
		VirtualMachineListResult: armcompute.VirtualMachineListResult{Value: f.vms},
	})
}

type fakeSubAssess struct {
	items []*armsecurity.SubAssessment
	err   error
}

func (f fakeSubAssess) NewListAllPager(string, *armsecurity.SubAssessmentsClientListAllOptions) *runtime.Pager[armsecurity.SubAssessmentsClientListAllResponse] {
	if f.err != nil {
		return errPager[armsecurity.SubAssessmentsClientListAllResponse](f.err)
	}
	return onePage(armsecurity.SubAssessmentsClientListAllResponse{
		SubAssessmentList: armsecurity.SubAssessmentList{Value: f.items},
	})
}

// ---- helpers ---------------------------------------------------------------

func vm(id string, labels map[string]string) *armcompute.VirtualMachine {
	m := &armcompute.VirtualMachine{ID: &id}
	if labels != nil {
		m.Tags = map[string]*string{}
		for k, v := range labels {
			val := v
			m.Tags[k] = &val
		}
	}
	return m
}

func serverFinding(cve string, sev armsecurity.Severity, patchable bool, resourceID string) *armsecurity.SubAssessment {
	code := armsecurity.SubAssessmentStatusCodeUnhealthy
	title := cve
	name := "sub-" + cve
	return &armsecurity.SubAssessment{
		Name: &name,
		Properties: &armsecurity.SubAssessmentProperties{
			DisplayName: &title,
			Status:      &armsecurity.SubAssessmentStatus{Code: &code, Severity: &sev},
			ResourceDetails: &armsecurity.AzureResourceDetails{
				Source: to(armsecurity.SourceAzure), ID: &resourceID,
			},
			AdditionalData: &armsecurity.ServerVulnerabilityProperties{
				Cve:       []*armsecurity.CVE{{Title: &title}},
				Patchable: &patchable,
				// A published time is present and deliberately ignored.
				PublishedTime: to(time.Now().AddDate(-4, 0, 0)),
			},
		},
	}
}

func to[T any](v T) *T { return &v }

func standard(plans ...string) fakePricing {
	f := fakePricing{tiers: map[string]armsecurity.PricingTier{},
		coverage: map[string]armsecurity.ResourcesCoverageStatus{}}
	for _, p := range plans {
		f.tiers[p] = armsecurity.PricingTierStandard
		f.coverage[p] = armsecurity.ResourcesCoverageStatusFullyCovered
	}
	return f
}

// ---- tests -----------------------------------------------------------------

func TestPricingFailureIsAnErrorNotAPass(t *testing.T) {
	p := Collect(context.Background(), Clients{
		Pricing: fakePricing{err: map[string]error{planServers: errors.New("AuthorizationFailed")}},
	}, vuln.DefaultPolicy(), sub)
	if len(p.Errors) == 0 {
		t.Fatal("a failed pricing read must be recorded")
	}
	got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now())
	if len(got) != 1 || got[0].Status != vuln.StatusError {
		t.Fatalf("want a single ERROR, got %+v", got)
	}
}

func TestMissingSubscriptionIsAnError(t *testing.T) {
	p := Collect(context.Background(), Clients{Pricing: standard(planServers)}, vuln.DefaultPolicy(), "")
	if len(p.Errors) == 0 {
		t.Fatal("no subscription id means nothing was assessed")
	}
}

// A plan that has never been configured answers 404. That is "off", not a
// reason to abandon the scan.
func TestUnconfiguredPlanReadsAsOff(t *testing.T) {
	f := standard(planServers)
	f.err = map[string]error{planContainers: errors.New("404 Not Found")}
	p := Collect(context.Background(), Clients{Pricing: f}, vuln.DefaultPolicy(), sub)
	if len(p.Errors) != 0 {
		t.Fatalf("a 404 on an unconfigured plan is not an error: %v", p.Errors)
	}
	if !p.ScannerEnabled {
		t.Fatal("Defender for Servers is on, so scanning is enabled")
	}
	if p.ClassEnabled[vuln.ClassImage] {
		t.Error("the container class should read as disabled")
	}
}

func TestDefenderOffMakesEveryMachineAGap(t *testing.T) {
	p := Collect(context.Background(), Clients{
		Pricing: fakePricing{}, // both plans Free
		VMs:     fakeVMs{vms: []*armcompute.VirtualMachine{vm("/vm/1", nil), vm("/vm/2", nil)}},
	}, vuln.DefaultPolicy(), sub)

	if p.ScannerEnabled {
		t.Fatal("no plan on Standard means nothing is scanning")
	}
	got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now())
	if len(got) != 1 || got[0].Key != vuln.AssessScannerEnabled || got[0].Status != vuln.StatusFail {
		t.Fatalf("want one scanner_enabled FAIL, got %+v", got)
	}
}

func TestPlanOnCoversTheInventory(t *testing.T) {
	p := Collect(context.Background(), Clients{
		Pricing: standard(planServers),
		VMs:     fakeVMs{vms: []*armcompute.VirtualMachine{vm("/vm/1", nil), vm("/vm/2", nil)}},
	}, vuln.DefaultPolicy(), sub)

	cov, ok := p.CoverageFor(vuln.ClassInstance)
	if !ok {
		t.Fatal("instance coverage should have been collected")
	}
	if cov.Covered != 2 || cov.Gaps != 0 {
		t.Fatalf("want 2 covered and no gaps, got %+v", cov)
	}
	if !strings.Contains(cov.Note, "fully covered") {
		t.Errorf("the plan's own verdict should be carried: %q", cov.Note)
	}
}

// Defender reports PartiallyCovered without naming the resources, so the
// verdict is stated rather than invented as a per-asset count.
func TestPartialCoverageIsStatedNotCounted(t *testing.T) {
	f := standard(planServers)
	f.coverage[planServers] = armsecurity.ResourcesCoverageStatusPartiallyCovered
	p := Collect(context.Background(), Clients{
		Pricing: f, VMs: fakeVMs{vms: []*armcompute.VirtualMachine{vm("/vm/1", nil)}},
	}, vuln.DefaultPolicy(), sub)

	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Gaps != 0 {
		t.Errorf("Defender does not say which resources, so no gap may be fabricated: %+v", cov)
	}
	if !strings.Contains(cov.Note, "partially covered") || !strings.Contains(cov.Note, "does not name") {
		t.Errorf("the note must say the verdict and its limit: %q", cov.Note)
	}
}

func TestScopedOutMachineIsExcludedNotFailed(t *testing.T) {
	policy := vuln.DefaultPolicy()
	policy.Scope.ExcludeTags = map[string]string{"Environment": "dev"}
	p := Collect(context.Background(), Clients{
		Pricing: fakePricing{}, // Defender off, so an unexcluded VM would be a gap
		VMs: fakeVMs{vms: []*armcompute.VirtualMachine{
			vm("/vm/dev", map[string]string{"Environment": "dev"}),
		}},
	}, policy, sub)
	// Scanner off short-circuits before coverage, so assert on the collector's
	// own behaviour with the plan on.
	f := standard(planServers)
	f.coverage[planServers] = armsecurity.ResourcesCoverageStatusFullyCovered
	p = Collect(context.Background(), Clients{
		Pricing: f,
		VMs: fakeVMs{vms: []*armcompute.VirtualMachine{
			vm("/vm/dev", map[string]string{"Environment": "dev"}),
			vm("/vm/prod", nil),
		}},
	}, policy, sub)
	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Excluded != 1 || cov.Covered != 1 {
		t.Fatalf("want one excluded and one covered, got %+v", cov)
	}
}

func TestVMListFailureIsRecorded(t *testing.T) {
	p := Collect(context.Background(), Clients{
		Pricing: standard(planServers),
		VMs:     fakeVMs{err: errors.New("AuthorizationFailed")},
	}, vuln.DefaultPolicy(), sub)
	if len(p.Errors) == 0 {
		t.Fatal("a failed inventory read must not silently shrink the denominator")
	}
	got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now())
	if got[0].Status != vuln.StatusError {
		t.Fatalf("want ERROR, got %+v", got)
	}
}

func TestOnlyVulnerabilitySubAssessmentsBecomeFindings(t *testing.T) {
	code := armsecurity.SubAssessmentStatusCodeUnhealthy
	sev := armsecurity.SeverityHigh
	// a posture/configuration sub-assessment: unhealthy, but not a CVE
	config := &armsecurity.SubAssessment{
		Name: to("config-1"),
		Properties: &armsecurity.SubAssessmentProperties{
			DisplayName: to("Storage account should use private link"),
			Status:      &armsecurity.SubAssessmentStatus{Code: &code, Severity: &sev},
		},
	}
	// a healthy vulnerability sub-assessment is a check that passed
	healthyCode := armsecurity.SubAssessmentStatusCodeHealthy
	healthy := serverFinding("CVE-2024-9999", armsecurity.SeverityLow, true, "/vm/1")
	healthy.Properties.Status.Code = &healthyCode

	p := &vuln.Posture{Source: "azure-defender"}
	CollectFindings(context.Background(), fakeSubAssess{items: []*armsecurity.SubAssessment{
		serverFinding("CVE-2024-0001", armsecurity.SeverityHigh, true, "/vm/1"),
		config,
		healthy,
	}}, sub, p)

	if len(p.Findings) != 1 {
		t.Fatalf("only the unhealthy CVE is a finding, got %d: %+v", len(p.Findings), p.Findings)
	}
	f := p.Findings[0]
	// Defender's severity scale stops at High - there is no Critical - and the
	// collector upper-cases it to match the policy keys.
	if f.ID != "CVE-2024-0001" || f.Severity != "HIGH" || f.AssetID != "/vm/1" {
		t.Errorf("finding fields not carried through: %+v", f)
	}
	if f.FixAvailable != "YES" {
		t.Errorf("patchable true means a fix is available, got %q", f.FixAvailable)
	}
}

// The published time is present in the payload and must not be used as the
// remediation clock.
func TestDefenderFindingsCarryNoAge(t *testing.T) {
	p := &vuln.Posture{Source: "azure-defender"}
	CollectFindings(context.Background(), fakeSubAssess{items: []*armsecurity.SubAssessment{
		serverFinding("CVE-2020-1234", armsecurity.SeverityHigh, true, "/vm/1"),
		serverFinding("CVE-2019-9999", armsecurity.SeverityMedium, false, "/vm/2"),
	}}, sub, p)

	if len(p.Findings) != 2 {
		t.Fatalf("expected two findings, got %d", len(p.Findings))
	}
	for _, f := range p.Findings {
		if f.HasAge() {
			t.Errorf("Defender reports no first-observed date; %s had %v", f.ID, f.FirstObserved)
		}
	}
	byID := map[string]vuln.Finding{}
	for _, f := range p.Findings {
		byID[f.ID] = f
	}
	if got := byID["CVE-2020-1234"].FixAvailable; got != "YES" {
		t.Errorf("patchable true means a fix is available, got %q", got)
	}
	if got := byID["CVE-2019-9999"].FixAvailable; got != "NO" {
		t.Errorf("patchable false means no fix, got %q", got)
	}

	// The patchable one is the case that matters: it could be remediated, but
	// there is no date to measure it against, so it must be neither passed nor
	// failed. An unpatchable finding is separately excluded from the window
	// because its age is irrelevant - there is nothing to apply.
	p.ScannerEnabled = true
	p.Coverage = []vuln.Coverage{{Class: vuln.ClassInstance, Covered: 1}}
	p.Findings = p.Findings[:1]
	var rem vuln.Assessment
	for _, a := range vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()) {
		if a.Key == vuln.AssessRemediation {
			rem = a
		}
	}
	if rem.Status != vuln.StatusInfo {
		t.Fatalf("an ageable-in-principle finding with no date is INFO; got %s: %s", rem.Status, rem.Evidence)
	}
	if !strings.Contains(rem.Detail, "no first-observed date") {
		t.Errorf("the reason must be stated: %s", rem.Detail)
	}
}

// A finding with no patch is excluded from the window, and with nothing left to
// measure the remediation practice is unproven rather than satisfied.
func TestUnpatchableFindingIsUnprovenNotPassed(t *testing.T) {
	p := &vuln.Posture{Source: "azure-defender", ScannerEnabled: true,
		Coverage: []vuln.Coverage{{Class: vuln.ClassInstance, Covered: 1}}}
	CollectFindings(context.Background(), fakeSubAssess{items: []*armsecurity.SubAssessment{
		serverFinding("CVE-2019-9999", armsecurity.SeverityHigh, false, "/vm/1"),
	}}, sub, p)

	var rem vuln.Assessment
	for _, a := range vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()) {
		if a.Key == vuln.AssessRemediation {
			rem = a
		}
	}
	if rem.Status != vuln.StatusInfo {
		t.Fatalf("nothing measurable is INFO, not %s: %s", rem.Status, rem.Evidence)
	}
	if !strings.Contains(rem.Detail, "compensating control") {
		t.Errorf("the detail should say what to do instead: %s", rem.Detail)
	}
}

func TestSubAssessmentFailureIsRecorded(t *testing.T) {
	p := &vuln.Posture{Source: "azure-defender"}
	CollectFindings(context.Background(), fakeSubAssess{err: errors.New("AuthorizationFailed")}, sub, p)
	if len(p.Errors) == 0 {
		t.Fatal("a failed sub-assessment read must be recorded")
	}
	if p.Findings != nil {
		t.Error("findings must stay nil so the evaluator skips the remediation assessment")
	}
}

func TestNilClientsAreSkippedNotFailed(t *testing.T) {
	p := Collect(context.Background(), Clients{Pricing: standard(planServers)}, vuln.DefaultPolicy(), sub)
	if len(p.Errors) != 0 {
		t.Fatalf("an absent VM client is not an error: %v", p.Errors)
	}
	cov, ok := p.CoverageFor(vuln.ClassInstance)
	if !ok || cov.InScope() != 0 {
		t.Fatalf("with no inventory the class carries only the plan's note, got %+v", cov)
	}
	if cov.Note == "" {
		t.Error("the plan verdict should still be reported")
	}
}
