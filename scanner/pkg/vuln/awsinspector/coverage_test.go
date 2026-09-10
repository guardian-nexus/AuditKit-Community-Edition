package awsinspector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

type fakeInspector struct {
	accountErr  error
	coverageErr error
	findingsErr error
	enabled     bool
	classes     map[string]bool // "ec2", "ecr", "lambda"
	resources   []inspectortypes.CoveredResource
	findings    []inspectortypes.Finding
}

func (f *fakeInspector) ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	if f.findingsErr != nil {
		return nil, f.findingsErr
	}
	return &inspector2.ListFindingsOutput{Findings: f.findings}, nil
}

func (f *fakeInspector) BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput, ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	if f.accountErr != nil {
		return nil, f.accountErr
	}
	st := inspectortypes.StatusDisabled
	if f.enabled {
		st = inspectortypes.StatusEnabled
	}
	on := func(name string) *inspectortypes.State {
		s := inspectortypes.StatusDisabled
		if f.classes[name] {
			s = inspectortypes.StatusEnabled
		}
		return &inspectortypes.State{Status: s}
	}
	id := "111122223333"
	return &inspector2.BatchGetAccountStatusOutput{
		Accounts: []inspectortypes.AccountState{{
			AccountId: &id,
			State:     &inspectortypes.State{Status: st},
			ResourceState: &inspectortypes.ResourceState{
				Ec2: on("ec2"), Ecr: on("ecr"), Lambda: on("lambda"),
			},
		}},
	}, nil
}

func (f *fakeInspector) ListCoverage(context.Context, *inspector2.ListCoverageInput, ...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error) {
	if f.coverageErr != nil {
		return nil, f.coverageErr
	}
	return &inspector2.ListCoverageOutput{CoveredResources: f.resources}, nil
}

type fakeEC2 struct{ instances []ec2types.Instance }

func (f *fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{Instances: f.instances}},
	}, nil
}

type fakeLambda struct{ arns []string }

func (f *fakeLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	out := &lambda.ListFunctionsOutput{}
	for i := range f.arns {
		arn := f.arns[i]
		out.Functions = append(out.Functions, lambdatypes.FunctionConfiguration{FunctionArn: &arn})
	}
	return out, nil
}

type fakeECR struct{ arns []string }

func (f *fakeECR) DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	out := &ecr.DescribeRepositoriesOutput{}
	for i := range f.arns {
		arn := f.arns[i]
		out.Repositories = append(out.Repositories, ecrtypes.Repository{RepositoryArn: &arn})
	}
	return out, nil
}

func instance(id string, running bool, tags map[string]string) ec2types.Instance {
	state := ec2types.InstanceStateNameStopped
	if running {
		state = ec2types.InstanceStateNameRunning
	}
	inst := ec2types.Instance{InstanceId: &id, State: &ec2types.InstanceState{Name: state}}
	for k, v := range tags {
		key, val := k, v
		inst.Tags = append(inst.Tags, ec2types.Tag{Key: &key, Value: &val})
	}
	return inst
}

func covered(id string, reason inspectortypes.ScanStatusReason, last *time.Time) inspectortypes.CoveredResource {
	return inspectortypes.CoveredResource{
		ResourceId:    &id,
		ResourceType:  inspectortypes.CoverageResourceTypeAwsEc2Instance,
		LastScannedAt: last,
		ScanStatus:    &inspectortypes.ScanStatus{Reason: reason},
	}
}

func allOn() map[string]bool { return map[string]bool{"ec2": true, "ecr": true, "lambda": true} }

func ago(d time.Duration) *time.Time { t := time.Now().Add(-d); return &t }

// A denied or failed read must never produce a pass. This is the defect that
// shipped in the GCP PCI checks and it is the one worth a permanent test.
func TestCollectErrorsNeverBecomeCompliant(t *testing.T) {
	for _, tc := range []struct {
		name string
		insp *fakeInspector
	}{
		{"account status denied", &fakeInspector{accountErr: errors.New("AccessDeniedException")}},
		{"coverage denied", &fakeInspector{enabled: true, classes: allOn(), coverageErr: errors.New("AccessDeniedException")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Collect(context.Background(), Clients{Inspector: tc.insp}, vuln.DefaultPolicy(), "")
			if len(p.Errors) == 0 {
				t.Fatal("expected the failed call to be recorded on the posture")
			}
			got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now())
			if len(got) != 1 || got[0].Status != vuln.StatusError {
				t.Fatalf("want a single ERROR assessment, got %+v", got)
			}
		})
	}
}

func TestScannerDisabledIsOneClearFailure(t *testing.T) {
	p := Collect(context.Background(),
		Clients{Inspector: &fakeInspector{enabled: false}}, vuln.DefaultPolicy(), "")
	if p.ScannerEnabled {
		t.Fatal("scanner should read as disabled")
	}
	got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now())
	if len(got) != 1 || got[0].Key != vuln.AssessScannerEnabled || got[0].Status != vuln.StatusFail {
		t.Fatalf("want one scanner_enabled FAIL, got %+v", got)
	}
}

func TestDispositionBuckets(t *testing.T) {
	cases := map[inspectortypes.ScanStatusReason]vuln.Disposition{
		// wire values, matching dispositionFor - see the comment there
		"SUCCESSFUL":             vuln.DispCovered,
		"PENDING_INITIAL_SCAN":   vuln.DispPending,
		"SCAN_IN_PROGRESS":       vuln.DispPending,
		"EXCLUDED_BY_TAG":        vuln.DispExcluded,
		"UNSUPPORTED_OS":         vuln.DispNotEligible,
		"UNSUPPORTED_RUNTIME":    vuln.DispNotEligible,
		"EC2_INSTANCE_STOPPED":   vuln.DispNotEligible,
		"RESOURCE_TERMINATED":    vuln.DispNotEligible,
		"UNMANAGED_EC2_INSTANCE": vuln.DispGap,
		"NO_INVENTORY":           vuln.DispGap,
		"STALE_INVENTORY":        vuln.DispGap,
		"ACCESS_DENIED":          vuln.DispGap,
		// Scan-on-push means the image is never re-examined, so a CVE disclosed
		// after the push is never noticed. That is a gap against RA.L2-3.11.2.
		"SCAN_FREQUENCY_SCAN_ON_PUSH": vuln.DispGap,
	}
	for reason, want := range cases {
		if got := dispositionFor(reason); got != want {
			t.Errorf("%s: got %s, want %s", reason, got, want)
		}
	}
}

func TestUncoveredInstanceIsAGap(t *testing.T) {
	insp := &fakeInspector{enabled: true, classes: allOn(),
		resources: []inspectortypes.CoveredResource{
			covered("i-covered", "SUCCESSFUL", ago(time.Hour)),
			covered("i-unmanaged", "UNMANAGED_EC2_INSTANCE", nil),
		}}
	ec2c := &fakeEC2{instances: []ec2types.Instance{
		instance("i-covered", true, nil),
		instance("i-unmanaged", true, nil),
		instance("i-unknown", true, nil),  // Inspector has never heard of it
		instance("i-stopped", false, nil), // paused by design, not a gap
	}}

	p := Collect(context.Background(), Clients{Inspector: insp, EC2: ec2c}, vuln.DefaultPolicy(), "")
	cov, ok := p.CoverageFor(vuln.ClassInstance)
	if !ok {
		t.Fatal("no instance coverage collected")
	}
	if cov.Covered != 1 || cov.Gaps != 2 {
		t.Fatalf("want 1 covered and 2 gaps, got covered=%d gaps=%d ids=%v", cov.Covered, cov.Gaps, cov.GapIDs)
	}
	if cov.InScope() != 3 {
		t.Fatalf("stopped instance must stay out of the denominator, in-scope=%d", cov.InScope())
	}

	a := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()), vuln.AssessCoverage)
	if a.Status != vuln.StatusFail {
		t.Fatalf("coverage should fail with 2 gaps, got %s", a.Status)
	}
	if !strings.Contains(a.Detail, "i-unknown") {
		t.Errorf("the uncovered asset should be named in the detail:\n%s", a.Detail)
	}
}

func TestExcludedAndIneligibleDoNotFail(t *testing.T) {
	insp := &fakeInspector{enabled: true, classes: allOn(),
		resources: []inspectortypes.CoveredResource{
			covered("i-1", "SUCCESSFUL", ago(time.Hour)),
			covered("i-tagged", "EXCLUDED_BY_TAG", nil),
			covered("i-oldos", "UNSUPPORTED_OS", nil),
		}}
	p := Collect(context.Background(), Clients{Inspector: insp}, vuln.DefaultPolicy(), "")
	a := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()), vuln.AssessCoverage)
	if a.Status != vuln.StatusPass {
		t.Fatalf("excluded and ineligible assets must not fail coverage, got %s: %s", a.Status, a.Evidence)
	}
}

func TestPolicyTagExclusionKeepsInventoryAssetOutOfTheDenominator(t *testing.T) {
	policy := vuln.DefaultPolicy()
	policy.Scope.ExcludeTags = map[string]string{"Environment": "dev"}

	insp := &fakeInspector{enabled: true, classes: allOn()}
	ec2c := &fakeEC2{instances: []ec2types.Instance{
		instance("i-dev", true, map[string]string{"Environment": "dev"}),
	}}
	p := Collect(context.Background(), Clients{Inspector: insp, EC2: ec2c}, policy, "")
	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Gaps != 0 || cov.Excluded != 1 {
		t.Fatalf("a scoped-out instance should be excluded not failed: gaps=%d excluded=%d", cov.Gaps, cov.Excluded)
	}
}

func TestStaleScanIsNotCoverage(t *testing.T) {
	policy := vuln.DefaultPolicy() // 30 days
	insp := &fakeInspector{enabled: true, classes: allOn(),
		resources: []inspectortypes.CoveredResource{
			covered("i-fresh", "SUCCESSFUL", ago(24*time.Hour)),
			covered("i-stale", "SUCCESSFUL", ago(90*24*time.Hour)),
		}}
	p := Collect(context.Background(), Clients{Inspector: insp}, policy, "")
	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Covered != 1 || cov.Stale != 1 {
		t.Fatalf("want 1 covered and 1 stale, got covered=%d stale=%d", cov.Covered, cov.Stale)
	}

	assessments := vuln.Evaluate(p, policy, time.Now())
	if a := findAssessment(t, assessments, vuln.AssessFreshness); a.Status != vuln.StatusFail {
		t.Fatalf("freshness should fail with a 90-day-old scan, got %s", a.Status)
	}
	// A stale asset is still reached by the scanner, so coverage itself passes.
	if a := findAssessment(t, assessments, vuln.AssessCoverage); a.Status != vuln.StatusPass {
		t.Fatalf("coverage should pass when the only problem is freshness, got %s", a.Status)
	}
}

func TestDisabledClassExplainsItself(t *testing.T) {
	insp := &fakeInspector{enabled: true, classes: map[string]bool{"ec2": true}} // ECR off
	p := Collect(context.Background(),
		Clients{Inspector: insp, ECR: &fakeECR{arns: []string{"arn:aws:ecr:::repository/app"}}},
		vuln.DefaultPolicy(), "")

	var reason string
	for _, a := range p.Assets {
		if a.Class == vuln.ClassRepo {
			reason = a.Reason
		}
	}
	if !strings.Contains(reason, "not enabled") {
		t.Fatalf("a repository in an account with ECR scanning off should say so, got %q", reason)
	}
}

func TestNilClientIsSkippedNotFailed(t *testing.T) {
	insp := &fakeInspector{enabled: true, classes: allOn()}
	p := Collect(context.Background(), Clients{Inspector: insp}, vuln.DefaultPolicy(), "")
	if len(p.Errors) != 0 {
		t.Fatalf("absent clients are not errors: %v", p.Errors)
	}
	if _, ok := p.CoverageFor(vuln.ClassInstance); ok {
		t.Fatal("a class nobody looked at must not appear in coverage")
	}
}

func findAssessment(t *testing.T, all []vuln.Assessment, key vuln.AssessmentKey) vuln.Assessment {
	t.Helper()
	for _, a := range all {
		if a.Key == key {
			return a
		}
	}
	t.Fatalf("no %s assessment in %+v", key, all)
	return vuln.Assessment{}
}

func finding(cve string, sev inspectortypes.Severity, firstSeen time.Time, fix inspectortypes.FixAvailable) inspectortypes.Finding {
	id, arn := cve, "arn:aws:inspector2:::finding/"+cve
	return inspectortypes.Finding{
		FindingArn:      &arn,
		Severity:        sev,
		FixAvailable:    fix,
		FirstObservedAt: &firstSeen,
		PackageVulnerabilityDetails: &inspectortypes.PackageVulnerabilityDetails{
			VulnerabilityId: &id,
		},
	}
}

func TestRemediationAgeingAgainstThePolicyWindow(t *testing.T) {
	policy := vuln.DefaultPolicy() // critical 30, high 90, medium 180
	now := time.Now()
	insp := &fakeInspector{enabled: true, classes: allOn(),
		resources: []inspectortypes.CoveredResource{
			covered("i-1", "SUCCESSFUL", ago(time.Hour)),
		},
		findings: []inspectortypes.Finding{
			finding("CVE-2024-0001", inspectortypes.SeverityCritical, now.AddDate(0, 0, -94), inspectortypes.FixAvailableYes),
			finding("CVE-2024-0002", inspectortypes.SeverityCritical, now.AddDate(0, 0, -5), inspectortypes.FixAvailableYes),
			finding("CVE-2024-0003", inspectortypes.SeverityHigh, now.AddDate(0, 0, -100), inspectortypes.FixAvailableYes),
			// past every window, but there is no patch: needs a compensating
			// control, so it must not count as overdue
			finding("CVE-2024-0004", inspectortypes.SeverityCritical, now.AddDate(0, 0, -400), inspectortypes.FixAvailableNo),
			// no window in policy for LOW, so never overdue
			finding("CVE-2024-0005", inspectortypes.SeverityLow, now.AddDate(0, 0, -900), inspectortypes.FixAvailableYes),
		}}

	p := Collect(context.Background(), Clients{Inspector: insp}, policy, "")
	CollectFindings(context.Background(), insp, p)
	if len(p.Findings) != 5 {
		t.Fatalf("want 5 findings, got %d", len(p.Findings))
	}

	a := findAssessment(t, vuln.Evaluate(p, policy, now), vuln.AssessRemediation)
	if a.Status != vuln.StatusFail {
		t.Fatalf("two overdue findings should fail, got %s: %s", a.Status, a.Evidence)
	}
	if a.Severity != "CRITICAL" {
		t.Errorf("an overdue critical should raise the severity, got %q", a.Severity)
	}
	if !strings.Contains(a.Evidence, "2 findings are past") {
		t.Errorf("expected exactly 2 overdue in the evidence: %s", a.Evidence)
	}
	if !strings.Contains(a.Evidence, "CVE-2024-0003") {
		t.Errorf("the oldest overdue finding should be named: %s", a.Evidence)
	}
	if !strings.Contains(a.Detail, "no fix available") {
		t.Errorf("the unpatchable finding should be called out: %s", a.Detail)
	}
}

// Findings that were never collected must not read as "nothing overdue".
func TestRemediationSilentWhenFindingsNotCollected(t *testing.T) {
	insp := &fakeInspector{enabled: true, classes: allOn(),
		resources: []inspectortypes.CoveredResource{covered("i-1", "SUCCESSFUL", ago(time.Hour))}}
	p := Collect(context.Background(), Clients{Inspector: insp}, vuln.DefaultPolicy(), "")
	for _, a := range vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()) {
		if a.Key == vuln.AssessRemediation {
			t.Fatalf("remediation must not be assessed when findings were not fetched: %+v", a)
		}
	}
}

func TestFindingsReadFailureIsRecorded(t *testing.T) {
	insp := &fakeInspector{enabled: true, classes: allOn(), findingsErr: errors.New("AccessDeniedException")}
	p := Collect(context.Background(), Clients{Inspector: insp}, vuln.DefaultPolicy(), "")
	CollectFindings(context.Background(), insp, p)
	if len(p.Errors) == 0 {
		t.Fatal("a denied ListFindings must be recorded")
	}
	got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now())
	if len(got) != 1 || got[0].Status != vuln.StatusError {
		t.Fatalf("want a single ERROR assessment, got %+v", got)
	}
}

func TestNoFindingsIsACleanPass(t *testing.T) {
	insp := &fakeInspector{enabled: true, classes: allOn(),
		resources: []inspectortypes.CoveredResource{covered("i-1", "SUCCESSFUL", ago(time.Hour))}}
	p := Collect(context.Background(), Clients{Inspector: insp}, vuln.DefaultPolicy(), "")
	CollectFindings(context.Background(), insp, p)
	a := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()), vuln.AssessRemediation)
	if a.Status != vuln.StatusPass {
		t.Fatalf("an empty active-findings list is a pass, got %s", a.Status)
	}
}

// Microsoft Defender reports a CVE's publication date and the time its
// assessment last ran, but never when a finding first appeared on the estate.
// Ageing from publication would fail a host for a vulnerability disclosed
// before that host existed, so a finding with no first-observed date must be
// counted and never overdue.
func TestFindingsWithNoAgeAreNeverOverdue(t *testing.T) {
	policy := vuln.DefaultPolicy()
	now := time.Now()
	p := &vuln.Posture{
		Source: "azure-defender", Provider: "azure", ScannerEnabled: true,
		Coverage: []vuln.Coverage{{Class: vuln.ClassInstance, Covered: 1}},
		Findings: []vuln.Finding{
			// zero FirstObserved: the scanner did not say
			{ID: "CVE-2019-0001", Severity: "CRITICAL", FixAvailable: "YES"},
			{ID: "CVE-2020-0002", Severity: "HIGH", FixAvailable: "YES"},
		},
	}
	a := findAssessment(t, vuln.Evaluate(p, policy, now), vuln.AssessRemediation)
	if a.Status != vuln.StatusInfo {
		t.Fatalf("nothing measurable is INFO, not a pass or a fail; got %s: %s", a.Status, a.Evidence)
	}
	if !strings.Contains(a.Detail, "no first-observed date") {
		t.Errorf("the reason should be stated: %s", a.Detail)
	}

	// Mixed: one ageable and overdue, one not ageable.
	p.Findings = append(p.Findings, vuln.Finding{
		ID: "CVE-2024-0003", Severity: "CRITICAL", FixAvailable: "YES",
		FirstObserved: now.AddDate(0, 0, -120),
	})
	a = findAssessment(t, vuln.Evaluate(p, policy, now), vuln.AssessRemediation)
	if a.Status != vuln.StatusFail {
		t.Fatalf("one overdue ageable finding must still fail; got %s", a.Status)
	}
	if !strings.Contains(a.Evidence, "1 findings are past") {
		t.Errorf("only the ageable one counts as overdue: %s", a.Evidence)
	}
	if !strings.Contains(a.Detail, "2 findings carry no first-observed date") {
		t.Errorf("the unageable pair should be reported: %s", a.Detail)
	}
}
