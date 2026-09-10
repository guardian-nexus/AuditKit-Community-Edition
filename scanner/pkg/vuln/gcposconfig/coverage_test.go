package gcposconfig

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/osconfig/v1"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

const project = "auditkit-test"

type fakeReports struct {
	reports []*osconfig.VulnerabilityReport
	err     error
}

func (f fakeReports) List(context.Context, string, string) (*osconfig.ListVulnerabilityReportsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &osconfig.ListVulnerabilityReportsResponse{VulnerabilityReports: f.reports}, nil
}

type fakeInstances struct {
	instances []*compute.Instance
	err       error
}

func (f fakeInstances) AggregatedList(context.Context, string, string) (*compute.InstanceAggregatedList, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &compute.InstanceAggregatedList{
		Items: map[string]compute.InstancesScopedList{
			"zones/us-central1-a": {Instances: f.instances},
		},
	}, nil
}

func inst(name, status string, labels map[string]string) *compute.Instance {
	return &compute.Instance{Name: name, Status: status, Labels: labels}
}

func report(instance string, updated time.Time, vulns ...*osconfig.VulnerabilityReportVulnerability) *osconfig.VulnerabilityReport {
	return &osconfig.VulnerabilityReport{
		Name: "projects/" + project + "/locations/us-central1-a/instances/" + instance + "/vulnerabilityReport",
		UpdateTime:      updated.Format(time.RFC3339),
		Vulnerabilities: vulns,
	}
}

func vulnerability(cve, severity string, firstSeen time.Time, fixAvailable bool) *osconfig.VulnerabilityReportVulnerability {
	v := &osconfig.VulnerabilityReportVulnerability{
		CreateTime: firstSeen.Format(time.RFC3339),
		UpdateTime: time.Now().Format(time.RFC3339),
		Details: &osconfig.VulnerabilityReportVulnerabilityDetails{
			Cve: cve, Severity: severity, Description: "test vulnerability",
		},
	}
	if fixAvailable {
		v.AvailableInventoryItemIds = []string{"upgraded-package-1"}
	}
	return v
}

// VM Manager not being enabled is not zero coverage, it is an unanswered
// question, and must never read as a pass.
func TestServiceDisabledIsAnError(t *testing.T) {
	for _, msg := range []string{
		"googleapi: Error 403: OS Config API has not been used in project",
		"SERVICE_DISABLED",
		"accessNotConfigured",
	} {
		p := Collect(context.Background(), Clients{Reports: fakeReports{err: errors.New(msg)}},
			vuln.DefaultPolicy(), project)
		if len(p.Errors) == 0 {
			t.Fatalf("%q should be recorded as an error", msg)
		}
		got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now())
		if len(got) != 1 || got[0].Status != vuln.StatusError {
			t.Fatalf("%q: want a single ERROR, got %+v", msg, got)
		}
	}
}

func TestMissingProjectIsAnError(t *testing.T) {
	p := Collect(context.Background(), Clients{Reports: fakeReports{}}, vuln.DefaultPolicy(), "")
	if len(p.Errors) == 0 {
		t.Fatal("no project id means nothing was assessed")
	}
}

func TestInstanceWithoutAReportIsAGap(t *testing.T) {
	now := time.Now()
	p := Collect(context.Background(), Clients{
		Reports: fakeReports{reports: []*osconfig.VulnerabilityReport{
			report("vm-covered", now.Add(-2*time.Hour)),
		}},
		Instances: fakeInstances{instances: []*compute.Instance{
			inst("vm-covered", "RUNNING", nil),
			inst("vm-no-agent", "RUNNING", nil),
		}},
	}, vuln.DefaultPolicy(), project)

	cov, ok := p.CoverageFor(vuln.ClassInstance)
	if !ok {
		t.Fatal("instance coverage should have been collected")
	}
	if cov.Covered != 1 || cov.Gaps != 1 {
		t.Fatalf("want 1 covered and 1 gap, got %+v", cov)
	}
	if len(cov.GapIDs) != 1 || cov.GapIDs[0] != "vm-no-agent" {
		t.Fatalf("the uncovered instance should be named, got %v", cov.GapIDs)
	}

	a := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), now), vuln.AssessCoverage)
	if a.Status != vuln.StatusFail {
		t.Fatalf("a gap must fail coverage, got %s", a.Status)
	}
	if !strings.Contains(a.Detail, "OS Config agent is not reporting") {
		t.Errorf("the reason should explain what is missing: %s", a.Detail)
	}
}

// A terminated instance has nothing running on it to be vulnerable.
func TestNonRunningInstancesAreNotGaps(t *testing.T) {
	p := Collect(context.Background(), Clients{
		Reports: fakeReports{},
		Instances: fakeInstances{instances: []*compute.Instance{
			inst("vm-stopped", "TERMINATED", nil),
			inst("vm-suspended", "SUSPENDED", nil),
		}},
	}, vuln.DefaultPolicy(), project)

	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.InScope() != 0 {
		t.Fatalf("stopped instances stay out of the denominator, got %+v", cov)
	}
}

func TestScopedOutInstanceIsExcludedNotFailed(t *testing.T) {
	policy := vuln.DefaultPolicy()
	policy.Scope.ExcludeTags = map[string]string{"env": "dev"}
	p := Collect(context.Background(), Clients{
		Reports: fakeReports{},
		Instances: fakeInstances{instances: []*compute.Instance{
			inst("vm-dev", "RUNNING", map[string]string{"env": "dev"}),
			inst("vm-prod", "RUNNING", nil),
		}},
	}, policy, project)

	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Excluded != 1 || cov.Gaps != 1 {
		t.Fatalf("want the dev box excluded and prod a gap, got %+v", cov)
	}
}

func TestStaleReportIsNotCoverage(t *testing.T) {
	now := time.Now()
	policy := vuln.DefaultPolicy() // stale after 30 days
	p := Collect(context.Background(), Clients{
		Reports: fakeReports{reports: []*osconfig.VulnerabilityReport{
			report("vm-fresh", now.AddDate(0, 0, -1)),
			report("vm-stale", now.AddDate(0, 0, -90)),
		}},
		Instances: fakeInstances{instances: []*compute.Instance{
			inst("vm-fresh", "RUNNING", nil), inst("vm-stale", "RUNNING", nil),
		}},
	}, policy, project)

	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Covered != 1 || cov.Stale != 1 {
		t.Fatalf("want 1 covered and 1 stale, got %+v", cov)
	}

	all := vuln.Evaluate(p, policy, now)
	if a := findAssessment(t, all, vuln.AssessFreshness); a.Status != vuln.StatusFail {
		t.Fatalf("a 90-day-old report is stale, got %s", a.Status)
	}
	// A stale asset is still reached by the scanner, so coverage itself passes.
	if a := findAssessment(t, all, vuln.AssessCoverage); a.Status != vuln.StatusPass {
		t.Fatalf("coverage passes when the only problem is freshness, got %s", a.Status)
	}
}

// Unlike Defender, VM Manager dates each finding, so GCP ages honestly.
func TestFindingsAreAgedFromFirstDetected(t *testing.T) {
	now := time.Now()
	policy := vuln.DefaultPolicy() // critical 30, high 90
	p := Collect(context.Background(), Clients{
		Reports: fakeReports{reports: []*osconfig.VulnerabilityReport{
			report("vm-1", now.Add(-time.Hour),
				vulnerability("CVE-2024-0001", "CRITICAL", now.AddDate(0, 0, -95), true),
				vulnerability("CVE-2024-0002", "CRITICAL", now.AddDate(0, 0, -5), true),
				vulnerability("CVE-2024-0003", "HIGH", now.AddDate(0, 0, -200), false),
			),
		}},
		Instances: fakeInstances{instances: []*compute.Instance{inst("vm-1", "RUNNING", nil)}},
	}, policy, project)

	if len(p.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(p.Findings))
	}
	byID := map[string]vuln.Finding{}
	for _, f := range p.Findings {
		byID[f.ID] = f
		if !f.HasAge() {
			t.Errorf("%s should carry a first-detected date", f.ID)
		}
		if f.AssetID != "vm-1" {
			t.Errorf("%s should name its instance, got %q", f.ID, f.AssetID)
		}
	}
	if got := byID["CVE-2024-0001"].FixAvailable; got != "YES" {
		t.Errorf("an available inventory item means a fix exists, got %q", got)
	}
	if got := byID["CVE-2024-0003"].FixAvailable; got != "NO" {
		t.Errorf("no available inventory item means no patch is offered, got %q", got)
	}

	a := findAssessment(t, vuln.Evaluate(p, policy, now), vuln.AssessRemediation)
	if a.Status != vuln.StatusFail {
		t.Fatalf("one overdue critical must fail, got %s: %s", a.Status, a.Evidence)
	}
	// CVE-0002 is inside the window; CVE-0003 has no fix and is excluded.
	if !strings.Contains(a.Evidence, "1 findings are past") {
		t.Errorf("exactly one finding is overdue: %s", a.Evidence)
	}
	if !strings.Contains(a.Evidence, "CVE-2024-0001") {
		t.Errorf("the oldest overdue finding should be named: %s", a.Evidence)
	}
}

func TestVulnerabilityWithoutACVEStillCounts(t *testing.T) {
	now := time.Now()
	v := &osconfig.VulnerabilityReportVulnerability{
		CreateTime:                now.AddDate(0, 0, -1).Format(time.RFC3339),
		AvailableInventoryItemIds: []string{"fix"},
	}
	p := Collect(context.Background(), Clients{
		Reports: fakeReports{reports: []*osconfig.VulnerabilityReport{report("vm-1", now, v)}},
	}, vuln.DefaultPolicy(), project)

	if len(p.Findings) != 1 {
		t.Fatalf("a vulnerability with no details is still a finding, got %d", len(p.Findings))
	}
	if p.Findings[0].ID != "(no CVE reported)" {
		t.Errorf("it needs some identifier for the report, got %q", p.Findings[0].ID)
	}
}

func TestInstanceListFailureIsRecorded(t *testing.T) {
	p := Collect(context.Background(), Clients{
		Reports:   fakeReports{},
		Instances: fakeInstances{err: errors.New("permission denied")},
	}, vuln.DefaultPolicy(), project)
	if len(p.Errors) == 0 {
		t.Fatal("a failed inventory read must not silently shrink the denominator")
	}
	if got := vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()); got[0].Status != vuln.StatusError {
		t.Fatalf("want ERROR, got %+v", got)
	}
}

// A report for an instance the inventory did not return - created between the
// two calls, or no inventory client at all - is still coverage.
func TestReportWithoutAnInventoryEntryIsStillCovered(t *testing.T) {
	now := time.Now()
	p := Collect(context.Background(), Clients{
		Reports: fakeReports{reports: []*osconfig.VulnerabilityReport{
			report("vm-orphan", now.Add(-time.Hour)),
		}},
	}, vuln.DefaultPolicy(), project)

	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Covered != 1 || cov.Gaps != 0 {
		t.Fatalf("want the reported instance counted as covered, got %+v", cov)
	}
}

func TestReportNameParsing(t *testing.T) {
	cases := map[string]string{
		"projects/p/locations/us-central1-a/instances/vm-1/vulnerabilityReport": "vm-1",
		"projects/p/locations/l/instances/vm-2":                                 "vm-2",
		"nonsense":                                                             "",
		"":                                                                     "",
	}
	for in, want := range cases {
		if got := instanceFromReportName(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func findAssessment(t *testing.T, all []vuln.Assessment, key vuln.AssessmentKey) vuln.Assessment {
	t.Helper()
	for _, a := range all {
		if a.Key == key {
			return a
		}
	}
	t.Fatalf("no %s assessment among %d", key, len(all))
	return vuln.Assessment{}
}
