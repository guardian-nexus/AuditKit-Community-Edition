package vuln

import (
	"strings"
	"testing"
	"time"
)

func ptr(t time.Time) *time.Time { return &t }

func posture(mut ...func(*Posture)) *Posture {
	p := &Posture{Source: "test-scanner", Provider: "test", ScannerEnabled: true}
	for _, m := range mut {
		m(p)
	}
	return p
}

func find(t *testing.T, all []Assessment, key AssessmentKey) Assessment {
	t.Helper()
	for _, a := range all {
		if a.Key == key {
			return a
		}
	}
	t.Fatalf("no %s assessment among %d", key, len(all))
	return Assessment{}
}

func absent(t *testing.T, all []Assessment, key AssessmentKey) {
	t.Helper()
	for _, a := range all {
		if a.Key == key {
			t.Fatalf("%s should not have been assessed: %+v", key, a)
		}
	}
}

// A posture carrying collection errors is one ERROR and nothing else. Reporting
// coverage alongside an error would invite reading the coverage number as fact.
func TestErrorsProduceOneErrorAndNothingElse(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Errors = []string{"AccessDeniedException"}
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 5}}
	})
	got := Evaluate(p, DefaultPolicy(), time.Now())
	if len(got) != 1 || got[0].Status != StatusError {
		t.Fatalf("want exactly one ERROR, got %+v", got)
	}
	if !strings.Contains(got[0].Evidence, "AccessDeniedException") {
		t.Errorf("the provider's own error should survive into the evidence: %s", got[0].Evidence)
	}
}

func TestScannerOffIsOneFailure(t *testing.T) {
	p := posture(func(p *Posture) { p.ScannerEnabled = false })
	got := Evaluate(p, DefaultPolicy(), time.Now())
	if len(got) != 1 || got[0].Key != AssessScannerEnabled || got[0].Status != StatusFail {
		t.Fatalf("want one scanner_enabled FAIL, got %+v", got)
	}
}

func TestNoAssetsIsInfoNotAPass(t *testing.T) {
	got := Evaluate(posture(), DefaultPolicy(), time.Now())
	a := find(t, got, AssessCoverage)
	if a.Status != StatusInfo {
		t.Fatalf("an empty account is INFO, not a pass; got %s", a.Status)
	}
	absent(t, got, AssessFreshness)
}

func TestCoverageDenominatorExcludesWhatItShould(t *testing.T) {
	c := Coverage{Class: ClassInstance, Covered: 3, Stale: 1, Gaps: 2,
		Excluded: 5, NotEligible: 7, Pending: 11}
	if got := c.InScope(); got != 6 {
		t.Fatalf("in-scope is covered+stale+gaps = 6, got %d", got)
	}
}

func TestCoveragePassesWithGapsOnlyOutsideScope(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 4,
			Excluded: 3, NotEligible: 2, OldestScan: ptr(time.Now().Add(-time.Hour))}}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessCoverage)
	if a.Status != StatusPass {
		t.Fatalf("excluded and ineligible assets must not fail coverage; got %s: %s", a.Status, a.Evidence)
	}
	if !strings.Contains(a.Evidence, "3 excluded") || !strings.Contains(a.Evidence, "2 not eligible") {
		t.Errorf("the report should account for them: %s", a.Evidence)
	}
}

func TestCoverageFailsAndNamesTheGaps(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1, Gaps: 1, GapIDs: []string{"i-orphan"}}}
		p.Assets = []Asset{{ID: "i-orphan", Class: ClassInstance,
			Disposition: DispGap, Reason: "no coverage record"}}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessCoverage)
	if a.Status != StatusFail {
		t.Fatalf("a gap must fail coverage; got %s", a.Status)
	}
	if !strings.Contains(a.Evidence, "1 of 2") || !strings.Contains(a.Evidence, "50% covered") {
		t.Errorf("evidence should carry the fraction: %s", a.Evidence)
	}
	if !strings.Contains(a.Detail, "i-orphan") || !strings.Contains(a.Detail, "no coverage record") {
		t.Errorf("detail should name the asset and the provider's reason: %s", a.Detail)
	}
}

// The gap list is capped so a report cannot be flooded, but the total must
// still be stated.
func TestGapListIsCappedButCountsAreNot(t *testing.T) {
	ids := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		ids = append(ids, "i-"+string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Gaps: len(ids), GapIDs: ids}}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessCoverage)
	if !strings.Contains(a.Detail, "and 30 more") {
		t.Errorf("expected the overflow line for 40 gaps: %s", a.Detail)
	}
	if !strings.Contains(a.Evidence, "40 of 40") {
		t.Errorf("the full count belongs in the evidence: %s", a.Evidence)
	}
}

// Defender for Cloud reports coverage with no scan timestamps at all. Passing
// freshness there would assert "every covered asset was scanned within 30 days"
// from no data.
func TestFreshnessWithoutTimestampsIsUnknownNotAPass(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Source = "azure-defender"
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 9}}
		p.Assets = []Asset{{ID: "vm-1", Class: ClassInstance, Disposition: DispCovered}}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessFreshness)
	if a.Status != StatusInfo {
		t.Fatalf("no timestamps means unknown, not a pass; got %s: %s", a.Status, a.Evidence)
	}
	if !strings.Contains(a.Evidence, "does not report when each asset was last scanned") {
		t.Errorf("the reason should be explicit: %s", a.Evidence)
	}
}

func TestFreshnessPassesAndFailsOnRealDates(t *testing.T) {
	now := time.Now()
	policy := DefaultPolicy() // stale after 30 days

	fresh := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 2, OldestScan: ptr(now.AddDate(0, 0, -3))}}
		p.Assets = []Asset{{ID: "a", Disposition: DispCovered, LastScanned: ptr(now.AddDate(0, 0, -3))}}
	})
	if a := find(t, Evaluate(fresh, policy, now), AssessFreshness); a.Status != StatusPass {
		t.Fatalf("a 3-day-old scan is fresh; got %s", a.Status)
	}

	stale := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1, Stale: 1,
			StaleIDs: []string{"a"}, OldestScan: ptr(now.AddDate(0, 0, -200))}}
		p.Assets = []Asset{{ID: "a", Disposition: DispStale, LastScanned: ptr(now.AddDate(0, 0, -200))}}
	})
	a := find(t, Evaluate(stale, policy, now), AssessFreshness)
	if a.Status != StatusFail {
		t.Fatalf("a 200-day-old scan is stale; got %s", a.Status)
	}
	if !strings.Contains(a.Detail, "not the same as a clean one") {
		t.Errorf("the detail should explain why a stale scan is not reassurance: %s", a.Detail)
	}
}

func TestRemediationAbsentWhenFindingsNotCollected(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1, OldestScan: ptr(time.Now())}}
	})
	absent(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessRemediation)
}

func TestRemediationEmptyListIsAPass(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1, OldestScan: ptr(time.Now())}}
		p.Findings = []Finding{}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessRemediation)
	if a.Status != StatusPass {
		t.Fatalf("no active findings is a pass; got %s", a.Status)
	}
}

func TestAgingBucketsBySeverityAgainstTheWindow(t *testing.T) {
	now := time.Now()
	policy := DefaultPolicy() // critical 30, high 90, medium 180
	fs := []Finding{
		{ID: "c-old", Severity: "CRITICAL", FixAvailable: "YES", FirstObserved: now.AddDate(0, 0, -31)},
		{ID: "c-new", Severity: "CRITICAL", FixAvailable: "YES", FirstObserved: now.AddDate(0, 0, -29)},
		{ID: "h-old", Severity: "HIGH", FixAvailable: "YES", FirstObserved: now.AddDate(0, 0, -91)},
		{ID: "m-new", Severity: "MEDIUM", FixAvailable: "YES", FirstObserved: now.AddDate(0, 0, -179)},
		{ID: "no-fix", Severity: "CRITICAL", FixAvailable: "NO", FirstObserved: now.AddDate(0, 0, -900)},
		{ID: "no-window", Severity: "LOW", FixAvailable: "YES", FirstObserved: now.AddDate(0, 0, -900)},
		{ID: "no-date", Severity: "CRITICAL", FixAvailable: "YES"},
	}
	got := Aging(fs, policy, now)

	by := map[string]SeverityAging{}
	for _, s := range got {
		by[s.Severity] = s
	}
	if c := by["CRITICAL"]; c.Overdue != 1 || c.NoFixAvailable != 1 || c.NoAgeReported != 1 || c.Total != 4 {
		t.Errorf("CRITICAL: want total 4, overdue 1, no-fix 1, no-date 1; got %+v", c)
	}
	if h := by["HIGH"]; h.Overdue != 1 {
		t.Errorf("HIGH one day past a 90-day window is overdue; got %+v", h)
	}
	if m := by["MEDIUM"]; m.Overdue != 0 {
		t.Errorf("MEDIUM one day inside a 180-day window is not overdue; got %+v", m)
	}
	if l := by["LOW"]; l.Overdue != 0 || l.Total != 1 {
		t.Errorf("a severity with no window is counted, never overdue; got %+v", l)
	}
	// severity order drives which one names the assessment's severity
	if got[0].Severity != "CRITICAL" {
		t.Errorf("aging must be severity-ordered, got %s first", got[0].Severity)
	}
}

func TestRemediationSeverityFollowsTheWorstOverdue(t *testing.T) {
	now := time.Now()
	only := func(f Finding) *Posture {
		return posture(func(p *Posture) {
			p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1, OldestScan: ptr(now)}}
			p.Findings = []Finding{f}
		})
	}
	crit := find(t, Evaluate(only(Finding{ID: "x", Severity: "CRITICAL", FixAvailable: "YES",
		FirstObserved: now.AddDate(0, 0, -100)}), DefaultPolicy(), now), AssessRemediation)
	if crit.Severity != "CRITICAL" {
		t.Errorf("an overdue critical raises severity to CRITICAL, got %q", crit.Severity)
	}
	high := find(t, Evaluate(only(Finding{ID: "y", Severity: "HIGH", FixAvailable: "YES",
		FirstObserved: now.AddDate(0, 0, -100)}), DefaultPolicy(), now), AssessRemediation)
	if high.Severity != "HIGH" {
		t.Errorf("an overdue high stays HIGH, got %q", high.Severity)
	}
}

func TestUnfixableFindingIsReportedNotFailed(t *testing.T) {
	now := time.Now()
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1, OldestScan: ptr(now)}}
		p.Findings = []Finding{{ID: "CVE-1", Severity: "CRITICAL", FixAvailable: "NO",
			FirstObserved: now.AddDate(0, 0, -900)}}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), now), AssessRemediation)
	if a.Status != StatusPass {
		t.Fatalf("a finding with no patch is not an overdue remediation; got %s: %s", a.Status, a.Evidence)
	}
	if !strings.Contains(a.Detail, "compensating control") {
		t.Errorf("the detail should say what to do instead of patching: %s", a.Detail)
	}
}

func TestPolicyIsStatedInEveryDetail(t *testing.T) {
	now := time.Now()
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1, OldestScan: ptr(now)}}
		p.Findings = []Finding{{ID: "a", Severity: "LOW", FixAvailable: "YES", FirstObserved: now}}
	})
	for _, a := range Evaluate(p, DefaultPolicy(), now) {
		switch a.Key {
		case AssessCoverage, AssessFreshness, AssessRemediation:
			if !strings.Contains(a.Detail, "policy:") {
				t.Errorf("%s detail must state the policy it measured against: %q", a.Key, a.Detail)
			}
		}
	}
}

func TestCoverageNoteSurvivesIntoTheDetail(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 2,
			OldestScan: ptr(time.Now()),
			Note:       "Defender reports the subscription as only partially covered"}}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessCoverage)
	if !strings.Contains(a.Detail, "only partially covered") {
		t.Errorf("a provider statement that is not a count must still reach the report: %s", a.Detail)
	}
}

// A class with nothing in it but a note still has something to say; a class
// with nothing at all should not clutter the report.
func TestEmptyClassesAreOmittedUnlessTheyCarryANote(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{
			{Class: ClassInstance, Covered: 1, OldestScan: ptr(time.Now())},
			{Class: ClassFunction},
			{Class: ClassImage, Note: "Defender for Containers is enabled"},
		}
	})
	a := find(t, Evaluate(p, DefaultPolicy(), time.Now()), AssessCoverage)
	if strings.Contains(a.Detail, string(ClassFunction)) {
		t.Errorf("an entirely empty class should be omitted: %s", a.Detail)
	}
	if !strings.Contains(a.Detail, string(ClassImage)) {
		t.Errorf("a class carrying only a note should appear: %s", a.Detail)
	}
}

func TestTotalsSumAcrossClasses(t *testing.T) {
	older, newer := time.Now().AddDate(0, 0, -50), time.Now().AddDate(0, 0, -2)
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{
			{Class: ClassInstance, Covered: 2, Gaps: 1, GapIDs: []string{"i-1"}, OldestScan: &newer},
			{Class: ClassFunction, Covered: 3, Gaps: 2, GapIDs: []string{"f-1", "f-2"}, OldestScan: &older},
		}
	})
	tot := p.Totals()
	if tot.Covered != 5 || tot.Gaps != 3 || len(tot.GapIDs) != 3 {
		t.Fatalf("totals should sum every class, got %+v", tot)
	}
	if tot.OldestScan == nil || !tot.OldestScan.Equal(older) {
		t.Errorf("the oldest scan across classes should win, got %v", tot.OldestScan)
	}
}

func TestCoverageForReportsWhetherAClassWasCollected(t *testing.T) {
	p := posture(func(p *Posture) {
		p.Coverage = []Coverage{{Class: ClassInstance, Covered: 1}}
	})
	if _, ok := p.CoverageFor(ClassInstance); !ok {
		t.Error("a collected class should be found")
	}
	if _, ok := p.CoverageFor(ClassImage); ok {
		t.Error("a class nobody looked at must not report as collected")
	}
}
