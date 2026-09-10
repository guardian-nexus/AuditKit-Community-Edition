package vuln

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status values mirror the scanner's own set. Only Pass and Fail are scoreable;
// Error means the check could not run, which is what a denied API call is.
const (
	StatusPass  = "PASS"
	StatusFail  = "FAIL"
	StatusInfo  = "INFO"
	StatusError = "ERROR"
)

// AssessmentKey names a judgement about vulnerability posture. It is not a
// control identifier: the per-provider adapter decides which controls each
// judgement answers, which is what keeps this package free of framework detail.
type AssessmentKey string

const (
	// AssessScannerEnabled - is a vulnerability scanner running at all.
	AssessScannerEnabled AssessmentKey = "scanner_enabled"
	// AssessCoverage - does it reach every in-scope asset.
	AssessCoverage AssessmentKey = "coverage"
	// AssessFreshness - has it looked recently enough.
	AssessFreshness AssessmentKey = "freshness"
)

// Assessment is one framework-neutral judgement, ready for an adapter to map
// onto whatever controls it satisfies.
type Assessment struct {
	Key         AssessmentKey
	Status      string
	Severity    string
	Evidence    string
	Remediation string
	// Detail carries the asset lists and the policy statement. It lands in a
	// report's remediation detail and in the evidence package, never in a
	// summary line.
	Detail string
}

const maxNamed = 10

// Evaluate turns a posture into assessments. It never infers a pass from
// missing data: a posture carrying collection errors produces ERROR, and a
// scanner that is switched off produces one clear failure rather than a
// coverage percentage of zero across every class.
func Evaluate(p *Posture, policy Policy, now time.Time) []Assessment {
	if len(p.Errors) > 0 {
		return []Assessment{{
			Key:      AssessCoverage,
			Status:   StatusError,
			Severity: "HIGH",
			Evidence: fmt.Sprintf("Could not read vulnerability coverage from %s: %s",
				p.Source, strings.Join(p.Errors, "; ")),
			Remediation: "Grant the scanning role read access to the vulnerability service, then re-run",
			Detail: "Coverage was not evaluated. This is reported as an error rather than a pass " +
				"because a call that did not complete proves nothing about posture.",
		}}
	}

	if !p.ScannerEnabled {
		return []Assessment{{
			Key:         AssessScannerEnabled,
			Status:      StatusFail,
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("No vulnerability scanning is active in this account (%s reports disabled)", p.Source),
			Remediation: "Enable vulnerability scanning, or import results from the scanner you do run",
			Detail: "Coverage and remediation ageing cannot be assessed while nothing is scanning. " +
				"If scanning happens outside this cloud account, import those results instead so the " +
				"evidence package reflects it.",
		}}
	}

	out := []Assessment{{
		Key:      AssessScannerEnabled,
		Status:   StatusPass,
		Evidence: fmt.Sprintf("Vulnerability scanning is active (%s)", p.Source),
	}}

	total := p.Totals()
	if total.InScope() == 0 && total.NotEligible+total.Excluded+total.Pending == 0 {
		out = append(out, Assessment{
			Key:      AssessCoverage,
			Status:   StatusInfo,
			Evidence: "No assets of a scannable class were found in this account",
			Detail:   "Nothing to cover. Re-run against an account that holds workloads.",
		})
		return out
	}

	out = append(out, assessCoverage(p, total, policy))
	out = append(out, assessFreshness(p, total, policy, now))
	return out
}

func assessCoverage(p *Posture, total Coverage, policy Policy) Assessment {
	a := Assessment{Key: AssessCoverage}
	detail := []string{policy.Describe(), perClass(p)}

	if total.Gaps == 0 {
		a.Status = StatusPass
		a.Evidence = fmt.Sprintf("All %d in-scope assets are covered by %s",
			total.InScope(), p.Source)
		if total.Excluded+total.NotEligible > 0 {
			a.Evidence += fmt.Sprintf(" (%d excluded by policy, %d not eligible for scanning)",
				total.Excluded, total.NotEligible)
		}
		a.Detail = strings.Join(detail, "\n\n")
		return a
	}

	pct := 100 * float64(total.Covered+total.Stale) / float64(total.InScope())
	a.Status = StatusFail
	a.Severity = "HIGH"
	a.Evidence = fmt.Sprintf("%d of %d in-scope assets are not covered by any vulnerability scan (%.0f%% covered)",
		total.Gaps, total.InScope(), pct)
	a.Remediation = "Bring the uncovered assets into scanning, or scope them out explicitly in vuln-policy.yaml"
	detail = append(detail, "Uncovered assets:\n"+namedList(total.GapIDs, p))
	a.Detail = strings.Join(detail, "\n\n")
	return a
}

func assessFreshness(p *Posture, total Coverage, policy Policy, now time.Time) Assessment {
	a := Assessment{Key: AssessFreshness}
	cutoff := policy.StaleBefore(now)

	if total.Stale == 0 {
		a.Status = StatusPass
		a.Evidence = fmt.Sprintf("Every covered asset was scanned within %d days", policy.StaleAfterDays)
		if total.OldestScan != nil {
			a.Evidence += fmt.Sprintf(" (oldest scan %s, %d days ago)",
				total.OldestScan.Format("2006-01-02"), daysAgo(*total.OldestScan, now))
		}
		a.Detail = policy.Describe()
		return a
	}

	a.Status = StatusFail
	a.Severity = "MEDIUM"
	a.Evidence = fmt.Sprintf("%d covered assets have not been scanned since %s (%d-day window)",
		total.Stale, cutoff.Format("2006-01-02"), policy.StaleAfterDays)
	a.Remediation = "Investigate why scanning stopped for these assets; a stale scan reports no new findings rather than none"
	a.Detail = strings.Join([]string{
		policy.Describe(),
		"A stale scan is not the same as a clean one: it returns the findings that were true when it " +
			"last ran, so zero new findings from a stale scanner is not evidence of zero vulnerabilities.",
		"Stale assets:\n" + namedList(total.StaleIDs, p),
	}, "\n\n")
	return a
}

// perClass renders the coverage breakdown, skipping classes with no assets so
// an account with no containers does not read as having a container problem.
func perClass(p *Posture) string {
	var b strings.Builder
	b.WriteString("Coverage by asset class:")
	for _, c := range p.Coverage {
		if c.InScope()+c.Excluded+c.NotEligible+c.Pending == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n  %-18s covered %d, stale %d, uncovered %d",
			c.Class, c.Covered, c.Stale, c.Gaps)
		if c.Excluded > 0 {
			fmt.Fprintf(&b, ", excluded %d", c.Excluded)
		}
		if c.NotEligible > 0 {
			fmt.Fprintf(&b, ", not eligible %d", c.NotEligible)
		}
		if c.Pending > 0 {
			fmt.Fprintf(&b, ", first scan pending %d", c.Pending)
		}
	}
	return b.String()
}

// namedList prints up to maxNamed asset ids with the scanner's own reason, then
// says how many more there are. A real account can hold thousands, and none of
// them belong in a report summary.
func namedList(ids []string, p *Posture) string {
	reason := map[string]string{}
	for _, a := range p.Assets {
		if a.Reason != "" {
			reason[a.ID] = a.Reason
		}
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)

	var b strings.Builder
	for i, id := range sorted {
		if i == maxNamed {
			fmt.Fprintf(&b, "\n  ... and %d more (full list in the evidence package)", len(sorted)-maxNamed)
			break
		}
		if r := reason[id]; r != "" {
			fmt.Fprintf(&b, "\n  %s  (%s)", id, r)
		} else {
			fmt.Fprintf(&b, "\n  %s", id)
		}
	}
	return b.String()
}

func daysAgo(t, now time.Time) int {
	return int(now.Sub(t).Hours() / 24)
}
