package checks

import (
	"fmt"
	"strings"
	"time"
)

// These helpers match pkg/aws/checks: a check whose API call failed reports an
// ERROR row for its control instead of vanishing, and a check that skipped
// resources it could not read does not report PASS (threat model A1).

// checkError is the result for a check whose API call failed before it could
// evaluate anything. These checks used to return an empty result, so the
// failure vanished; now the control is named in the report's errored list.
func checkError(control, name string, frameworks map[string]string, err error) CheckResult {
	return CheckResult{
		Control:     control,
		Name:        name,
		Status:      StatusError,
		Evidence:    fmt.Sprintf("Could not run this check: %v", err),
		Remediation: "Grant the scanning identity read access to this service (see SECURITY.md), then re-run the scan",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		Frameworks:  frameworks,
	}
}

// unreadable collects the resources a check could not inspect. Per-resource
// lookups were written "if err == nil && <finding>", so a denied lookup read as
// "nothing wrong here" and a user whose policies could not be listed counted as
// clean. A check that found no problem among the resources it could read, but
// skipped some, has not shown that the control passes.
type unreadable struct {
	names []string
	first error
}

func (u *unreadable) add(name string, err error) {
	u.names = append(u.names, name)
	if u.first == nil {
		u.first = err
	}
}

// passOrError returns pass unchanged when every resource was read, and an ERROR
// naming the unread ones otherwise.
func (u *unreadable) passOrError(pass CheckResult) CheckResult {
	if len(u.names) == 0 {
		return pass
	}
	// Collapse repeats: a lookup denied for every user is one line, not fifty.
	counts := map[string]int{}
	var order []string
	for _, n := range u.names {
		if counts[n] == 0 {
			order = append(order, n)
		}
		counts[n]++
	}
	shown := make([]string, 0, len(order))
	for _, n := range order {
		if counts[n] > 1 {
			shown = append(shown, fmt.Sprintf("%s x%d", n, counts[n]))
		} else {
			shown = append(shown, n)
		}
	}
	pass.Status = StatusError
	pass.Evidence = fmt.Sprintf("Could not complete %d lookup(s), so the check is incomplete: %s (first error: %v)",
		len(u.names), strings.Join(shown, ", "), u.first)
	return pass
}

// finish applies the same rule to a check that returns several results for
// one control: when any lookup failed, a PASS or INFO built from what could
// not be read becomes ERROR, and a check that produced nothing at all reports
// an ERROR row for its control instead of vanishing. A FAIL stands.
func (u *unreadable) finish(results []CheckResult, control, name string) []CheckResult {
	if len(u.names) == 0 {
		return results
	}
	if len(results) == 0 {
		return []CheckResult{u.passOrError(checkError(control, name, nil, u.first))}
	}
	for i := range results {
		if results[i].Status == StatusPass || results[i].Status == StatusInfo {
			results[i] = u.passOrError(results[i])
		}
	}
	return results
}
