package vuln

import (
	"fmt"
	"strings"
	"time"
)

// Policy is the standard a posture is measured against. The Community edition
// measures against DefaultPolicy and has no loader: a configurable remediation
// window belongs with the ageing and SLA reporting, which is a Pro feature.
//
// The struct is kept identical to Pro's on purpose, so the collector and the
// evaluator are the same code in both editions rather than two that drift.
// Policy is the standard a posture is measured against. No framework states one
// for us: PCI-DSS 6.3.3 says critical patches within one month, and CMMC
// RA.L2-3.11.3 says "in accordance with risk assessments" and names no number
// at all. So the tool cannot invent a window and imply it is the requirement -
// it measures against a stated policy and says which policy it used.
type Policy struct {
	// RemediationDays maps a severity to the number of days allowed before a
	// finding is out of policy. Keys are the provider's own severity words,
	// upper-cased. Not every provider uses all of them: Microsoft Defender's
	// scale stops at HIGH and has no CRITICAL band, so an Azure finding is
	// never measured against the critical window. Consumed in phase 2; declared here so the
	// config file has one shape from the start.
	RemediationDays map[string]int `yaml:"remediation_days"`

	// StaleAfterDays is how old the most recent scan of an asset may be before
	// coverage is reported as stale. The default is tighter than PCI-DSS
	// 11.3.1's quarterly cadence on purpose: the cloud scanners this reads are
	// continuous, so a month-old scan already means something is wrong.
	StaleAfterDays int `yaml:"stale_after_days"`

	Scope Scope `yaml:"scope"`
}

// Scope is what the operator has decided not to scan. An asset excluded here is
// counted and listed but never failed - scoping dev accounts out is a decision,
// and the report should show the decision rather than punish it.
type Scope struct {
	ExcludeAccounts []string          `yaml:"exclude_accounts"`
	ExcludeTags     map[string]string `yaml:"exclude_tags"`
}

// DefaultPolicy is what applies when the operator has not written a config.
func DefaultPolicy() Policy {
	return Policy{
		RemediationDays: map[string]int{
			"CRITICAL": 30,
			"HIGH":     90,
			"MEDIUM":   180,
		},
		StaleAfterDays: 30,
	}
}

// Describe renders the policy for a report, so a reader can see the standard
// applied rather than having to assume one.
func (p Policy) Describe() string {
	return fmt.Sprintf("policy: critical %dd, high %dd, medium %dd, scan considered stale after %dd",
		p.RemediationDays["CRITICAL"], p.RemediationDays["HIGH"],
		p.RemediationDays["MEDIUM"], p.StaleAfterDays)
}

// StaleBefore is the instant a scan must be newer than to count as fresh.
func (p Policy) StaleBefore(now time.Time) time.Time {
	return now.AddDate(0, 0, -p.StaleAfterDays)
}

// AccountExcluded reports whether the operator scoped an account out.
func (p Policy) AccountExcluded(accountID string) bool {
	for _, a := range p.Scope.ExcludeAccounts {
		if strings.EqualFold(strings.TrimSpace(a), accountID) {
			return true
		}
	}
	return false
}

// TagExcluded reports whether any of an asset's tags scope it out.
func (p Policy) TagExcluded(tags map[string]string) bool {
	for k, want := range p.Scope.ExcludeTags {
		if got, ok := tags[k]; ok && strings.EqualFold(got, want) {
			return true
		}
	}
	return false
}
