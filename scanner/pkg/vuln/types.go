// Package vuln turns what a vulnerability scanner already found into the
// evidence an assessor asks for: which assets are covered, how fresh the
// coverage is, and how long findings have gone unremediated against a stated
// policy.
//
// It is deliberately not a scanner. Collectors read a provider's own scan
// results; importers read a third-party tool's output file. Both produce a
// Posture, and Evaluate turns a Posture into framework-neutral Assessments.
// Only the per-provider adapter in pkg/<provider>/checks knows about control
// identifiers, so a new scanner source costs one collector and nothing else.
package vuln

import "time"

// AssetClass groups assets that a scanner reaches in different ways. A gap in
// one class says nothing about another: Inspector can cover every EC2 instance
// in an account and no container image in it.
type AssetClass string

const (
	ClassInstance AssetClass = "instance"
	ClassImage    AssetClass = "container_image"
	ClassFunction AssetClass = "function"
	ClassRepo     AssetClass = "image_repository"
)

// Disposition is what a scanner's reason for not covering an asset means for an
// assessment. Providers report dozens of reasons; an assessor only cares which
// of these buckets each one falls into.
type Disposition string

const (
	// DispCovered - scanned, and the scan is within the freshness window.
	DispCovered Disposition = "covered"
	// DispStale - the scanner knows the asset but has not looked recently.
	DispStale Disposition = "stale"
	// DispGap - the asset should be scanned and is not. This is the finding.
	DispGap Disposition = "gap"
	// DispExcluded - the operator deliberately excluded it. Counted and listed,
	// never failed: a contractor who scopes dev accounts out has made a choice,
	// not a mistake.
	DispExcluded Disposition = "excluded"
	// DispNotEligible - the scanner cannot scan this asset at all: unsupported
	// OS or runtime, stopped, terminated, archived.
	DispNotEligible Disposition = "not_eligible"
	// DispPending - transient. A first scan is queued or running, and it will
	// resolve without anyone doing anything.
	DispPending Disposition = "pending"
)

// Asset is one thing a scanner should be looking at.
type Asset struct {
	ID          string      `json:"id"`
	Class       AssetClass  `json:"class"`
	Disposition Disposition `json:"disposition"`
	// Reason is the provider's own status string, kept verbatim. An assessor
	// asking "why is this one not scanned" wants the scanner's answer, not ours.
	Reason      string     `json:"reason,omitempty"`
	LastScanned *time.Time `json:"last_scanned,omitempty"`
}

// Coverage is a scanner's reach over one asset class.
type Coverage struct {
	Class       AssetClass `json:"class"`
	Covered     int        `json:"covered"`
	Stale       int        `json:"stale"`
	Gaps        int        `json:"gaps"`
	Excluded    int        `json:"excluded"`
	NotEligible int        `json:"not_eligible"`
	Pending     int        `json:"pending"`
	// GapIDs and StaleIDs name the assets behind the counts. An evidence
	// package needs the list, not just the number.
	GapIDs   []string `json:"gap_ids,omitempty"`
	StaleIDs []string `json:"stale_ids,omitempty"`
	// OldestScan is the least recently scanned covered asset in the class.
	OldestScan *time.Time `json:"oldest_scan,omitempty"`
}

// InScope is every asset the class expects a scanner to reach: what is covered
// or stale, plus what should be and is not. Excluded, ineligible and pending
// assets are outside the denominator by design.
func (c Coverage) InScope() int { return c.Covered + c.Stale + c.Gaps }

// Posture is everything one collector or importer learned in a single pass.
type Posture struct {
	// Source names the scanner, not the cloud: "aws-inspector2", "nessus".
	Source    string    `json:"source"`
	Provider  string    `json:"provider"`
	AccountID string    `json:"account_id,omitempty"`
	Collected time.Time `json:"collected"`

	// ScannerEnabled is whether the scanner is switched on at all. False here
	// makes every coverage number meaningless, so Evaluate reports that rather
	// than a coverage percentage of zero.
	ScannerEnabled bool `json:"scanner_enabled"`

	// ClassEnabled records per-asset-class enablement, because a scanner can be
	// on for virtual machines and off for container images. An unset class with
	// assets in it is a gap with a much more useful reason than "not covered".
	ClassEnabled map[AssetClass]bool `json:"class_enabled,omitempty"`

	Coverage []Coverage `json:"coverage,omitempty"`
	Assets   []Asset    `json:"assets,omitempty"`

	// Errors holds calls that did not complete. A collector that could not read
	// coverage records the failure here and Evaluate emits ERROR, because a
	// denied API call must never read as compliance. Asserting a pass from a
	// call that never returned is how the GCP PCI 8.6.3 and 10.4.1.1 defects
	// shipped.
	Errors []string `json:"errors,omitempty"`
}

// Coverage for one class, and whether it was collected at all.
func (p *Posture) CoverageFor(class AssetClass) (Coverage, bool) {
	for _, c := range p.Coverage {
		if c.Class == class {
			return c, true
		}
	}
	return Coverage{}, false
}

// Totals sums every collected class.
func (p *Posture) Totals() Coverage {
	t := Coverage{}
	for _, c := range p.Coverage {
		t.Covered += c.Covered
		t.Stale += c.Stale
		t.Gaps += c.Gaps
		t.Excluded += c.Excluded
		t.NotEligible += c.NotEligible
		t.Pending += c.Pending
		t.GapIDs = append(t.GapIDs, c.GapIDs...)
		t.StaleIDs = append(t.StaleIDs, c.StaleIDs...)
		if c.OldestScan != nil && (t.OldestScan == nil || c.OldestScan.Before(*t.OldestScan)) {
			t.OldestScan = c.OldestScan
		}
	}
	return t
}
