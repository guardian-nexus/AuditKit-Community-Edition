package tracker

import (
	"fmt"
	"sort"
	"time"
)

// DefaultEvidenceMaxAge is how long collected evidence stays current before it
// should be recaptured. Audit periods are typically annual and assessors expect
// evidence from within the period under review, so evidence older than this is
// reported as stale rather than counted as done.
const DefaultEvidenceMaxAge = 90 * 24 * time.Hour

// ScanItem is the minimal view of a scan result the tracker needs.
type ScanItem struct {
	ControlID string
	Name      string
	Status    string
}

// RequiresEvidence reports whether a control needs a human to produce evidence.
//
// Everything except ERROR does. A passing control still needs a screenshot
// proving it was configured that way, which is the part people forget: the
// scanner saying S3 is encrypted is not what the assessor samples, the console
// screenshot is. ERROR means the check could not run, so there is nothing to
// evidence until the permission is fixed and the scan repeated.
func RequiresEvidence(status string) bool {
	return status != "ERROR" && status != ""
}

// SyncFromScan reconciles the tracker against the controls a scan just
// produced. Controls new to this scan are added. Controls that no longer appear
// are marked not currently required rather than deleted, because evidence
// already collected for them is still part of the audit trail.
func (t *EvidenceTracker) SyncFromScan(items []ScanItem) (added, retired int) {
	seen := make(map[string]bool, len(items))

	for _, it := range items {
		if !RequiresEvidence(it.Status) {
			continue
		}
		seen[it.ControlID] = true

		existing, ok := t.Controls[it.ControlID]
		if !ok {
			added++
			existing = EvidenceItem{ControlID: it.ControlID, ControlName: it.Name}
		}
		existing.ControlName = it.Name
		existing.Status = it.Status
		existing.Required = true
		t.Controls[it.ControlID] = existing
	}

	for id, item := range t.Controls {
		if !seen[id] && item.Required {
			item.Required = false
			t.Controls[id] = item
			retired++
		}
	}

	t.LastScan = time.Now()
	t.LastUpdate = t.LastScan
	t.TotalControls = len(t.Controls)
	t.Collected = t.countCollected()
	return added, retired
}

// Record marks evidence as collected for a control, noting who captured it and
// where the artifact lives.
func (t *EvidenceTracker) Record(controlID, notes, artifact, by string) error {
	item, exists := t.Controls[controlID]
	if !exists {
		return fmt.Errorf("control %s is not tracked - run a scan first so the tracker knows about it", controlID)
	}

	now := time.Now()
	item.EvidenceCollected = true
	item.CollectedDate = &now
	if notes != "" {
		item.Notes = notes
	}
	if artifact != "" {
		item.ScreenshotPath = artifact
	}
	if by != "" {
		item.CollectedBy = by
	}

	t.Controls[controlID] = item
	t.Collected = t.countCollected()
	t.LastUpdate = now
	return t.Save()
}

// IsStale reports whether an item's evidence predates the cutoff.
func (i EvidenceItem) IsStale(maxAge time.Duration) bool {
	if !i.EvidenceCollected || i.CollectedDate == nil {
		return false
	}
	return time.Since(*i.CollectedDate) > maxAge
}

// Summary is a point-in-time view of evidence collection.
type Summary struct {
	Required    int
	Collected   int
	Stale       int
	Outstanding int
	Retired     int
}

// Summarise counts the tracker against the given staleness cutoff. Stale
// evidence is deliberately not counted as collected: evidence from outside the
// audit period is evidence the assessor will reject.
func (t *EvidenceTracker) Summarise(maxAge time.Duration) Summary {
	var s Summary
	for _, item := range t.Controls {
		if !item.Required {
			s.Retired++
			continue
		}
		s.Required++
		switch {
		case item.IsStale(maxAge):
			s.Stale++
		case item.EvidenceCollected:
			s.Collected++
		default:
			s.Outstanding++
		}
	}
	return s
}

// Outstanding returns the controls still needing evidence, stale ones included,
// ordered by control ID so successive runs read consistently.
func (t *EvidenceTracker) Outstanding(maxAge time.Duration) []EvidenceItem {
	out := []EvidenceItem{}
	for _, item := range t.Controls {
		if !item.Required {
			continue
		}
		if !item.EvidenceCollected || item.IsStale(maxAge) {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return out
}

// StaleItems returns collected evidence that has aged past the cutoff.
func (t *EvidenceTracker) StaleItems(maxAge time.Duration) []EvidenceItem {
	out := []EvidenceItem{}
	for _, item := range t.Controls {
		if item.Required && item.IsStale(maxAge) {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CollectedDate.Before(*out[j].CollectedDate)
	})
	return out
}
