// Package importers reads a third-party vulnerability scan file and turns it
// into the same Posture the cloud collectors produce.
//
// This is the phase that reaches an actual customer. Amazon Inspector, Defender
// for Servers and Security Command Center Premium all bill per asset, and the
// small defence contractors this product is sold to run Nessus, or Trivy in a
// pipeline, or nothing. Without an import path the vulnerability evidence
// feature only serves the customers who least need the price.
//
// Two limits are shared by all three formats and are reported rather than
// glossed over.
//
// None of them says when a finding was first observed. Nessus reports the
// plugin's publication date, Trivy and Grype report the CVE's. Ageing from
// those would fail a host for a vulnerability disclosed before the host
// existed, so imported findings arrive unageable and the evaluator declines to
// measure them against the remediation window. Counts by severity are still
// reported, and are still evidence.
//
// None of them can establish coverage. A scan file lists the targets the
// scanner was pointed at; the hosts nobody pointed it at appear nowhere in the
// file. So these postures are not coverage-authoritative and the evaluator
// reports what was scanned as a floor rather than a fraction.
package importers

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// Supported lists the sources Parse accepts, for help text and error messages.
func Supported() []string { return []string{"grype", "nessus", "trivy"} }

// Parse reads a scan file from a named source.
func Parse(source, path string, policy vuln.Policy) (*vuln.Posture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}

	switch strings.ToLower(strings.TrimSpace(source)) {
	case "nessus":
		return parseNessus(data, policy, filepath.Base(path))
	case "trivy":
		return parseTrivy(data, policy, filepath.Base(path))
	case "grype":
		return parseGrype(data, policy, filepath.Base(path))
	}
	return nil, fmt.Errorf("unknown source %q; supported: %s",
		source, strings.Join(Supported(), ", "))
}

// Detect guesses the source from the file's own content, so a user who names
// the wrong source gets told rather than getting an empty report. Returns an
// empty string when nothing matches.
func Detect(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	head := string(data)
	if len(head) > 4096 {
		head = head[:4096]
	}
	switch {
	case strings.Contains(head, "NessusClientData"):
		return "nessus"
	case strings.Contains(head, `"SchemaVersion"`) || strings.Contains(head, `"ArtifactType"`):
		return "trivy"
	case strings.Contains(head, `"matches"`) && strings.Contains(head, `"grype"`):
		return "grype"
	}
	return ""
}

// normaliseSeverity maps a scanner's own word onto the policy's severity keys.
// An unrecognised word is upper-cased and passed through: the policy names no
// window for it, so Aging counts it and never calls it overdue, which is the
// safe direction for a word nobody anticipated.
func normaliseSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH", "IMPORTANT":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW", "MINOR":
		return "LOW"
	case "NEGLIGIBLE", "INFORMATIONAL", "INFO", "NONE", "":
		return "INFORMATIONAL"
	}
	return strings.ToUpper(strings.TrimSpace(s))
}

// finalise fills in the parts every import shares: the coverage roll-up over
// whatever assets the file mentioned, and the flags that keep the evaluator
// honest about what an import can and cannot establish.
//
// It applies the staleness window too. Marking every scanned asset "covered"
// regardless of when the scan ran produced a report that passed freshness
// while printing a year-old scan date in the same line.
func finalise(p *vuln.Posture, policy vuln.Policy, assets map[string]*vuln.Asset) {
	p.ScannerEnabled = true
	p.CoverageAuthoritative = false

	ids := make([]string, 0, len(assets))
	for id := range assets {
		ids = append(ids, id)
	}
	// Map iteration order is random, and a report whose asset list reshuffles
	// between runs looks like a changing estate.
	sort.Strings(ids)

	// Group by the asset's own class. Filing an image scan under the instance
	// class put Trivy's coverage where nothing looked for it, and its scan
	// date with it.
	stale := policy.StaleBefore(p.Collected)
	byClass := map[vuln.AssetClass]*vuln.Coverage{}
	for _, id := range ids {
		a := assets[id]
		cov, ok := byClass[a.Class]
		if !ok {
			cov = &vuln.Coverage{Class: a.Class}
			byClass[a.Class] = cov
		}
		if a.LastScanned != nil && a.LastScanned.Before(stale) {
			a.Disposition = vuln.DispStale
			cov.Stale++
			cov.StaleIDs = append(cov.StaleIDs, a.ID)
		} else {
			cov.Covered++
		}
		if a.LastScanned != nil && (cov.OldestScan == nil || a.LastScanned.Before(*cov.OldestScan)) {
			cov.OldestScan = a.LastScanned
		}
		p.Assets = append(p.Assets, *a)
	}
	classes := make([]vuln.AssetClass, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	for _, c := range classes {
		p.Coverage = append(p.Coverage, *byClass[c])
	}

	sort.SliceStable(p.Findings, func(i, j int) bool {
		if p.Findings[i].AssetID != p.Findings[j].AssetID {
			return p.Findings[i].AssetID < p.Findings[j].AssetID
		}
		return p.Findings[i].ID < p.Findings[j].ID
	})
}
