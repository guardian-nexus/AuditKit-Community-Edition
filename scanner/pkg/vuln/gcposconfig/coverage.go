// Package gcposconfig collects vulnerability coverage and findings from VM
// Manager's vulnerability reports.
//
// VM Manager is the right primitive for this product rather than Security
// Command Center. SCC's vulnerability sources need the Premium tier, which the
// small defence contractors this tool is sold to do not buy; VM Manager comes
// with Compute Engine and reports per-instance CVEs as long as the OS Config
// agent is running. Coverage is therefore a genuine per-instance question - an
// instance with no vulnerability report is one nothing is looking at - which is
// the same shape as Amazon Inspector and unlike Defender for Cloud.
//
// It also reports a real remediation clock. Each vulnerability carries a
// CreateTime documented as "the timestamp for when the vulnerability was first
// detected", so unlike Defender these findings can be aged honestly.
package gcposconfig

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/osconfig/v1"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// ReportsAPI lists VM Manager's vulnerability reports. The parent accepts "-"
// for both location and instance, which is how one call covers every zone.
type ReportsAPI interface {
	List(ctx context.Context, parent string, pageToken string) (*osconfig.ListVulnerabilityReportsResponse, error)
}

// InstancesAPI is the inventory denominator: what exists to be scanned.
type InstancesAPI interface {
	AggregatedList(ctx context.Context, project string, pageToken string) (*compute.InstanceAggregatedList, error)
}

// Clients bundles what Collect needs. A nil client means that part is skipped
// rather than reported as a gap.
type Clients struct {
	Reports   ReportsAPI
	Instances InstancesAPI
}

const maxPages = 100

// Collect reads coverage and findings in one pass. Unlike the AWS and Azure
// collectors these are not separable: VM Manager returns the findings inside
// the per-instance report that also establishes coverage, so asking for
// coverage already fetches them.
func Collect(ctx context.Context, c Clients, policy vuln.Policy, projectID string) *vuln.Posture {
	p := &vuln.Posture{
		Source:    "gcp-vm-manager",
		Provider:  "gcp",
		AccountID: projectID,
		Collected: time.Now(),
	}
	if c.Reports == nil || projectID == "" {
		p.Errors = append(p.Errors, "VM Manager client or project id not configured")
		return p
	}

	reports, err := listReports(ctx, c.Reports, projectID)
	if err != nil {
		// A project that has never enabled the API answers with a permission or
		// service-disabled error. That is "nothing is scanning", not a coverage
		// number, and it must not read as a pass.
		if isDisabled(err) {
			p.Errors = append(p.Errors, fmt.Sprintf(
				"VM Manager is not enabled on project %s: %v", projectID, err))
			return p
		}
		p.Errors = append(p.Errors, fmt.Sprintf("vulnerabilityReports.list: %v", err))
		return p
	}

	// Reports existing at all is the signal that VM Manager is running. An
	// empty list in a project with instances means the agent is nowhere.
	p.ScannerEnabled = true
	p.ClassEnabled = map[vuln.AssetClass]bool{vuln.ClassInstance: true}

	scanned := map[string]*osconfig.VulnerabilityReport{}
	for _, r := range reports {
		if id := instanceFromReportName(r.Name); id != "" {
			scanned[id] = r
		}
	}

	cov := vuln.Coverage{Class: vuln.ClassInstance}
	findings := []vuln.Finding{}
	stale := policy.StaleBefore(time.Now())
	counted := map[string]bool{}

	if c.Instances != nil {
		instances, err := listInstances(ctx, c.Instances, projectID, policy)
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("instances.aggregatedList: %v", err))
			return p
		}
		for _, inst := range instances {
			counted[inst.ID] = true
			report, ok := scanned[inst.ID]
			switch {
			case inst.Disposition == vuln.DispExcluded:
				cov.Excluded++
			case !ok:
				inst.Disposition = vuln.DispGap
				inst.Reason = "no VM Manager vulnerability report; the OS Config agent is not reporting for this instance"
				cov.Gaps++
				cov.GapIDs = append(cov.GapIDs, inst.ID)
			default:
				updated := parseTime(report.UpdateTime)
				inst.LastScanned = updated
				if updated != nil && updated.Before(stale) {
					inst.Disposition = vuln.DispStale
					cov.Stale++
					cov.StaleIDs = append(cov.StaleIDs, inst.ID)
				} else {
					inst.Disposition = vuln.DispCovered
					cov.Covered++
				}
				if updated != nil && (cov.OldestScan == nil || updated.Before(*cov.OldestScan)) {
					cov.OldestScan = updated
				}
			}
			p.Assets = append(p.Assets, inst)
		}
	}

	// Reports for instances the inventory did not return - a nil instances
	// client, or an instance created between the two calls - still count as
	// covered rather than being dropped.
	for id, report := range scanned {
		if counted[id] {
			continue
		}
		updated := parseTime(report.UpdateTime)
		cov.Covered++
		p.Assets = append(p.Assets, vuln.Asset{
			ID: id, Class: vuln.ClassInstance,
			Disposition: vuln.DispCovered, LastScanned: updated,
		})
	}

	for id, report := range scanned {
		for _, v := range report.Vulnerabilities {
			findings = append(findings, convert(id, v))
		}
	}

	p.Coverage = append(p.Coverage, cov)
	p.Findings = findings
	return p
}

func convert(assetID string, v *osconfig.VulnerabilityReportVulnerability) vuln.Finding {
	f := vuln.Finding{AssetID: assetID}
	if v.Details != nil {
		f.ID = v.Details.Cve
		f.Title = v.Details.Description
		f.Severity = strings.ToUpper(v.Details.Severity)
	}
	if f.ID == "" {
		f.ID = "(no CVE reported)"
	}
	if t := parseTime(v.CreateTime); t != nil {
		f.FirstObserved = *t
	}
	f.LastObserved = parseTime(v.UpdateTime)
	// An available inventory item is the upgraded package that fixes it, so its
	// presence is the fix-available signal. Absence means no patch is offered
	// on this image, which needs a compensating control rather than a patch.
	if len(v.AvailableInventoryItemIds) > 0 {
		f.FixAvailable = "YES"
	} else {
		f.FixAvailable = "NO"
	}
	return f
}

func listReports(ctx context.Context, api ReportsAPI, projectID string) ([]*osconfig.VulnerabilityReport, error) {
	parent := fmt.Sprintf("projects/%s/locations/-/instances/-", projectID)
	var out []*osconfig.VulnerabilityReport
	token := ""
	for page := 0; page < maxPages; page++ {
		resp, err := api.List(ctx, parent, token)
		if err != nil {
			return nil, err
		}
		out = append(out, resp.VulnerabilityReports...)
		if resp.NextPageToken == "" {
			return out, nil
		}
		token = resp.NextPageToken
	}
	return out, nil
}

func listInstances(ctx context.Context, api InstancesAPI, projectID string, policy vuln.Policy) ([]vuln.Asset, error) {
	var out []vuln.Asset
	token := ""
	for page := 0; page < maxPages; page++ {
		resp, err := api.AggregatedList(ctx, projectID, token)
		if err != nil {
			return nil, err
		}
		for _, scoped := range resp.Items {
			for _, inst := range scoped.Instances {
				if inst == nil || inst.Name == "" {
					continue
				}
				// A terminated instance is not a coverage gap: nothing is
				// running on it to be vulnerable.
				if inst.Status != "RUNNING" {
					continue
				}
				asset := vuln.Asset{ID: inst.Name, Class: vuln.ClassInstance}
				if inst.Labels != nil && policy.TagExcluded(inst.Labels) {
					asset.Disposition = vuln.DispExcluded
					asset.Reason = "excluded by vuln-policy.yaml scope"
				}
				out = append(out, asset)
			}
		}
		if resp.NextPageToken == "" {
			return out, nil
		}
		token = resp.NextPageToken
	}
	return out, nil
}

// instanceFromReportName pulls the instance out of
// projects/{p}/locations/{l}/instances/{i}/vulnerabilityReport.
func instanceFromReportName(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		if p == "instances" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

func isDisabled(err error) bool {
	s := err.Error()
	for _, marker := range []string{"has not been used", "SERVICE_DISABLED", "accessNotConfigured", "403"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}
