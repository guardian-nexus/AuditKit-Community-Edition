package checks

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
)

// CISGKEReport accounts for the CIS GKE v2.0.0 recommendations a scan does not
// answer.
//
// These were the last requirements the scanner knew about and never mentioned.
// CIS GKE v2.0.0 is not a selectable framework - its recommendations are reached
// only as tags inside a GCP scan - so no code path existed that could
// report a gap, and the unassessed recommendations appeared nowhere: not as a
// finding, not as a manual item, not as a denominator.
//
// Reported as one row rather than one per recommendation, for the reason
// 800-53 is: the useful content is the fraction and why the remainder is out
// of reach, and most of these need access to the worker nodes rather than the
// control plane the scanner talks to.
//
// The split between what the benchmark marks Automated and Manual comes from
// the catalog, so it stays true when the benchmark is revised rather than
// being a number written here once.
type CISGKEReport struct {
	assessed map[string]bool
}

func NewCISGKEReport(assessed map[string]bool) *CISGKEReport {
	return &CISGKEReport{assessed: assessed}
}

func (c *CISGKEReport) Name() string { return "CIS GKE v2.0.0 coverage" }

func (c *CISGKEReport) Run(ctx context.Context) ([]CheckResult, error) {
	catalog := mappings.CatalogFor("cis-gke")
	if catalog == nil {
		return nil, nil
	}

	var automatedGap, manualGap []string
	for id, assessment := range catalog {
		if c.assessed[id] {
			continue
		}
		if assessment == "Automated" {
			automatedGap = append(automatedGap, id)
		} else {
			manualGap = append(manualGap, id)
		}
	}
	sort.Strings(automatedGap)
	sort.Strings(manualGap)

	done := len(catalog) - len(automatedGap) - len(manualGap)
	if len(automatedGap)+len(manualGap) == 0 {
		return nil, nil
	}

	return []CheckResult{{
		Control:  "CIS-GKE-COVERAGE",
		Name:     "CIS GKE v2.0.0 recommendations not assessed",
		Status:   StatusManual,
		Severity: "MEDIUM",
		Evidence: fmt.Sprintf(
			"MANUAL: %d of %d CIS GKE v2.0.0 recommendations are assessed. "+
				"%d are marked Manual by the benchmark and need a human to judge them. "+
				"%d are marked Automated but need access to the worker nodes and kubelet "+
				"configuration, which this scanner does not have - it reads the managed "+
				"control plane only.",
			done, len(catalog), len(manualGap), len(automatedGap)),
		Remediation: "Run the CIS benchmark tooling on the nodes themselves for the " +
			"node-level recommendations, and record the manual assessments alongside this scan.",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Node-level CIS results from kube-bench or the equivalent, plus the manual assessment record.",
		Frameworks:      map[string]string{"CIS-GKE": "coverage"},
	}}, nil
}
