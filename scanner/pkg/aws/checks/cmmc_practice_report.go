package checks

import (
	"context"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/mappings"
)

// CMMCPracticeReport reports the CMMC practices the automated checks did not
// measure, so a CMMC report carries all 110 requirements of NIST SP 800-171
// Rev 2 rather than only the subset this provider can scan.
//
// Without it the denominator is whatever happens to be automated, and a reader
// cannot tell a practice that passed from one that was never looked at. Most of
// the 110 are organisational - training records, personnel screening, physical
// access logs - and no cloud API answers them, so they are reported as manual
// with the evidence an assessor asks for.
//
// The covered set comes from the results the other suites actually produced,
// not from a hand-kept list of exclusions. A hand-kept list rots: the first
// automated check added for a practice would leave it reported twice, once with
// a verdict and once as an unanswered question.
type CMMCPracticeReport struct {
	covered map[string]bool
}

// NewCMMCPracticeReport takes the practice ids already reported by this
// provider's own checks.
func NewCMMCPracticeReport(covered map[string]bool) *CMMCPracticeReport {
	return &CMMCPracticeReport{covered: covered}
}

func (c *CMMCPracticeReport) Name() string { return "CMMC Practice Reporting" }

func (c *CMMCPracticeReport) Run(ctx context.Context) ([]CheckResult, error) {
	practices := mappings.CMMCPracticesExcept(c.covered)
	out := make([]CheckResult, 0, len(practices))
	for _, p := range practices {
		out = append(out, CheckResult{
			Control:  p.ID,
			Name:     "[CMMC] " + p.Name,
			Status:   StatusManual,
			Severity: "MEDIUM",
			Priority: PriorityMedium,
			Evidence: "MANUAL: An assessor will ask to see " + p.Evidence,
			// Deliberately not a remediation command. These are requirements
			// about how the organisation operates; a CLI line would imply the
			// practice can be satisfied by changing a setting.
			Remediation:     p.Remedy,
			ScreenshotGuide: "Attach the document, record or configuration showing " + p.Evidence,
			ConsoleURL:      "https://console.aws.amazon.com/",
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CMMC": p.ID},
		})
	}
	return out, nil
}
