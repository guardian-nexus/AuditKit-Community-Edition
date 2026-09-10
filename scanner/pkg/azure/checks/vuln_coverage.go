package checks

import (
	"context"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/azuredefender"
)

// Emit selects which control this instance answers. A scan of every framework
// runs the CMMC and PCI passes back to back, so an instance that emitted both
// would report the same control twice and count it twice in the score.
type Emit int

const (
	EmitCMMC Emit = iota
	EmitPCI
)

// VulnCoverageChecks answers the vulnerability-scanning practices from what
// Defender for Cloud actually covers. It is the only file in this package that
// knows a coverage assessment maps onto RA.L2-3.11.2 and PCI-DSS 11.3.1;
// pkg/vuln carries no framework detail, which is what lets AWS, Azure and GCP
// share one evaluator.
type VulnCoverageChecks struct {
	clients        azuredefender.Clients
	policy         vuln.Policy
	subscriptionID string
	emit           Emit
}

// The Community edition measures against the built-in policy. Configurable
// remediation windows ship with the ageing and SLA reporting in AuditKit Pro.
func NewVulnCoverageChecks(c azuredefender.Clients, subscriptionID string, emit Emit) *VulnCoverageChecks {
	return &VulnCoverageChecks{clients: c, policy: vuln.DefaultPolicy(),
		subscriptionID: subscriptionID, emit: emit}
}

func (c *VulnCoverageChecks) Name() string { return "Vulnerability Scan Coverage" }

func (c *VulnCoverageChecks) Run(ctx context.Context) ([]CheckResult, error) {
	posture := azuredefender.Collect(ctx, c.clients, c.policy, c.subscriptionID)
	if c.emit == EmitCMMC && posture.ScannerEnabled && len(posture.Errors) == 0 {
		azuredefender.CollectFindings(ctx, c.clients.SubAssessments, c.subscriptionID, posture)
	}

	assessments := map[vuln.AssessmentKey]vuln.Assessment{}
	for _, a := range vuln.Evaluate(posture, c.policy, time.Now()) {
		assessments[a.Key] = a
	}

	if c.emit == EmitPCI {
		return []CheckResult{c.pciInternalScanControl(assessments)}, nil
	}
	out := []CheckResult{c.scanningControl(assessments)}
	if r, ok := c.remediationControl(assessments); ok {
		out = append(out, r)
	}
	return out, nil
}

func (c *VulnCoverageChecks) scanningControl(a map[vuln.AssessmentKey]vuln.Assessment) CheckResult {
	res := CheckResult{
		Control:         "RA.L2-3.11.2",
		Name:            "[CMMC L2] Vulnerability Scanning",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Defender for Cloud -> Environment settings -> the subscription -> Screenshot the Defender for Servers plan showing On | Defender for Cloud -> Inventory -> Screenshot the resource coverage",
		ConsoleURL:      "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings",
		Frameworks:      map[string]string{"CMMC": "RA.L2-3.11.2", "NIST 800-171": "3.11.2"},
	}
	if enabled, ok := a[vuln.AssessScannerEnabled]; ok && enabled.Status != vuln.StatusPass {
		return applyAssessment(res, enabled)
	}
	cov, hasCov := a[vuln.AssessCoverage]
	if !hasCov {
		return c.errorResult(res.Control, res.Name, "Coverage was not assessed")
	}
	if cov.Status == vuln.StatusError {
		return applyAssessment(res, cov)
	}
	fresh, hasFresh := a[vuln.AssessFreshness]
	// Freshness can fail a control but must not make it unknown. A provider
	// that reports coverage without scan timestamps leaves the cadence
	// unproven, not disproven, and demoting a proven coverage result to INFO
	// would drop it out of the score and under-report the provider. The
	// caveat is appended to the evidence instead.
	decided := cov
	if hasFresh && cov.Status == vuln.StatusPass && fresh.Status == vuln.StatusFail {
		decided = fresh
	}
	res = applyAssessment(res, decided)
	if hasFresh && decided.Key != fresh.Key {
		res.Evidence += " | " + fresh.Evidence
	}
	if decided.Key != cov.Key {
		res.Evidence += " | " + cov.Evidence
	}
	return res
}

// PCI-DSS 11.3.1 - internal vulnerability scans at least quarterly across every
// in-scope system, with rescans until findings are resolved.
func (c *VulnCoverageChecks) pciInternalScanControl(a map[vuln.AssessmentKey]vuln.Assessment) CheckResult {
	res := CheckResult{
		Control:         "PCI-11.3.1",
		Name:            "Internal Vulnerability Scanning",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Defender for Cloud -> Recommendations -> Screenshot the vulnerability assessment findings with their resource coverage",
		ConsoleURL:      "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5",
		Frameworks:      map[string]string{FrameworkPCI: "11.3.1"},
	}
	if enabled, ok := a[vuln.AssessScannerEnabled]; ok && enabled.Status != vuln.StatusPass {
		return applyAssessment(res, enabled)
	}
	cov, hasCov := a[vuln.AssessCoverage]
	if !hasCov {
		return c.errorResult(res.Control, res.Name, "Coverage was not assessed")
	}
	if cov.Status == vuln.StatusError {
		return applyAssessment(res, cov)
	}
	fresh, hasFresh := a[vuln.AssessFreshness]
	if cov.Status != vuln.StatusPass {
		res = applyAssessment(res, cov)
		res.Remediation = "Scanning must reach every in-scope system for 11.3.1; onboard the uncovered resources"
		return res
	}
	// 11.3.1 names a cadence explicitly - at least quarterly, and rescans
	// until resolved - so an unproven cadence cannot be a pass here even
	// though it can stand for RA.L2-3.11.2. A failure and an unknown are
	// carried through with their own statuses rather than collapsed together.
	if hasFresh && fresh.Status != vuln.StatusPass {
		res = applyAssessment(res, fresh)
		if fresh.Status == vuln.StatusFail {
			res.Remediation = "11.3.1 requires scans at least quarterly and rescans until findings are resolved"
		} else {
			res.Remediation = "Capture the scan cadence from the provider's console for the evidence package; " +
				"11.3.1 requires at least quarterly scans and this API does not report scan dates"
		}
		return res
	}
	res.Status = StatusPass
	res.Priority = PriorityInfo
	res.Evidence = cov.Evidence
	if hasFresh {
		res.Evidence += " | " + fresh.Evidence
	}
	res.RemediationDetail = cov.Detail
	return res
}

// RA.L2-3.11.3 - remediate vulnerabilities in accordance with risk
// assessments. Defender reports no first-observed date, so this frequently
// lands as INFO with the reason rather than a pass or a fail; see the
// azuredefender package comment.
func (c *VulnCoverageChecks) remediationControl(a map[vuln.AssessmentKey]vuln.Assessment) (CheckResult, bool) {
	rem, ok := a[vuln.AssessRemediation]
	if !ok {
		return CheckResult{}, false
	}
	res := CheckResult{
		Control:         "RA.L2-3.11.3",
		Name:            "[CMMC L2] Remediate Vulnerabilities",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Defender for Cloud -> Recommendations -> Vulnerabilities -> Screenshot the open findings by severity | Screenshot the remediation timeline or exception register for anything deliberately not patched",
		ConsoleURL:      "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5",
		Frameworks:      map[string]string{"CMMC": "RA.L2-3.11.3", "NIST 800-171": "3.11.3"},
	}
	return applyAssessment(res, rem), true
}

func applyAssessment(res CheckResult, a vuln.Assessment) CheckResult {
	res.Status = a.Status
	res.Evidence = a.Evidence
	if a.Remediation != "" {
		res.Remediation = a.Remediation
	}
	if a.Detail != "" {
		res.RemediationDetail = a.Detail
	}
	if a.Severity != "" {
		res.Severity = a.Severity
	}
	if a.Status == StatusPass {
		res.Priority = PriorityInfo
	}
	return res
}

// errorResult keeps a check that could not run out of the compliance score.
func (c *VulnCoverageChecks) errorResult(control, name, evidence string) CheckResult {
	return CheckResult{
		Control:     control,
		Name:        name,
		Status:      StatusError,
		Severity:    "HIGH",
		Evidence:    evidence,
		Remediation: "Grant the scanning principal Security Reader on the subscription so Defender pricing, sub-assessments and the VM inventory can be read",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings",
		Frameworks:  map[string]string{"CMMC": control},
	}
}
