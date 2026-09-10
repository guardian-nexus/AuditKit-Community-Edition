package checks

import (
	"context"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/awsinspector"
)

// VulnCoverageChecks answers the vulnerability-scanning practices from what
// Inspector actually reaches, rather than telling the reader to document a
// procedure. It is the only place in this package that knows a coverage
// assessment maps onto RA.L2-3.11.2 and PCI-DSS 11.3.1; pkg/vuln carries no
// framework detail so Azure and GCP reuse the same evaluator.
// Emit selects which control this instance answers. A scan of every framework
// runs the CMMC and PCI passes back to back, so an instance that emitted both
// would report the same control twice and count it twice in the score.
type Emit int

const (
	EmitCMMC Emit = iota
	EmitPCI
)

type VulnCoverageChecks struct {
	clients   awsinspector.Clients
	policy    vuln.Policy
	accountID string
	emit      Emit
}

// The Community edition measures against the built-in policy. Configurable
// remediation windows ship with the ageing and SLA reporting in AuditKit Pro.
func NewVulnCoverageChecks(c awsinspector.Clients, accountID string, emit Emit) *VulnCoverageChecks {
	return &VulnCoverageChecks{clients: c, policy: vuln.DefaultPolicy(), accountID: accountID, emit: emit}
}

func (c *VulnCoverageChecks) Name() string { return "Vulnerability Scan Coverage" }

func (c *VulnCoverageChecks) Run(ctx context.Context) ([]CheckResult, error) {
	posture := awsinspector.Collect(ctx, c.clients, c.policy, c.accountID)
	// Remediation ageing needs the findings as well as the coverage. Only the
	// CMMC pass asks for them, so a PCI-only scan does not pay for the walk.
	if c.emit == EmitCMMC && posture.ScannerEnabled && len(posture.Errors) == 0 {
		awsinspector.CollectFindings(ctx, c.clients.Inspector, posture)
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

// RA.L2-3.11.2 - scan for vulnerabilities periodically and when new ones are
// identified. Coverage answers the first half; freshness answers the second,
// because a scanner that has not run cannot have noticed a new CVE.
func (c *VulnCoverageChecks) scanningControl(a map[vuln.AssessmentKey]vuln.Assessment) CheckResult {
	res := CheckResult{
		Control:         "RA.L2-3.11.2",
		Name:            "[CMMC L2] Vulnerability Scanning",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Inspector Console -> Account management -> Screenshot showing scanning enabled for EC2, ECR and Lambda | Inspector -> Coverage -> Screenshot the resource coverage list",
		ConsoleURL:      "https://console.aws.amazon.com/inspector/v2/home#/coverage",
		Frameworks:      map[string]string{"CMMC": "RA.L2-3.11.2", "NIST 800-171": "3.11.2"},
	}

	// A scanner that is off, or a read that failed, decides the control on its
	// own - there is no coverage number worth reporting in either case.
	if enabled, ok := a[vuln.AssessScannerEnabled]; ok && enabled.Status != vuln.StatusPass {
		return applyAssessment(res, enabled)
	}
	if cov, ok := a[vuln.AssessCoverage]; ok && cov.Status == vuln.StatusError {
		return applyAssessment(res, cov)
	}

	cov, hasCov := a[vuln.AssessCoverage]
	fresh, hasFresh := a[vuln.AssessFreshness]
	if !hasCov {
		return c.errorResult(res.Control, res.Name, "Coverage was not assessed")
	}

	// The worse of the two decides the control, and both are reported.
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
	if hasCov && decided.Key != cov.Key {
		res.Evidence += " | " + cov.Evidence
	}
	return res
}

// PCI-DSS 11.3.1 - internal vulnerability scans at least quarterly and after
// any significant change, with rescans until resolved. This control used to be
// claimed by the "is Inspector switched on" check, which proves none of it.
func (c *VulnCoverageChecks) pciInternalScanControl(a map[vuln.AssessmentKey]vuln.Assessment) CheckResult {
	res := CheckResult{
		Control:         "PCI-11.3.1",
		Name:            "Internal Vulnerability Scanning",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Inspector Console -> Coverage -> Screenshot showing every in-scope resource covered, with the last-scanned column visible",
		ConsoleURL:      "https://console.aws.amazon.com/inspector/v2/home#/coverage",
		Frameworks:      map[string]string{FrameworkPCI: "11.3.1"},
	}

	if enabled, ok := a[vuln.AssessScannerEnabled]; ok && enabled.Status != vuln.StatusPass {
		return applyAssessment(res, enabled)
	}

	cov, hasCov := a[vuln.AssessCoverage]
	fresh, hasFresh := a[vuln.AssessFreshness]
	if !hasCov {
		return c.errorResult(res.Control, res.Name, "Coverage was not assessed")
	}
	if cov.Status == vuln.StatusError {
		return applyAssessment(res, cov)
	}

	// 11.3.1 needs both reach and cadence, so a gap in either fails it.
	if cov.Status != vuln.StatusPass {
		res = applyAssessment(res, cov)
		res.Remediation = "Scanning must reach every in-scope system for 11.3.1; bring the uncovered assets into scope"
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
	res.RemediationDetail = detailWithPolicy(cov, fresh, hasFresh)
	return res
}

// RA.L2-3.11.3 - remediate vulnerabilities in accordance with risk
// assessments. The practice names no window, so the check measures against the
// stated policy and reports which one it used. Reported only when findings were
// actually collected: zero overdue from data nobody fetched is not a pass.
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
		ScreenshotGuide: "Inspector Console -> Findings -> Sort by first-observed date -> Screenshot the oldest unremediated critical and high findings | Exceptions -> Screenshot the risk acceptance for anything deliberately not patched",
		ConsoleURL:      "https://console.aws.amazon.com/inspector/v2/home#/findings",
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

func detailWithPolicy(cov, fresh vuln.Assessment, hasFresh bool) string {
	out := cov.Detail
	if hasFresh && fresh.Detail != "" {
		out += "\n\n" + fresh.Detail
	}
	return out
}

// errorResult keeps a check that could not run out of the compliance score.
// ERROR is excluded from scoring; PASS would assert compliance from a call that
// never returned.
func (c *VulnCoverageChecks) errorResult(control, name, evidence string) CheckResult {
	return CheckResult{
		Control:     control,
		Name:        name,
		Status:      StatusError,
		Severity:    "HIGH",
		Evidence:    evidence,
		Remediation: "Grant inspector2:ListCoverage, inspector2:BatchGetAccountStatus, ec2:DescribeInstances, lambda:ListFunctions and ecr:DescribeRepositories to the scanning role",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/inspector/v2/home",
		Frameworks:  map[string]string{"CMMC": control},
	}
}
