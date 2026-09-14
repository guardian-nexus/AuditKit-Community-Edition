// The Community edition answers whether scanning is happening and whether it
// reaches every in-scope asset. It deliberately does not fetch findings, so no
// remediation ageing is performed and RA.L2-3.11.3 is not reported: measuring
// findings against a remediation window, and the evidence package built from
// it, are AuditKit Pro. Third-party scan import is Pro for the same reason.
package checks

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/osconfig/v1"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/vuln"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/vuln/gcposconfig"
)

// Emit selects which control this instance answers. A scan of every framework
// runs the CMMC and PCI passes back to back, so an instance that emitted both
// would report the same control twice and count it twice in the score.
type Emit int

const (
	EmitCMMC Emit = iota
	EmitPCI
)

// VulnCoverageChecks answers the vulnerability-scanning practices from VM
// Manager's reports. It is the only file in this package that knows a coverage
// assessment maps onto RA.L2-3.11.2 and PCI-DSS 11.3.1.
type VulnCoverageChecks struct {
	clients   gcposconfig.Clients
	policy    vuln.Policy
	projectID string
	emit      Emit
	initErr   error
}

// osconfigReports adapts the generated service to the narrow interface.
type osconfigReports struct{ svc *osconfig.Service }

func (o osconfigReports) List(ctx context.Context, parent, pageToken string) (*osconfig.ListVulnerabilityReportsResponse, error) {
	call := o.svc.Projects.Locations.Instances.VulnerabilityReports.List(parent).Context(ctx)
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}
	return call.Do()
}

type computeInstances struct{ svc *compute.Service }

func (c computeInstances) AggregatedList(ctx context.Context, project, pageToken string) (*compute.InstanceAggregatedList, error) {
	call := c.svc.Instances.AggregatedList(project).Context(ctx)
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}
	return call.Do()
}

// newWithClients is the injectable form. The clients are constructed by the
// caller, which is what makes the control mapping testable without credentials.
func newWithClients(clients gcposconfig.Clients, projectID string, emit Emit, initErr error) *VulnCoverageChecks {
	// The Community edition measures against the built-in policy. Configurable
	// remediation windows ship with the ageing and SLA reporting in AuditKit Pro.
	return &VulnCoverageChecks{clients: clients, projectID: projectID, emit: emit,
		policy: vuln.DefaultPolicy(), initErr: initErr}
}

// NewVulnCoverageChecksWithClients is the injectable constructor, matching the
// AWS adapter whose exported constructor already takes its clients. GCP was the
// one provider whose control mapping could only be reached with live
// credentials, and it is the one whose adapter shipped unreachable once.
func NewVulnCoverageChecksWithClients(clients gcposconfig.Clients, projectID string, emit Emit) *VulnCoverageChecks {
	return newWithClients(clients, projectID, emit, nil)
}

// NewVulnCoverageChecks builds its clients from application default
// credentials, matching how the other GCP checkers in this package work.
func NewVulnCoverageChecks(ctx context.Context, projectID string, emit Emit) *VulnCoverageChecks {
	var clients gcposconfig.Clients

	osSvc, err := osconfig.NewService(ctx, option.WithScopes(osconfig.CloudPlatformScope))
	if err != nil {
		return newWithClients(clients, projectID, emit, fmt.Errorf("osconfig service: %w", err))
	}
	clients.Reports = osconfigReports{svc: osSvc}

	// The inventory is the denominator. Without it coverage cannot be
	// expressed as a fraction, so its absence is an error rather than a
	// silently smaller number.
	compSvc, err := compute.NewService(ctx, option.WithScopes(compute.CloudPlatformScope))
	if err != nil {
		return newWithClients(clients, projectID, emit, fmt.Errorf("compute service: %w", err))
	}
	clients.Instances = computeInstances{svc: compSvc}
	return newWithClients(clients, projectID, emit, nil)
}

func (c *VulnCoverageChecks) Name() string { return "Vulnerability Scan Coverage" }

func (c *VulnCoverageChecks) Run(ctx context.Context) ([]CheckResult, error) {
	control, name := "RA.L2-3.11.2", "[CMMC L2] Vulnerability Scanning"
	if c.emit == EmitPCI {
		control, name = "PCI-11.3.1", "Internal Vulnerability Scanning"
	}
	if c.initErr != nil {
		return []CheckResult{c.errorResult(control, name,
			"Could not reach VM Manager: "+c.initErr.Error())}, nil
	}
	posture := gcposconfig.Collect(ctx, c.clients, c.policy, c.projectID)
	// VM Manager returns findings inside the same call that establishes
	// coverage, so they are discarded here rather than never fetched.
	// Remediation ageing is a Pro feature.
	posture.Findings = nil
	assessments := map[vuln.AssessmentKey]vuln.Assessment{}
	for _, a := range vuln.Evaluate(posture, c.policy, time.Now()) {
		assessments[a.Key] = a
	}

	if c.emit == EmitPCI {
		return []CheckResult{c.pciInternalScanControl(assessments)}, nil
	}
	return []CheckResult{c.scanningControl(assessments)}, nil
}

func (c *VulnCoverageChecks) scanningControl(a map[vuln.AssessmentKey]vuln.Assessment) CheckResult {
	res := CheckResult{
		Control:         "RA.L2-3.11.2",
		Name:            "[CMMC L2] Vulnerability Scanning",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Compute Engine -> VM Manager -> OS patch management -> Screenshot the vulnerability reports list showing every instance | Screenshot an instance's vulnerability report",
		ConsoleURL:      "https://console.cloud.google.com/compute/osPatchManagement",
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

func (c *VulnCoverageChecks) pciInternalScanControl(a map[vuln.AssessmentKey]vuln.Assessment) CheckResult {
	res := CheckResult{
		Control:         "PCI-11.3.1",
		Name:            "Internal Vulnerability Scanning",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Compute Engine -> VM Manager -> Screenshot the vulnerability reports covering every in-scope instance, with the report timestamps visible",
		ConsoleURL:      "https://console.cloud.google.com/compute/osPatchManagement",
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
		res.Remediation = "Scanning must reach every in-scope system for 11.3.1; install the OS Config agent on the uncovered instances"
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
		Remediation: "Enable the OS Config API and grant the scanning principal roles/osconfig.vulnerabilityReportViewer and roles/compute.viewer",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.cloud.google.com/compute/osPatchManagement",
		Frameworks:  map[string]string{"CMMC": control},
	}
}
