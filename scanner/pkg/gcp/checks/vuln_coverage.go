package checks

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/osconfig/v1"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln/gcposconfig"
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

// NewVulnCoverageChecks builds its own clients from application default
// credentials, matching how the other GCP checkers in this package work.
func NewVulnCoverageChecks(ctx context.Context, projectID string, emit Emit) *VulnCoverageChecks {
	c := &VulnCoverageChecks{projectID: projectID, emit: emit, policy: vuln.DefaultPolicy()}

	osSvc, err := osconfig.NewService(ctx, option.WithScopes(osconfig.CloudPlatformScope))
	if err != nil {
		c.initErr = fmt.Errorf("osconfig service: %w", err)
		return c
	}
	c.clients.Reports = osconfigReports{svc: osSvc}

	// The inventory is the denominator. Without it coverage cannot be
	// expressed as a fraction, so its absence is an error rather than a
	// silently smaller number.
	compSvc, err := compute.NewService(ctx, option.WithScopes(compute.CloudPlatformScope))
	if err != nil {
		c.initErr = fmt.Errorf("compute service: %w", err)
		return c
	}
	c.clients.Instances = computeInstances{svc: compSvc}
	return c
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
	decided := cov
	if hasFresh && cov.Status == vuln.StatusPass && fresh.Status != vuln.StatusPass {
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
	if hasFresh && fresh.Status != vuln.StatusPass {
		res = applyAssessment(res, fresh)
		res.Remediation = "11.3.1 requires scans at least quarterly and rescans until findings are resolved"
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
// assessments. VM Manager reports when each vulnerability was first detected,
// so unlike Defender for Cloud these can be aged against the policy window.
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
		ScreenshotGuide: "Compute Engine -> VM Manager -> Screenshot the oldest unremediated critical and high vulnerabilities with their first-detected dates | Screenshot the risk acceptance for anything deliberately not patched",
		ConsoleURL:      "https://console.cloud.google.com/compute/osPatchManagement",
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
		Remediation: "Enable the OS Config API and grant the scanning principal roles/osconfig.vulnerabilityReportViewer and roles/compute.viewer",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.cloud.google.com/compute/osPatchManagement",
		Frameworks:  map[string]string{"CMMC": control},
	}
}
