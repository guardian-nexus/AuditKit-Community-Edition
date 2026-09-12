package gcp

import (
	"context"
	"fmt"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
	"strings"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/storage"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/gcp/checks"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/sqladmin/v1"
)

type GCPScanner struct {
	// Cached result of runSuites, so the shared suite list runs once per scan.
	suiteCache  []ScanResult
	suiteCached bool

	projectID      string
	storageClient  *storage.Client
	iamClient      *admin.IamClient
	computeService *compute.Service
	sqlService     *sqladmin.Service
	loggingClient  *logging.ConfigClient
	kmsClient      *kms.KeyManagementClient
	gkeService     *container.Service
}

type ScanResult struct {
	Control           string
	Name              string
	Status            string
	Evidence          string
	Remediation       string
	RemediationDetail string
	Severity          string
	ScreenshotGuide   string
	ConsoleURL        string
	Frameworks        map[string]string
}

func NewScanner(projectID string) (*GCPScanner, error) {
	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %v", err)
	}

	// Use the IAM Admin API client (not google.golang.org/api/iam/v1)
	iamClient, err := admin.NewIamClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %v", err)
	}

	computeService, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}

	// Use sqladmin v1 (not v1beta4)
	sqlService, err := sqladmin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create SQL service: %v", err)
	}

	loggingClient, err := logging.NewConfigClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create logging client: %v", err)
	}

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %v", err)
	}

	gkeService, err := container.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GKE service: %v", err)
	}

	return &GCPScanner{
		projectID:      projectID,
		storageClient:  storageClient,
		iamClient:      iamClient,
		computeService: computeService,
		sqlService:     sqlService,
		loggingClient:  loggingClient,
		kmsClient:      kmsClient,
		gkeService:     gkeService,
	}, nil
}

func (s *GCPScanner) Close() error {
	if s.storageClient != nil {
		s.storageClient.Close()
	}
	if s.iamClient != nil {
		s.iamClient.Close()
	}
	if s.loggingClient != nil {
		s.loggingClient.Close()
	}
	if s.kmsClient != nil {
		s.kmsClient.Close()
	}
	return nil
}

func (s *GCPScanner) GetProjectID() string {
	return s.projectID
}

func (s *GCPScanner) GetAccountID(ctx context.Context) string {
	return s.projectID
}

func (s *GCPScanner) ScanServices(ctx context.Context, services []string, verbose bool, framework string) ([]ScanResult, error) {
	var results []ScanResult
	framework = strings.ToLower(framework)

	switch framework {
	case "soc2":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	case "pci", "pci-dss":
		results = append(results, s.runPCIChecks(ctx, verbose)...)
	case "cmmc":
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
	case "cis", "cis-gcp":
		results = append(results, s.runCISChecks(ctx, verbose)...)
	case "all",
		// Derived frameworks are reported through the crosswalk, which can
		// map any suite's findings. Falling through to the SOC2 suite alone
		// meant an 800-53, ISO or HIPAA scan never saw the PCI, CMMC or CIS
		// checks that map onto it.
		"800-53", "nist800-53", "nist-800-53", "iso27001", "iso-27001", "gdpr", "nist-csf", "csf", "hipaa", "fedramp-low", "fedramp-moderate", "fedramp-high":
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
		results = append(results, s.runPCIChecks(ctx, verbose)...)
		results = append(results, s.runCMMCChecks(ctx, verbose)...)
		results = append(results, s.runCISChecks(ctx, verbose)...)
		// The paths share one suite list, so the same finding arrives once
		// per path.
		results = dedupeIdenticalResults(results)
	default:
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	return results, nil
}

// allSuites is every check suite this provider has, constructed once.
//
// Each framework path used to hand-pick its own subset, so a suite claiming a
// framework ran only if somebody had remembered to add it to that path. The
// PCI path constructed one aggregate checker while the suites carrying PCI
// tags - BigQuery, Compute, GKE, SQL, network, IAM - never ran on a PCI scan,
// so the report was a fraction of what the mappings already covered and said
// nothing about the difference.
//
// The framework filter belongs at the report layer, where
// controlMatchesFramework already applies it, including to the results that
// carry no Frameworks field and match through their control id in the
// framework's catalog. An in-scan filter on tag presence is narrower than that
// and silently drops them.
//
// The aggregate PCI checker is listed here for the same reason. The PCI path
// used to construct it itself, so it was the one suite runSuites did not know
// about, and the only way to run it was to run that path.
func (s *GCPScanner) allSuites() []checks.Check {
	return []checks.Check{
		checks.NewGCPCC1Checks(s.iamClient, s.projectID),
		checks.NewGCPCC2Checks(),
		checks.NewGCPCC3Checks(s.projectID),
		checks.NewGCPCC4Checks(s.projectID),
		checks.NewGCPCC5Checks(s.projectID),
		checks.NewGCPCC6Checks(s.storageClient, s.iamClient, s.computeService, s.sqlService, s.projectID),
		checks.NewGCPCC7Checks(s.loggingClient, s.computeService, s.projectID),
		checks.NewGCPCC8Checks(s.projectID),
		checks.NewGCPCC9Checks(s.storageClient, s.sqlService, s.projectID),
		checks.NewGCPAvailabilityConfidentialityChecks(s.storageClient, s.sqlService, s.computeService, s.projectID),
		checks.NewStorageChecks(s.storageClient, s.projectID),
		checks.NewIAMChecks(s.iamClient, s.projectID),
		checks.NewComputeChecks(s.computeService, s.projectID),
		checks.NewNetworkChecks(s.computeService, s.projectID),
		checks.NewSQLChecks(s.sqlService, s.projectID),
		checks.NewKMSChecks(s.kmsClient, s.projectID),
		checks.NewLoggingChecks(s.loggingClient, s.projectID),
		checks.NewBigQueryChecks(s.projectID),
		checks.NewGCPCISManualChecks(s.projectID),
		checks.NewGKEChecks(s.gkeService, s.projectID),
		checks.NewGCPCMMCLevel1Checks(s.storageClient, s.iamClient, s.computeService, s.projectID),
		checks.NewGCPPCIChecks(s.storageClient, s.iamClient, s.computeService, s.sqlService, s.kmsClient, s.loggingClient, s.projectID),
	}
}

// runSuites runs every suite and converts the results. Shared by the framework
// paths so none of them can quietly run a different set.
func (s *GCPScanner) runSuites(ctx context.Context, verbose bool, label string) []ScanResult {
	// Run once per scan. The framework paths share this list, so a scan
	// that calls several of them would otherwise re-run every suite.
	//
	// Each caller gets its own copy. The paths append their extras to what
	// this returns, and appending onto the cached slice itself writes into
	// the backing array the next path's rows start from.
	if s.suiteCached {
		return append([]ScanResult(nil), s.suiteCache...)
	}
	var results []ScanResult
	for _, check := range s.allSuites() {
		if verbose {
			fmt.Printf("  Running %s check module...\n", label)
		}
		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("  Warning: %v\n", err)
		}
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Name:              cr.Name,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          severityOf(cr),
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}
	s.suiteCache, s.suiteCached = results, true
	return append([]ScanResult(nil), results...)
}

// severityOf reads a result's severity from whichever field the suite filled.
// The GCP suites mostly set Priority.Level; the CMMC suites set only Severity,
// and the CMMC path that used to run them directly read that field. Now that
// every suite reaches the report through runSuites, a blank here would drop a
// HIGH finding to LOW at the report layer.
func severityOf(cr checks.CheckResult) string {
	if cr.Priority.Level != "" {
		return cr.Priority.Level
	}
	return cr.Severity
}

func (s *GCPScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		fmt.Println("Running SOC2 compliance checks for GCP...")
	}
	return s.runSuites(ctx, verbose, "SOC2")
}

// runVulnCoverage builds the vulnerability coverage check for one framework and
// converts its results. emit keeps the CMMC and PCI passes from each reporting
// the other's control, which would double-count it on a scan of all frameworks.
func (s *GCPScanner) runVulnCoverage(ctx context.Context, emit checks.Emit) []ScanResult {
	vc := checks.NewVulnCoverageChecks(ctx, s.projectID, emit)
	crs, err := vc.Run(ctx)
	if err != nil {
		return nil
	}
	out := make([]ScanResult, 0, len(crs))
	for _, cr := range crs {
		out = append(out, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	return out
}

func (s *GCPScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		fmt.Println("Running PCI-DSS v4.0.1 checks for GCP...")
	}

	// Every suite, once. The aggregate PCI checker this path used to
	// construct itself is in allSuites with the rest.
	results := s.runSuites(ctx, verbose, "PCI-DSS")

	// PCI-DSS 11.3.1 wants scans quarterly across every in-scope system.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitPCI)...)

	return results
}

func (s *GCPScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		fmt.Println("Running CMMC - all 110 practices reported, the technical ones measured")
		fmt.Println("")
		fmt.Println("IMPORTANT DISCLAIMER:")
		fmt.Println("This scanner tests technical controls that can be automated.")
		fmt.Println("")
		fmt.Println("CMMC Level 1 requires 17 practices. Many controls require")
		fmt.Println("organizational documentation and policies that cannot be")
		fmt.Println("verified through automated scanning.")
		fmt.Println("")
		fmt.Println("A high automated check score does NOT mean you are CMMC")
		fmt.Println("compliant. This is a technical assessment tool, not a")
		fmt.Println("compliance certification.")
		fmt.Println("")
	}

	// Every suite, once. Level 1 is in allSuites; constructing it here as
	// well, which this path used to do, ran it twice and reported each of
	// its practices twice.
	results := s.runSuites(ctx, verbose, "CMMC")

	// Vulnerability scan coverage, read from VM Manager rather than asked for as a document.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitCMMC)...)

	// Every practice nothing above reported, reported as a manual requirement.
	// A CMMC report's denominator is the benchmark's 110, not the subset this
	// provider can automate, or a reader cannot tell an absent practice from a
	// satisfied one. This runs after the suites so a practice answered only
	// through another suite's CMMC tag is not reported as unanswered as well.
	results = append(results, s.reportRemainingCMMCPractices(ctx, results)...)

	if verbose {
		fmt.Printf("\nCMMC scan complete: all %d practices reported\n", mappings.CMMCPracticeCount)
		fmt.Println("")
		fmt.Println("WHAT AUDITKIT PRO ADDS:")
		fmt.Println("  - More of the 110 practices measured rather than asked for")
		fmt.Println("  - Evidence packages an assessor can read directly")
		fmt.Println("  - Multi-account scanning and continuous monitoring")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro")
	}

	return results
}

// reportRemainingCMMCPractices fills in the practices the suites above did not
// name. The covered set is computed from the results just produced rather than
// kept by hand, so adding an automated check for a practice removes it from
// here automatically instead of leaving it reported twice.
func (s *GCPScanner) reportRemainingCMMCPractices(ctx context.Context, reported []ScanResult) []ScanResult {
	covered := map[string]bool{}
	for _, r := range reported {
		covered[r.Control] = true
		// A tag may name more than one practice. None do today, but a
		// single-key read would silently report both of them again.
		for _, id := range strings.Split(r.Frameworks["CMMC"], ",") {
			if id = strings.TrimSpace(id); id != "" {
				covered[id] = true
			}
		}
	}
	var out []ScanResult
	rows, _ := checks.NewCMMCPracticeReport(covered).Run(ctx)
	for _, cr := range rows {
		out = append(out, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	return out
}

func (s *GCPScanner) runCISChecks(ctx context.Context, verbose bool) []ScanResult {
	if verbose {
		cisEd, _ := mappings.EditionFor("CIS-GCP")
		fmt.Println("Running " + cisEd.Describe())
		fmt.Println("")
	}

	// Every suite, once. This path used to run ten of them itself, keeping
	// the rows with a CIS-GCP tag under a "[CIS GCP n] ..." display name, and
	// then call runSuites too, so a CIS scan ran those suites twice and
	// reported each finding twice. The report layer derives the CIS
	// recommendation id from the tag, so nothing here renames or filters rows.
	results := s.runSuites(ctx, verbose, "CIS")

	// Every recommendation nothing above measured, reported with the evidence
	// an assessor asks for. A report's denominator is the benchmark's 93, not
	// the subset this scanner reaches, or a reader cannot tell an absent
	// recommendation from a satisfied one.
	results = append(results, s.reportRemainingCISGCP(ctx, results)...)
	results = append(results, s.reportRemainingCISGKE(ctx, results)...)

	if verbose {
		// The old line quoted a control total for a benchmark version nobody
		// had read. State what this scan covers; the registry states the edition.
		fmt.Println("\nThis scan covers the CIS controls automatable via the GCP API")
		fmt.Println("")
	}

	return results
}

// reportRemainingCISGCP fills in the recommendations the checks above did not
// name. The covered set comes from the results just produced rather than a
// hand-kept list, so automating one of these removes it from here rather than
// leaving it reported twice.
func (s *GCPScanner) reportRemainingCISGCP(ctx context.Context, reported []ScanResult) []ScanResult {
	covered := map[string]bool{}
	for _, r := range reported {
		covered[strings.TrimPrefix(r.Control, "CIS-GCP-")] = true
		for _, id := range strings.Split(r.Frameworks["CIS-GCP"], ",") {
			if id = strings.TrimSpace(id); id != "" {
				covered[id] = true
			}
		}
	}
	var out []ScanResult
	rows, _ := checks.NewCISGCPManualReport(covered).Run(ctx)
	for _, cr := range rows {
		out = append(out, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Severity,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}
	return out
}

// dedupeIdenticalResults removes results that are the same finding reported by
// more than one framework path. It keys on control, status and evidence, so
// genuinely distinct findings that share a control id - several resources
// failing the same criterion - are preserved.
//
// Needed since the framework paths share one suite list: a scan that runs
// several of them, which is what the derived frameworks do, would otherwise
// report every finding once per path.
func dedupeIdenticalResults(results []ScanResult) []ScanResult {
	seen := make(map[string]bool, len(results))
	deduped := make([]ScanResult, 0, len(results))
	for _, result := range results {
		key := result.Control + "\x00" + result.Status + "\x00" + result.Evidence
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, result)
	}
	return deduped
}

// reportRemainingCISGKE accounts for the CIS-GKE recommendations the checks
// above did not reach. The assessed set is derived from the results just
// produced, so answering one removes it from the gap rather than leaving it
// counted both ways.
func (s *GCPScanner) reportRemainingCISGKE(ctx context.Context, reported []ScanResult) []ScanResult {
	assessed := map[string]bool{}
	for _, r := range reported {
		for _, id := range strings.Split(r.Frameworks["CIS-GKE"], ",") {
			if id = strings.TrimSpace(id); id != "" {
				assessed[id] = true
			}
		}
	}
	rows, _ := checks.NewCISGKEReport(assessed).Run(ctx)
	var out []ScanResult
	for _, cr := range rows {
		out = append(out, ScanResult{
			Control:         cr.Control,
			Name:            cr.Name,
			Status:          cr.Status,
			Evidence:        cr.Evidence,
			Remediation:     cr.Remediation,
			Severity:        cr.Severity,
			ScreenshotGuide: cr.ScreenshotGuide,
			Frameworks:      cr.Frameworks,
		})
	}
	return out
}
