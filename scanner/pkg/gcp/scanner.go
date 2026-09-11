package gcp

import (
	"context"
	"fmt"
	"github.com/guardian-nexus/auditkit/scanner/pkg/mappings"
	"strings"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/storage"
	"github.com/guardian-nexus/auditkit/scanner/pkg/gcp/checks"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/sqladmin/v1"
)

type GCPScanner struct {
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
	default:
		results = append(results, s.runSOC2Checks(ctx, verbose)...)
	}

	return results, nil
}

func (s *GCPScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running SOC2 compliance checks for GCP...")
	}

	// Run SOC2 CC1-CC9 check modules that exist in GCP
	soc2Checks := []checks.Check{
		// CC1 & CC2: Control Environment & Communication
		// FIXED: Match actual constructor signatures from soc2_cc1_cc2.go
		checks.NewGCPCC1Checks(s.iamClient, s.projectID),
		checks.NewGCPCC2Checks(),

		// CC3, CC4, CC5: Risk Assessment, Monitoring, Control Activities
		// FIXED: Match actual constructor signatures from soc2_cc3_cc5.go
		checks.NewGCPCC3Checks(s.projectID),
		checks.NewGCPCC4Checks(s.projectID),
		checks.NewGCPCC5Checks(s.projectID),

		// CC6, CC7, CC8, CC9: Access Controls, Operations, Change Mgmt, Risk Mitigation
		// FIXED: Match actual constructor signatures from soc2_cc6_cc9.go
		checks.NewGCPCC6Checks(s.storageClient, s.iamClient, s.computeService, s.sqlService, s.projectID),
		checks.NewGCPCC7Checks(s.loggingClient, s.computeService, s.projectID),
		checks.NewGCPCC8Checks(s.projectID),
		checks.NewGCPCC9Checks(s.storageClient, s.sqlService, s.projectID),
		checks.NewGCPAvailabilityConfidentialityChecks(s.storageClient, s.sqlService, s.computeService, s.projectID),

		// Also run traditional checks for backward compatibility
		checks.NewStorageChecks(s.storageClient, s.projectID),
		checks.NewIAMChecks(s.iamClient, s.projectID),
		checks.NewComputeChecks(s.computeService, s.projectID),
		checks.NewNetworkChecks(s.computeService, s.projectID),
		checks.NewSQLChecks(s.sqlService, s.projectID),
	}

	for _, check := range soc2Checks {
		if verbose {
			// GCP checks don't have Name() method, use type assertion or reflection
			fmt.Printf("  Running SOC2 check module...\n")
		}

		checkResults, err := check.Run(ctx)
		if err != nil && verbose {
			fmt.Printf("    Warning: %v\n", err)
		}

		// Convert CheckResult to ScanResult
		for _, cr := range checkResults {
			results = append(results, ScanResult{
				Control:           cr.Control,
				Name:              cr.Name,
				Status:            cr.Status,
				Evidence:          cr.Evidence,
				Remediation:       cr.Remediation,
				RemediationDetail: cr.RemediationDetail,
				Severity:          cr.Priority.Level,
				ScreenshotGuide:   cr.ScreenshotGuide,
				ConsoleURL:        cr.ConsoleURL,
				Frameworks:        cr.Frameworks,
			})
		}
	}

	return results
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
	var results []ScanResult

	if verbose {
		fmt.Println("Running PCI-DSS v4.0.1 checks for GCP...")
		fmt.Println("Checking all 12 PCI-DSS requirements...")
	}

	// Use the comprehensive GCPPCIChecks implementation
	pciChecker := checks.NewGCPPCIChecks(
		s.storageClient,
		s.iamClient,
		s.computeService,
		s.sqlService,
		s.kmsClient,
		s.loggingClient,
		s.projectID,
	)

	checkResults, _ := pciChecker.Run(ctx)
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Name:              cr.Name,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	// PCI-DSS 11.3.1 wants scans quarterly across every in-scope system.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitPCI)...)

	return results
}

func (s *GCPScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

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

	// ONLY Level 1 (17 practices) - Note: CMMC checks need different signature
	level1 := checks.NewGCPCMMCLevel1Checks(s.storageClient, s.iamClient, s.computeService, s.projectID)
	results1, _ := level1.Run(ctx)
	for _, cr := range results1 {
		results = append(results, ScanResult{
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

	if verbose {
		fmt.Printf("\nCMMC scan complete: %d practices reported\n", len(results))
		fmt.Println("")
		fmt.Println("WHAT AUDITKIT PRO ADDS:")
		fmt.Println("  - More of the 110 practices measured rather than asked for")
		fmt.Println("  - Evidence packages an assessor can read directly")
		fmt.Println("  - Multi-account scanning and continuous monitoring")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro")
	}

	// Vulnerability scan coverage, read from VM Manager rather than asked for as a document.
	results = append(results, s.runVulnCoverage(ctx, checks.EmitCMMC)...)

	// Every practice nothing above reported, reported as a manual requirement.
	// A CMMC report's denominator is the benchmark's 110, not the subset this
	// provider can automate, or a reader cannot tell an absent practice from a
	// satisfied one.
	results = append(results, s.reportRemainingCMMCPractices(ctx, results)...)

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
	var results []ScanResult

	if verbose {
		cisEd, _ := mappings.EditionFor("CIS-GCP")
		fmt.Println("Running " + cisEd.Describe())
		fmt.Println("Using existing checks with CIS control mappings...")
		fmt.Println("")
	}

	// Run existing GCP check modules - they return results with Frameworks map
	checkModules := []checks.Check{
		checks.NewIAMChecks(s.iamClient, s.projectID),
		checks.NewStorageChecks(s.storageClient, s.projectID),
		checks.NewComputeChecks(s.computeService, s.projectID),
		checks.NewNetworkChecks(s.computeService, s.projectID),
		checks.NewSQLChecks(s.sqlService, s.projectID),
		checks.NewKMSChecks(s.kmsClient, s.projectID),         // CIS 1.9, 1.10 - KMS security
		checks.NewLoggingChecks(s.loggingClient, s.projectID), // CIS 2.2, 2.3, 2.13 - Logging
		checks.NewBigQueryChecks(s.projectID),                 // CIS 7.1, 7.2, 7.3 - BigQuery security
		checks.NewGCPCISManualChecks(s.projectID),             // CIS manual controls (Section 2 - Logging/Monitoring alerts)
		checks.NewGKEChecks(s.gkeService, s.projectID),        // CIS 8.1-8.5 - GKE/Kubernetes security
	}

	// Track which CIS sections we're covering
	sectionCounts := make(map[string]int)

	for _, check := range checkModules {
		if verbose {
			fmt.Printf("  Running CIS check module...\n")
		}

		checkResults, checkErr := check.Run(ctx)
		if checkErr != nil && verbose {
			fmt.Printf("    Warning: %v\n", checkErr)
		}

		for _, cr := range checkResults {
			// Check if this control has CIS-GCP mapping in Frameworks
			if cr.Frameworks != nil && cr.Frameworks["CIS-GCP"] != "" {
				cisControls := cr.Frameworks["CIS-GCP"]

				// Enhance control name with CIS numbers
				enhancedName := fmt.Sprintf("[CIS GCP %s] %s", cisControls, cr.Control)

				// Track section coverage (extract first digit from control number)
				if len(cisControls) > 0 {
					section := string(cisControls[0])
					switch section {
					case "1":
						sectionCounts["Identity and Access Management"]++
					case "2":
						sectionCounts["Logging and Monitoring"]++
					case "3":
						sectionCounts["Networking"]++
					case "4":
						sectionCounts["Virtual Machines"]++
					case "5":
						sectionCounts["Cloud Storage"]++
					case "6":
						sectionCounts["Cloud SQL"]++
					case "7":
						sectionCounts["BigQuery"]++
					case "8":
						sectionCounts["GKE/Kubernetes"]++
					}
				}

				results = append(results, ScanResult{
					Control:           enhancedName,
					Status:            cr.Status,
					Evidence:          cr.Evidence,
					Remediation:       cr.Remediation,
					RemediationDetail: cr.RemediationDetail,
					Severity:          cr.Priority.Level,
					ScreenshotGuide:   cr.ScreenshotGuide,
					ConsoleURL:        cr.ConsoleURL,
					Frameworks:        cr.Frameworks,
				})
			}
		}
	}

	if verbose {
		fmt.Printf("\nCIS GCP scan complete: %d controls tested\n", len(results))
		if len(sectionCounts) > 0 {
			fmt.Println("\nSection Coverage:")
			for section, count := range sectionCounts {
				fmt.Printf("  %s: %d controls\n", section, count)
			}
		}
		// The old line quoted a control total for a benchmark version nobody
		// had read. State what this scan covers; the registry states the edition.
		fmt.Println("\nThis scan covers the CIS controls automatable via the GCP API")
		fmt.Println("")
	}

	// Every recommendation nothing above measured, reported with the evidence
	// an assessor asks for. A report's denominator is the benchmark's 93, not
	// the subset this scanner reaches, or a reader cannot tell an absent
	// recommendation from a satisfied one.
	results = append(results, s.reportRemainingCISGCP(ctx, results)...)

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
