package gcp

import (
	"context"
	"fmt"
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
	case "all":
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

	return results
}

func (s *GCPScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running CMMC Level 1 (17 practices) - Open Source")
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
		fmt.Printf("\nCMMC Level 1 scan complete: %d controls tested\n", len(results))
		fmt.Println("")
		fmt.Println("UNLOCK CMMC LEVEL 2:")
		fmt.Println("  - 110 additional Level 2 practices for CUI")
		fmt.Println("  - Required for DoD contractors handling CUI")
		fmt.Println("  - Complete evidence collection guides")
		fmt.Println("  - November 10, 2025 deadline compliance")
		fmt.Println("")
		fmt.Println("Visit https://auditkit.io/pro for full CMMC Level 2")
	}

	return results
}

func (s *GCPScanner) runCISChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	if verbose {
		fmt.Println("Running CIS Google Cloud Platform Foundation Benchmark v4.0")
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
		fmt.Println("\nNote: CIS GCP Benchmark v4.0 has ~70 total controls")
		fmt.Println("This scan covers controls automatable via GCP API")
		fmt.Println("")
	}

	return results
}
