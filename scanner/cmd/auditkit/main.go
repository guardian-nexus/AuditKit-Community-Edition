package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gcpScanner "github.com/guardian-nexus/auditkit/scanner/pkg/gcp"
	awsScanner "github.com/guardian-nexus/auditkit/scanner/pkg/aws"
	azureScanner "github.com/guardian-nexus/auditkit/scanner/pkg/azure"
	"github.com/guardian-nexus/auditkit/scanner/pkg/cli"
	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations"
	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations/prowler"
	"github.com/guardian-nexus/auditkit/scanner/pkg/integrations/scubagear"
	"github.com/guardian-nexus/auditkit/scanner/pkg/offline"
	"github.com/guardian-nexus/auditkit/scanner/pkg/remediation"
	"github.com/guardian-nexus/auditkit/scanner/pkg/report"
	"github.com/guardian-nexus/auditkit/scanner/pkg/tracker"
	"github.com/guardian-nexus/auditkit/scanner/pkg/updater"
	"github.com/guardian-nexus/auditkit/scanner/pkg/mappings"
)

const CurrentVersion = "v0.8.2"

type ComplianceResult struct {
	Timestamp       time.Time       `json:"timestamp"`
	Provider        string          `json:"provider"`
	Framework       string          `json:"framework"`
	AccountID       string          `json:"account_id,omitempty"`
	Score           float64         `json:"score"`
	TotalControls   int             `json:"total_controls"`
	PassedControls  int             `json:"passed_controls"`
	FailedControls  int             `json:"failed_controls"`
	Controls        []ControlResult `json:"controls"`
	Recommendations []string        `json:"recommendations"`
}

type ControlResult struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	Severity          string            `json:"severity,omitempty"`
	Status            string            `json:"status"`
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Priority          string            `json:"priority,omitempty"`
	Impact            string            `json:"impact,omitempty"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

type ProgressData struct {
	AccountID    string          `json:"account_id"`
	LastScan     time.Time       `json:"last_scan"`
	FirstScan    time.Time       `json:"first_scan"`
	ScanCount    int             `json:"scan_count"`
	ScoreHistory []ScorePoint    `json:"score_history"`
	FixedIssues  map[string]bool `json:"fixed_issues"`
}

type ScorePoint struct {
	Date      time.Time `json:"date"`
	Score     float64   `json:"score"`
	Framework string    `json:"framework"`
}

func main() {
	var (
		provider  = flag.String("provider", "aws", "Cloud provider: aws, azure, gcp")
		profile   = flag.String("profile", "default", "AWS profile, Azure subscription, or GCP project ID")
		framework = flag.String("framework", "all", "Compliance framework: soc2, pci, cmmc, hipaa, gdpr, nist-csf, all")
		format    = flag.String("format", "text", "Output format (text, json, html, pdf, csv)")
		output    = flag.String("output", "", "Output file (default: stdout)")
		verbose   = flag.Bool("verbose", false, "Verbose output")
		full      = flag.Bool("full", false, "Show all controls in text output (default: truncated for readability)")
		services  = flag.String("services", "all", "Comma-separated services to scan")
		source    = flag.String("source", "", "Integration source: scubagear, prowler")
		file      = flag.String("file", "", "Integration file to parse")
		offlineMode = flag.Bool("offline", false, "Use cached scan results (no cloud API calls)")
		cacheFile   = flag.String("cache-file", "", "Load scan from specific cache file")
	)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	flag.CommandLine.Parse(os.Args[2:])

	switch command {
	case "scan":
		runScan(*provider, *profile, *framework, *format, *output, *verbose, *full, *services, *offlineMode, *cacheFile)
	case "integrate":
		runIntegration(*source, *file, *format, *output, *verbose)
	case "evidence":
		runEvidenceTracker(*provider, *profile, *output)
	case "fix":
		generateFixScript(*provider, *profile, *output)
	case "progress":
		showProgress(*provider, *profile)
	case "compare":
		compareScan(*provider, *profile)
	case "cache":
		runCacheCommand(*provider, *profile, *framework, *verbose)
	case "update":
		updater.CheckForUpdates()
	case "version":
		fmt.Printf("AuditKit %s - Multi-cloud compliance scanning (AWS, Azure, GCP, M365)\n", CurrentVersion)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AuditKit - Multi-Cloud Compliance Scanner

Usage:
  auditkit scan [options]        Scan infrastructure for compliance
  auditkit integrate [options]   Import external tool results (ScubaGear, Prowler)
  auditkit evidence [options]    Track evidence collection progress
  auditkit fix [options]         Generate remediation script
  auditkit progress              Show compliance improvement over time
  auditkit compare               Compare last two scans
  auditkit cache [options]       Manage offline scan cache
  auditkit update                Check for updates
  auditkit version               Show version

Options:
  -provider string   Cloud provider: aws, azure, gcp (default "aws")
  -profile string    AWS profile, Azure subscription, or GCP project (default "default")
  -framework string  Compliance framework: soc2, pci, cmmc, hipaa, gdpr, nist-csf, 800-53, all (default "all")
  -format string     Output format (text, json, html, pdf, csv) (default "text")
  -output string     Output file (default: stdout)
  -services string   Services to scan (default "all")
  -source string     Integration source: scubagear, prowler
  -file string       File to parse for integration
  -verbose          Verbose output
  -full             Show all controls in text output (default: truncated)
  -offline          Use cached scan results (no cloud API calls)
  -cache-file       Load scan from specific cache file

Frameworks:
  soc2      SOC2 Type II Common Criteria (full coverage)
  pci       PCI-DSS v4.0 (full coverage)
  cmmc      CMMC Level 1 (17 practices)
  hipaa     HIPAA Security Rule (experimental)
  gdpr      GDPR Technical Controls (Articles 5, 25, 32, etc.)
  nist-csf  NIST Cybersecurity Framework 2.0 (ID, PR, DE, RS, RC)
  800-53    NIST 800-53 Rev 5 (via framework crosswalk)
  cis       CIS Benchmarks (auto-detects provider)
  cis-aws   CIS AWS Foundations (~60 controls)
  cis-azure CIS Azure Foundations (~90 controls)
  cis-gcp   CIS GCP Foundations (~50 controls)
  all       Run all available frameworks

Integration Examples:
  # Import ScubaGear M365 results
  auditkit integrate -source scubagear -file ScubaResults.json

  # Generate unified PDF with M365 findings
  auditkit integrate -source scubagear -file ScubaResults.json -format pdf

Examples:
  # AWS SOC2 scan
  auditkit scan -provider aws -framework soc2

  # Azure PCI-DSS scan
  auditkit scan -provider azure -framework pci

  # GCP SOC2 scan
  auditkit scan -provider gcp -profile my-project-id -framework soc2
  
  # GCP with environment variable
  export GOOGLE_CLOUD_PROJECT=my-project-id
  auditkit scan -provider gcp -framework soc2

  # NIST 800-53 scan
  auditkit scan -provider aws -framework 800-53

  # Generate PDF report
  auditkit scan -format pdf -output report.pdf
  
  # Show all controls (not truncated)
  auditkit scan -provider aws -framework cmmc --full

For more information: https://github.com/guardian-nexus/auditkit`)
}

func runIntegration(source, file, format, output string, verbose bool) {
	if source == "" || file == "" {
		fmt.Fprintf(os.Stderr, "Error: Both -source and -file are required for integration\n")
		fmt.Fprintf(os.Stderr, "Example: auditkit integrate -source scubagear -file ScubaResults.json\n")
		os.Exit(1)
	}

	ctx := context.Background()

	switch strings.ToLower(source) {
	case "scubagear":
		if verbose {
			fmt.Fprintf(os.Stderr, "Loading ScubaGear integration...\n")
		}

		mappingsDir := filepath.Join("mappings", "scubagear")
		
		if _, err := os.Stat(mappingsDir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: ScubaGear mappings not found at %s\n", mappingsDir)
			fmt.Fprintf(os.Stderr, "Make sure entra.json exists in mappings/scubagear/\n")
			os.Exit(1)
		}

		integration := scubagear.NewScubaGearIntegration(mappingsDir)
		
		if verbose {
			fmt.Fprintf(os.Stderr, "Loading mappings from %s...\n", mappingsDir)
		}

		if err := integration.LoadMappings(); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading mappings: %v\n", err)
			os.Exit(1)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "Parsing ScubaGear results from %s...\n", file)
		}

		results, err := integration.ParseFile(ctx, file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ScubaGear file: %v\n", err)
			os.Exit(1)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "Found %d M365 findings\n", len(results))
		}

		integrationResult := convertIntegrationResults(results, "M365")

		switch format {
		case "text":
			printIntegrationSummary(integrationResult)
		case "json":
			data, _ := json.MarshalIndent(integrationResult, "", "  ")
			if output != "" {
				os.WriteFile(output, data, 0644)
				fmt.Printf("Results saved to %s\n", output)
			} else {
				fmt.Println(string(data))
			}
		case "pdf":
			if output == "" {
				output = fmt.Sprintf("auditkit-m365-report-%s.pdf", time.Now().Format("2006-01-02-150405"))
			}
			pdfResult := report.ComplianceResult{
				Timestamp:       integrationResult.Timestamp,
				Provider:        integrationResult.Provider,
				AccountID:       integrationResult.AccountID,
				Score:           integrationResult.Score,
				TotalControls:   integrationResult.TotalControls,
				PassedControls:  integrationResult.PassedControls,
				FailedControls:  integrationResult.FailedControls,
				Controls:        convertControlsForPDF(integrationResult.Controls),
				Recommendations: integrationResult.Recommendations,
				Framework:       integrationResult.Framework,
			}
			err := report.GeneratePDF(pdfResult, output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating PDF: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("M365 compliance report saved to %s\n", output)
		default:
			fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
			os.Exit(1)
		}

	case "prowler":
		if file == "" {
			fmt.Fprintf(os.Stderr, "Error: -file flag required for Prowler integration\n")
			fmt.Fprintf(os.Stderr, "Usage: auditkit integrate -source prowler -file prowler-output.json\n")
			fmt.Fprintf(os.Stderr, "\nGenerate Prowler output with:\n")
			fmt.Fprintf(os.Stderr, "  prowler aws --output-formats json -o prowler-output\n")
			fmt.Fprintf(os.Stderr, "  prowler azure --output-formats json -o prowler-output\n")
			fmt.Fprintf(os.Stderr, "  prowler gcp --output-formats json -o prowler-output\n")
			os.Exit(1)
		}

		prowlerIntegration := prowler.NewProwlerIntegration()

		if verbose {
			fmt.Fprintf(os.Stderr, "Parsing Prowler output: %s\n", file)
		}

		results, err := prowlerIntegration.ParseFile(ctx, file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Prowler file: %v\n", err)
			os.Exit(1)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "Found %d Prowler findings\n", len(results))
		}

		// Detect provider from first result
		detectedProvider := "AWS"
		if len(results) > 0 && strings.Contains(results[0].Product, "AZURE") {
			detectedProvider = "Azure"
		} else if len(results) > 0 && strings.Contains(results[0].Product, "GCP") {
			detectedProvider = "GCP"
		}

		integrationResult := convertIntegrationResults(results, detectedProvider)

		switch format {
		case "text":
			printIntegrationSummary(integrationResult)
		case "json":
			data, _ := json.MarshalIndent(integrationResult, "", "  ")
			if output != "" {
				os.WriteFile(output, data, 0644)
				fmt.Printf("Results saved to %s\n", output)
			} else {
				fmt.Println(string(data))
			}
		case "pdf":
			if output == "" {
				output = fmt.Sprintf("auditkit-prowler-report-%s.pdf", time.Now().Format("2006-01-02-150405"))
			}
			pdfResult := report.ComplianceResult{
				Timestamp:       integrationResult.Timestamp,
				Provider:        integrationResult.Provider,
				AccountID:       integrationResult.AccountID,
				Score:           integrationResult.Score,
				TotalControls:   integrationResult.TotalControls,
				PassedControls:  integrationResult.PassedControls,
				FailedControls:  integrationResult.FailedControls,
				Controls:        convertControlsForPDF(integrationResult.Controls),
				Recommendations: integrationResult.Recommendations,
				Framework:       integrationResult.Framework,
			}
			err := report.GeneratePDF(pdfResult, output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating PDF: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Prowler compliance report saved to %s\n", output)
		default:
			fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown integration source: %s\n", source)
		fmt.Fprintf(os.Stderr, "Supported sources: scubagear, prowler\n")
		os.Exit(1)
	}
}

func convertIntegrationResults(results []integrations.IntegrationResult, provider string) ComplianceResult {
	controls := []ControlResult{}
	passed := 0
	failed := 0

	for _, r := range results {
		control := ControlResult{
			ID:              r.RuleID,
			Name:            r.Title,
			Category:        r.Product,
			Severity:        getSeverityFromStatus(r.Status),
			Status:          r.Status,
			Evidence:        r.Evidence,
			Remediation:     r.Remediation,
			ScreenshotGuide: r.ScreenshotGuide,
			ConsoleURL:      r.ConsoleURL,
			Frameworks:      r.Frameworks,
		}

		controls = append(controls, control)

		if r.Status == "PASS" {
			passed++
		} else if r.Status == "FAIL" {
			failed++
		}
	}

	score := 0.0
	if len(controls) > 0 {
		score = float64(passed) / float64(len(controls)) * 100
	}

	return ComplianceResult{
		Timestamp:       time.Now(),
		Provider:        provider,
		Framework:       "soc2",
		AccountID:       "M365-tenant",
		Score:           score,
		TotalControls:   len(controls),
		PassedControls:  passed,
		FailedControls:  failed,
		Controls:        controls,
		Recommendations: generateIntegrationRecommendations(controls),
	}
}

func getSeverityFromStatus(status string) string {
	switch status {
	case "FAIL":
		return "HIGH"
	case "PASS":
		return "PASSED"
	default:
		return "MEDIUM"
	}
}

func generateIntegrationRecommendations(controls []ControlResult) []string {
	recs := []string{}
	failedCount := 0

	for _, c := range controls {
		if c.Status == "FAIL" {
			failedCount++
		}
	}

	if failedCount > 0 {
		recs = append(recs, fmt.Sprintf("Fix %d failed M365 security controls", failedCount))
	}

	recs = append(recs, "Review Microsoft Entra ID conditional access policies")
	recs = append(recs, "Ensure MFA is enforced for all users")
	recs = append(recs, "Configure identity protection policies")
	recs = append(recs, "Enable security defaults if not using conditional access")

	return recs
}

func printIntegrationSummary(result ComplianceResult) {
	fmt.Printf("\n")
	fmt.Printf("AuditKit M365 Integration Results\n")
	fmt.Printf("===================================\n")
	fmt.Printf("Provider: %s\n", result.Provider)
	fmt.Printf("Scan Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("\n")
	
	scoreColor := "\033[32m"
	if result.Score < 80 {
		scoreColor = "\033[33m"
	}
	if result.Score < 60 {
		scoreColor = "\033[31m"
	}
	fmt.Printf("Compliance Score: %s%.1f%%\033[0m\n", scoreColor, result.Score)
	fmt.Printf("Controls Passed: %d/%d\n", result.PassedControls, result.TotalControls)
	fmt.Printf("\n")

	if result.FailedControls > 0 {
		fmt.Printf("\033[31mFailed M365 Controls:\033[0m\n")
		fmt.Printf("------------------------\n")
		for _, control := range result.Controls {
			if control.Status == "FAIL" {
				fmt.Printf("\033[31m[FAIL]\033[0m %s - %s\n", control.ID, control.Name)
				fmt.Printf("  Issue: %s\n", control.Evidence)
				if control.Remediation != "" {
					fmt.Printf("  Fix: %s\n", control.Remediation)
				}
				if control.ConsoleURL != "" {
					fmt.Printf("  URL: %s\n", control.ConsoleURL)
				}
				fmt.Printf("\n")
			}
		}
	}

	fmt.Printf("\n\033[32mPassed Controls:\033[0m\n")
	fmt.Printf("-------------------\n")
	for _, control := range result.Controls {
		if control.Status == "PASS" {
			fmt.Printf("  - %s - %s\n", control.ID, control.Name)
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Printf("\nRecommendations:\n")
		fmt.Printf("------------------\n")
		for i, rec := range result.Recommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
	}

	fmt.Printf("\nFor detailed report:\n")
	fmt.Printf("   auditkit integrate -source scubagear -file <file> -format pdf\n")
	fmt.Printf("\n")
}

func runOfflineScan(provider, profile, framework, format, output string, verbose, full bool, cacheFile string) {
	cache, err := offline.NewCache()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing cache: %v\n", err)
		os.Exit(1)
	}

	var cachedScan *offline.CachedScan

	if cacheFile != "" {
		// Load from specific file
		cachedScan, err = cache.LoadFromFile(cacheFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading cache file: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Try to get account ID from environment or use profile
		accountID := profile
		if provider == "aws" && profile == "default" {
			// Try to get AWS account ID from environment
			if awsAccount := os.Getenv("AWS_ACCOUNT_ID"); awsAccount != "" {
				accountID = awsAccount
			}
		}

		// Load latest cached scan
		cachedScan, err = cache.LoadLatest(provider, accountID, framework)
		if err != nil {
			fmt.Fprintf(os.Stderr, "No cached scan found for %s/%s/%s\n", provider, accountID, framework)
			fmt.Fprintf(os.Stderr, "\nTo create a cache, run a scan first:\n")
			fmt.Fprintf(os.Stderr, "  auditkit scan -provider %s -framework %s\n\n", provider, framework)
			fmt.Fprintf(os.Stderr, "To list cached scans:\n")
			fmt.Fprintf(os.Stderr, "  auditkit cache\n")
			os.Exit(1)
		}
	}

	if verbose {
		fmt.Printf("Loading cached scan from %s\n", cachedScan.Timestamp.Format(time.RFC3339))
		age := time.Since(cachedScan.Timestamp)
		if age > 24*time.Hour {
			fmt.Printf("Warning: Cached scan is %.0f hours old\n", age.Hours())
		}
	}

	// Convert cached scan to ComplianceResult
	result := convertCachedToComplianceResult(cachedScan)

	// Display offline mode indicator
	fmt.Printf("\n%s[OFFLINE MODE]%s Loading cached scan from %s\n",
		cli.Yellow, cli.Reset, cachedScan.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Cache age: %s\n\n", time.Since(cachedScan.Timestamp).Round(time.Minute))

	// Output results using existing formatters
	switch format {
	case "text":
		if output == "" {
			printTextSummary(result, full)
		} else {
			outputTextToFile(result, output)
		}
	case "pdf":
		pdfResult := report.ComplianceResult{
			Timestamp:       result.Timestamp,
			Provider:        result.Provider,
			AccountID:       result.AccountID,
			Score:           result.Score,
			TotalControls:   result.TotalControls,
			PassedControls:  result.PassedControls,
			FailedControls:  result.FailedControls,
			Controls:        convertControlsForPDF(result.Controls),
			Recommendations: result.Recommendations,
			Framework:       result.Framework,
		}

		if output == "" {
			output = fmt.Sprintf("auditkit-%s-%s-report-%s-offline.pdf",
				provider,
				strings.ToLower(framework),
				time.Now().Format("2006-01-02-150405"))
		}

		err := report.GeneratePDF(pdfResult, output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating PDF: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PDF report saved to %s (from cached scan)\n", output)
	case "json":
		outputJSON(result, output)
	case "html":
		outputHTML(result, output)
	case "csv":
		outputCSV(result, output)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
		os.Exit(1)
	}
}

func convertCachedToComplianceResult(cached *offline.CachedScan) ComplianceResult {
	controls := []ControlResult{}
	for _, c := range cached.Controls {
		controls = append(controls, ControlResult{
			ID:                c.ID,
			Name:              c.Name,
			Category:          c.Category,
			Severity:          c.Severity,
			Status:            c.Status,
			Evidence:          c.Evidence,
			Remediation:       c.Remediation,
			RemediationDetail: c.RemediationDetail,
			Priority:          c.Priority,
			Impact:            c.Impact,
			ScreenshotGuide:   c.ScreenshotGuide,
			ConsoleURL:        c.ConsoleURL,
			Frameworks:        c.Frameworks,
		})
	}

	return ComplianceResult{
		Timestamp:       cached.Timestamp,
		Provider:        cached.Provider,
		Framework:       cached.Framework,
		AccountID:       cached.AccountID,
		Score:           cached.Score,
		TotalControls:   cached.TotalControls,
		PassedControls:  cached.PassedControls,
		FailedControls:  cached.FailedControls,
		Controls:        controls,
		Recommendations: cached.Recommendations,
	}
}

func saveScanToCache(result ComplianceResult, version string) error {
	cache, err := offline.NewCache()
	if err != nil {
		return err
	}

	cachedControls := []offline.CachedControl{}
	for _, c := range result.Controls {
		cachedControls = append(cachedControls, offline.CachedControl{
			ID:                c.ID,
			Name:              c.Name,
			Category:          c.Category,
			Severity:          c.Severity,
			Status:            c.Status,
			Evidence:          c.Evidence,
			Remediation:       c.Remediation,
			RemediationDetail: c.RemediationDetail,
			Priority:          c.Priority,
			Impact:            c.Impact,
			ScreenshotGuide:   c.ScreenshotGuide,
			ConsoleURL:        c.ConsoleURL,
			Frameworks:        c.Frameworks,
		})
	}

	cachedScan := offline.CachedScan{
		Timestamp:       result.Timestamp,
		Provider:        result.Provider,
		Framework:       result.Framework,
		AccountID:       result.AccountID,
		Score:           result.Score,
		TotalControls:   result.TotalControls,
		PassedControls:  result.PassedControls,
		FailedControls:  result.FailedControls,
		Controls:        cachedControls,
		Recommendations: result.Recommendations,
		Version:         version,
	}

	return cache.Save(cachedScan)
}

func runCacheCommand(provider, profile, framework string, verbose bool) {
	cache, err := offline.NewCache()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing cache: %v\n", err)
		os.Exit(1)
	}

	info, err := cache.GetCacheInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading cache: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nAuditKit Offline Cache")
	fmt.Println("======================")
	fmt.Printf("Cache location: %s\n", info["cache_path"])
	fmt.Printf("Total cached files: %v\n", info["total_files"])

	scans, ok := info["scans"].([]map[string]interface{})
	if ok && len(scans) > 0 {
		fmt.Println("\nCached Scans:")
		for _, scan := range scans {
			ts, ok := scan["timestamp"].(time.Time)
			age := ""
			if ok {
				age = time.Since(ts).Round(time.Minute).String() + " ago"
			}
			fmt.Printf("  - %s | %s | %s | Score: %.1f%% | %s\n",
				scan["provider"], scan["framework"], scan["account"],
				scan["score"], age)
		}
	} else {
		fmt.Println("\nNo cached scans found.")
		fmt.Println("Run a scan first: auditkit scan -provider aws -framework soc2")
	}

	fmt.Println("\nOffline Usage:")
	fmt.Println("  auditkit scan --offline              Load latest cached scan")
	fmt.Println("  auditkit scan --cache-file <path>    Load specific cache file")
	fmt.Println()
}

func runScan(provider, profile, framework, format, output string, verbose bool, full bool, services string, offlineMode bool, cacheFile string) {
	// Handle offline mode
	if offlineMode || cacheFile != "" {
		runOfflineScan(provider, profile, framework, format, output, verbose, full, cacheFile)
		return
	}

	validFrameworks := map[string]bool{
		"soc2":             true,
		"pci":              true,
		"hipaa":            true,
		"cmmc":             true,
		"gdpr":             true,
		"nist-csf":         true,
		"csf":              true,
		"800-53":           true,
		"nist800-53":       true,
		"fedramp-low":      true,
		"fedramp-moderate": true,
		"fedramp-high":     true,
		"iso27001":         true,
		"iso-27001":        true,
		"cis":              true,
		"cis-aws":          true,
		"cis-azure":        true,
		"cis-gcp":          true,
		"all":              true,
	}

	if !validFrameworks[strings.ToLower(framework)] {
		fmt.Fprintf(os.Stderr, "Error: Invalid framework: %s\n", framework)
		fmt.Fprintf(os.Stderr, "Valid options: soc2, pci, cmmc (Level 1), hipaa, gdpr, nist-csf, 800-53, fedramp-low, fedramp-moderate, fedramp-high, iso27001, cis, cis-aws, cis-azure, cis-gcp, all\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "CMMC Level 2 requires upgrade to Pro:\n")
		fmt.Fprintf(os.Stderr, "  Visit: https://auditkit.io/pro\n")
		fmt.Fprintf(os.Stderr, "  Email: sales@auditkit.io\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Starting %s compliance scan for %s...\n", 
			strings.ToUpper(framework), provider)
	}

	result := performScan(provider, profile, framework, verbose, services)

	saveProgress(result.AccountID, result.Score, result.Controls, framework)

	// Save to offline cache for later offline use
	if err := saveScanToCache(result, CurrentVersion); err != nil {
		if verbose {
			fmt.Printf("Note: Could not save to offline cache: %v\n", err)
		}
	} else if verbose {
		fmt.Println("Scan saved to offline cache")
	}

	automatedChecks := result.PassedControls + result.FailedControls
	manualChecks := 0
	for _, control := range result.Controls {
		if control.Status == "MANUAL" || control.Status == "INFO" {
			manualChecks++
		}
	}

	if result.Score >= 90 {
		fmt.Printf("\nCONGRATULATIONS! %.1f%% of automated checks passed!\n", result.Score)
		
		if manualChecks > 0 {
			fmt.Printf("\n⚠️  NOTE: %d additional manual controls require documentation.\n", manualChecks)
			fmt.Printf("   Use 'auditkit evidence' to generate collection checklist.\n")
		}
	} else if result.Score >= 70 {
		fmt.Printf("\nGetting there! %.1f%% of automated checks passed.\n", result.Score)
		
		if manualChecks > 0 {
			fmt.Printf("\n⚠️  NOTE: %d additional manual controls require documentation.\n", manualChecks)
			fmt.Printf("   Use 'auditkit evidence' to generate collection checklist.\n")
		}
		
		fmt.Println("Run 'auditkit compare' to see your progress over time.")
	} else {
		fmt.Printf("\nAutomated Check Score: %.1f%% (%d/%d passed)\n", 
			result.Score, result.PassedControls, automatedChecks)
		
		if manualChecks > 0 {
			fmt.Printf("\n⚠️  IMPORTANT: Only %d of %d total controls are automated.\n", 
				automatedChecks, automatedChecks+manualChecks)
			fmt.Printf("   %d controls require manual documentation and evidence.\n", manualChecks)
			fmt.Printf("   Use 'auditkit evidence' to track what you need to collect.\n")
		}
	}

	switch format {
	case "text":
		if output == "" {
			printTextSummary(result, full)
		} else {
			outputTextToFile(result, output)
		}
	case "pdf":
		pdfResult := report.ComplianceResult{
			Timestamp:       result.Timestamp,
			Provider:        result.Provider,
			AccountID:       result.AccountID,
			Score:           result.Score,
			TotalControls:   result.TotalControls,
			PassedControls:  result.PassedControls,
			FailedControls:  result.FailedControls,
			Controls:        convertControlsForPDF(result.Controls),
			Recommendations: result.Recommendations,
			Framework:       result.Framework,
		}

		if output == "" {
			output = fmt.Sprintf("auditkit-%s-%s-report-%s.pdf", 
				provider,
				strings.ToLower(framework), 
				time.Now().Format("2006-01-02-150405"))
		}

		err := report.GeneratePDF(pdfResult, output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating PDF: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PDF report saved to %s\n", output)
		fmt.Printf("Review failed controls for screenshot requirements\n")
	case "json":
		outputJSON(result, output)
	case "html":
		outputHTML(result, output)
	case "csv":
		outputCSV(result, output)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
		os.Exit(1)
	}
}

func performScan(provider, profile, framework string, verbose bool, services string) ComplianceResult {
	var scanResults []interface{}
	var accountID string

	ctx := context.Background()

	// Start spinner for visual feedback
	var spinner *cli.Spinner
	if !verbose {
		spinner = cli.NewSpinner(fmt.Sprintf("Scanning %s for %s compliance...", strings.ToUpper(provider), strings.ToUpper(framework)))
		spinner.Start()
	}

	// CIS CHANGE: Normalize framework name
	framework = strings.ToLower(strings.TrimSpace(framework))
	
	// CIS CHANGE: Handle CIS framework auto-detection
	if framework == "cis" {
		switch provider {
		case "aws":
			framework = "cis-aws"
		case "azure":
			framework = "cis-azure"
		case "gcp":
			framework = "cis-gcp"
		}
		if verbose {
			fmt.Printf("Auto-detected CIS framework: %s\n", framework)
		}
	}
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing AWS scanner: %v\n", err)
			fmt.Fprintf(os.Stderr, "\nMake sure you have AWS credentials configured:\n")
			fmt.Fprintf(os.Stderr, "  aws configure --profile %s\n", profile)
			os.Exit(1)
		}
		
		accountID = scanner.GetAccountID(ctx)
		
		if verbose {
			fmt.Fprintf(os.Stderr, "Scanning AWS Account: %s\n", accountID)
			fmt.Fprintf(os.Stderr, "Framework: %s\n", strings.ToUpper(framework))
		}
		
		serviceList := strings.Split(services, ",")
		if services == "all" {
			serviceList = []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
		}
		
		awsResults, err := scanner.ScanServices(ctx, serviceList, verbose, framework)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning during scan: %v\n", err)
		}
		
		for _, r := range awsResults {
			scanResults = append(scanResults, r)
		}
		
	case "azure":
		// Get subscription ID from environment variable
		subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
		if subscriptionID == "" {
			subscriptionID = profile // fallback to profile flag if env var not set
		}
		scanner, err := azureScanner.NewScanner(subscriptionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing Azure scanner: %v\n", err)
			fmt.Fprintf(os.Stderr, "\nMake sure you have Azure credentials configured:\n")
			fmt.Fprintf(os.Stderr, "  az login\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_SUBSCRIPTION_ID=<your-subscription-id>\n")
			fmt.Fprintf(os.Stderr, "\nOr use service principal:\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_CLIENT_ID=<client-id>\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_CLIENT_SECRET=<client-secret>\n")
			fmt.Fprintf(os.Stderr, "  export AZURE_TENANT_ID=<tenant-id>\n")
			os.Exit(1)
		}
		
		accountID = scanner.GetAccountID(ctx)
		
		if verbose {
			fmt.Fprintf(os.Stderr, "Scanning Azure Subscription: %s\n", accountID)
			fmt.Fprintf(os.Stderr, "Framework: %s\n", strings.ToUpper(framework))
		}
		
		serviceList := strings.Split(services, ",")
		if services == "all" {
			serviceList = []string{"storage", "aad", "network", "compute", "sql"}
		}
		
		azureResults, err := scanner.ScanServices(ctx, serviceList, verbose, framework)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning during scan: %v\n", err)
		}
		
		for _, r := range azureResults {
			scanResults = append(scanResults, r)
		}
		
	case "gcp":
		// Get GCP project ID from profile flag or environment
		projectID := profile
		if projectID == "" || projectID == "default" {
			projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
			if projectID == "" {
				projectID = os.Getenv("GCP_PROJECT")
			}
		}

		scanner, err := gcpScanner.NewScanner(projectID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing GCP scanner: %v\n", err)
			fmt.Fprintf(os.Stderr, "\nMake sure you have GCP credentials configured:\n")
			fmt.Fprintf(os.Stderr, "  gcloud auth application-default login\n")
			fmt.Fprintf(os.Stderr, "  export GOOGLE_CLOUD_PROJECT=your-project-id\n")
			fmt.Fprintf(os.Stderr, "\nOr use service account:\n")
			fmt.Fprintf(os.Stderr, "  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json\n")
			os.Exit(1)
		}
		defer scanner.Close()

		accountID = scanner.GetAccountID(ctx)

		if verbose {
			fmt.Fprintf(os.Stderr, "Scanning GCP Project: %s\n", accountID)
			fmt.Fprintf(os.Stderr, "Framework: %s\n", strings.ToUpper(framework))
		}

		serviceList := strings.Split(services, ",")
		if services == "all" {
			serviceList = []string{"storage", "iam", "compute", "network", "sql", "kms", "logging"}
		}

		gcpResults, err := scanner.ScanServices(ctx, serviceList, verbose, framework)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning during GCP scan: %v\n", err)
		}

		for _, r := range gcpResults {
			scanResults = append(scanResults, r)
		}
		
	default:
		fmt.Fprintf(os.Stderr, "Unknown provider: %s\n", provider)
		fmt.Fprintf(os.Stderr, "Supported providers: aws, azure, gcp\n")
		os.Exit(1)
	}
	
	// Convert scan results to ComplianceResult format
	controls := []ControlResult{}
	passed := 0
	failed := 0
	critical := 0
	high := 0
	
	// Load crosswalk once if needed for 800-53 or FedRAMP
	var crosswalk *mappings.Crosswalk
	var crosswalkErr error
	var fedRAMPBaselines *mappings.FedRAMPBaselines
	var fedRAMPErr error
	requestedUpper := strings.ToUpper(framework)
	requestedLower := strings.ToLower(framework)

	if requestedUpper == "800-53" || requestedUpper == "NIST800-53" || strings.HasPrefix(requestedLower, "fedramp-") || requestedLower == "iso27001" || requestedLower == "iso-27001" {
		crosswalk, crosswalkErr = mappings.GetCrosswalk()
		if crosswalkErr != nil && verbose {
			fmt.Fprintf(os.Stderr, "Warning: Could not load 800-53 crosswalk: %v\n", crosswalkErr)
		}

		// Load FedRAMP baselines if needed
		if strings.HasPrefix(requestedLower, "fedramp-") {
			fedRAMPBaselines, fedRAMPErr = mappings.GetFedRAMPBaselines()
			if fedRAMPErr != nil && verbose {
				fmt.Fprintf(os.Stderr, "Warning: Could not load FedRAMP baselines: %v\n", fedRAMPErr)
			}
		}
	}

	// Stop spinner before processing results
	if spinner != nil {
		spinner.StopWithSuccess(fmt.Sprintf("Scanned %d controls", len(scanResults)))
	}

	for _, result := range scanResults {
		var control ControlResult
		
		// Type assertion based on provider
		switch provider {
		case "aws":
			awsResult := result.(awsScanner.ScanResult)
				priority, impact := getPriorityAndImpact(awsResult.Control, awsResult.Severity, awsResult.Status, framework)
				control = ControlResult{
					ID:                awsResult.Control,
					Name:              getControlName(awsResult.Control),
					Category:          getControlCategory(awsResult.Control),
					Severity:          awsResult.Severity,
					Status:            awsResult.Status,
					Evidence:          awsResult.Evidence,
					Remediation:       awsResult.Remediation,
					RemediationDetail: awsResult.RemediationDetail,
					Priority:          priority,
					Impact:            impact,
					ScreenshotGuide:   awsResult.ScreenshotGuide,
					ConsoleURL:        awsResult.ConsoleURL,
					Frameworks:        awsResult.Frameworks,
			}
		case "azure":
			azureResult := result.(azureScanner.ScanResult)
				priority, impact := getPriorityAndImpact(azureResult.Control, azureResult.Severity, azureResult.Status, framework)
				control = ControlResult{
					ID:                azureResult.Control,
					Name:              getControlName(azureResult.Control),
					Category:          getControlCategory(azureResult.Control),
					Severity:          azureResult.Severity,
					Status:            azureResult.Status,
					Evidence:          azureResult.Evidence,
					Remediation:       azureResult.Remediation,
					RemediationDetail: azureResult.RemediationDetail,
					Priority:          priority,
					Impact:            impact,
					ScreenshotGuide:   azureResult.ScreenshotGuide,
					ConsoleURL:        azureResult.ConsoleURL,
					Frameworks:        azureResult.Frameworks,
			}
		case "gcp":
			gcpResult := result.(gcpScanner.ScanResult)
				priority, impact := getPriorityAndImpact(gcpResult.Control, gcpResult.Severity, gcpResult.Status, framework)
				control = ControlResult{
					ID:                gcpResult.Control,
					Name:              getControlName(gcpResult.Control),
					Category:          getControlCategory(gcpResult.Control),
					Severity:          gcpResult.Severity,
					Status:            gcpResult.Status,
					Evidence:          gcpResult.Evidence,
					Remediation:       gcpResult.Remediation,
					RemediationDetail: gcpResult.RemediationDetail,
					Priority:          priority,
					Impact:            impact,
					ScreenshotGuide:   gcpResult.ScreenshotGuide,
					ConsoleURL:        gcpResult.ConsoleURL,
					Frameworks:        gcpResult.Frameworks,
				}
			}
		// Filter by framework if not "all"
		if framework != "all" {
			hasRequestedFramework := false

			// Special handling for 800-53 using crosswalk
			if (requestedUpper == "800-53" || requestedUpper == "NIST800-53") && crosswalk != nil {
				// Try to derive 800-53 IDs (works with OR without Frameworks map)
				nist80053IDs := crosswalk.Get800_53String(control.Frameworks, control.ID)

				if nist80053IDs != "" {
					hasRequestedFramework = true
					originalID := control.ID

					// Replace control ID with 800-53 IDs
					control.ID = nist80053IDs

					// Update control name to show source
					control.Name = fmt.Sprintf("%s (via %s)", control.Name, originalID)

					// Add to frameworks map
					if control.Frameworks == nil {
						control.Frameworks = make(map[string]string)
					}
					control.Frameworks["NIST800-53"] = nist80053IDs
					control.Frameworks["Source"] = originalID

					if verbose {
						fmt.Fprintf(os.Stderr, "✓ Mapped %s → %s\n", originalID, nist80053IDs)
					}
				}
			} else if strings.HasPrefix(requestedLower, "fedramp-") && crosswalk != nil && fedRAMPBaselines != nil {
				// Special handling for FedRAMP baselines
				nist80053IDs := crosswalk.Get800_53String(control.Frameworks, control.ID)

				if nist80053IDs != "" {
					// Check if any of the 800-53 controls are in the requested FedRAMP baseline
					controlList := strings.Split(nist80053IDs, ", ")
					inBaseline := false

					for _, ctrl := range controlList {
						if fedRAMPBaselines.IsInFedRAMPBaseline(ctrl, requestedLower) {
							inBaseline = true
							break
						}
					}

					if inBaseline {
						hasRequestedFramework = true
						originalID := control.ID

						// Replace control ID with 800-53 IDs
						control.ID = nist80053IDs

						// Update control name to show source and baseline
						baselineName := strings.ToUpper(strings.Replace(requestedLower, "fedramp-", "FedRAMP ", 1))
						control.Name = fmt.Sprintf("%s (via %s, %s)", control.Name, originalID, baselineName)

						// Add to frameworks map
						if control.Frameworks == nil {
							control.Frameworks = make(map[string]string)
						}
						control.Frameworks["NIST800-53"] = nist80053IDs
						control.Frameworks["FedRAMP"] = baselineName
						control.Frameworks["Source"] = originalID

						if verbose {
							fmt.Fprintf(os.Stderr, "✓ Mapped %s → %s (%s)\n", originalID, nist80053IDs, baselineName)
						}
					}
				}
			} else if (requestedLower == "iso27001" || requestedLower == "iso-27001") && crosswalk != nil {
				// Special handling for ISO 27001
				nist80053IDs := crosswalk.Get800_53String(control.Frameworks, control.ID)

				if nist80053IDs != "" {
					hasRequestedFramework = true
					originalID := control.ID

					// Replace control ID with 800-53 IDs
					control.ID = nist80053IDs

					// Update control name to show source and ISO 27001
					control.Name = fmt.Sprintf("%s (via %s, ISO 27001)", control.Name, originalID)

					// Add to frameworks map
					if control.Frameworks == nil {
						control.Frameworks = make(map[string]string)
					}
					control.Frameworks["NIST800-53"] = nist80053IDs
					control.Frameworks["ISO27001"] = "ISO 27001:2022"
					control.Frameworks["Source"] = originalID

					if verbose {
						fmt.Fprintf(os.Stderr, "✓ Mapped %s → %s (ISO 27001)\n", originalID, nist80053IDs)
					}
				}
			} else if strings.HasPrefix(framework, "cis") {
				// CIS works via Frameworks map - check for CIS-AWS, CIS-Azure, CIS-GCP
				if control.Frameworks != nil {
					for fw := range control.Frameworks {
						fwUpper := strings.ToUpper(fw)
						if strings.HasPrefix(fwUpper, "CIS") {
							hasRequestedFramework = true
							break
						}
					}
				}
			} else if control.Frameworks != nil && len(control.Frameworks) > 0 {
				// Standard framework matching for other frameworks (only if Frameworks exists)
				for fw := range control.Frameworks {
					fwUpper := strings.ToUpper(fw)
					if fwUpper == requestedUpper ||
						(requestedUpper == "PCI" && fwUpper == "PCI-DSS") ||
						(requestedUpper == "PCI-DSS" && fwUpper == "PCI") ||
						(requestedUpper == "SOC2" && fwUpper == "SOC2") ||
						(requestedUpper == "CMMC" && fwUpper == "CMMC") ||
						(requestedUpper == "HIPAA" && fwUpper == "HIPAA") ||
						(requestedUpper == "GDPR" && fwUpper == "GDPR") ||
						((requestedUpper == "NIST-CSF" || requestedUpper == "CSF") && fwUpper == "NIST-CSF") {
						hasRequestedFramework = true
						break
					}
				}
			}

			if !hasRequestedFramework {
				continue
			}
		}

		controls = append(controls, control)
		
		if control.Status == "PASS" {
			passed++
		} else if control.Status == "FAIL" {
			failed++
			if control.Severity == "CRITICAL" {
				critical++
			} else if control.Severity == "HIGH" {
				high++
			}
		}
	}
	
	score := 0.0
	automatedChecks := passed + failed
	if automatedChecks > 0 {
		score = float64(passed) / float64(automatedChecks) * 100
	}
	
	return ComplianceResult{
		Timestamp:       time.Now(),
		Provider:        provider,
		Framework:       framework,
		AccountID:       accountID,
		Score:           score,
		TotalControls:   len(controls),
		PassedControls:  passed,
		FailedControls:  failed,
		Controls:        controls,
		Recommendations: generatePrioritizedRecommendations(controls, critical, high, framework),
	}
}

func saveProgress(accountID string, score float64, controls []ControlResult, framework string) error {
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")
	
	os.MkdirAll(filepath.Dir(dataPath), 0755)
	
	var progress ProgressData
	if data, err := os.ReadFile(dataPath); err == nil {
		json.Unmarshal(data, &progress)
	} else {
		progress = ProgressData{
			AccountID:    accountID,
			FirstScan:    time.Now(),
			FixedIssues:  make(map[string]bool),
			ScoreHistory: []ScorePoint{},
		}
	}
	
	progress.LastScan = time.Now()
	progress.ScanCount++
	progress.ScoreHistory = append(progress.ScoreHistory, ScorePoint{
		Date:      time.Now(),
		Score:     score,
		Framework: framework,
	})
	
	for _, control := range controls {
		if control.Status == "PASS" {
			progress.FixedIssues[control.ID] = true
		}
	}
	
	data, _ := json.MarshalIndent(progress, "", "  ")
	return os.WriteFile(dataPath, data, 0644)
}

func showProgress(provider, profile string) {
	var accountID string
	ctx := context.Background()
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	case "azure":
		// Get subscription ID from environment variable
		subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
		if subscriptionID == "" {
			subscriptionID = profile // fallback to profile flag if env var not set
		}
		scanner, err := azureScanner.NewScanner(subscriptionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	case "gcp":
		projectID := profile
		if projectID == "" || projectID == "default" {
			projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
			if projectID == "" {
				projectID = os.Getenv("GCP_PROJECT")
			}
		}
		scanner, err := gcpScanner.NewScanner(projectID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		defer scanner.Close()
		accountID = scanner.GetAccountID(ctx)
	}
	
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")
	
	data, err := os.ReadFile(dataPath)
	if err != nil {
		fmt.Println("No previous scans found. Run 'auditkit scan' first!")
		return
	}
	
	var progress ProgressData
	json.Unmarshal(data, &progress)
	
	fmt.Println("\nYour Compliance Journey Progress")
	fmt.Println("===================================")
	fmt.Printf("Account: %s\n", progress.AccountID)
	fmt.Printf("First scan: %s\n", progress.FirstScan.Format("Jan 2, 2006"))
	fmt.Printf("Total scans: %d\n", progress.ScanCount)
	fmt.Printf("Issues fixed: %d\n", len(progress.FixedIssues))
	
	if len(progress.ScoreHistory) > 1 {
		first := progress.ScoreHistory[0].Score
		last := progress.ScoreHistory[len(progress.ScoreHistory)-1].Score
		improvement := last - first
		
		if improvement > 0 {
			fmt.Printf("Score improvement: +%.1f%% (%.1f%% → %.1f%%)\n", improvement, first, last)
		}
		
		fmt.Println("\nScore Trend:")
		startIdx := 0
		if len(progress.ScoreHistory) > 5 {
			startIdx = len(progress.ScoreHistory) - 5
		}
		for _, point := range progress.ScoreHistory[startIdx:] {
			bars := int(point.Score / 5)
			barString := strings.Repeat("█", bars)
			framework := point.Framework
			if framework == "" {
				framework = "SOC2"
			}
			fmt.Printf("%s [%s]: %s %.1f%%\n",
				point.Date.Format("Jan 02"),
				framework,
				barString,
				point.Score)
		}
	}
	
	fmt.Println("\nTip: Run 'auditkit scan -framework 800-53' to check NIST 800-53 compliance")
}

func compareScan(provider, profile string) {
	var accountID string
	ctx := context.Background()
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	case "azure":
		// Get subscription ID from environment variable
		subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
		if subscriptionID == "" {
			subscriptionID = profile // fallback to profile flag if env var not set
		}
		scanner, err := azureScanner.NewScanner(subscriptionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
	case "gcp":
		projectID := profile
		if projectID == "" || projectID == "default" {
			projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
			if projectID == "" {
				projectID = os.Getenv("GCP_PROJECT")
			}
		}
		scanner, err := gcpScanner.NewScanner(projectID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		defer scanner.Close()
		accountID = scanner.GetAccountID(ctx)
	}
	
	homeDir, _ := os.UserHomeDir()
	dataPath := filepath.Join(homeDir, ".auditkit", accountID+".json")
	
	data, err := os.ReadFile(dataPath)
	if err != nil {
		fmt.Println("Need at least 2 scans to compare. Run 'auditkit scan' first!")
		return
	}
	
	var progress ProgressData
	json.Unmarshal(data, &progress)
	
	if len(progress.ScoreHistory) < 2 {
		fmt.Println("Need at least 2 scans to compare.")
		return
	}
	
	prev := progress.ScoreHistory[len(progress.ScoreHistory)-2]
	curr := progress.ScoreHistory[len(progress.ScoreHistory)-1]
	
	fmt.Println("\nCompliance Progress Report")
	fmt.Println("============================")
	fmt.Printf("Previous: %.1f%% [%s] (%s)\n", prev.Score, prev.Framework, prev.Date.Format("Jan 2, 3:04 PM"))
	fmt.Printf("Current:  %.1f%% [%s] (%s)\n", curr.Score, curr.Framework, curr.Date.Format("Jan 2, 3:04 PM"))
	
	improvement := curr.Score - prev.Score
	if improvement > 0 {
		fmt.Printf("\nImproved by %.1f%%!\n", improvement)
	} else if improvement < 0 {
		fmt.Printf("\nDeclined by %.1f%%\n", -improvement)
	} else {
		fmt.Println("\nNo change")
	}
	
	fmt.Println("\nTo see what changed, run:")
	fmt.Println("  auditkit scan -verbose")
}

func generateFixScript(provider, profile, output string) {
	fmt.Println("Generating remediation script...")
	
	ctx := context.Background()
	var accountID string
	var controls []remediation.ControlResult
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning AWS Account %s to identify fixes...\n", accountID)
		
		services := []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			controls = append(controls, remediation.ControlResult{
				Control:           result.Control,
				Status:            result.Status,
				Severity:          result.Severity,
				RemediationDetail: result.RemediationDetail,
			})
		}
	case "azure":
		subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
		if subscriptionID == "" {
			subscriptionID = profile
		}
		scanner, err := azureScanner.NewScanner(subscriptionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning Azure Subscription %s to identify fixes...\n", accountID)

		services := []string{"storage", "aad", "network", "compute", "sql"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")

		for _, result := range scanResults {
			controls = append(controls, remediation.ControlResult{
				Control:           result.Control,
				Status:            result.Status,
				Severity:          result.Severity,
				RemediationDetail: result.RemediationDetail,
			})
		}
	case "gcp":
		projectID := profile
		if projectID == "" || projectID == "default" {
			projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
			if projectID == "" {
				projectID = os.Getenv("GCP_PROJECT")
			}
		}
		scanner, err := gcpScanner.NewScanner(projectID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		defer scanner.Close()
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning GCP Project %s to identify fixes...\n", accountID)
		
		services := []string{"storage", "iam", "network", "sql"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			gcpResult := result
				controls = append(controls, remediation.ControlResult{
					Control:           gcpResult.Control,
					Status:            gcpResult.Status,
					Severity:          gcpResult.Severity,
					RemediationDetail: gcpResult.RemediationDetail,
				})
		}
	}
	
	if output == "" {
		output = fmt.Sprintf("auditkit-%s-fixes.sh", provider)
	}
	
	err := remediation.GenerateFixScript(controls, output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating fix script: %v\n", err)
		return
	}
	
	fmt.Printf("Fix script generated: %s\n", output)
	fmt.Println("REVIEW CAREFULLY before running!")
	fmt.Printf("   chmod +x %s\n", output)
	fmt.Printf("   ./%s\n", output)
}

func runEvidenceTracker(provider, profile, output string) {
	fmt.Println("Generating evidence collection tracker...")
	
	ctx := context.Background()
	var accountID string
	var controls []tracker.ControlResult
	
	switch provider {
	case "aws":
		scanner, err := awsScanner.NewScanner(profile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning AWS Account %s...\n", accountID)
		
		services := []string{"s3", "iam", "ec2", "cloudtrail", "rds"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			controls = append(controls, tracker.ControlResult{
				Control: result.Control,
				Status:  result.Status,
			})
		}
	case "azure":
		// Get subscription ID from environment variable
		subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
		if subscriptionID == "" {
			subscriptionID = profile // fallback to profile flag if env var not set
		}
		scanner, err := azureScanner.NewScanner(subscriptionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning Azure Subscription %s...\n", accountID)
		
		services := []string{"storage", "aad", "network"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			controls = append(controls, tracker.ControlResult{
				Control: result.Control,
				Status:  result.Status,
			})
		}
	case "gcp":
		projectID := profile
		if projectID == "" || projectID == "default" {
			projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
			if projectID == "" {
				projectID = os.Getenv("GCP_PROJECT")
			}
		}
		scanner, err := gcpScanner.NewScanner(projectID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		defer scanner.Close()
		accountID = scanner.GetAccountID(ctx)
		fmt.Printf("Scanning GCP Project %s...\n", accountID)
		
		services := []string{"storage", "iam", "network", "sql"}
		scanResults, _ := scanner.ScanServices(ctx, services, false, "soc2")
		
		for _, result := range scanResults {
			gcpResult := result
				controls = append(controls, tracker.ControlResult{
					Control: gcpResult.Control,
					Status:  gcpResult.Status,
				})
			}
		}
		
	if output == "" {
		output = "evidence-tracker.html"
	}
	
	html := generateEvidenceTrackerHTML(controls, accountID)
	err := os.WriteFile(output, []byte(html), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating tracker: %v\n", err)
		return
	}
	
	fmt.Printf("Evidence tracker saved to %s\n", output)
	fmt.Println("Open this file in your browser and check off evidence as you collect it!")
}

func getPriorityAndImpact(controlID, severity, status, framework string) (string, string) {
	if status == "PASS" {
		return "PASSED", "Control is properly configured"
	}
	
	criticalByFramework := map[string]map[string]bool{
		"pci": {
			"CC6.2": true,
			"CC6.3": true,
			"CC6.6": true,
			"CC7.1": true,
		},
		"hipaa": {
			"CC6.3": true,
			"CC7.1": true,
			"CC6.6": true,
		},
		"soc2": {
			"CC6.6": true,
			"CC6.2": true,
			"CC6.1": true,
		},
	}
	
	if framework != "all" && framework != "" {
		if frameworkCritical, exists := criticalByFramework[strings.ToLower(framework)]; exists {
			if frameworkCritical[controlID] && severity == "CRITICAL" {
				return fmt.Sprintf("%s CRITICAL", strings.ToUpper(framework)), 
					fmt.Sprintf("%s AUDIT BLOCKER - Fix immediately or fail %s", strings.ToUpper(framework), strings.ToUpper(framework))
			}
		}
	}
	
	if severity == "CRITICAL" {
		return "CRITICAL", "AUDIT BLOCKER - Fix immediately or fail compliance"
	} else if severity == "HIGH" {
		return "HIGH", "Major finding - Auditor will flag this"
	} else if severity == "MEDIUM" {
		return "MEDIUM", "Should fix - Makes audit smoother"
	} else {
		return "LOW", "Nice to have - Strengthens posture"
	}
}

func printTextSummary(result ComplianceResult, full bool) {
	frameworkLabel := "Multi-Framework"
	if result.Framework != "" && result.Framework != "all" {
		frameworkLabel = strings.ToUpper(result.Framework)
	}

	// Print summary box
	fmt.Print(cli.SummaryBox(
		result.Provider,
		result.AccountID,
		frameworkLabel,
		result.Score,
		result.PassedControls,
		result.FailedControls,
		result.TotalControls,
	))
	fmt.Printf("Scan Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, control := range result.Controls {
		if control.Status == "FAIL" {
			if strings.Contains(control.Priority, "CRITICAL") {
				criticalCount++
			} else if strings.Contains(control.Priority, "HIGH") {
				highCount++
			} else {
				mediumCount++
			}
		}
	}

	if criticalCount > 0 || highCount > 0 {
		fmt.Println()
		if criticalCount > 0 {
			fmt.Printf("  %s %s%d issues require immediate attention%s\n",
				cli.Critical(), cli.Red, criticalCount, cli.Reset)
		}
		if highCount > 0 {
			fmt.Printf("  %s %s%d high priority issues%s\n",
				cli.High(), cli.Yellow, highCount, cli.Reset)
		}
	}
	fmt.Println()
	
	if result.FailedControls > 0 {
		hasCritical := false
		criticalShown := 0
		for _, control := range result.Controls {
			if control.Status == "FAIL" && strings.Contains(control.Priority, "CRITICAL") {
				if !hasCritical {
					cli.Header("CRITICAL - Fix These NOW")
					hasCritical = true
				}

				if !full && criticalShown >= 10 {
					remaining := criticalCount - 10
					if remaining > 0 {
						fmt.Printf("  %s... and %d more critical issues (use --full to see all)%s\n\n",
							cli.Dim, remaining, cli.Reset)
					}
					break
				}

				fmt.Printf("\n%s %s%s%s - %s\n", cli.Fail(), cli.Bold, control.ID, cli.Reset, control.Name)
				fmt.Printf("  %sIssue:%s %s\n", cli.Dim, cli.Reset, control.Evidence)
				
				if control.Remediation != "" {
					fmt.Printf("  %sFix:%s %s\n", cli.Green, cli.Reset, control.Remediation)
				}

				if control.ScreenshotGuide != "" {
					fmt.Printf("  %sEvidence:%s %s\n", cli.Cyan, cli.Reset, control.ScreenshotGuide)
				}

				if control.ConsoleURL != "" {
					fmt.Printf("  %sConsole:%s %s\n", cli.Blue, cli.Reset, control.ConsoleURL)
				}
				fmt.Println()
				criticalShown++
			}
		}

		hasHigh := false
		highShown := 0
		for _, control := range result.Controls {
			if control.Status == "FAIL" && strings.Contains(control.Priority, "HIGH") {
				if !hasHigh {
					cli.SubHeader("HIGH Priority Issues")
					hasHigh = true
				}

				if !full && highShown >= 10 {
					remaining := highCount - highShown
					if remaining > 0 {
						fmt.Printf("  %s... and %d more high priority issues (use --full to see all)%s\n\n",
							cli.Dim, remaining, cli.Reset)
					}
					break
				}

				fmt.Printf("\n%s%s[FAIL]%s %s%s%s - %s\n",
					cli.Yellow, cli.Bold, cli.Reset, cli.Bold, control.ID, cli.Reset, control.Name)
				fmt.Printf("  %sIssue:%s %s\n", cli.Dim, cli.Reset, control.Evidence)

				if control.Remediation != "" {
					fmt.Printf("  %sFix:%s %s\n", cli.Green, cli.Reset, control.Remediation)
				}

				if control.ScreenshotGuide != "" {
					fmt.Printf("  %sEvidence:%s %s\n", cli.Cyan, cli.Reset, control.ScreenshotGuide)
				}

				if control.ConsoleURL != "" {
					fmt.Printf("  %sConsole:%s %s\n", cli.Blue, cli.Reset, control.ConsoleURL)
				}
				fmt.Println()
				highShown++
			}
		}
		
		hasOther := false
		otherShown := 0
		otherCount := 0
		for _, control := range result.Controls {
			if control.Status == "FAIL" && !strings.Contains(control.Priority, "CRITICAL") && !strings.Contains(control.Priority, "HIGH") {
				otherCount++
			}
		}
		
		for _, control := range result.Controls {
			if control.Status == "FAIL" && !strings.Contains(control.Priority, "CRITICAL") && !strings.Contains(control.Priority, "HIGH") {
				if !hasOther {
					cli.SubHeader("Other Issues")
					hasOther = true
				}

				if !full && otherShown >= 10 {
					remaining := otherCount - 10
					if remaining > 0 {
						fmt.Printf("  %s... and %d more issues (use --full to see all)%s\n\n",
							cli.Dim, remaining, cli.Reset)
					}
					break
				}

				fmt.Printf("%s %s - %s\n", cli.Fail(), control.ID, control.Name)
				fmt.Printf("  %sIssue:%s %s\n", cli.Dim, cli.Reset, control.Evidence)
				if control.Remediation != "" {
					fmt.Printf("  %sFix:%s %s\n", cli.Green, cli.Reset, control.Remediation)
				}
				fmt.Println()
				otherShown++
			}
		}

		hasInfo := false
		infoShown := 0
		infoCount := 0
		for _, control := range result.Controls {
			if control.Status == "MANUAL" || control.Status == "INFO" {
				infoCount++
			}
		}

		for _, control := range result.Controls {
			if control.Status == "MANUAL" || control.Status == "INFO" {
				if !hasInfo {
					cli.SubHeader("Manual Documentation Required")
					hasInfo = true
				}

				if !full && infoShown >= 20 {
					remaining := infoCount - 20
					if remaining > 0 {
						fmt.Printf("  %s... and %d more manual controls (use --full to see all)%s\n\n",
							cli.Dim, remaining, cli.Reset)
					}
					break
				}

				fmt.Printf("%s %s - %s\n", cli.Info(), control.ID, control.Name)
				fmt.Printf("  %sGuidance:%s %s\n", cli.Dim, cli.Reset, control.Evidence)
				if control.ScreenshotGuide != "" {
					fmt.Printf("  %sEvidence:%s %s\n", cli.Cyan, cli.Reset, control.ScreenshotGuide)
				}
				fmt.Println()
				infoShown++
			}
		}
	}

	// Passed controls section
	cli.SubHeader("Passed Controls")
	passCount := 0
	for _, control := range result.Controls {
		if control.Status == "PASS" {
			fmt.Printf("  %s %s - %s\n", cli.Pass(), control.ID, control.Name)
			passCount++
			if !full && passCount >= 15 {
				remaining := result.PassedControls - 15
				if remaining > 0 {
					fmt.Printf("  %s... and %d more passing controls (use --full to see all)%s\n",
						cli.Dim, remaining, cli.Reset)
				}
				break
			}
		}
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		cli.SubHeader("Priority Action Items")
		for i, rec := range result.Recommendations {
			if i >= 5 {
				break
			}
			fmt.Printf("  %s%d.%s %s\n", cli.Cyan, i+1, cli.Reset, rec)
		}
	}

	// Footer tips
	fmt.Println()
	if !full && result.TotalControls > 50 {
		fmt.Printf("%sTip:%s Use --full flag to see all %d controls without truncation\n",
			cli.Yellow, cli.Reset, result.TotalControls)
		fmt.Printf("     auditkit scan -provider %s -framework %s --full\n\n",
			result.Provider, strings.ToLower(result.Framework))
	}
	fmt.Printf("%sFor detailed %s report:%s\n", cli.Cyan, frameworkLabel, cli.Reset)
	fmt.Printf("   auditkit scan -provider %s -framework %s -format pdf -output report.pdf\n",
		result.Provider, strings.ToLower(result.Framework))
	fmt.Printf("\n%sTo track evidence collection progress:%s\n", cli.Cyan, cli.Reset)
	fmt.Printf("   auditkit evidence -provider %s\n", result.Provider)
	fmt.Println()
}

func generatePrioritizedRecommendations(controls []ControlResult, criticalCount, highCount int, framework string) []string {
	recs := []string{}
	
	if framework == "pci" {
		if criticalCount > 0 {
			recs = append(recs, fmt.Sprintf("PCI-DSS URGENT: Fix %d CRITICAL issues - QSA will fail your assessment", criticalCount))
		}
		recs = append(recs, "Document cardholder data flow and network segmentation")
	} else if framework == "hipaa" {
		if criticalCount > 0 {
			recs = append(recs, fmt.Sprintf("HIPAA URGENT: Fix %d CRITICAL issues - violates Security Rule", criticalCount))
		}
		recs = append(recs, "Ensure all Business Associate Agreements (BAAs) are in place")
	} else {
		if criticalCount > 0 {
			recs = append(recs, fmt.Sprintf("URGENT: Fix %d CRITICAL issues immediately - these WILL fail your audit", criticalCount))
		}
	}
	
	hasPublicS3 := false
	hasNoMFA := false
	hasOpenPorts := false
	hasOldKeys := false
	hasNoLogging := false
	hasNoEncryption := false
	
	for _, control := range controls {
		if control.Status == "FAIL" {
			switch control.ID {
			case "CC6.2":
				hasPublicS3 = true
			case "CC6.6":
				hasNoMFA = true
			case "CC6.1":
				hasOpenPorts = true
			case "CC6.8":
				hasOldKeys = true
			case "CC7.1":
				hasNoLogging = true
			case "CC6.3":
				hasNoEncryption = true
			}
		}
	}
	
	if hasNoMFA {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 8.3.1: Enable MFA for all console access immediately")
		} else {
			recs = append(recs, "CRITICAL: Enable MFA for root/admin accounts TODAY - auditors check this first")
		}
	}
	if hasPublicS3 {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 1.2.1: No direct public access to cardholder data environment")
		} else {
			recs = append(recs, "CRITICAL: Block public access on storage - data exposure = instant fail")
		}
	}
	if hasNoEncryption {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 3.4: Encrypt all stored cardholder data")
		} else if framework == "hipaa" {
			recs = append(recs, "HIPAA 164.312(a)(2)(iv): Implement encryption for ePHI")
		} else {
			recs = append(recs, "MEDIUM: Enable encryption on all storage - best practice")
		}
	}
	if hasOpenPorts {
		recs = append(recs, "HIGH: Close management ports from internet - major security finding")
	}
	if hasOldKeys {
		recs = append(recs, "HIGH: Rotate access keys/credentials older than 90 days - compliance requirement")
	}
	if hasNoLogging {
		if framework == "pci" {
			recs = append(recs, "PCI-DSS 10.1: Implement audit trails to link access to individual users")
		} else {
			recs = append(recs, "HIGH: Enable audit logging - required for compliance")
		}
	}
	
	recs = append(recs, "Enable continuous compliance monitoring")
	recs = append(recs, "Document your security policies and procedures")
	recs = append(recs, "Set up automated alerting for security events")
	if framework == "pci" {
		recs = append(recs, "Schedule quarterly vulnerability scans (PCI-DSS 11.2)")
	}
	recs = append(recs, "Schedule quarterly access reviews")
	
	if strings.HasPrefix(strings.ToLower(framework), "cis") {
		recs = append(recs, "CIS Note: Some controls require manual verification")
		recs = append(recs, "CIS Level 1 included in FREE (basic security)")
		
		// Provider-specific CIS guidance
		switch strings.ToLower(framework) {
		case "cis", "cis-aws":
			recs = append(recs,
				"CIS AWS Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services")
		case "cis-azure":
			recs = append(recs,
				"CIS Azure Benchmark: https://www.cisecurity.org/benchmark/azure")
		case "cis-gcp":
			recs = append(recs,
				"CIS GCP Benchmark: https://www.cisecurity.org/benchmark/google_cloud_computing_platform")
		}
	}

	return recs
}

func convertControlsForPDF(controls []ControlResult) []report.ControlResult {
	pdfControls := []report.ControlResult{}
	for _, c := range controls {
		pdfControls = append(pdfControls, report.ControlResult{
			ID:              c.ID,
			Name:            c.Name,
			Category:        c.Category,
			Severity:        c.Severity,
			Status:          c.Status,
			Evidence:        c.Evidence,
			Remediation:     c.Remediation,
			ScreenshotGuide: c.ScreenshotGuide,
			ConsoleURL:      c.ConsoleURL,
			Frameworks:      c.Frameworks,
		})
	}
	return pdfControls
}

func getControlName(controlID string) string {
	controlNames := map[string]string{
		"CC1.1": "Organizational Governance",
		"CC1.2": "Board Oversight",
		"CC1.3": "Organizational Structure",
		"CC1.4": "Commitment to Competence",
		"CC1.5": "Accountability",
		"CC2.1": "Information and Communication",
		"CC2.2": "Internal Communication",
		"CC2.3": "External Communication",
		"CC3.1": "Risk Assessment Process",
		"CC3.2": "Risk Identification",
		"CC3.3": "Risk Analysis",
		"CC3.4": "Risk Management",
		"CC4.1": "Monitoring Activities",
		"CC4.2": "Evaluation of Deficiencies",
		"CC5.1": "Control Activities",
		"CC5.2": "Technology Controls",
		"CC5.3": "Policy Implementation",
		"CC6.1": "Logical and Physical Access Controls",
		"CC6.2": "Network Security",
		"CC6.3": "Encryption at Rest",
		"CC6.6": "Authentication Controls",
		"CC6.7": "Password Policy",
		"CC6.8": "Access Key Rotation",
		"CC7.1": "Security Monitoring and Logging",
		"CC7.2": "Incident Detection and Response",
		"CC7.3": "Security Event Analysis",
		"CC7.4": "Performance Monitoring",
		"CC7.5": "Vulnerability Management",
		"CC8.1": "Change Management Process",
		"CC9.1": "Risk Mitigation",
		"CC9.2": "Vendor Management",
		"A1.1":  "Availability Monitoring",
		"A1.2":  "Backup and Recovery",
		"A1.3":  "Disaster Recovery",
		"PI1.1": "Privacy Controls",
		"PI1.2": "Data Subject Rights",
		"PI1.3": "Data Retention",
		"PI1.4": "Data Disposal",
		"PI1.5": "Privacy Notice",
		"PI1.6": "Data Quality",
		"C1.1":  "Confidentiality Controls",
		"C1.2":  "Data Classification",
		"PCI-1.2.1": "Network Segmentation",
		"PCI-1.3.1": "No Direct Public Access",
		"PCI-2.2.2": "Default Configuration Changes",
		"PCI-3.4":   "Encryption at Rest",
		"PCI-3.5":   "Encryption Key Management",
		"PCI-4.1":   "Encryption in Transit",
		"PCI-7.1":   "Least Privilege Access",
		"PCI-8.1.4": "Remove Inactive Users",
		"PCI-8.1.8": "Session Timeout",
		"PCI-8.2.3": "Password Strength",
		"PCI-8.2.4": "Password Rotation",
		"PCI-8.3.1": "MFA for All Access",
		"PCI-10.1":  "Audit Trail Implementation",
		"PCI-10.5.3": "Log Retention",
		"PCI-11.2.2": "Quarterly Vulnerability Scans",
	}
	
	if name, ok := controlNames[controlID]; ok {
		return name
	}
	return "Security Control"
}

func getControlCategory(controlID string) string {
	if strings.HasPrefix(controlID, "CC") {
		return "Common Criteria"
	} else if strings.HasPrefix(controlID, "A") {
		return "Availability"
	} else if strings.HasPrefix(controlID, "PI") {
		return "Privacy"
	} else if strings.HasPrefix(controlID, "C") {
		return "Confidentiality"
	} else if strings.HasPrefix(controlID, "PCI") {
		return "PCI-DSS"
	}
	return "Security"
}

func outputTextToFile(result ComplianceResult, output string) {
	var sb strings.Builder
	frameworkLabel := "Multi-Framework"
	if result.Framework != "" && result.Framework != "all" {
		frameworkLabel = strings.ToUpper(result.Framework)
	}
	
	sb.WriteString(fmt.Sprintf("AuditKit %s Compliance Report\n", frameworkLabel))
	sb.WriteString(fmt.Sprintf("==========================\n"))
	sb.WriteString(fmt.Sprintf("Generated: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Provider: %s\n", result.Provider))
	sb.WriteString(fmt.Sprintf("Framework: %s\n", frameworkLabel))
	sb.WriteString(fmt.Sprintf("Account: %s\n\n", result.AccountID))
	sb.WriteString(fmt.Sprintf("COMPLIANCE SCORE: %.1f%%\n", result.Score))
	sb.WriteString(fmt.Sprintf("Controls Passed: %d/%d\n", result.PassedControls, result.TotalControls))
	sb.WriteString(fmt.Sprintf("Controls Failed: %d\n\n", result.FailedControls))
	
	sb.WriteString("FAILED CONTROLS:\n")
	sb.WriteString("----------------\n")
	for _, control := range result.Controls {
		if control.Status == "FAIL" {
			sb.WriteString(fmt.Sprintf("\n%s [%s] %s - %s\n", control.Priority, control.Severity, control.ID, control.Name))
			sb.WriteString(fmt.Sprintf("  Issue: %s\n", control.Evidence))
			sb.WriteString(fmt.Sprintf("  Impact: %s\n", control.Impact))
			if control.Remediation != "" {
				sb.WriteString(fmt.Sprintf("  Fix: %s\n", control.Remediation))
			}
		}
	}
	
	sb.WriteString("\n\nRECOMMENDATIONS:\n")
	sb.WriteString("----------------\n")
	for i, rec := range result.Recommendations {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
	}
	
	err := os.WriteFile(output, []byte(sb.String()), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Report saved to %s\n", output)
}

func outputJSON(result ComplianceResult, output string) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
		os.Exit(1)
	}
	
	if output != "" {
		err = os.WriteFile(output, data, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("JSON report saved to %s\n", output)
	} else {
		fmt.Print(string(data))
	}
}

func outputHTML(result ComplianceResult, output string) {
	htmlResult := report.ComplianceResult{
		Timestamp:       result.Timestamp,
		Provider:        result.Provider,
		AccountID:       result.AccountID,
		Score:           result.Score,
		TotalControls:   result.TotalControls,
		PassedControls:  result.PassedControls,
		FailedControls:  result.FailedControls,
		Controls:        convertControlsForPDF(result.Controls),
		Recommendations: result.Recommendations,
		Framework:       result.Framework,
	}
	
	html := report.GenerateHTML(htmlResult)

	if output == "" {
		output = fmt.Sprintf("auditkit-%s-%s-report-%s.html", 
			strings.ToLower(result.Provider),
			strings.ToLower(result.Framework), 
			time.Now().Format("2006-01-02-150405"))
	}

	err := os.WriteFile(output, []byte(html), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing HTML file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("HTML report saved to %s\n", output)
	fmt.Printf("Open in browser: file://%s/%s\n", getCurrentDir(), output)
}

func outputCSV(result ComplianceResult, output string) {
	var csvData strings.Builder

	// CSV Header
	csvData.WriteString("Control ID,Control Name,Category,Status,Severity,Priority,Evidence,Remediation,Console URL\n")

	// CSV Rows
	for _, control := range result.Controls {
		// Escape CSV fields (handle commas and quotes)
		controlID := escapeCSVField(control.ID)
		controlName := escapeCSVField(control.Name)
		category := escapeCSVField(control.Category)
		status := escapeCSVField(control.Status)
		severity := escapeCSVField(control.Severity)
		priority := escapeCSVField(control.Priority)
		evidence := escapeCSVField(control.Evidence)
		remediation := escapeCSVField(control.Remediation)
		consoleURL := escapeCSVField(control.ConsoleURL)

		csvData.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			controlID, controlName, category, status, severity, priority,
			evidence, remediation, consoleURL))
	}

	if output == "" {
		output = fmt.Sprintf("auditkit-%s-%s-report-%s.csv",
			strings.ToLower(result.Provider),
			strings.ToLower(result.Framework),
			time.Now().Format("2006-01-02-150405"))
	}

	err := os.WriteFile(output, []byte(csvData.String()), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CSV file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CSV report saved to %s\n", output)
	fmt.Printf("Import into Excel, Google Sheets, or other spreadsheet tools\n")
}

// escapeCSVField properly escapes CSV fields containing commas, quotes, or newlines
func escapeCSVField(field string) string {
	// Replace newlines with spaces
	field = strings.ReplaceAll(field, "\n", " ")
	field = strings.ReplaceAll(field, "\r", "")

	// If field contains comma, quote, or was modified, wrap in quotes
	if strings.Contains(field, ",") || strings.Contains(field, "\"") {
		// Escape existing quotes by doubling them
		field = strings.ReplaceAll(field, "\"", "\"\"")
		field = fmt.Sprintf("\"%s\"", field)
	}

	return field
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return dir
}

func generateEvidenceTrackerHTML(controls []tracker.ControlResult, accountID string) string {
	// Count pass/fail for progress
	passCount := 0
	failCount := 0
	for _, c := range controls {
		if c.Status == "PASS" {
			passCount++
		} else {
			failCount++
		}
	}
	totalCount := len(controls)
	progressPct := 0.0
	if totalCount > 0 {
		progressPct = float64(passCount) / float64(totalCount) * 100
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>AuditKit Evidence Collection Tracker</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 40px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            max-width: 900px;
            margin: 0 auto;
        }
        h1 { color: #10b981; margin-bottom: 5px; }
        .subtitle { color: #64748b; margin-top: 0; }
        .stats {
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }
        .stat {
            background: #f8fafc;
            padding: 15px 25px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-number { font-size: 28px; font-weight: bold; color: #0f172a; }
        .stat-label { font-size: 12px; color: #64748b; text-transform: uppercase; }
        .stat.pass .stat-number { color: #10b981; }
        .stat.fail .stat-number { color: #ef4444; }
        .progress {
            background: #e2e8f0;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }
        .progress-bar {
            background: linear-gradient(90deg, #10b981, #059669);
            height: 100%%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        .section-title {
            margin-top: 30px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
            color: #0f172a;
        }
        .control {
            padding: 15px;
            margin: 10px 0;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 15px;
            transition: all 0.2s;
        }
        .control:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .control.pass { border-left: 4px solid #10b981; }
        .control.fail { border-left: 4px solid #ef4444; }
        .control.collected { background: #ecfdf5; }
        input[type="checkbox"] {
            width: 20px;
            height: 20px;
            cursor: pointer;
            accent-color: #10b981;
        }
        .control-info { flex: 1; }
        .control-id { font-weight: 600; color: #0f172a; }
        .control-status {
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 4px;
            margin-left: 10px;
        }
        .control-status.pass { background: #d1fae5; color: #065f46; }
        .control-status.fail { background: #fee2e2; color: #991b1b; }
        .notes {
            width: 100%%;
            padding: 8px;
            margin-top: 8px;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            display: none;
            font-size: 14px;
        }
        .control.collected .notes { display: block; }
        .btn-group { margin-top: 30px; display: flex; gap: 10px; }
        button {
            background: #10b981;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }
        button:hover { background: #059669; }
        button.secondary { background: #64748b; }
        button.secondary:hover { background: #475569; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            color: #64748b;
            font-size: 13px;
            text-align: center;
        }
        .footer a { color: #10b981; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Evidence Collection Tracker</h1>
        <p class="subtitle">Account: %s | Generated: %s</p>

        <div class="stats">
            <div class="stat pass">
                <div class="stat-number">%d</div>
                <div class="stat-label">Passing</div>
            </div>
            <div class="stat fail">
                <div class="stat-number">%d</div>
                <div class="stat-label">Failing</div>
            </div>
            <div class="stat">
                <div class="stat-number">%d</div>
                <div class="stat-label">Total Controls</div>
            </div>
        </div>

        <div class="progress">
            <div class="progress-bar" id="progress-bar" style="width: %.0f%%">
                <span id="progress-text">0/%d Evidence Collected</span>
            </div>
        </div>

        <h2 class="section-title">Controls Requiring Evidence</h2>
        <p style="color: #64748b; margin-bottom: 20px;">Check off each control as you collect screenshots and documentation.</p>
        <div id="controls">`,
		accountID,
		time.Now().Format("January 2, 2006"),
		passCount,
		failCount,
		totalCount,
		progressPct,
		totalCount)

	// Add each control
	for _, control := range controls {
		statusClass := "fail"
		statusText := "FAIL"
		if control.Status == "PASS" {
			statusClass = "pass"
			statusText = "PASS"
		}

		html += fmt.Sprintf(`
            <div class="control %s" data-control="%s">
                <input type="checkbox" onchange="toggleEvidence(this)">
                <div class="control-info">
                    <span class="control-id">%s</span>
                    <span class="control-status %s">%s</span>
                    <input type="text" class="notes" placeholder="Add notes about evidence collected...">
                </div>
            </div>`, statusClass, control.Control, control.Control, statusClass, statusText)
	}

	html += fmt.Sprintf(`
        </div>

        <div class="btn-group">
            <button onclick="exportProgress()">Export Progress (JSON)</button>
            <button class="secondary" onclick="window.print()">Print Checklist</button>
        </div>

        <div class="footer">
            <p>Generated by <a href="https://auditkit.io">AuditKit</a> | Evidence is saved in your browser's local storage</p>
        </div>

        <script>
        const STORAGE_KEY = 'auditkit_evidence_%s';

        function toggleEvidence(checkbox) {
            const control = checkbox.closest('.control');
            if (checkbox.checked) {
                control.classList.add('collected');
            } else {
                control.classList.remove('collected');
            }
            updateProgress();
            saveToLocal();
        }

        function updateProgress() {
            const total = document.querySelectorAll('.control').length;
            const collected = document.querySelectorAll('.control.collected').length;
            const percentage = total > 0 ? (collected / total * 100).toFixed(0) : 0;

            const bar = document.getElementById('progress-bar');
            bar.style.width = percentage + '%%';
            document.getElementById('progress-text').textContent = collected + '/' + total + ' Evidence Collected';
        }

        function saveToLocal() {
            const controls = {};
            document.querySelectorAll('.control').forEach(el => {
                const id = el.dataset.control;
                const collected = el.classList.contains('collected');
                const notes = el.querySelector('.notes').value;
                controls[id] = { collected, notes };
            });
            localStorage.setItem(STORAGE_KEY, JSON.stringify(controls));
        }

        function loadFromLocal() {
            const saved = localStorage.getItem(STORAGE_KEY);
            if (saved) {
                const controls = JSON.parse(saved);
                Object.keys(controls).forEach(id => {
                    const el = document.querySelector('[data-control="' + id + '"]');
                    if (el && controls[id]) {
                        if (controls[id].collected) {
                            el.classList.add('collected');
                            el.querySelector('input[type="checkbox"]').checked = true;
                        }
                        if (controls[id].notes) {
                            el.querySelector('.notes').value = controls[id].notes;
                        }
                    }
                });
                updateProgress();
            }
        }

        function exportProgress() {
            const data = {
                account: '%s',
                exportDate: new Date().toISOString(),
                controls: {}
            };

            document.querySelectorAll('.control').forEach(el => {
                const id = el.dataset.control;
                data.controls[id] = {
                    status: el.classList.contains('pass') ? 'PASS' : 'FAIL',
                    evidenceCollected: el.classList.contains('collected'),
                    notes: el.querySelector('.notes').value
                };
            });

            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'evidence-progress-%s.json';
            a.click();
        }

        // Auto-save notes on blur
        document.querySelectorAll('.notes').forEach(input => {
            input.addEventListener('blur', saveToLocal);
        });

        // Load saved progress on page load
        loadFromLocal();
        </script>
    </div>
</body>
</html>`, accountID, accountID, accountID)

	return html
}

