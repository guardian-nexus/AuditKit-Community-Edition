package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/core"
	"github.com/guardian-nexus/auditkit/scanner/pkg/providers/gcp"
)

var CurrentVersion = "v0.8.4"

func main() {
	var (
		project   = flag.String("project", "", "GCP project ID (or set GOOGLE_CLOUD_PROJECT)")
		framework = flag.String("framework", "all", "Compliance framework: soc2, pci, cis-gcp, all")
		format    = flag.String("format", "text", "Output format (text, json)")
		output    = flag.String("output", "", "Output file (default: stdout)")
		verbose   = flag.Bool("verbose", false, "Verbose output")
		services  = flag.String("services", "all", "Comma-separated services to scan")
	)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	flag.CommandLine.Parse(os.Args[2:])

	switch command {
	case "scan":
		runScan(*project, *framework, *format, *output, *verbose, *services)
	case "version":
		fmt.Printf("AuditKit GCP Scanner %s\n", CurrentVersion)
		fmt.Println("Optimized GCP-only binary (no AWS, Azure, or M365 dependencies)")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AuditKit GCP Scanner - Optimized GCP-only binary

Usage:
  auditkit-gcp scan [options]    Scan GCP for compliance
  auditkit-gcp version            Show version

Options:
  -project string     GCP project ID (or set GOOGLE_CLOUD_PROJECT env var)
  -framework string   Framework: soc2, pci, cis-gcp, all (default "all")
  -format string      Output format (text, json) (default "text")
  -output string      Output file (default: stdout)
  -services string    Services to scan (default "all")
  -verbose            Verbose output

Examples:
  # SOC2 scan
  export GOOGLE_CLOUD_PROJECT=my-project-id
  auditkit-gcp scan -framework soc2

  # CIS GCP scan with JSON output
  auditkit-gcp scan -project my-project -framework cis-gcp -format json

  # Specific services
  auditkit-gcp scan -services storage,iam,compute

Binary Size: ~40-60MB (vs 360MB for full multi-cloud auditkit)
For multi-cloud scanning, use the full 'auditkit' binary instead.`)
}

func runScan(projectID, framework, format, output string, verbose bool, services string) {
	ctx := context.Background()

	// Get project ID from env if not specified
	if projectID == "" || projectID == "default" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("GCP_PROJECT")
		}
	}

	if projectID == "" {
		fmt.Fprintf(os.Stderr, "Error: GCP project ID required\n")
		fmt.Fprintf(os.Stderr, "Set via -project flag or GOOGLE_CLOUD_PROJECT env var\n")
		os.Exit(1)
	}

	// Normalize framework
	framework = strings.ToLower(strings.TrimSpace(framework))
	if framework == "cis" {
		framework = "cis-gcp"
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Starting %s scan for GCP...\n", strings.ToUpper(framework))
	}

	// Initialize GCP provider
	provider := gcp.NewProvider()
	if err := provider.Initialize(projectID); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing GCP: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nMake sure you have GCP credentials configured:\n")
		fmt.Fprintf(os.Stderr, "  gcloud auth application-default login\n")
		fmt.Fprintf(os.Stderr, "  export GOOGLE_CLOUD_PROJECT=%s\n", projectID)
		os.Exit(1)
	}
	defer provider.Close()

	accountID := provider.GetAccountID(ctx)
	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning GCP Project: %s\n", accountID)
		fmt.Fprintf(os.Stderr, "Framework: %s\n", strings.ToUpper(framework))
	}

	// Parse services
	serviceList := strings.Split(services, ",")
	if services == "all" {
		serviceList = []string{"storage", "iam", "compute", "network", "sql", "kms", "logging"}
	}

	// Scan
	results, err := provider.Scan(ctx, serviceList, framework, verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning during scan: %v\n", err)
	}

	// Calculate score
	passed := 0
	failed := 0
	for _, r := range results {
		if r.Status == "PASS" {
			passed++
		} else if r.Status == "FAIL" {
			failed++
		}
	}

	score := 0.0
	total := passed + failed
	if total > 0 {
		score = float64(passed) / float64(total) * 100
	}

	// Output results
	switch format {
	case "text":
		printTextSummary(accountID, framework, score, passed, failed)
	case "json":
		outputJSON(accountID, framework, score, passed, failed, results, output)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
		os.Exit(1)
	}
}

func printTextSummary(accountID, framework string, score float64, passed, failed int) {
	fmt.Printf("\n")
	fmt.Printf("AuditKit GCP %s Compliance Scan\n", strings.ToUpper(framework))
	fmt.Printf("=====================================\n")
	fmt.Printf("GCP Project: %s\n", accountID)
	fmt.Printf("Framework: %s\n", strings.ToUpper(framework))
	fmt.Printf("Scan Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("\n")

	scoreColor := "\033[32m"
	if score < 80 {
		scoreColor = "\033[33m"
	}
	if score < 60 {
		scoreColor = "\033[31m"
	}
	fmt.Printf("Compliance Score: %s%.1f%%\033[0m\n", scoreColor, score)
	fmt.Printf("Controls Passed: %d/%d\n", passed, passed+failed)
	fmt.Printf("\n")

	fmt.Printf("For detailed JSON output:\n")
	fmt.Printf("  auditkit-gcp scan -framework %s -format json -output report.json\n", framework)
	fmt.Printf("\n")
}

func outputJSON(accountID, framework string, score float64, passed, failed int, results []core.ScanResult, output string) {
	report := map[string]interface{}{
		"timestamp":       time.Now(),
		"provider":        "gcp",
		"framework":       framework,
		"account_id":      accountID,
		"score":           score,
		"total_controls":  passed + failed,
		"passed_controls": passed,
		"failed_controls": failed,
		"controls":        results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
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
		fmt.Println(string(data))
	}
}
