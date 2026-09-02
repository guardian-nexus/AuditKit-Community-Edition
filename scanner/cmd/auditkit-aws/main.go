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
	"github.com/guardian-nexus/auditkit/scanner/pkg/providers/aws"
)

var CurrentVersion = "v0.8.5"

func main() {
	var (
		profile   = flag.String("profile", "default", "AWS profile to use")
		framework = flag.String("framework", "all", "Compliance framework: soc2, pci, cmmc, cis-aws, all")
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
		runScan(*profile, *framework, *format, *output, *verbose, *services)
	case "version":
		fmt.Printf("AuditKit AWS Scanner %s\n", CurrentVersion)
		fmt.Println("Optimized AWS-only binary (no Azure, GCP, or M365 dependencies)")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AuditKit AWS Scanner - Optimized AWS-only binary

Usage:
  auditkit-aws scan [options]    Scan AWS for compliance
  auditkit-aws version            Show version

Options:
  -profile string     AWS profile (default "default")
  -framework string   Framework: soc2, pci, cmmc, cis-aws, all (default "all")
  -format string      Output format (text, json) (default "text")
  -output string      Output file (default: stdout)
  -services string    Services to scan (default "all")
  -verbose            Verbose output

Examples:
  # SOC2 scan
  auditkit-aws scan -framework soc2

  # CIS AWS scan with JSON output
  auditkit-aws scan -framework cis-aws -format json -output report.json

  # Specific AWS profile
  auditkit-aws scan -profile production -framework pci

Binary Size: ~80-100MB (vs 360MB for full multi-cloud auditkit)
For multi-cloud scanning, use the full 'auditkit' binary instead.`)
}

func runScan(profile, framework, format, output string, verbose bool, services string) {
	ctx := context.Background()

	// Normalize framework
	framework = strings.ToLower(strings.TrimSpace(framework))
	if framework == "cis" {
		framework = "cis-aws"
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Starting %s scan for AWS...\n", strings.ToUpper(framework))
	}

	// Initialize AWS provider
	provider := aws.NewProvider()
	if err := provider.Initialize(profile); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing AWS: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nMake sure you have AWS credentials configured:\n")
		fmt.Fprintf(os.Stderr, "  aws configure --profile %s\n", profile)
		os.Exit(1)
	}

	accountID := provider.GetAccountID(ctx)
	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning AWS Account: %s\n", accountID)
		fmt.Fprintf(os.Stderr, "Framework: %s\n", strings.ToUpper(framework))
	}

	// Parse services
	serviceList := strings.Split(services, ",")
	if services == "all" {
		serviceList = []string{"s3", "iam", "ec2", "cloudtrail", "rds", "lambda", "ecs", "eks"}
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
		printTextSummary(accountID, framework, score, passed, failed, len(results))
	case "json":
		outputJSON(accountID, framework, score, passed, failed, results, output)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
		os.Exit(1)
	}
}

func printTextSummary(accountID, framework string, score float64, passed, failed, total int) {
	fmt.Printf("\n")
	fmt.Printf("AuditKit AWS %s Compliance Scan\n", strings.ToUpper(framework))
	fmt.Printf("=====================================\n")
	fmt.Printf("AWS Account: %s\n", accountID)
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

	// Show failed controls
	if failed > 0 {
		fmt.Printf("\033[31mFailed Controls: %d\033[0m\n", failed)
		fmt.Printf("(Use -format json for detailed results)\n")
	}

	fmt.Printf("\n")
	fmt.Printf("For detailed JSON output:\n")
	fmt.Printf("  auditkit-aws scan -framework %s -format json -output report.json\n", framework)
	fmt.Printf("\n")
}

func outputJSON(accountID, framework string, score float64, passed, failed int, results []core.ScanResult, output string) {
	report := map[string]interface{}{
		"timestamp":       time.Now(),
		"provider":        "aws",
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
