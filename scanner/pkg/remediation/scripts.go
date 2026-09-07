package remediation

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type ControlResult struct {
	Control           string
	Status            string
	Severity          string
	RemediationDetail string
}

func GenerateFixScript(results []ControlResult, outputPath string) error {
	script := strings.Builder{}
	script.WriteString("#!/bin/bash\n")
	script.WriteString("# AuditKit Auto-Remediation Script\n")
	script.WriteString("# Generated: " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	script.WriteString("#  REVIEW BEFORE RUNNING - This will modify your AWS account!\n\n")

	script.WriteString("set -e  # Exit on error\n\n")
	script.WriteString("echo 'AuditKit Auto-Remediation Starting...'\n\n")

	criticalFixes := []string{}
	highFixes := []string{}

	for _, control := range results {
		if control.Status == "FAIL" && control.RemediationDetail != "" {
			if control.Severity == "CRITICAL" {
				criticalFixes = append(criticalFixes, control.RemediationDetail)
			} else if control.Severity == "HIGH" {
				highFixes = append(highFixes, control.RemediationDetail)
			}
		}
	}

	if len(criticalFixes) > 0 {
		script.WriteString("# CRITICAL FIXES (Do these first!)\n")
		for i, fix := range criticalFixes {
			script.WriteString(fmt.Sprintf("echo '[%d/%d] Applying critical fix...'\n", i+1, len(criticalFixes)))
			script.WriteString(fix + "\n\n")
		}
	}

	if len(highFixes) > 0 {
		script.WriteString("#  HIGH PRIORITY FIXES\n")
		for i, fix := range highFixes {
			script.WriteString(fmt.Sprintf("echo '[%d/%d] Applying high priority fix...'\n", i+1, len(highFixes)))
			script.WriteString("# " + fix + "  # Uncomment to run\n\n")
		}
	}

	script.WriteString("echo 'Remediation complete! Re-run auditkit scan to verify.'\n")

	return os.WriteFile(outputPath, []byte(script.String()), 0755)
}
