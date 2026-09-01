package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

type ComplianceResult struct {
	Timestamp       time.Time
	Provider        string
	AccountID       string
	Framework       string
	Score           float64
	TotalControls   int
	PassedControls  int
	FailedControls  int
	Controls        []ControlResult
	Recommendations []string
}

type ControlResult struct {
	ID              string
	Name            string
	Category        string
	Severity        string
	Status          string
	Evidence        string
	Remediation     string
	ScreenshotGuide string
	ConsoleURL      string
	Frameworks      map[string]string
}

// Generate unique report ID from timestamp + license
func generateReportID() string {
	licenseKey := os.Getenv("AUDITKIT_PRO_LICENSE")
	if licenseKey == "" {
		licenseKey = "unlicensed"
	}
	data := time.Now().String() + licenseKey
	hash := sha256.Sum256([]byte(data))
	return strings.ToUpper(hex.EncodeToString(hash[:8]))
}

func GeneratePDF(result ComplianceResult, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)

	// Get license info for watermark
	licenseKey := os.Getenv("AUDITKIT_PRO_LICENSE")
	lastEight := ""
	if len(licenseKey) >= 8 {
		lastEight = licenseKey[len(licenseKey)-8:]
	}
	reportID := generateReportID()
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Footer on every page WITH WATERMARK
	pdf.SetFooterFunc(func() {
		pdf.SetY(-20)
		pdf.SetFont("Arial", "", 8)
		pdf.SetTextColor(108, 117, 125)

		// First line: License, Report ID, Timestamp
		if lastEight != "" {
			pdf.CellFormat(0, 4, fmt.Sprintf("AuditKit Pro | License: ***-%s | Report ID: %s | %s",
				lastEight, reportID, timestamp), "", 1, "C", false, 0, "")
		} else {
			pdf.CellFormat(0, 4, fmt.Sprintf("AuditKit | Report ID: %s | %s",
				reportID, timestamp), "", 1, "C", false, 0, "")
		}

		// Second line: Warning (only for Pro)
		if lastEight != "" {
			pdf.SetFont("Arial", "", 7)
			pdf.SetTextColor(220, 53, 69)
			pdf.CellFormat(0, 4, "This report is licensed to subscriber only - Unauthorized distribution prohibited", "", 1, "C", false, 0, "")
		}

		// Third line: Support
		pdf.SetFont("Arial", "", 7)
		pdf.SetTextColor(108, 117, 125)
		pdf.CellFormat(0, 4, "For support and documentation, visit auditkit.io", "", 0, "C", false, 0, "")
	})

	// Cover Page
	generateCoverPage(pdf, result)

	// COMPLIANCE DISCLAIMER - NEW PAGE
	generateComplianceDisclaimer(pdf, result)

	// Executive Summary
	generateExecutiveSummary(pdf, result)

	// Critical Issues
	generateCriticalIssues(pdf, result)

	// Evidence Collection Guide - ALL CONTROLS
	generateEvidenceGuideComplete(pdf, result)

	// Evidence Checklist
	generateEvidenceChecklist(pdf, result)

	return pdf.OutputFileAndClose(outputPath)
}

func generateCoverPage(pdf *gofpdf.Fpdf, result ComplianceResult) {
	pdf.AddPage()

	// AuditKit Logo Area (top)
	pdf.SetFont("Arial", "B", 32)
	pdf.SetTextColor(3, 102, 214)
	pdf.CellFormat(0, 20, "AuditKit", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 12)
	pdf.SetTextColor(108, 117, 125)
	pdf.CellFormat(0, 6, "Multi-Cloud Compliance Scanner", "", 1, "C", false, 0, "")
	pdf.Ln(20)

	// Framework Title with Level Detection
	frameworkLabel := "Multi-Framework Compliance Report"
	if result.Framework != "" && result.Framework != "all" {
		if result.Framework == "cmmc" {
			if result.TotalControls <= 17 {
				frameworkLabel = "CMMC Level 1 Compliance Report"
			} else {
				frameworkLabel = "CMMC Level 2 Compliance Report"
			}
		} else {
			frameworkLabel = strings.ToUpper(result.Framework) + " Compliance Report"
		}
	}

	pdf.SetFont("Arial", "B", 28)
	pdf.SetTextColor(0, 0, 0)
	pdf.MultiCell(0, 12, frameworkLabel, "", "C", false)
	pdf.Ln(30)

	// Compliance Score - Large Circle
	drawScoreCircle(pdf, result.Score)
	pdf.Ln(20)

	// Quick Stats
	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(108, 117, 125)

	statsY := pdf.GetY()

	// Total Controls
	pdf.SetXY(30, statsY)
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(50, 10, fmt.Sprintf("%d", result.TotalControls), "", 1, "C", false, 0, "")
	pdf.SetXY(30, pdf.GetY())
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(108, 117, 125)
	pdf.CellFormat(50, 6, "Total Controls", "", 0, "C", false, 0, "")

	// Passed
	pdf.SetXY(85, statsY)
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(40, 167, 69)
	pdf.CellFormat(50, 10, fmt.Sprintf("%d", result.PassedControls), "", 1, "C", false, 0, "")
	pdf.SetXY(85, pdf.GetY())
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(108, 117, 125)
	pdf.CellFormat(50, 6, "Passed", "", 0, "C", false, 0, "")

	// Failed
	pdf.SetXY(140, statsY)
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(220, 53, 69)
	pdf.CellFormat(50, 10, fmt.Sprintf("%d", result.FailedControls), "", 1, "C", false, 0, "")
	pdf.SetXY(140, pdf.GetY())
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(108, 117, 125)
	pdf.CellFormat(50, 6, "Failed", "", 0, "C", false, 0, "")

	pdf.Ln(30)

	// Report Details
	pdf.SetY(250)
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(108, 117, 125)
	pdf.CellFormat(0, 5, fmt.Sprintf("Generated: %s", result.Timestamp.Format("January 2, 2006 at 3:04 PM")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5, fmt.Sprintf("Provider: %s | Account: %s", strings.ToUpper(result.Provider), result.AccountID), "", 1, "C", false, 0, "")
}

func generateComplianceDisclaimer(pdf *gofpdf.Fpdf, result ComplianceResult) {
	pdf.AddPage()

	// Count automated vs manual
	automated := 0
	manual := 0
	passed := 0
	failed := 0

	for _, control := range result.Controls {
		if control.Status == "INFO" || control.Status == "MANUAL" {
			manual++
		} else {
			automated++
			if control.Status == "PASS" {
				passed++
			} else if control.Status == "FAIL" {
				failed++
			}
		}
	}

	automatedScore := 0.0
	if automated > 0 {
		automatedScore = float64(passed) / float64(automated) * 100
	}

	// Warning banner
	pdf.SetFillColor(255, 243, 205)
	pdf.Rect(15, pdf.GetY(), 180, 50, "F")

	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(133, 100, 4)
	pdf.SetY(pdf.GetY() + 8)
	pdf.CellFormat(0, 10, "IMPORTANT: COMPLIANCE DISCLAIMER", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "B", 12)
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(3)
	pdf.CellFormat(0, 6, "Automated Technical Checks Only", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(33, 37, 41)
	pdf.Ln(3)

	disclaimerText := fmt.Sprintf("This compliance score of %.1f%% is based ONLY on %d automated technical checks (%.1f%% of automated checks passed).", result.Score, automated, automatedScore)
	pdf.SetX(20)
	pdf.MultiCell(170, 5, disclaimerText, "", "C", false)

	disclaimerText2 := fmt.Sprintf("The remaining %d controls require manual documentation and cannot be automated.", manual)
	pdf.SetX(20)
	pdf.MultiCell(170, 5, disclaimerText2, "", "C", false)

	pdf.Ln(10)

	// What's included / not included - TWO BOXES
	pdf.SetFont("Arial", "B", 13)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "What This Report Covers", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// LEFT BOX - Automated (GREEN)
	currentY := pdf.GetY()
	pdf.SetFillColor(212, 244, 221)
	pdf.Rect(15, currentY, 85, 60, "F")

	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(40, 167, 69)
	pdf.SetXY(20, currentY+3)
	pdf.CellFormat(75, 6, fmt.Sprintf("Automated: %d controls", automated), "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(33, 37, 41)

	automatedItems := []string{
		"Infrastructure configuration",
		"Access controls (IAM/RBAC)",
		"Encryption settings",
		"Network security rules",
		"Logging and monitoring",
		"Security group rules",
	}

	pdf.SetXY(20, pdf.GetY()+2)
	for _, item := range automatedItems {
		pdf.SetX(20)
		pdf.MultiCell(75, 4, "  - "+item, "", "L", false)
	}

	// RIGHT BOX - Manual (RED)
	pdf.SetFillColor(254, 242, 242)
	pdf.Rect(105, currentY, 90, 60, "F")

	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(220, 53, 69)
	pdf.SetXY(110, currentY+3)
	pdf.CellFormat(80, 6, fmt.Sprintf("Manual: %d controls", manual), "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(33, 37, 41)

	manualItems := []string{
		"Policies and procedures",
		"Training records",
		"Incident response plans",
		"Business continuity plans",
		"Third-party assessments",
		"Physical security controls",
	}

	pdf.SetXY(110, currentY+11)
	for _, item := range manualItems {
		pdf.SetX(110)
		pdf.MultiCell(80, 4, "  - "+item, "", "L", false)
	}

	pdf.SetY(currentY + 65)

	// Your actual compliance statement
	pdf.SetFont("Arial", "B", 12)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "Your Actual Compliance May Be Higher", "", 1, "L", false, 0, "")

	pdf.SetFillColor(246, 248, 250)
	boxY := pdf.GetY()
	pdf.Rect(15, boxY, 180, 35, "F")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(33, 37, 41)
	pdf.SetY(boxY + 4)

	pdf.SetX(20)
	pdf.MultiCell(170, 5, fmt.Sprintf("If you already have documentation for the %d manual controls (policies, procedures, training records, etc.), your true compliance score could be significantly higher than %.1f%%.", manual, result.Score), "", "L", false)

	pdf.Ln(2)
	pdf.SetX(20)
	pdf.SetFont("Arial", "B", 10)
	pdf.MultiCell(170, 5, "This tool identifies technical gaps but cannot verify your documentation. Both are required for certification.", "", "L", false)

	pdf.Ln(8)

	// Critical warning
	warningY := pdf.GetY()
	pdf.SetFillColor(220, 53, 69)
	pdf.Rect(15, warningY, 180, 20, "F")

	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetY(warningY + 5)
	pdf.CellFormat(0, 5, "THIS IS NOT A CERTIFICATION", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.CellFormat(0, 4, "This tool assists with compliance but does not replace formal third-party assessment", "", 1, "C", false, 0, "")
}

func drawScoreCircle(pdf *gofpdf.Fpdf, score float64) {
	centerX := 105.0
	centerY := pdf.GetY() + 25
	radius := 25.0

	var r, g, b int
	if score < 60 {
		r, g, b = 220, 53, 69
	} else if score < 80 {
		r, g, b = 255, 193, 7
	} else {
		r, g, b = 40, 167, 69
	}

	pdf.SetFillColor(r, g, b)
	pdf.SetAlpha(0.1, "Normal")
	pdf.Circle(centerX, centerY, radius, "F")
	pdf.SetAlpha(1.0, "Normal")

	pdf.SetDrawColor(r, g, b)
	pdf.SetLineWidth(2)
	pdf.Circle(centerX, centerY, radius, "D")
	pdf.SetLineWidth(0.2)

	pdf.SetFont("Arial", "B", 36)
	pdf.SetTextColor(r, g, b)

	scoreText := fmt.Sprintf("%.0f%%", score)
	textWidth := pdf.GetStringWidth(scoreText)

	pdf.SetXY(centerX-textWidth/2, centerY-8)
	pdf.CellFormat(textWidth, 12, scoreText, "", 0, "C", false, 0, "")

	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(108, 117, 125)

	labelText := "Compliance Score"
	labelWidth := pdf.GetStringWidth(labelText)

	pdf.SetXY(centerX-labelWidth/2, centerY+6)
	pdf.CellFormat(labelWidth, 6, labelText, "", 0, "C", false, 0, "")
}

func generateExecutiveSummary(pdf *gofpdf.Fpdf, result ComplianceResult) {
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 12, "Executive Summary", "", 1, "L", false, 0, "")
	pdf.Ln(5)

	pdf.SetFillColor(246, 248, 250)
	pdf.Rect(15, pdf.GetY(), 180, 40, "F")

	pdf.SetFont("Arial", "", 11)
	pdf.SetTextColor(33, 37, 41)
	summaryY := pdf.GetY() + 8
	pdf.SetXY(20, summaryY)

	statusText := "requires immediate attention"
	if result.Score >= 80 {
		statusText = "is in good standing"
	} else if result.Score >= 60 {
		statusText = "needs improvement"
	}

	summary := fmt.Sprintf("Your %s environment %s with a compliance score of %.1f%%. Out of %d controls evaluated, %d passed and %d failed. Immediate action is required on %d critical issues.",
		strings.ToUpper(result.Provider),
		statusText,
		result.Score,
		result.TotalControls,
		result.PassedControls,
		result.FailedControls,
		countCritical(result.Controls))

	pdf.MultiCell(170, 5, summary, "", "L", false)
	pdf.Ln(10)

	if len(result.Recommendations) > 0 {
		pdf.SetFont("Arial", "B", 14)
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(0, 10, "Top Priority Actions", "", 1, "L", false, 0, "")

		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(33, 37, 41)

		for i, rec := range result.Recommendations {
			if i >= 5 {
				break
			}

			pdf.CellFormat(10, 6, fmt.Sprintf("%d.", i+1), "", 0, "L", false, 0, "")
			pdf.MultiCell(170, 6, rec, "", "L", false)
			pdf.Ln(2)
		}
	}
}

func generateCriticalIssues(pdf *gofpdf.Fpdf, result ComplianceResult) {
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(220, 53, 69)

	// Dynamic title based on framework and level
	criticalTitle := "Critical Findings"
	if result.Framework == "cmmc" {
		if result.TotalControls <= 17 {
			criticalTitle = "CMMC Level 1 Critical Findings"
		} else {
			criticalTitle = "CMMC Level 2 Critical Findings"
		}
	} else if result.Framework == "pci" {
		criticalTitle = "PCI-DSS Critical Violations"
	} else if result.Framework == "hipaa" {
		criticalTitle = "HIPAA Security Rule Violations"
	} else if result.Framework == "soc2" {
		criticalTitle = "SOC2 Critical Control Failures"
	}

	pdf.CellFormat(0, 12, criticalTitle, "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(108, 117, 125)
	pdf.MultiCell(0, 5, "These issues must be resolved before your audit. Each failure represents a significant compliance gap.", "", "L", false)
	pdf.Ln(8)

	criticalCount := 0
	for _, control := range result.Controls {
		if control.Status == "FAIL" && control.Severity == "CRITICAL" {
			criticalCount++
			generateControlCard(pdf, control, criticalCount, result.Framework)
		}
	}

	if criticalCount == 0 {
		pdf.SetFillColor(212, 244, 221)
		pdf.Rect(15, pdf.GetY(), 180, 15, "F")
		pdf.SetTextColor(40, 167, 69)
		pdf.SetFont("Arial", "B", 11)
		pdf.CellFormat(0, 15, "[PASS] No critical issues found - excellent work!", "", 1, "C", false, 0, "")
	}
}

func generateControlCard(pdf *gofpdf.Fpdf, control ControlResult, number int, framework string) {
	startY := pdf.GetY()

	if startY > 240 {
		pdf.AddPage()
		startY = pdf.GetY()
	}

	pdf.SetFillColor(254, 242, 242)
	pdf.Rect(15, startY, 180, 0, "F")

	pdf.SetFont("Arial", "B", 12)
	pdf.SetTextColor(220, 53, 69)

	controlLabel := fmt.Sprintf("%d. [%s] %s", number, control.ID, control.Name)

	pdf.SetXY(20, startY+3)
	pdf.MultiCell(170, 6, controlLabel, "", "L", false)

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(33, 37, 41)
	pdf.SetX(20)
	pdf.MultiCell(170, 5, fmt.Sprintf("Issue: %s", control.Evidence), "", "L", false)
	pdf.Ln(2)

	if control.Remediation != "" {
		pdf.SetFont("Courier", "", 9)
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFillColor(248, 249, 250)

		remediationY := pdf.GetY()
		pdf.Rect(20, remediationY, 170, 0, "F")

		pdf.SetXY(23, remediationY+2)
		pdf.MultiCell(164, 4, fmt.Sprintf("$ %s", control.Remediation), "", "L", false)

		endY := pdf.GetY()
		pdf.SetDrawColor(222, 226, 230)
		pdf.Rect(20, remediationY, 170, endY-remediationY+2, "D")
	}

	endY := pdf.GetY() + 3
	pdf.SetDrawColor(220, 53, 69)
	pdf.SetLineWidth(0.5)
	pdf.Rect(15, startY, 180, endY-startY, "D")
	pdf.SetLineWidth(0.2)

	pdf.SetY(endY + 5)
}

func generateEvidenceGuideComplete(pdf *gofpdf.Fpdf, result ComplianceResult) {
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 12, "Evidence Collection Guide", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(108, 117, 125)

	evidenceNote := "Your auditor requires evidence for ALL controls. Follow these steps:"
	if result.Framework == "cmmc" {
		if result.TotalControls <= 17 {
			evidenceNote = "C3PAO assessor requires evidence for ALL CMMC Level 1 practices:"
		} else {
			evidenceNote = "C3PAO assessor requires evidence for ALL CMMC Level 2 practices:"
		}
	}

	pdf.MultiCell(0, 5, evidenceNote, "", "L", false)
	pdf.Ln(8)

	// Separate controls by status
	failedControls := []ControlResult{}
	passedControls := []ControlResult{}
	infoControls := []ControlResult{}

	for _, control := range result.Controls {
		if control.Status == "FAIL" {
			failedControls = append(failedControls, control)
		} else if control.Status == "PASS" {
			passedControls = append(passedControls, control)
		} else if control.Status == "INFO" || control.Status == "MANUAL" {
			infoControls = append(infoControls, control)
		}
	}

	// Show ALL failed controls - NO TRUNCATION
	if len(failedControls) > 0 {
		pdf.SetFont("Arial", "B", 14)
		pdf.SetTextColor(220, 53, 69)
		pdf.CellFormat(0, 8, fmt.Sprintf("Failed Controls - Fix Then Screenshot (%d total)", len(failedControls)), "", 1, "L", false, 0, "")
		pdf.Ln(3)

		for i, control := range failedControls {
			generateEvidenceCard(pdf, control, i+1)
		}
	}

	// Show ALL passed controls - NO TRUNCATION
	if len(passedControls) > 0 {
		if len(failedControls) > 0 {
			pdf.AddPage()
		}

		pdf.SetFont("Arial", "B", 14)
		pdf.SetTextColor(40, 167, 69)
		pdf.CellFormat(0, 8, fmt.Sprintf("Passed Controls - Collect Evidence (%d total)", len(passedControls)), "", 1, "L", false, 0, "")

		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(108, 117, 125)
		pdf.MultiCell(0, 5, "These controls passed automated checks. You still need screenshots for audit evidence.", "", "L", false)
		pdf.Ln(5)

		for i, control := range passedControls {
			generateEvidenceCard(pdf, control, i+1)
		}
	}

	// Show ALL INFO controls - NO TRUNCATION
	if len(infoControls) > 0 {
		pdf.AddPage()

		pdf.SetFont("Arial", "B", 14)
		pdf.SetTextColor(3, 102, 214)
		pdf.CellFormat(0, 8, fmt.Sprintf("Manual Documentation Required (%d total)", len(infoControls)), "", 1, "L", false, 0, "")

		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(108, 117, 125)
		pdf.MultiCell(0, 5, "These controls require manual documentation or policy evidence that cannot be automated.", "", "L", false)
		pdf.Ln(5)

		for i, control := range infoControls {
			generateInfoCard(pdf, control, i+1)
		}
	}
}

func generateEvidenceCard(pdf *gofpdf.Fpdf, control ControlResult, number int) {
	startY := pdf.GetY()

	if startY > 240 {
		pdf.AddPage()
		startY = pdf.GetY()
	}

	pdf.SetFillColor(255, 255, 255)
	pdf.SetDrawColor(222, 226, 230)
	pdf.Rect(15, startY, 180, 0, "FD")

	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(0, 0, 0)
	pdf.SetXY(20, startY+3)

	// Clean ALL special characters including unicode arrows
	cleanID := strings.ReplaceAll(control.ID, "→", "->")
	cleanID = strings.ReplaceAll(cleanID, "•", "-")
	cleanName := strings.ReplaceAll(control.Name, "→", "->")
	cleanName = strings.ReplaceAll(cleanName, "•", "-")

	pdf.CellFormat(0, 6, fmt.Sprintf("%d. %s - %s", number, cleanID, cleanName), "", 1, "L", false, 0, "")

	if control.ConsoleURL != "" {
		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(3, 102, 214)
		pdf.SetX(20)
		pdf.CellFormat(0, 5, fmt.Sprintf("Console: %s", control.ConsoleURL), "", 1, "L", false, 0, "")
	}

	if control.ScreenshotGuide != "" {
		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(73, 80, 87)

		// Clean ALL unicode characters
		cleanGuide := strings.ReplaceAll(control.ScreenshotGuide, "→", "->")
		cleanGuide = strings.ReplaceAll(cleanGuide, "•", "-")
		cleanGuide = strings.ReplaceAll(cleanGuide, "â†'", "->") // Corrupted encoding
		cleanGuide = strings.ReplaceAll(cleanGuide, "â", "")     // Remove remaining artifacts

		steps := strings.Split(cleanGuide, "\n")
		for _, step := range steps {
			step = strings.TrimSpace(step)
			if len(step) > 0 {
				pdf.SetX(23)
				pdf.MultiCell(167, 4, fmt.Sprintf("- %s", step), "", "L", false)
			}
		}
	}

	endY := pdf.GetY() + 3
	pdf.SetDrawColor(222, 226, 230)
	pdf.Rect(15, startY, 180, endY-startY, "D")

	pdf.SetY(endY + 3)
}

func generateInfoCard(pdf *gofpdf.Fpdf, control ControlResult, number int) {
	startY := pdf.GetY()

	if startY > 240 {
		pdf.AddPage()
		startY = pdf.GetY()
	}

	pdf.SetDrawColor(3, 102, 214)
	pdf.SetLineWidth(0.3)

	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(3, 102, 214)
	pdf.SetXY(20, startY+3)

	// Clean ALL special characters including unicode arrows
	cleanID := strings.ReplaceAll(control.ID, "→", "->")
	cleanID = strings.ReplaceAll(cleanID, "•", "-")
	cleanID = strings.ReplaceAll(cleanID, "â†'", "->")
	cleanID = strings.ReplaceAll(cleanID, "â", "")
	cleanName := strings.ReplaceAll(control.Name, "→", "->")
	cleanName = strings.ReplaceAll(cleanName, "•", "-")
	cleanName = strings.ReplaceAll(cleanName, "â†'", "->")
	cleanName = strings.ReplaceAll(cleanName, "â", "")

	pdf.MultiCell(170, 6, fmt.Sprintf("%d. [INFO] %s - %s", number, cleanID, cleanName), "", "L", false)

	// Evidence guidance
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(73, 80, 87)
	pdf.SetX(23)

	cleanEvidence := strings.ReplaceAll(control.Evidence, "→", "->")
	cleanEvidence = strings.ReplaceAll(cleanEvidence, "â†'", "->")
	cleanEvidence = strings.ReplaceAll(cleanEvidence, "â", "")
	pdf.MultiCell(167, 5, fmt.Sprintf("Documentation Required: %s", cleanEvidence), "", "L", false)

	// Screenshot guide
	if control.ScreenshotGuide != "" {
		pdf.SetFont("Arial", "I", 9)
		pdf.SetTextColor(108, 117, 125)

		cleanGuide := strings.ReplaceAll(control.ScreenshotGuide, "→", "->")
		cleanGuide = strings.ReplaceAll(cleanGuide, "•", "-")
		cleanGuide = strings.ReplaceAll(cleanGuide, "â†'", "->")
		cleanGuide = strings.ReplaceAll(cleanGuide, "â", "")

		steps := strings.Split(cleanGuide, "\n")
		for _, step := range steps {
			step = strings.TrimSpace(step)
			if len(step) > 0 {
				pdf.SetX(26)
				pdf.MultiCell(164, 4, fmt.Sprintf("- %s", step), "", "L", false)
			}
		}
	}

	// Console URL
	if control.ConsoleURL != "" {
		pdf.SetFont("Arial", "", 9)
		pdf.SetTextColor(3, 102, 214)
		pdf.SetX(23)
		pdf.CellFormat(0, 5, fmt.Sprintf("Console: %s", control.ConsoleURL), "", 1, "L", false, 0, "")
	}

	endY := pdf.GetY() + 3
	pdf.SetDrawColor(3, 102, 214)
	pdf.Rect(15, startY, 180, endY-startY, "D")
	pdf.SetLineWidth(0.2)

	pdf.SetY(endY + 3)
}

func generateEvidenceChecklist(pdf *gofpdf.Fpdf, result ComplianceResult) {
	pdf.AddPage()

	// Dynamic title based on framework
	checklistTitle := "Evidence Checklist"
	if result.Framework == "cmmc" {
		if result.TotalControls <= 17 {
			checklistTitle = "CMMC Level 1 Evidence Checklist"
		} else {
			checklistTitle = "CMMC Level 2 Evidence Checklist"
		}
	} else if result.Framework == "pci" {
		checklistTitle = "PCI-DSS Evidence Checklist"
	} else if result.Framework == "hipaa" {
		checklistTitle = "HIPAA Evidence Checklist"
	} else if result.Framework == "soc2" {
		checklistTitle = "SOC2 Evidence Checklist"
	}

	pdf.SetFont("Arial", "B", 20)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 12, checklistTitle, "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(108, 117, 125)
	pdf.CellFormat(0, 5, "Check off each item as you collect evidence for your audit", "", 1, "L", false, 0, "")
	pdf.Ln(8)

	checklistItems := getFrameworkChecklist(result.Framework, result.TotalControls)

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(33, 37, 41)

	for _, item := range checklistItems {
		pdf.SetX(20)
		// Clean special characters
		cleanItem := strings.ReplaceAll(item, "->", "->")
		pdf.MultiCell(170, 6, cleanItem, "", "L", false)
	}
}

func getFrameworkChecklist(framework string, totalControls int) []string {
	switch strings.ToLower(framework) {
	case "pci", "pci-dss":
		return []string{
			"[ ] Cardholder Data Environment (CDE) Network Diagram",
			"[ ] Firewall Configuration Screenshots (Requirement 1)",
			"[ ] User Access Control Matrix (Requirement 7)",
			"[ ] MFA Configuration for All Admin Access (Requirement 8.3)",
			"[ ] Password Policy Settings (Requirement 8.2)",
			"[ ] Access Key Rotation Report (< 90 days)",
			"[ ] Encryption Settings for Data at Rest (Requirement 3.4)",
			"[ ] Audit Log Configuration (Requirement 10)",
			"[ ] Log Retention Settings (90+ days minimum)",
			"[ ] Vulnerability Scan Results (Requirement 11)",
			"[ ] Security Patch Documentation (Requirement 6.2)",
			"[ ] Incident Response Plan (Requirement 12.10)",
		}
	case "hipaa":
		return []string{
			"[ ] Access Control Documentation (164.312(a)(1))",
			"[ ] Unique User Identification Settings (164.312(a)(2)(i))",
			"[ ] Automatic Logoff Configuration (164.312(a)(2)(iii))",
			"[ ] Encryption/Decryption Methods (164.312(a)(2)(iv))",
			"[ ] Audit Logs and Controls (164.312(b))",
			"[ ] Integrity Controls Documentation (164.312(c)(1))",
			"[ ] Transmission Security Settings (164.312(e)(1))",
			"[ ] Business Associate Agreements (BAAs)",
			"[ ] Risk Assessment Documentation",
			"[ ] Workforce Training Records",
			"[ ] Contingency Plan and Backup Procedures",
			"[ ] Physical Safeguards Documentation",
		}
	case "cmmc":
		if totalControls <= 17 {
			// CMMC Level 1
			return []string{
				"[ ] Access Control Policy (AC.L1-3.1.1 - 3.1.2)",
				"[ ] Identification and Authentication (IA.L1-3.5.1 - 3.5.2)",
				"[ ] Media Protection (MP.L1-3.8.3)",
				"[ ] Physical Protection (PE.L1-3.10.1 - 3.10.5)",
				"[ ] Personnel Security (PS.L1-3.9.1 - 3.9.2)",
				"[ ] System and Communications Protection (SC.L1-3.13.1 - 3.13.16)",
				"[ ] System and Information Integrity (SI.L1-3.14.1 - 3.14.5)",
				"",
				"For CMMC Level 2 (CUI Protection - 110 additional practices):",
				"Visit auditkit.io/pro",
			}
		} else {
			// CMMC Level 2
			return []string{
				"[ ] Access Control Policy (AC.L2-3.1.1 - 3.1.22)",
				"[ ] Awareness and Training Records (AT.L2-3.2.1 - 3.2.3)",
				"[ ] Audit and Accountability Logs (AU.L2-3.3.1 - 3.3.9)",
				"[ ] Configuration Management Documentation (CM.L2-3.4.1 - 3.4.9)",
				"[ ] Identification and Authentication (IA.L2-3.5.1 - 3.5.11)",
				"[ ] Incident Response Plan (IR.L2-3.6.1 - 3.6.3)",
				"[ ] Maintenance Documentation (MA.L2-3.7.1 - 3.7.6)",
				"[ ] Media Protection Procedures (MP.L2-3.8.1 - 3.8.9)",
				"[ ] Personnel Security (PS.L2-3.9.1 - 3.9.2)",
				"[ ] Physical Protection (PE.L2-3.10.1 - 3.10.6)",
				"[ ] Risk Assessment Documentation (RA.L2-3.11.1 - 3.11.4)",
				"[ ] Security Assessment Reports (CA.L2-3.12.1 - 3.12.5)",
				"[ ] System and Communications Protection (SC.L2-3.13.1 - 3.13.16)",
				"[ ] System and Information Integrity (SI.L2-3.14.1 - 3.14.7)",
			}
		}
	default:
		return []string{
			"[ ] AWS Account Summary Page",
			"[ ] IAM Dashboard showing MFA status",
			"[ ] Password Policy Settings",
			"[ ] S3 Bucket Encryption Settings",
			"[ ] CloudTrail Configuration",
			"[ ] Security Groups Configuration",
			"[ ] Access Key Age Report",
			"[ ] VPC Flow Logs Configuration",
			"[ ] AWS Config Dashboard",
		}
	}
}

func countCritical(controls []ControlResult) int {
	count := 0
	for _, control := range controls {
		if control.Status == "FAIL" && control.Severity == "CRITICAL" {
			count++
		}
	}
	return count
}
