package remediation

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type ControlResult struct {
	Control           string
	Status            string
	Severity          string
	RemediationDetail string
}

// GenerateFixScript writes the CRITICAL and HIGH fixes for failed controls as a
// shell script in which every line of every fix is commented out.
//
// HIGH fixes used to get one "# " in front of a multi-line RemediationDetail,
// leaving lines two onward live: "uncomment to run" ran them anyway. CRITICAL
// fixes were written uncommented, but most CRITICAL remediation text is prose
// ("1. Sign in as root user"), which aborted the script under set -e after
// earlier fixes had run, and some is a command with a placeholder in it
// ("--access-key-id OLD_KEY_ID") that half-applies a change. A script that
// changes an account is reviewed line by line and uncommented on purpose.
func GenerateFixScript(results []ControlResult, outputPath string) error {
	script := strings.Builder{}
	script.WriteString("#!/bin/bash\n")
	script.WriteString("# AuditKit Auto-Remediation Script\n")
	script.WriteString("# Generated: " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	script.WriteString("#  REVIEW BEFORE RUNNING - This will modify your cloud account!\n")
	script.WriteString("#\n")
	script.WriteString("# Every fix below is commented out. Read each one, replace any placeholder,\n")
	script.WriteString("# and uncomment only the lines you intend to run. Steps written as prose\n")
	script.WriteString("# are done by hand.\n\n")

	script.WriteString("set -e  # Exit on error\n\n")

	criticalFixes := []ControlResult{}
	highFixes := []ControlResult{}

	for _, control := range results {
		if control.Status == "FAIL" && control.RemediationDetail != "" {
			if control.Severity == "CRITICAL" {
				criticalFixes = append(criticalFixes, control)
			} else if control.Severity == "HIGH" {
				highFixes = append(highFixes, control)
			}
		}
	}

	writeFixes := func(title string, fixes []ControlResult) {
		if len(fixes) == 0 {
			return
		}
		script.WriteString("# " + title + "\n\n")
		for i, fix := range fixes {
			script.WriteString(CommentBlock(fmt.Sprintf("[%d/%d] %s", i+1, len(fixes), fix.Control)))
			script.WriteString(CommentBlock(fix.RemediationDetail))
			script.WriteString("\n")
		}
	}
	writeFixes("CRITICAL FIXES (do these first)", criticalFixes)
	writeFixes("HIGH PRIORITY FIXES", highFixes)

	script.WriteString(fmt.Sprintf("echo %s\n", ShellQuote(fmt.Sprintf(
		"%d critical and %d high fix(es) listed as comments; nothing was changed. Uncomment the ones to apply, then re-run.",
		len(criticalFixes), len(highFixes)))))

	return os.WriteFile(outputPath, []byte(script.String()), 0755)
}

// CommentBlock comments out every line of text, not just the first, so
// multi-line or numbered remediation text cannot leave a live shell line.
func CommentBlock(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	var b strings.Builder
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	for _, line := range strings.Split(text, "\n") {
		b.WriteString("# ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// ShellQuote returns s as a single bash word: wrapped in single quotes, with
// each embedded single quote closed, escaped and reopened. Nothing inside is
// expanded or executed.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// OneLine flattens text for a context that must stay on one line, such as a
// comment header, by turning line breaks into spaces.
func OneLine(s string) string {
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

// safeWord is the character set a cloud resource identifier is allowed for it
// to be placed in a command: names, ids, ARNs and paths, nothing a shell treats
// specially.
var safeWord = regexp.MustCompile(`^[A-Za-z0-9._:/@+=,-]+$`)

// SafeResource reports whether a stored resource can be handed to a CLI
// command. Findings often carry a console URL or prose here, and imported
// findings carry whatever the imported file said.
func SafeResource(resource string) bool {
	r := strings.TrimSpace(resource)
	if r == "" || strings.HasPrefix(r, "http://") || strings.HasPrefix(r, "https://") {
		return false
	}
	return safeWord.MatchString(r)
}

// cloudRunners are the commands a remediation line may start with and still be
// emitted live. Remediation text can come from an imported scan file, so this
// is deliberately the cloud and infrastructure CLIs only - no shells, curl,
// sudo or echo.
var cloudRunners = map[string]bool{
	"aws": true, "az": true, "gcloud": true, "gsutil": true, "kubectl": true, "terraform": true,
}

// placeholder matches the ways remediation text marks a value the operator
// must supply: <trail-name>, OLD_KEY_ID, YOUR_BUCKET.
var placeholder = regexp.MustCompile(`<[^>]*>|\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b`)

// RunnableCommand reports whether a single remediation line may be written into
// a script as a live command: it starts with a cloud CLI, contains no shell
// control characters, so it cannot chain, substitute or redirect into anything
// else, and has no placeholder left to fill in. Anything else is emitted as a
// comment for the operator to run by hand.
func RunnableCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 || !cloudRunners[fields[0]] {
		return false
	}
	if strings.ContainsAny(line, ";&|`$<>()\\\n\r") {
		return false
	}
	return !placeholder.MatchString(line)
}
