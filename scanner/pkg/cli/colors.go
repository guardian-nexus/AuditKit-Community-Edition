// Package cli provides CLI output formatting utilities
package cli

import (
	"fmt"
	"os"
	"strings"
)

// ANSI color codes
const (
	Reset      = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"

	// Foreground colors
	Red        = "\033[31m"
	Green      = "\033[32m"
	Yellow     = "\033[33m"
	Blue       = "\033[34m"
	Magenta    = "\033[35m"
	Cyan       = "\033[36m"
	White      = "\033[37m"

	// Bright foreground colors
	BrightRed    = "\033[91m"
	BrightGreen  = "\033[92m"
	BrightYellow = "\033[93m"
	BrightBlue   = "\033[94m"
	BrightCyan   = "\033[96m"

	// Background colors
	BgRed      = "\033[41m"
	BgGreen    = "\033[42m"
	BgYellow   = "\033[43m"
)

// IsColorEnabled checks if color output should be enabled
func IsColorEnabled() bool {
	// Disable colors if NO_COLOR env is set or not a terminal
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	// Check if stdout is a terminal
	fi, _ := os.Stdout.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Color wraps text with color codes
func Color(color, text string) string {
	if !IsColorEnabled() {
		return text
	}
	return color + text + Reset
}

// Pass returns green-colored "[PASS]"
func Pass() string {
	return Color(Green, "[PASS]")
}

// Fail returns red-colored "[FAIL]"
func Fail() string {
	return Color(Red, "[FAIL]")
}

// Warn returns yellow-colored "[WARN]"
func Warn() string {
	return Color(Yellow, "[WARN]")
}

// Info returns cyan-colored "[INFO]"
func Info() string {
	return Color(Cyan, "[INFO]")
}

// Critical returns bright red bold "[CRITICAL]"
func Critical() string {
	return Color(Bold+BrightRed, "[CRITICAL]")
}

// High returns yellow "[HIGH]"
func High() string {
	return Color(Yellow, "[HIGH]")
}

// Medium returns blue "[MEDIUM]"
func Medium() string {
	return Color(Blue, "[MEDIUM]")
}

// Low returns dim "[LOW]"
func Low() string {
	return Color(Dim, "[LOW]")
}

// ScoreColor returns appropriate color for a compliance score
func ScoreColor(score float64) string {
	if score >= 90 {
		return BrightGreen
	} else if score >= 80 {
		return Green
	} else if score >= 60 {
		return Yellow
	}
	return Red
}

// FormatScore formats a compliance score with color
func FormatScore(score float64) string {
	return Color(ScoreColor(score), fmt.Sprintf("%.1f%%", score))
}

// FormatStatus returns formatted status with appropriate color
func FormatStatus(status string) string {
	switch strings.ToUpper(status) {
	case "PASS":
		return Pass()
	case "FAIL":
		return Fail()
	case "WARN", "WARNING":
		return Warn()
	case "INFO", "MANUAL":
		return Info()
	default:
		return "[" + status + "]"
	}
}

// FormatSeverity returns formatted severity with appropriate color
func FormatSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return Critical()
	case "HIGH":
		return High()
	case "MEDIUM":
		return Medium()
	case "LOW":
		return Low()
	default:
		return "[" + severity + "]"
	}
}

// Header prints a bold header line
func Header(text string) {
	fmt.Printf("\n%s%s%s\n", Bold, text, Reset)
	fmt.Println(strings.Repeat("=", len(text)))
}

// SubHeader prints a subheader
func SubHeader(text string) {
	fmt.Printf("\n%s%s%s\n", Cyan, text, Reset)
	fmt.Println(strings.Repeat("-", len(text)))
}

// Success prints a success message
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", Color(Green, "OK"), msg)
}

// Error prints an error message to stderr
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", Color(Red, "ERROR:"), msg)
}

// Warning prints a warning message
func Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", Color(Yellow, "WARNING:"), msg)
}
