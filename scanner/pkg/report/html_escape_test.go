package report

import (
	"strings"
	"testing"
)

// Every string in a result can come from the scanned account (an Entra display
// name, a tag) or an imported file. The report interpolated them raw, so this
// markup ran in the assessor's browser, or quietly rewrote what the page said.
func TestHTMLReportEscapesScanData(t *testing.T) {
	const payload = `<script>alert(1)</script><b onmouseover=x>`
	controls := []ControlResult{}
	for _, status := range []string{"FAIL", "PASS", "INFO", "MANUAL", "ERROR"} {
		controls = append(controls, ControlResult{
			ID:                status + "-1" + payload,
			Name:              "name" + payload,
			Category:          "cat" + payload,
			Severity:          "HIGH",
			Status:            status,
			Evidence:          "evidence" + payload,
			Remediation:       "fix" + payload,
			RemediationDetail: "detail" + payload,
			ScreenshotGuide:   "step one" + payload + "\nstep two",
			ConsoleURL:        "javascript:alert(document.cookie)",
			Frameworks:        map[string]string{"SOC2": "CC6.1" + payload},
		})
	}
	html := GenerateHTML(ComplianceResult{
		Provider:        "aws" + payload,
		AccountID:       "123" + payload,
		Region:          "us-east-1" + payload,
		Framework:       "soc2",
		Controls:        controls,
		Recommendations: []string{"rec" + payload},
	})

	if strings.Contains(html, "<script>alert(1)") || strings.Contains(html, "<b onmouseover") {
		t.Fatal("scan data reached the HTML report unescaped")
	}
	if strings.Contains(html, "javascript:alert") {
		t.Fatal("a javascript: console URL reached an href")
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("the escaped payload is missing; the field may have been dropped instead of escaped")
	}
}

func TestEscapeForHTMLKeepsWebConsoleLinks(t *testing.T) {
	r := escapeForHTML(ComplianceResult{Controls: []ControlResult{{ConsoleURL: "https://console.aws.amazon.com/iam/home#/users?a=1&b=2"}}})
	if got := r.Controls[0].ConsoleURL; got != "https://console.aws.amazon.com/iam/home#/users?a=1&amp;b=2" {
		t.Fatalf("console link = %q", got)
	}
}

func TestEscapeForHTMLDoesNotModifyTheCaller(t *testing.T) {
	in := ComplianceResult{Controls: []ControlResult{{Evidence: "<x>", Frameworks: map[string]string{"SOC2": "<y>"}}}}
	_ = escapeForHTML(in)
	if in.Controls[0].Evidence != "<x>" || in.Controls[0].Frameworks["SOC2"] != "<y>" {
		t.Fatal("escaping modified the result the caller passed in, which other formats reuse")
	}
}
