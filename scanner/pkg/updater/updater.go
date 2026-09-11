package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// CurrentVersion is set by main at startup. It used to be a second, stale
// constant that no build flag overrode, so a v0.8.6 binary reported
// "New version available: v0.8.6 (you have v0.3.0)" to everyone.
var CurrentVersion = "dev"

type ReleaseInfo struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	URL     string `json:"html_url"`
}

// newerVersion reports whether a is a later release than b, comparing each
// dotted component numerically.
func newerVersion(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out []int
	for _, seg := range strings.Split(v, ".") {
		n, err := strconv.Atoi(seg)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func CheckForUpdates() {
	// Check GitHub releases API
	resp, err := http.Get("https://api.github.com/repos/guardian-nexus/AuditKit-Community-Edition/releases/latest")
	if err != nil {
		fmt.Println("Unable to check for updates")
		return
	}
	defer resp.Body.Close()

	var release ReleaseInfo
	json.NewDecoder(resp.Body).Decode(&release)

	// A plain string compare says v0.9.0 > v0.10.0. Compare the numbers.
	if newerVersion(release.TagName, CurrentVersion) {
		fmt.Printf("\n New version available: %s (you have %s)\n", release.TagName, CurrentVersion)
		fmt.Printf("   Update: go install github.com/guardian-nexus/AuditKit-Community-Edition/scanner/cmd/auditkit@latest\n")
		fmt.Printf("   Or download: %s\n\n", release.URL)
	} else {
		fmt.Printf("You're on the latest version (%s)\n", CurrentVersion)
	}
}
