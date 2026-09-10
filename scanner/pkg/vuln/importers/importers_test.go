package importers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// recentNessus substitutes scan timestamps relative to now, so the fixture
// does not become stale simply by the calendar moving.
func recentNessus() string {
	now := time.Now()
	return strings.NewReplacer(
		"SCAN_TS_A", fmt.Sprint(now.Add(-2*time.Hour).Unix()),
		"SCAN_TS_B", fmt.Sprint(now.Add(-1*time.Hour).Unix()),
	).Replace(nessusXML)
}

// agedNessus substitutes a scan date well outside any sane freshness window.
func agedNessus() string {
	old := fmt.Sprint(time.Now().AddDate(-1, 0, 0).Unix())
	return strings.NewReplacer("SCAN_TS_A", old, "SCAN_TS_B", old).Replace(nessusXML)
}

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const trivyJSON = `{
  "SchemaVersion": 2,
  "ArtifactName": "registry.example.com/app:1.4.2",
  "ArtifactType": "container_image",
  "CreatedAt": "2026-09-08T11:02:00Z",
  "Results": [
    {
      "Target": "registry.example.com/app:1.4.2 (debian 12.5)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-2511",
          "PkgName": "openssl",
          "InstalledVersion": "3.0.11-1",
          "FixedVersion": "3.0.13-1",
          "Severity": "HIGH",
          "Title": "openssl: unbounded memory growth",
          "PublishedDate": "2021-05-04T00:00:00Z"
        },
        {
          "VulnerabilityID": "CVE-2023-45853",
          "PkgName": "zlib",
          "InstalledVersion": "1.2.13",
          "Severity": "CRITICAL",
          "Title": "zlib: integer overflow"
        }
      ]
    }
  ]
}`

const grypeJSON = `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-2511",
        "severity": "High",
        "description": "openssl issue",
        "fix": {"versions": ["3.0.13-1"], "state": "fixed"}
      },
      "artifact": {"name": "openssl", "version": "3.0.11-1"}
    },
    {
      "vulnerability": {
        "id": "CVE-2022-1234",
        "severity": "Negligible",
        "fix": {"versions": [], "state": "not-fixed"}
      },
      "artifact": {"name": "libfoo", "version": "1.0"}
    }
  ],
  "source": {"type": "image", "target": {"userInput": "app:1.4.2", "imageID": "sha256:abc"}},
  "descriptor": {"name": "grype", "version": "0.74.0", "timestamp": "2026-09-08T11:05:00Z"}
}`

const nessusXML = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Quarterly internal scan">
    <ReportHost name="10.0.4.21">
      <HostProperties>
        <tag name="host-ip">10.0.4.21</tag>
        <tag name="HOST_END_TIMESTAMP">SCAN_TS_A</tag>
      </HostProperties>
      <ReportItem pluginID="156032" pluginName="OpenSSL 3.0.x &lt; 3.0.13" severity="3">
        <cve>CVE-2024-2511</cve>
        <risk_factor>High</risk_factor>
        <solution>Upgrade to OpenSSL 3.0.13 or later.</solution>
      </ReportItem>
      <ReportItem pluginID="19506" pluginName="Nessus Scan Information" severity="0">
        <risk_factor>None</risk_factor>
      </ReportItem>
      <ReportItem pluginID="200001" pluginName="Unsupported OS" severity="4">
        <cve>CVE-2020-1111</cve>
        <cve>CVE-2020-2222</cve>
        <risk_factor>Critical</risk_factor>
        <solution>The vendor has released no patch; the operating system is unsupported.</solution>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.4.22">
      <HostProperties>
        <tag name="HOST_END_TIMESTAMP">SCAN_TS_B</tag>
      </HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

// ---- shared guarantees -----------------------------------------------------

// No third-party format reports when a finding was first observed. Ageing from
// the CVE's publication date would fail a host for a vulnerability disclosed
// before the host existed.
func TestNoImportedFindingIsAgeable(t *testing.T) {
	for _, tc := range []struct{ source, name, body string }{
		{"trivy", "trivy.json", trivyJSON},
		{"grype", "grype.json", grypeJSON},
		{"nessus", "scan.nessus", recentNessus()},
	} {
		t.Run(tc.source, func(t *testing.T) {
			p, err := Parse(tc.source, write(t, tc.name, tc.body), vuln.DefaultPolicy())
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(p.Findings) == 0 {
				t.Fatal("expected findings")
			}
			for _, f := range p.Findings {
				if f.HasAge() {
					t.Errorf("%s reported an age for %s: %v", tc.source, f.ID, f.FirstObserved)
				}
			}
			rem := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()), vuln.AssessRemediation)
			if rem.Status != vuln.StatusInfo {
				t.Fatalf("unageable findings are INFO, not %s: %s", rem.Status, rem.Evidence)
			}
		})
	}
}

// An import lists the targets the scanner was pointed at, so it cannot report a
// coverage fraction.
func TestImportedCoverageIsNeverAuthoritative(t *testing.T) {
	for _, tc := range []struct{ source, name, body string }{
		{"trivy", "trivy.json", trivyJSON},
		{"grype", "grype.json", grypeJSON},
		{"nessus", "scan.nessus", recentNessus()},
	} {
		t.Run(tc.source, func(t *testing.T) {
			p, err := Parse(tc.source, write(t, tc.name, tc.body), vuln.DefaultPolicy())
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if p.CoverageAuthoritative {
				t.Error("an imported scan must not claim to know the estate")
			}
			cov := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()), vuln.AssessCoverage)
			if cov.Status != vuln.StatusInfo {
				t.Fatalf("coverage from an import is INFO, not %s: %s", cov.Status, cov.Evidence)
			}
		})
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	path := write(t, "scan.nessus", recentNessus())
	first, err := Parse("nessus", path, vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := Parse("nessus", path, vuln.DefaultPolicy())
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Assets) != len(first.Assets) || len(again.Findings) != len(first.Findings) {
			t.Fatal("counts changed between runs")
		}
		for j := range first.Assets {
			if again.Assets[j].ID != first.Assets[j].ID {
				t.Fatalf("asset order changed between runs at %d", j)
			}
		}
		for j := range first.Findings {
			if again.Findings[j].ID != first.Findings[j].ID {
				t.Fatalf("finding order changed between runs at %d", j)
			}
		}
	}
}

// ---- Trivy -----------------------------------------------------------------

func TestTrivyFields(t *testing.T) {
	p, err := Parse("trivy", write(t, "trivy.json", trivyJSON), vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != "trivy" || p.AccountID != "registry.example.com/app:1.4.2" {
		t.Errorf("source and artifact should be carried: %+v", p)
	}
	if len(p.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(p.Findings))
	}
	byID := map[string]vuln.Finding{}
	for _, f := range p.Findings {
		byID[f.ID] = f
	}
	if got := byID["CVE-2024-2511"].FixAvailable; got != "YES" {
		t.Errorf("a FixedVersion means a fix exists, got %q", got)
	}
	if got := byID["CVE-2023-45853"].FixAvailable; got != "NO" {
		t.Errorf("no FixedVersion means no patch published, got %q", got)
	}
	if got := byID["CVE-2023-45853"].Severity; got != "CRITICAL" {
		t.Errorf("severity should normalise to the policy key, got %q", got)
	}
	// CreatedAt is a real scan date, so freshness is assessable here.
	cov, _ := p.CoverageFor(vuln.ClassImage)
	if cov.OldestScan == nil {
		t.Error("Trivy's CreatedAt should become a scan date")
	}
}

func TestTrivyNonImageArtifactIsNotAnImage(t *testing.T) {
	body := strings.Replace(trivyJSON, `"ArtifactType": "container_image"`, `"ArtifactType": "filesystem"`, 1)
	p, err := Parse("trivy", write(t, "fs.json", body), vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.CoverageFor(vuln.ClassInstance); !ok {
		t.Error("a filesystem scan belongs in the instance class, not the image class")
	}
}

// ---- Grype -----------------------------------------------------------------

func TestGrypeFields(t *testing.T) {
	p, err := Parse("grype", write(t, "grype.json", grypeJSON), vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if p.AccountID != "app:1.4.2" {
		t.Errorf("the user's own target string should be the identifier, got %q", p.AccountID)
	}
	byID := map[string]vuln.Finding{}
	for _, f := range p.Findings {
		byID[f.ID] = f
	}
	if got := byID["CVE-2024-2511"].FixAvailable; got != "YES" {
		t.Errorf(`fix state "fixed" means a fix exists, got %q`, got)
	}
	if got := byID["CVE-2022-1234"].FixAvailable; got != "NO" {
		t.Errorf(`fix state "not-fixed" means no fix, got %q`, got)
	}
	if got := byID["CVE-2022-1234"].Severity; got != "INFORMATIONAL" {
		t.Errorf("Negligible normalises to INFORMATIONAL, got %q", got)
	}
}

func TestGrypeDirectoryTargetIsAString(t *testing.T) {
	body := strings.Replace(grypeJSON,
		`"source": {"type": "image", "target": {"userInput": "app:1.4.2", "imageID": "sha256:abc"}}`,
		`"source": {"type": "directory", "target": "/opt/app"}`, 1)
	p, err := Parse("grype", write(t, "dir.json", body), vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if p.AccountID != "/opt/app" {
		t.Errorf("a directory target is a bare string, got %q", p.AccountID)
	}
}

// ---- Nessus ----------------------------------------------------------------

func TestNessusFields(t *testing.T) {
	p, err := Parse("nessus", write(t, "scan.nessus", recentNessus()), vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if p.AccountID != "Quarterly internal scan" {
		t.Errorf("the report name should be carried, got %q", p.AccountID)
	}
	// Both hosts appear, including the one with no findings.
	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Covered != 2 {
		t.Fatalf("want both scanned hosts, got %+v", cov)
	}
	if cov.OldestScan == nil {
		t.Error("HOST_END_TIMESTAMP should become a scan date")
	}

	// Informational plugin output is not a vulnerability, and one plugin with
	// two CVEs is two findings.
	if len(p.Findings) != 3 {
		t.Fatalf("want 3 findings (1 high + 2 CVEs on the critical plugin), got %d: %+v",
			len(p.Findings), p.Findings)
	}
	sev := map[string]int{}
	fix := map[string]string{}
	for _, f := range p.Findings {
		sev[f.Severity]++
		fix[f.ID] = f.FixAvailable
	}
	if sev["CRITICAL"] != 2 || sev["HIGH"] != 1 || sev["INFORMATIONAL"] != 0 {
		t.Errorf("severity mapping from the numeric attribute is wrong: %v", sev)
	}
	if fix["CVE-2024-2511"] != "YES" {
		t.Errorf(`a solution saying "Upgrade to" means a fix exists, got %q`, fix["CVE-2024-2511"])
	}
	if fix["CVE-2020-1111"] != "NO" {
		t.Errorf(`"released no patch" means no fix, got %q`, fix["CVE-2020-1111"])
	}
}

func TestNessusPluginWithoutACVEStillCounts(t *testing.T) {
	body := strings.Replace(recentNessus(), "<cve>CVE-2024-2511</cve>", "", 1)
	p, err := Parse("nessus", write(t, "scan.nessus", body), vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range p.Findings {
		if strings.HasPrefix(f.ID, "nessus-plugin-") {
			found = true
		}
	}
	if !found {
		t.Error("a plugin with no CVE still needs an identifier for the report")
	}
}

// ---- refusing the wrong file ----------------------------------------------

// The worst outcome for an importer is reporting zero findings from a file it
// did not understand, because that reads as a clean scan.
func TestWrongFileIsRefusedNotReportedAsClean(t *testing.T) {
	cases := []struct{ source, name, body string }{
		{"trivy", "other.json", `{"hello":"world"}`},
		{"grype", "other.json", `{"hello":"world"}`},
		{"nessus", "other.xml", `<?xml version="1.0"?><other><thing/></other>`},
		{"trivy", "grype.json", grypeJSON},
		{"nessus", "trivy.json", trivyJSON},
	}
	for _, tc := range cases {
		if _, err := Parse(tc.source, write(t, tc.name, tc.body), vuln.DefaultPolicy()); err == nil {
			t.Errorf("%s should have refused %s", tc.source, tc.name)
		}
	}
}

func TestEmptyAndMissingFilesAreRefused(t *testing.T) {
	if _, err := Parse("trivy", write(t, "empty.json", ""), vuln.DefaultPolicy()); err == nil {
		t.Error("an empty file should be refused")
	}
	if _, err := Parse("trivy", filepath.Join(t.TempDir(), "nope.json"), vuln.DefaultPolicy()); err == nil {
		t.Error("a missing file should be refused")
	}
	if _, err := Parse("clair", write(t, "x.json", "{}"), vuln.DefaultPolicy()); err == nil {
		t.Error("an unknown source should be refused")
	}
}

func TestDetectIdentifiesEachFormat(t *testing.T) {
	cases := map[string]string{
		write(t, "a.json", trivyJSON):        "trivy",
		write(t, "b.json", grypeJSON):        "grype",
		write(t, "c.nessus", recentNessus()): "nessus",
		write(t, "d.json", `{"x":1}`):        "",
	}
	for path, want := range cases {
		if got := Detect(path); got != want {
			t.Errorf("%s: detected %q, want %q", filepath.Base(path), got, want)
		}
	}
}

func TestNessusSeverityMapping(t *testing.T) {
	cases := map[string]string{"4": "CRITICAL", "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL"}
	for numeric, want := range cases {
		if got := nessusSeverity(numeric, ""); got != want {
			t.Errorf("severity %q: got %q, want %q", numeric, got, want)
		}
	}
	// an absent numeric falls back to the free-text risk factor
	if got := nessusSeverity("", "Medium"); got != "MEDIUM" {
		t.Errorf("risk_factor fallback: got %q", got)
	}
}

func findAssessment(t *testing.T, all []vuln.Assessment, key vuln.AssessmentKey) vuln.Assessment {
	t.Helper()
	for _, a := range all {
		if a.Key == key {
			return a
		}
	}
	t.Fatalf("no %s assessment among %d", key, len(all))
	return vuln.Assessment{}
}

// Running the Nessus import end to end printed "scanned within 30 days (oldest
// scan 367 days ago)" in one sentence: every scanned asset was marked covered
// regardless of the scan date, so freshness saw nothing stale.
func TestOldScanIsStaleNotFresh(t *testing.T) {
	p, err := Parse("nessus", write(t, "old.nessus", agedNessus()), vuln.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	cov, _ := p.CoverageFor(vuln.ClassInstance)
	if cov.Stale != 2 || cov.Covered != 0 {
		t.Fatalf("a year-old scan is stale, not covered: %+v", cov)
	}
	a := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()), vuln.AssessFreshness)
	if a.Status != vuln.StatusFail {
		t.Fatalf("a year-old scan must fail freshness, got %s: %s", a.Status, a.Evidence)
	}
	if strings.Contains(a.Evidence, "within") {
		t.Errorf("the evidence must not claim the scan was recent: %s", a.Evidence)
	}
}

// And the evaluator refuses to pass even if a collector forgets to mark stale.
func TestFreshnessDoesNotTrustAContradictoryStaleCount(t *testing.T) {
	old := time.Now().AddDate(0, 0, -200)
	p := &vuln.Posture{
		Source: "buggy-collector", ScannerEnabled: true, CoverageAuthoritative: true,
		// Stale deliberately zero while the oldest scan is 200 days old.
		Coverage: []vuln.Coverage{{Class: vuln.ClassInstance, Covered: 3, OldestScan: &old}},
		Assets:   []vuln.Asset{{ID: "a", Disposition: vuln.DispCovered, LastScanned: &old}},
	}
	a := findAssessment(t, vuln.Evaluate(p, vuln.DefaultPolicy(), time.Now()), vuln.AssessFreshness)
	if a.Status != vuln.StatusFail {
		t.Fatalf("an oldest scan outside the window cannot pass, got %s: %s", a.Status, a.Evidence)
	}
	if !strings.Contains(a.Evidence, "days old") || !strings.Contains(a.Evidence, "past the 30-day window") {
		t.Errorf("the age and the window should both be stated: %s", a.Evidence)
	}
}
