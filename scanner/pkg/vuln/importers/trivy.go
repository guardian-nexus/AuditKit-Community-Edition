package importers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// trivyReport is the subset of Trivy's JSON this needs. Trivy scans one
// artifact per invocation, so a file describes a single image, filesystem or
// repository - which is why an import can never speak to estate coverage.
type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	ArtifactType  string `json:"ArtifactType"`
	CreatedAt     string `json:"CreatedAt"`
	Results       []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			PublishedDate    string `json:"PublishedDate"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivy(data []byte, policy vuln.Policy, filename string) (*vuln.Posture, error) {
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse %s as Trivy JSON: %w", filename, err)
	}
	// Trivy writes a schema version on every report. Its absence means this is
	// some other tool's JSON, and reporting zero findings from it would look
	// like a clean scan.
	if r.SchemaVersion == 0 && r.ArtifactName == "" {
		return nil, fmt.Errorf("%s does not look like a Trivy report: no SchemaVersion or ArtifactName", filename)
	}

	p := &vuln.Posture{
		Source:    "trivy",
		Provider:  "imported",
		AccountID: r.ArtifactName,
		Collected: time.Now(),
	}

	class := vuln.ClassImage
	if r.ArtifactType != "container_image" {
		// A filesystem or repository scan is not an image, and calling it one
		// would put it in the wrong bucket on the report.
		class = vuln.ClassInstance
	}

	// Trivy's CreatedAt, where present, is when the scan ran - a real scan
	// date, unlike the per-finding dates which are CVE publication.
	var scanned *time.Time
	if t, err := time.Parse(time.RFC3339, r.CreatedAt); err == nil {
		scanned = &t
	}

	assets := map[string]*vuln.Asset{}
	id := r.ArtifactName
	if id == "" {
		id = filename
	}
	assets[id] = &vuln.Asset{ID: id, Class: class,
		Disposition: vuln.DispCovered, LastScanned: scanned,
		Reason: "scanned by Trivy (" + r.ArtifactType + ")"}

	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			f := vuln.Finding{
				ID:      v.VulnerabilityID,
				Title:   v.Title,
				AssetID: id,
				// Deliberately zero: PublishedDate is when the CVE was
				// disclosed, not when it appeared on this artifact.
				Severity: normaliseSeverity(v.Severity),
			}
			if f.ID == "" {
				f.ID = "(no CVE reported)"
			}
			if f.Title == "" {
				f.Title = v.PkgName + " " + v.InstalledVersion
			}
			// A fixed version is the upgrade that resolves it. No fixed
			// version means no patch is published for this package yet.
			if v.FixedVersion != "" {
				f.FixAvailable = "YES"
			} else {
				f.FixAvailable = "NO"
			}
			p.Findings = append(p.Findings, f)
		}
	}

	finalise(p, policy, assets)
	return p, nil
}
