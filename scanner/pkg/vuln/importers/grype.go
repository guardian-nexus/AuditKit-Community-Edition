package importers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// grypeReport is the subset of Grype's JSON this needs.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Fix         struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
	Source struct {
		Type   string          `json:"type"`
		Target json.RawMessage `json:"target"`
	} `json:"source"`
	Descriptor struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Timestamp string `json:"timestamp"`
	} `json:"descriptor"`
}

func parseGrype(data []byte, policy vuln.Policy, filename string) (*vuln.Posture, error) {
	var r grypeReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse %s as Grype JSON: %w", filename, err)
	}
	if r.Descriptor.Name == "" && r.Matches == nil {
		return nil, fmt.Errorf("%s does not look like a Grype report: no descriptor and no matches", filename)
	}

	p := &vuln.Posture{
		Source:    "grype",
		Provider:  "imported",
		Collected: time.Now(),
	}

	// Grype records when it ran, which is a genuine scan date.
	var scanned *time.Time
	if t, err := time.Parse(time.RFC3339, r.Descriptor.Timestamp); err == nil {
		scanned = &t
	}

	// The target's shape varies by source type - a string for a directory, an
	// object for an image - so it is decoded loosely and a readable name taken
	// from whatever is there.
	id := grypeTarget(r.Source.Target)
	if id == "" {
		id = filename
	}
	p.AccountID = id

	class := vuln.ClassImage
	if r.Source.Type != "image" {
		class = vuln.ClassInstance
	}

	assets := map[string]*vuln.Asset{id: {
		ID: id, Class: class, Disposition: vuln.DispCovered, LastScanned: scanned,
		Reason: "scanned by Grype (" + r.Source.Type + ")",
	}}

	for _, m := range r.Matches {
		f := vuln.Finding{
			ID:       m.Vulnerability.ID,
			Title:    m.Vulnerability.Description,
			AssetID:  id,
			Severity: normaliseSeverity(m.Vulnerability.Severity),
		}
		if f.ID == "" {
			f.ID = "(no CVE reported)"
		}
		if f.Title == "" {
			f.Title = m.Artifact.Name + " " + m.Artifact.Version
		}
		// Grype states the fix state directly, which is better than inferring
		// it: "not-fixed" and "unknown" are different from "no fix listed".
		switch m.Vulnerability.Fix.State {
		case "fixed":
			f.FixAvailable = "YES"
		case "not-fixed", "wont-fix":
			f.FixAvailable = "NO"
		default:
			if len(m.Vulnerability.Fix.Versions) > 0 {
				f.FixAvailable = "YES"
			} else {
				f.FixAvailable = "UNKNOWN"
			}
		}
		p.Findings = append(p.Findings, f)
	}

	finalise(p, policy, assets)
	return p, nil
}

// grypeTarget pulls a readable name out of source.target, which Grype writes
// as a bare string for a directory and as an object for an image.
func grypeTarget(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		UserInput string   `json:"userInput"`
		ImageID   string   `json:"imageID"`
		Tags      []string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if obj.UserInput != "" {
			return obj.UserInput
		}
		if len(obj.Tags) > 0 {
			return obj.Tags[0]
		}
		return obj.ImageID
	}
	return ""
}
