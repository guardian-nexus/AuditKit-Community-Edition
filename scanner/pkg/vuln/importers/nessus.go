package importers

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// nessusFile is the subset of the .nessus v2 XML this needs. Unlike the two
// container scanners, a Nessus report covers many hosts, so it does carry a
// real per-host picture - but still only of the hosts the scan was pointed at.
type nessusFile struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Report  struct {
		Name  string `xml:"name,attr"`
		Hosts []struct {
			Name       string `xml:"name,attr"`
			Properties struct {
				Tags []struct {
					Name  string `xml:"name,attr"`
					Value string `xml:",chardata"`
				} `xml:"tag"`
			} `xml:"HostProperties"`
			Items []struct {
				PluginID   string   `xml:"pluginID,attr"`
				PluginName string   `xml:"pluginName,attr"`
				Severity   string   `xml:"severity,attr"`
				CVEs       []string `xml:"cve"`
				RiskFactor string   `xml:"risk_factor"`
				Solution   string   `xml:"solution"`
			} `xml:"ReportItem"`
		} `xml:"ReportHost"`
	} `xml:"Report"`
}

// nessusSeverity maps Nessus's numeric severity onto a severity word. The
// numeric attribute is authoritative; risk_factor is free text and is only a
// fallback.
func nessusSeverity(numeric, riskFactor string) string {
	switch strings.TrimSpace(numeric) {
	case "4":
		return "CRITICAL"
	case "3":
		return "HIGH"
	case "2":
		return "MEDIUM"
	case "1":
		return "LOW"
	case "0":
		return "INFORMATIONAL"
	}
	return normaliseSeverity(riskFactor)
}

// nessusScanTime reads HOST_END in preference to HOST_START: the scan finished
// then, which is the point at which its findings were true.
func nessusScanTime(tags map[string]string) *time.Time {
	for _, key := range []string{"HOST_END_TIMESTAMP", "HOST_START_TIMESTAMP"} {
		if v, ok := tags[key]; ok {
			if unix, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				t := time.Unix(unix, 0).UTC()
				return &t
			}
		}
	}
	// The non-timestamp forms are locale-ish strings such as
	// "Mon Sep  8 14:02:11 2026". Parsed on a best-effort basis; an
	// unparseable date leaves the asset without a scan time rather than
	// inventing one.
	for _, key := range []string{"HOST_END", "HOST_START"} {
		if v, ok := tags[key]; ok {
			for _, layout := range []string{
				"Mon Jan _2 15:04:05 2006", "Mon Jan 2 15:04:05 2006",
				time.RFC3339, "2006/01/02 15:04:05",
			} {
				if t, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
					return &t
				}
			}
		}
	}
	return nil
}

func parseNessus(data []byte, policy vuln.Policy, filename string) (*vuln.Posture, error) {
	var f nessusFile
	if err := xml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s as Nessus XML: %w", filename, err)
	}
	if len(f.Report.Hosts) == 0 {
		// A report with no hosts is either the wrong file or a scan that
		// reached nothing. Either way, reporting it as a clean estate would be
		// wrong, so it is an error the reader has to look at.
		return nil, fmt.Errorf("%s contains no ReportHost entries; it is not a Nessus scan, or the scan reached no hosts", filename)
	}

	p := &vuln.Posture{
		Source:    "nessus",
		Provider:  "imported",
		AccountID: f.Report.Name,
		Collected: time.Now(),
	}

	assets := map[string]*vuln.Asset{}
	for _, host := range f.Report.Hosts {
		tags := map[string]string{}
		for _, t := range host.Properties.Tags {
			tags[t.Name] = t.Value
		}
		id := host.Name
		if ip, ok := tags["host-ip"]; ok && id == "" {
			id = ip
		}
		if id == "" {
			continue
		}
		assets[id] = &vuln.Asset{
			ID: id, Class: vuln.ClassInstance, Disposition: vuln.DispCovered,
			LastScanned: nessusScanTime(tags),
			Reason:      "scanned by Nessus",
		}

		for _, item := range host.Items {
			sev := nessusSeverity(item.Severity, item.RiskFactor)
			// Informational plugin output is the bulk of a Nessus report and
			// is not a vulnerability. Counting it would put a four-figure
			// finding count on a clean host.
			if sev == "INFORMATIONAL" {
				continue
			}
			// One plugin can report several CVEs; each is its own finding so
			// the counts match what an assessor sees in the console.
			cves := []string{}
			for _, c := range item.CVEs {
				if c = strings.TrimSpace(c); c != "" {
					cves = append(cves, c)
				}
			}
			if len(cves) == 0 {
				cves = []string{"nessus-plugin-" + item.PluginID}
			}
			for _, cve := range cves {
				p.Findings = append(p.Findings, vuln.Finding{
					ID:       cve,
					Title:    item.PluginName,
					AssetID:  id,
					Severity: sev,
					// Nessus reports the plugin's publication date, not when
					// this finding first appeared on this host.
					FixAvailable: nessusFixAvailable(item.Solution),
				})
			}
		}
	}

	if len(assets) == 0 {
		return nil, fmt.Errorf("%s named no hosts that could be identified", filename)
	}
	finalise(p, policy, assets)
	return p, nil
}

// nessusFixAvailable reads the plugin's solution text. Nessus has no
// machine-readable patch flag, so "UNKNOWN" is the honest answer whenever the
// text does not clearly say a fix exists or does not.
func nessusFixAvailable(solution string) string {
	s := strings.ToLower(solution)
	switch {
	case s == "" || strings.Contains(s, "n/a"):
		return "UNKNOWN"
	case strings.Contains(s, "no patch"), strings.Contains(s, "no known fix"),
		strings.Contains(s, "no fix"), strings.Contains(s, "unsupported"):
		return "NO"
	case strings.Contains(s, "upgrade"), strings.Contains(s, "update"),
		strings.Contains(s, "apply"), strings.Contains(s, "patch"):
		return "YES"
	}
	return "UNKNOWN"
}
