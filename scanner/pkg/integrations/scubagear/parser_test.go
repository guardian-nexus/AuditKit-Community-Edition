package scubagear

import (
	"context"
	"testing"
)

// A ScubaResults.json in the shape CISA's ScubaGear actually writes.
//
// Four things here differed from what this parser assumed, and each on its own
// was enough to make a real report import as nothing:
//
//   - Results is keyed by baseline name ("AAD", "SharePoint"), not by the
//     lower-case product argument, and not by the domain the mapping files use.
//   - Each value is an array of GROUPS, each carrying a Controls array. The
//     parser modelled it as a flat array of findings, which parses without
//     error and yields zero rows.
//   - The policy id lives in "Control ID"; "Requirement" holds prose.
//   - "Result" is a string, not a boolean.
const realScubaResults = `{
  "ReportSummary": { "Date": "2026-09-07", "Tenant": "contoso.onmicrosoft.com" },
  "Results": {
    "AAD": [
      {
        "GroupName": "Legacy Authentication",
        "GroupNumber": "1",
        "GroupReferenceURL": "https://github.com/cisagov/ScubaGear",
        "Controls": [
          {"Control ID": "MS.AAD.1.1v1", "Requirement": "Legacy authentication SHALL be blocked.",
           "Result": "Fail", "Criticality": "Shall", "Details": "1 conditional access policy found."}
        ]
      },
      {
        "GroupName": "Strong Authentication",
        "GroupNumber": "3",
        "Controls": [
          {"Control ID": "MS.AAD.3.1v1", "Requirement": "Phishing-resistant MFA SHALL be enforced.",
           "Result": "Pass", "Criticality": "Shall", "Details": "Requirement met."}
        ]
      }
    ],
    "SharePoint": [
      {
        "GroupName": "External Sharing",
        "GroupNumber": "1",
        "Controls": [
          {"Control ID": "MS.SHAREPOINT.1.1v1", "Requirement": "External sharing SHALL be limited.",
           "Result": "Fail", "Criticality": "Shall", "Details": "Sharing set to Anyone."}
        ]
      }
    ],
    "EXO": [
      {
        "GroupName": "SPF",
        "GroupNumber": "2",
        "Controls": [
          {"Control ID": "MS.EXO.2.2v2", "Requirement": "An SPF policy SHALL be published.",
           "Result": "Omitted", "Criticality": "Shall", "Details": "Omitted by operator."}
        ]
      }
    ]
  }
}`

// The same content without the group wrapper, which hand-assembled files and
// the raw Rego provider output use.
const flatScubaResults = `{
  "Results": {
    "AAD": [
      {"Control ID": "MS.AAD.1.1v1", "Result": "Fail"},
      {"Control ID": "MS.AAD.3.1v1", "Result": "Pass"}
    ]
  }
}`

func TestParseFlatShape(t *testing.T) {
	s := NewScubaGearIntegration("")
	results, err := s.Parse(context.Background(), []byte(flatScubaResults))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
}

func TestParseRealScubaGearFormat(t *testing.T) {
	s := NewScubaGearIntegration("")
	results, err := s.Parse(context.Background(), []byte(realScubaResults))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	byID := map[string]string{}
	for _, r := range results {
		byID[r.RuleID] = r.Status
	}

	// AAD findings resolve only if the "AAD" key maps to the "entra" domain and
	// the "v1" suffix is trimmed.
	for id, want := range map[string]string{
		"MS.AAD.1.1":        "FAIL",
		"MS.AAD.3.1":        "PASS",
		"MS.SHAREPOINT.1.1": "FAIL",
		"MS.EXO.2.2":        "MANUAL", // Omitted is not a failure
	} {
		got, ok := byID[id]
		if !ok {
			t.Errorf("%s: not found in results (mapping or domain lookup failed)", id)
			continue
		}
		if got != want {
			t.Errorf("%s: status = %s, want %s", id, got, want)
		}
	}

	if len(results) != 4 {
		t.Errorf("got %d results, want 4: %v", len(results), byID)
	}
}

// The raw Rego provider output uses PolicyId and a boolean RequirementMet.
func TestParseRawRegoShape(t *testing.T) {
	raw := `{"Results": {"aad": [
	  {"PolicyId": "MS.AAD.1.1v1", "RequirementMet": false},
	  {"PolicyId": "MS.AAD.3.1v1", "RequirementMet": true}
	]}}`
	s := NewScubaGearIntegration("")
	results, err := s.Parse(context.Background(), []byte(raw))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for _, r := range results {
		if r.RuleID == "MS.AAD.1.1" && r.Status != "FAIL" {
			t.Errorf("MS.AAD.1.1 status = %s, want FAIL", r.Status)
		}
		if r.RuleID == "MS.AAD.3.1" && r.Status != "PASS" {
			t.Errorf("MS.AAD.3.1 status = %s, want PASS", r.Status)
		}
	}
}

func TestTrimBaselineVersion(t *testing.T) {
	cases := map[string]string{
		"MS.AAD.1.1v1":       "MS.AAD.1.1",
		"MS.EXO.2.2v2":       "MS.EXO.2.2",
		"MS.DEFENDER.1.10v1": "MS.DEFENDER.1.10",
		"MS.AAD.1.1":         "MS.AAD.1.1", // already unsuffixed
		"":                   "",
	}
	for in, want := range cases {
		if got := trimBaselineVersion(in); got != want {
			t.Errorf("trimBaselineVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
