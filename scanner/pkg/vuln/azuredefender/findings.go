package azuredefender

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// nowFunc is a seam for tests.
var nowFunc = time.Now

// maxSubAssessmentPages caps the walk, matching the Inspector collector. The
// assessment needs aggregates, and truncation is recorded rather than hidden.
const maxSubAssessmentPages = 100

// CollectFindings appends Defender's vulnerability sub-assessments to the
// posture.
//
// Only sub-assessments whose additional data is one of the vulnerability shapes
// are taken. Defender's sub-assessments also carry configuration and posture
// findings, and counting those as vulnerabilities would inflate every number
// on the report.
//
// Every finding arrives with a zero FirstObserved. Defender reports the CVE's
// PublishedTime and the assessment's TimeGenerated; neither says when the
// finding appeared on this estate, and the evaluator refuses to age a finding
// it cannot date. See the package comment.
func CollectFindings(ctx context.Context, api SubAssessmentsAPI, subscriptionID string, p *vuln.Posture) {
	if api == nil || subscriptionID == "" {
		return
	}
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)

	findings := []vuln.Finding{}
	pager := api.NewListAllPager(scope, nil)
	for page := 0; pager.More(); page++ {
		if page >= maxSubAssessmentPages {
			p.Errors = append(p.Errors, fmt.Sprintf(
				"SubAssessments.ListAll: stopped after %d pages; findings are the first %d",
				maxSubAssessmentPages, len(findings)))
			break
		}
		resp, err := pager.NextPage(ctx)
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("SubAssessments.ListAll: %v", err))
			return
		}
		for _, sa := range resp.Value {
			if f, ok := convert(sa); ok {
				findings = append(findings, f)
			}
		}
	}
	p.Findings = findings
}

func convert(sa *armsecurity.SubAssessment) (vuln.Finding, bool) {
	if sa == nil || sa.Properties == nil {
		return vuln.Finding{}, false
	}
	props := sa.Properties

	// A healthy sub-assessment is a check that passed, not a vulnerability.
	if props.Status != nil && props.Status.Code != nil &&
		*props.Status.Code != armsecurity.SubAssessmentStatusCodeUnhealthy {
		return vuln.Finding{}, false
	}

	cve, patchable, ok := vulnerabilityData(props.AdditionalData)
	if !ok {
		return vuln.Finding{}, false // configuration or posture finding, not a CVE
	}

	f := vuln.Finding{
		ID:           firstNonEmpty(cve, deref(props.ID), deref(sa.Name)),
		Title:        firstNonEmpty(deref(props.DisplayName), deref(props.Description)),
		FixAvailable: "UNKNOWN",
		// Deliberately left zero: see the package comment.
		FirstObserved: time.Time{},
	}
	if props.Status != nil && props.Status.Severity != nil {
		f.Severity = strings.ToUpper(string(*props.Status.Severity))
	}
	if patchable != nil {
		if *patchable {
			f.FixAvailable = "YES"
		} else {
			f.FixAvailable = "NO"
		}
	}
	if props.ResourceDetails != nil {
		f.AssetID = resourceID(props.ResourceDetails)
	}
	return f, true
}

// vulnerabilityData pulls the CVE identifier and patchability out of whichever
// vulnerability shape Defender used, and reports false for anything that is not
// a vulnerability sub-assessment at all.
func vulnerabilityData(data armsecurity.AdditionalDataClassification) (cve string, patchable *bool, ok bool) {
	switch d := data.(type) {
	case *armsecurity.ServerVulnerabilityProperties:
		return firstCVE(d.Cve), d.Patchable, true
	case *armsecurity.ContainerRegistryVulnerabilityProperties:
		return firstCVE(d.Cve), d.Patchable, true
	case *armsecurity.SQLServerVulnerabilityProperties:
		// SQL vulnerability assessment reports rule failures rather than CVEs.
		// It is a real finding but it has no CVE and no patchability, so it is
		// carried with an empty identifier rather than dropped.
		return "", nil, true
	}
	return "", nil, false
}

func firstCVE(cves []*armsecurity.CVE) string {
	for _, c := range cves {
		if c != nil && c.Title != nil && *c.Title != "" {
			return *c.Title
		}
	}
	return ""
}

func resourceID(d armsecurity.ResourceDetailsClassification) string {
	switch r := d.(type) {
	case *armsecurity.AzureResourceDetails:
		return deref(r.ID)
	case *armsecurity.OnPremiseResourceDetails:
		return deref(r.MachineName)
	case *armsecurity.OnPremiseSQLResourceDetails:
		return deref(r.MachineName)
	}
	return ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
