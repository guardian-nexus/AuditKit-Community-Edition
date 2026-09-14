package awsinspector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/vuln"
)

// FindingsAPI is the second half of the Inspector surface: what it found, as
// opposed to what it reaches.
type FindingsAPI interface {
	ListFindings(context.Context, *inspector2.ListFindingsInput, ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error)
}

// maxFindingPages caps the walk. A real account can hold tens of thousands of
// findings and the assessment needs aggregates, not the full set: 100 pages at
// the service maximum is 10,000 findings, well past the point where one more
// changes any conclusion. Truncation is recorded rather than hidden.
const maxFindingPages = 100

// CollectFindings appends active findings to the posture. It is separate from
// Collect because coverage is useful on its own and cheap, while this walks
// every finding in the account.
//
// A failed read is recorded on the posture, never swallowed: Evaluate skips the
// remediation assessment entirely when findings were not collected, rather than
// reporting zero overdue from data nobody fetched.
func CollectFindings(ctx context.Context, api FindingsAPI, p *vuln.Posture) {
	if api == nil {
		return
	}

	// Suppressed and closed findings are deliberately excluded. A suppressed
	// finding is an accepted risk and belongs in the exception register, not in
	// the overdue count; a closed one has been remediated.
	active := string(inspectortypes.FindingStatusActive)
	filter := &inspectortypes.FilterCriteria{
		FindingStatus: []inspectortypes.StringFilter{{
			Comparison: inspectortypes.StringComparisonEquals,
			Value:      &active,
		}},
	}

	findings := []vuln.Finding{}
	var token *string
	for page := 0; ; page++ {
		if page >= maxFindingPages {
			p.Errors = append(p.Errors, fmt.Sprintf(
				"ListFindings: stopped after %d pages; remediation ageing is based on the first %d findings",
				maxFindingPages, len(findings)))
			break
		}
		out, err := api.ListFindings(ctx, &inspector2.ListFindingsInput{
			FilterCriteria: filter,
			NextToken:      token,
		})
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("ListFindings: %v", err))
			return
		}
		for _, f := range out.Findings {
			findings = append(findings, convert(f))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	p.Findings = findings
}

func convert(f inspectortypes.Finding) vuln.Finding {
	out := vuln.Finding{
		ID:               aws(f.FindingArn),
		Title:            aws(f.Title),
		Severity:         string(f.Severity),
		FixAvailable:     string(f.FixAvailable),
		ExploitAvailable: f.ExploitAvailable == inspectortypes.ExploitAvailableYes,
		Score:            f.InspectorScore,
		LastObserved:     f.LastObservedAt,
	}
	if f.FirstObservedAt != nil {
		out.FirstObserved = *f.FirstObservedAt
	}
	// A finding can name several resources; the first is the one the report
	// points at, and the full set lives in the evidence package.
	if len(f.Resources) > 0 {
		out.AssetID = aws(f.Resources[0].Id)
	}
	// A CVE identifier reads better in a report than a finding ARN, and it is
	// what an assessor will ask about by name.
	if f.PackageVulnerabilityDetails != nil && f.PackageVulnerabilityDetails.VulnerabilityId != nil {
		out.ID = *f.PackageVulnerabilityDetails.VulnerabilityId
	}
	return out
}
