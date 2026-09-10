// Package awsinspector collects vulnerability coverage from Amazon Inspector v2.
//
// Inspector's ListCoverage already reports every resource it knows about and,
// crucially, why it is not scanning the ones it is not scanning. That reason is
// the whole feature: it separates "you have not fixed your SSM agent" from "this
// runtime cannot be scanned" from "you excluded it by tag". Inventory calls are
// still needed on top, because a resource Inspector has never heard of - a
// region or account that was never enabled - appears in no coverage record at
// all, and that is the worst kind of gap.
package awsinspector

import (
	"context"
	"fmt"
	"time"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// Narrow interfaces over the four clients, so the collector can be exercised
// without a live account.
type (
	InspectorAPI interface {
		BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput, ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error)
		ListCoverage(context.Context, *inspector2.ListCoverageInput, ...func(*inspector2.Options)) (*inspector2.ListCoverageOutput, error)
		// FindingsAPI is embedded so one client satisfies both halves; coverage
		// is collected on its own and findings only when asked for.
		FindingsAPI
	}
	EC2API interface {
		DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	}
	LambdaAPI interface {
		ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	}
	ECRAPI interface {
		DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	}
)

// Clients bundles what Collect needs. A nil client means that asset class is
// skipped rather than reported as uncovered - claiming a gap because we never
// looked would be the same defect as claiming a pass.
type Clients struct {
	Inspector InspectorAPI
	EC2       EC2API
	Lambda    LambdaAPI
	ECR       ECRAPI
}

// dispositionFor maps Inspector's scan status onto what it means for an
// assessment. Inspector documents around thirty reasons; an assessor only cares
// which of six buckets each falls into.
//
// The reasons are matched as the wire strings AWS documents rather than as SDK
// constants. Two editions of this scanner pin different inspector2 versions,
// and AWS adds reasons faster than either gets bumped - keying on constants
// meant the same file would not compile against the older SDK, and a reason
// added next quarter would be a compile error rather than a new case.
func dispositionFor(reason inspectortypes.ScanStatusReason) vuln.Disposition {
	switch string(reason) {
	case "SUCCESSFUL":
		return vuln.DispCovered

	// Transient. A first or repeat scan is queued and will resolve unattended.
	case "PENDING_INITIAL_SCAN", "PENDING_REVIVAL_SCAN", "SCAN_IN_PROGRESS",
		"DEEP_INSPECTION_NO_INVENTORY":
		return vuln.DispPending

	// The operator chose this. Counted and listed, never failed.
	case "EXCLUDED_BY_TAG", "PENDING_DISABLE":
		return vuln.DispExcluded

	// Inspector cannot scan this at all, or there is nothing left to scan.
	case "UNSUPPORTED_OS", "UNSUPPORTED_RUNTIME", "UNSUPPORTED_MEDIA_TYPE",
		"UNSUPPORTED_LANGUAGE", "UNSUPPORTED_CODE_ARTIFACTS", "UNSUPPORTED_CONFIG_FILE",
		"IMAGE_SIZE_EXCEEDED", "IMAGE_ARCHIVED", "RESOURCE_TERMINATED",
		"EC2_INSTANCE_STOPPED", "SCAN_ELIGIBILITY_EXPIRED", "NO_RESOURCES_FOUND":
		return vuln.DispNotEligible

	// Everything else is a gap the operator has to close: an unmanaged
	// instance, missing inventory, a denied key policy, a repository set to
	// scan once on push and therefore blind to newly disclosed CVEs. An
	// unrecognised reason lands here too, which is the safe direction: it
	// surfaces for a human rather than quietly counting as covered.
	default:
		return vuln.DispGap
	}
}

// Collect reads Inspector coverage and the asset inventory, and returns the
// posture. Errors from individual calls are recorded on the posture rather than
// returned, so a partial read is reported as an error for that class instead of
// silently narrowing the denominator.
func Collect(ctx context.Context, c Clients, policy vuln.Policy, accountID string) *vuln.Posture {
	p := &vuln.Posture{
		Source: "aws-inspector2",
		// this collector enumerates the account, so it knows what it did not reach
		CoverageAuthoritative: true,
		Provider:              "aws",
		AccountID:             accountID,
		Collected:             time.Now(),
	}

	if c.Inspector == nil {
		p.Errors = append(p.Errors, "Inspector client not configured")
		return p
	}

	status, err := c.Inspector.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		p.Errors = append(p.Errors, fmt.Sprintf("BatchGetAccountStatus: %v", err))
		return p
	}
	enabled := map[vuln.AssetClass]bool{}
	for _, acct := range status.Accounts {
		if acct.State != nil && acct.State.Status == inspectortypes.StatusEnabled {
			p.ScannerEnabled = true
		}
		if accountID == "" && acct.AccountId != nil {
			p.AccountID = *acct.AccountId
		}
		// Inspector is enabled per resource type. An account with EC2 scanning
		// on and ECR scanning off is not "covered"; it has a whole asset class
		// nobody is looking at, and the reason should say so rather than
		// leaving every repository reading "no coverage record".
		if rs := acct.ResourceState; rs != nil {
			if rs.Ec2 != nil && rs.Ec2.Status == inspectortypes.StatusEnabled {
				enabled[vuln.ClassInstance] = true
			}
			if rs.Ecr != nil && rs.Ecr.Status == inspectortypes.StatusEnabled {
				enabled[vuln.ClassRepo] = true
				enabled[vuln.ClassImage] = true
			}
			if rs.Lambda != nil && rs.Lambda.Status == inspectortypes.StatusEnabled {
				enabled[vuln.ClassFunction] = true
			}
		}
	}
	if !p.ScannerEnabled {
		return p
	}
	p.ClassEnabled = enabled

	known, err := listCoverage(ctx, c.Inspector)
	if err != nil {
		p.Errors = append(p.Errors, fmt.Sprintf("ListCoverage: %v", err))
		return p
	}

	stale := policy.StaleBefore(time.Now())
	byClass := map[vuln.AssetClass]*vuln.Coverage{}
	get := func(class vuln.AssetClass) *vuln.Coverage {
		if _, ok := byClass[class]; !ok {
			byClass[class] = &vuln.Coverage{Class: class}
		}
		return byClass[class]
	}

	// Everything Inspector has a record for.
	seen := map[string]bool{}
	for _, r := range known {
		class, ok := classFor(r.ResourceType)
		if !ok {
			continue
		}
		id := aws(r.ResourceId)
		seen[id] = true

		asset := vuln.Asset{ID: id, Class: class, LastScanned: r.LastScannedAt}
		if r.ScanStatus != nil {
			asset.Reason = string(r.ScanStatus.Reason)
			asset.Disposition = dispositionFor(r.ScanStatus.Reason)
		} else {
			asset.Disposition = vuln.DispGap
			asset.Reason = "no scan status reported"
		}
		// A covered asset whose last scan predates the window is stale, not
		// covered. Inspector reports SUCCESSFUL indefinitely.
		if asset.Disposition == vuln.DispCovered && r.LastScannedAt != nil && r.LastScannedAt.Before(stale) {
			asset.Disposition = vuln.DispStale
		}
		tally(get(class), asset)
		p.Assets = append(p.Assets, asset)
	}

	// Inventory, for assets Inspector has no record of at all.
	for _, inv := range inventories(ctx, c, policy, p) {
		for _, asset := range inv {
			if seen[asset.ID] {
				continue
			}
			if !p.ClassEnabled[asset.Class] {
				asset.Reason = fmt.Sprintf("Inspector scanning is not enabled for %s in this account", asset.Class)
			} else {
				asset.Reason = "no Inspector coverage record for this resource"
			}
			if asset.Disposition == "" {
				asset.Disposition = vuln.DispGap
			}
			tally(get(asset.Class), asset)
			p.Assets = append(p.Assets, asset)
		}
	}

	for _, class := range []vuln.AssetClass{vuln.ClassInstance, vuln.ClassFunction, vuln.ClassRepo, vuln.ClassImage} {
		if cov, ok := byClass[class]; ok {
			p.Coverage = append(p.Coverage, *cov)
		}
	}
	return p
}

func tally(c *vuln.Coverage, a vuln.Asset) {
	switch a.Disposition {
	case vuln.DispCovered:
		c.Covered++
		if a.LastScanned != nil && (c.OldestScan == nil || a.LastScanned.Before(*c.OldestScan)) {
			c.OldestScan = a.LastScanned
		}
	case vuln.DispStale:
		c.Stale++
		c.StaleIDs = append(c.StaleIDs, a.ID)
		if a.LastScanned != nil && (c.OldestScan == nil || a.LastScanned.Before(*c.OldestScan)) {
			c.OldestScan = a.LastScanned
		}
	case vuln.DispGap:
		c.Gaps++
		c.GapIDs = append(c.GapIDs, a.ID)
	case vuln.DispExcluded:
		c.Excluded++
	case vuln.DispNotEligible:
		c.NotEligible++
	case vuln.DispPending:
		c.Pending++
	}
}

func classFor(t inspectortypes.CoverageResourceType) (vuln.AssetClass, bool) {
	switch t {
	case inspectortypes.CoverageResourceTypeAwsEc2Instance:
		return vuln.ClassInstance, true
	case inspectortypes.CoverageResourceTypeAwsLambdaFunction:
		return vuln.ClassFunction, true
	case inspectortypes.CoverageResourceTypeAwsEcrRepository:
		return vuln.ClassRepo, true
	case inspectortypes.CoverageResourceTypeAwsEcrContainerImage:
		return vuln.ClassImage, true
	}
	return "", false
}

func listCoverage(ctx context.Context, api InspectorAPI) ([]inspectortypes.CoveredResource, error) {
	var out []inspectortypes.CoveredResource
	var token *string
	for {
		page, err := api.ListCoverage(ctx, &inspector2.ListCoverageInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, page.CoveredResources...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

// inventories lists what actually exists, per class. A client that is nil, or a
// call that fails, contributes nothing and records the failure - it must not
// reduce the denominator.
func inventories(ctx context.Context, c Clients, policy vuln.Policy, p *vuln.Posture) [][]vuln.Asset {
	var all [][]vuln.Asset

	if c.EC2 != nil {
		assets, err := listInstances(ctx, c.EC2, policy)
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("DescribeInstances: %v", err))
		} else {
			all = append(all, assets)
		}
	}
	if c.Lambda != nil {
		assets, err := listFunctions(ctx, c.Lambda)
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("ListFunctions: %v", err))
		} else {
			all = append(all, assets)
		}
	}
	if c.ECR != nil {
		assets, err := listRepositories(ctx, c.ECR)
		if err != nil {
			p.Errors = append(p.Errors, fmt.Sprintf("DescribeRepositories: %v", err))
		} else {
			all = append(all, assets)
		}
	}
	return all
}

func listInstances(ctx context.Context, api EC2API, policy vuln.Policy) ([]vuln.Asset, error) {
	var out []vuln.Asset
	var token *string
	for {
		page, err := api.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				// A stopped instance is not a coverage gap: Inspector pauses
				// scanning by design and resumes when it starts again.
				if inst.State == nil || inst.State.Name != ec2types.InstanceStateNameRunning {
					continue
				}
				asset := vuln.Asset{ID: aws(inst.InstanceId), Class: vuln.ClassInstance}
				if policy.TagExcluded(tagMap(inst.Tags)) {
					asset.Disposition = vuln.DispExcluded
					asset.Reason = "excluded by vuln-policy.yaml scope"
				}
				out = append(out, asset)
			}
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func listFunctions(ctx context.Context, api LambdaAPI) ([]vuln.Asset, error) {
	var out []vuln.Asset
	var marker *string
	for {
		page, err := api.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			out = append(out, vuln.Asset{ID: aws(fn.FunctionArn), Class: vuln.ClassFunction})
		}
		if page.NextMarker == nil || *page.NextMarker == "" {
			return out, nil
		}
		marker = page.NextMarker
	}
}

func listRepositories(ctx context.Context, api ECRAPI) ([]vuln.Asset, error) {
	var out []vuln.Asset
	var token *string
	for {
		page, err := api.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, repo := range page.Repositories {
			out = append(out, vuln.Asset{ID: aws(repo.RepositoryArn), Class: vuln.ClassRepo})
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func tagMap(tags []ec2types.Tag) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[aws(t.Key)] = aws(t.Value)
	}
	return m
}

func aws(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
