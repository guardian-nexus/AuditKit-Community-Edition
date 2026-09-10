// Package azuredefender collects vulnerability coverage and findings from
// Microsoft Defender for Cloud.
//
// Defender's model is different from Inspector's in two ways that matter, and
// both are reported rather than papered over.
//
// Coverage is a property of the *plan*, not the agent: Defender for Servers
// either covers a subscription's virtual machines or it does not, and the
// pricing API reports FullyCovered, PartiallyCovered or NotCovered without
// naming the resources behind that verdict. So a partially covered
// subscription is stated as such instead of being turned into a per-asset gap
// count the provider never gave us.
//
// Findings carry no first-observed date. A sub-assessment reports the CVE's
// publication time and the time the assessment last ran, neither of which is
// when the finding appeared on this estate. Ageing from publication would fail
// a host for a vulnerability disclosed before the host existed, so findings
// arrive with a zero FirstObserved and the evaluator declines to age them.
package azuredefender

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/guardian-nexus/auditkit/scanner/pkg/vuln"
)

// PricingAPI reads whether a Defender plan is on, and how much of the
// subscription it actually reaches.
type PricingAPI interface {
	Get(ctx context.Context, scopeID string, pricingName string, opts *armsecurity.PricingsClientGetOptions) (armsecurity.PricingsClientGetResponse, error)
}

// SubAssessmentsAPI lists the individual findings under every assessment.
type SubAssessmentsAPI interface {
	NewListAllPager(scope string, opts *armsecurity.SubAssessmentsClientListAllOptions) *runtime.Pager[armsecurity.SubAssessmentsClientListAllResponse]
}

// VMAPI is the inventory denominator: what exists to be scanned.
type VMAPI interface {
	NewListAllPager(opts *armcompute.VirtualMachinesClientListAllOptions) *runtime.Pager[armcompute.VirtualMachinesClientListAllResponse]
}

// Clients bundles what Collect needs. A nil client means that part is skipped
// rather than reported as a gap: claiming a finding because we never looked is
// the same defect as claiming a pass.
type Clients struct {
	Pricing        PricingAPI
	SubAssessments SubAssessmentsAPI
	VMs            VMAPI
}

// Defender plan names. VirtualMachines is Defender for Servers, which is the
// plan that carries integrated vulnerability assessment.
const (
	planServers    = "VirtualMachines"
	planContainers = "Containers"
)

// Collect reads Defender coverage for a subscription.
func Collect(ctx context.Context, c Clients, policy vuln.Policy, subscriptionID string) *vuln.Posture {
	p := &vuln.Posture{
		Source:    "azure-defender",
		Provider:  "azure",
		AccountID: subscriptionID,
		Collected: nowFunc(),
	}
	if c.Pricing == nil || subscriptionID == "" {
		p.Errors = append(p.Errors, "Defender pricing client or subscription id not configured")
		return p
	}
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)

	servers, serversErr := planState(ctx, c.Pricing, scope, planServers)
	if serversErr != nil {
		p.Errors = append(p.Errors, fmt.Sprintf("Pricings.Get(%s): %v", planServers, serversErr))
		return p
	}
	containers, containersErr := planState(ctx, c.Pricing, scope, planContainers)
	if containersErr != nil {
		// One plan failing must not silently narrow the picture, but it also
		// should not discard the plan that did answer.
		p.Errors = append(p.Errors, fmt.Sprintf("Pricings.Get(%s): %v", planContainers, containersErr))
		return p
	}

	p.ScannerEnabled = servers.enabled || containers.enabled
	p.ClassEnabled = map[vuln.AssetClass]bool{
		vuln.ClassInstance: servers.enabled,
		vuln.ClassImage:    containers.enabled,
		vuln.ClassRepo:     containers.enabled,
	}
	if !p.ScannerEnabled {
		return p
	}

	if cov, ok := instanceCoverage(ctx, c, policy, servers, p); ok {
		p.Coverage = append(p.Coverage, cov)
	}
	if containers.enabled {
		p.Coverage = append(p.Coverage, vuln.Coverage{
			Class: vuln.ClassImage,
			Note:  "Defender for Containers is enabled; " + containers.describe(),
		})
	}
	return p
}

type planInfo struct {
	enabled  bool
	coverage armsecurity.ResourcesCoverageStatus
	name     string
}

func (pi planInfo) describe() string {
	switch pi.coverage {
	case armsecurity.ResourcesCoverageStatusFullyCovered:
		return "Defender reports the subscription's resources as fully covered"
	case armsecurity.ResourcesCoverageStatusPartiallyCovered:
		return "Defender reports the subscription as only partially covered, and does not name " +
			"the resources it is not reaching. Check the plan's per-resource onboarding in the portal"
	case armsecurity.ResourcesCoverageStatusNotCovered:
		return "Defender reports the plan as covering none of the subscription's resources"
	}
	return "Defender did not report a resource coverage status for this plan"
}

func planState(ctx context.Context, api PricingAPI, scope, name string) (planInfo, error) {
	out, err := api.Get(ctx, scope, name, nil)
	if err != nil {
		// A plan that has never been configured reads as absent, not as an
		// error worth abandoning the scan for.
		if isNotFound(err) {
			return planInfo{name: name}, nil
		}
		return planInfo{name: name}, err
	}
	pi := planInfo{name: name}
	if out.Properties == nil {
		return pi, nil
	}
	if out.Properties.PricingTier != nil {
		pi.enabled = *out.Properties.PricingTier == armsecurity.PricingTierStandard
	}
	if out.Properties.ResourcesCoverageStatus != nil {
		pi.coverage = *out.Properties.ResourcesCoverageStatus
	}
	return pi, nil
}

// instanceCoverage builds the virtual-machine picture. With Defender for
// Servers off, every machine is a gap and the reason is unambiguous. With it
// on, coverage is whatever the plan reports, and the machines are listed as
// covered rather than individually verified - Defender does not expose a
// per-machine assessment state through this API.
func instanceCoverage(ctx context.Context, c Clients, policy vuln.Policy, servers planInfo, p *vuln.Posture) (vuln.Coverage, bool) {
	if c.VMs == nil {
		if !servers.enabled {
			return vuln.Coverage{Class: vuln.ClassInstance,
				Note: "Defender for Servers is not enabled on this subscription"}, true
		}
		return vuln.Coverage{Class: vuln.ClassInstance, Note: servers.describe()}, true
	}

	machines, err := listVMs(ctx, c.VMs, policy)
	if err != nil {
		p.Errors = append(p.Errors, fmt.Sprintf("VirtualMachines.ListAll: %v", err))
		return vuln.Coverage{}, false
	}

	cov := vuln.Coverage{Class: vuln.ClassInstance}
	for _, m := range machines {
		switch {
		case m.Disposition == vuln.DispExcluded:
			cov.Excluded++
		case !servers.enabled:
			cov.Gaps++
			cov.GapIDs = append(cov.GapIDs, m.ID)
			m.Reason = "Defender for Servers is not enabled on this subscription"
		default:
			cov.Covered++
			m.Disposition = vuln.DispCovered
			m.Reason = string(servers.coverage)
		}
		p.Assets = append(p.Assets, m)
	}
	if servers.enabled {
		cov.Note = servers.describe()
	} else {
		cov.Note = "Defender for Servers is not enabled on this subscription, so nothing is " +
			"scanning these machines for vulnerabilities"
	}
	return cov, true
}

func listVMs(ctx context.Context, api VMAPI, policy vuln.Policy) ([]vuln.Asset, error) {
	var out []vuln.Asset
	pager := api.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vm := range page.Value {
			if vm == nil || vm.ID == nil {
				continue
			}
			asset := vuln.Asset{ID: *vm.ID, Class: vuln.ClassInstance, Disposition: vuln.DispGap}
			if policy.TagExcluded(tagMap(vm.Tags)) {
				asset.Disposition = vuln.DispExcluded
				asset.Reason = "excluded by vuln-policy.yaml scope"
			}
			out = append(out, asset)
		}
	}
	return out, nil
}

func tagMap(tags map[string]*string) map[string]string {
	m := make(map[string]string, len(tags))
	for k, v := range tags {
		if v != nil {
			m[k] = *v
		}
	}
	return m
}

func isNotFound(err error) bool {
	s := err.Error()
	return strings.Contains(s, "404") || strings.Contains(s, "NotFound")
}
