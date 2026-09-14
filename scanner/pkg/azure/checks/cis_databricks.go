package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

// CISDatabricksChecks answers the six automated Azure Databricks
// recommendations in CIS Microsoft Azure Foundations v6.0.0 section 2.1. The
// other six in that section are manual and reported by
// CISFoundationsManualChecks.
//
// Three clients, because two of the recommendations are about the workspace's
// relationship with resources it does not own: 2.1.2 asks whether the subnets
// in the customer's own virtual network carry a security group, and 2.1.7 asks
// whether a diagnostic setting exists on the workspace, which lives in Azure
// Monitor rather than in Databricks.
type CISDatabricksChecks struct {
	workspaces  *armdatabricks.WorkspacesClient
	vnets       *armnetwork.VirtualNetworksClient
	diagnostics *armmonitor.DiagnosticSettingsClient
}

func NewCISDatabricksChecks(workspaces *armdatabricks.WorkspacesClient,
	vnets *armnetwork.VirtualNetworksClient,
	diagnostics *armmonitor.DiagnosticSettingsClient) *CISDatabricksChecks {
	return &CISDatabricksChecks{workspaces: workspaces, vnets: vnets, diagnostics: diagnostics}
}

func (c *CISDatabricksChecks) Name() string { return "CIS Azure Databricks" }

const databricksConsole = "https://portal.azure.com/#browse/Microsoft.Databricks%2Fworkspaces"

// workspace is one Databricks workspace reduced to what the six
// recommendations ask about.
type workspace struct {
	name, id string
	props    *armdatabricks.WorkspaceProperties
}

// customVNetID is the virtual network the workspace was deployed into, empty
// when Databricks manages the network itself. It is the single fact 2.1.1
// turns on, and it also decides whether 2.1.2 has anything to look at.
func (w workspace) customVNetID() string {
	if w.props == nil || w.props.Parameters == nil || w.props.Parameters.CustomVirtualNetworkID == nil {
		return ""
	}
	return deref(w.props.Parameters.CustomVirtualNetworkID.Value)
}

func (w workspace) customSubnets() []string {
	if w.props == nil || w.props.Parameters == nil {
		return nil
	}
	var out []string
	for _, p := range []*armdatabricks.WorkspaceCustomStringParameter{
		w.props.Parameters.CustomPrivateSubnetName,
		w.props.Parameters.CustomPublicSubnetName,
	} {
		if p != nil && deref(p.Value) != "" {
			out = append(out, deref(p.Value))
		}
	}
	return out
}

func (c *CISDatabricksChecks) gather(ctx context.Context) ([]workspace, error) {
	if c.workspaces == nil {
		return nil, fmt.Errorf("databricks workspaces client not configured")
	}
	var out []workspace
	pager := c.workspaces.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, w := range page.Value {
			if w == nil || w.Name == nil {
				continue
			}
			out = append(out, workspace{name: *w.Name, id: deref(w.ID), props: w.Properties})
		}
	}
	return out, nil
}

func (c *CISDatabricksChecks) Run(ctx context.Context) ([]CheckResult, error) {
	return []CheckResult{
		c.customVirtualNetwork(ctx),
		c.subnetSecurityGroups(ctx),
		c.diagnosticLogDelivery(ctx),
		c.noPublicIP(ctx),
		c.publicNetworkAccess(ctx),
		c.privateEndpoints(ctx),
	}, nil
}

// dbVerdict is netVerdict's wording for workspaces, kept separate only so the
// "no workspaces" case can say Databricks is not in use rather than that an
// empty estate passed.
func dbVerdict(base CheckResult, offenders []string, total int) CheckResult {
	if total == 0 {
		base.Status = StatusPass
		base.Evidence = "No Azure Databricks workspaces exist in this subscription"
		base.Priority = PriorityInfo
		return base
	}
	return netVerdict(base, "Databricks workspace(s)", offenders, total)
}

func (c *CISDatabricksChecks) customVirtualNetwork(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-2.1.1",
		Name:        "Databricks Deployed in a Customer-Managed Virtual Network",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Redeploy the workspace into your own virtual network (VNet injection)",
		RemediationDetail: `A workspace on the Databricks-managed network cannot be moved; it has to be
recreated with VNet injection and the data migrated.

az databricks workspace create \
  --name <workspace> --resource-group <resource-group> --location <region> \
  --sku premium \
  --vnet <virtual-network-id> \
  --private-subnet <private-subnet> --public-subnet <public-subnet>

On the managed network you cannot attach a security group, route traffic
through a firewall, or use a private endpoint - which is why the three
recommendations that follow depend on this one.`,
		ScreenshotGuide: "Azure Databricks -> each workspace -> Networking -> Screenshot the virtual network, showing it is not Databricks-managed",
		ConsoleURL:      databricksConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "2.1.1", "SOC2": "CC6.6"},
	}
	spaces, err := c.gather(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list Databricks workspaces: %v", err)
		return base
	}
	offenders := []string{}
	for _, w := range spaces {
		if w.customVNetID() == "" {
			offenders = append(offenders, w.name)
		}
	}
	return dbVerdict(base, offenders, len(spaces))
}

func (c *CISDatabricksChecks) subnetSecurityGroups(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-2.1.2",
		Name:        "Network Security Groups Configured for Databricks Subnets",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Associate a network security group with the private and public subnets the workspace uses",
		RemediationDetail: `az network vnet subnet update \
  --name <databricks-subnet> \
  --vnet-name <virtual-network> \
  --resource-group <resource-group> \
  --network-security-group <nsg>

Databricks requires specific rules in that group for the control plane to reach
the clusters, so start from the rule set in Microsoft's VNet injection guidance
rather than an empty group.`,
		ScreenshotGuide: "Virtual networks -> the injected network -> Subnets -> Screenshot the Databricks private and public subnets with a security group",
		ConsoleURL:      databricksConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "2.1.2", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
	}
	spaces, err := c.gather(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list Databricks workspaces: %v", err)
		return base
	}
	if len(spaces) == 0 {
		base.Status = StatusPass
		base.Evidence = "No Azure Databricks workspaces exist in this subscription"
		base.Priority = PriorityInfo
		return base
	}
	if c.vnets == nil {
		base.Status = StatusError
		base.Evidence = "Virtual networks client not configured, so the Databricks subnets could not be read"
		return base
	}
	// Which subnets carry a security group, keyed "<vnet-id>/<subnet-name>"
	// lowercased. Built once: several workspaces commonly share one network.
	secured := map[string]bool{}
	known := map[string]bool{}
	pager := c.vnets.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			base.Status = StatusError
			base.Evidence = fmt.Sprintf("Unable to list virtual networks: %v", err)
			return base
		}
		for _, v := range page.Value {
			if v == nil || v.Properties == nil {
				continue
			}
			vnetID := strings.ToLower(deref(v.ID))
			for _, sn := range v.Properties.Subnets {
				if sn == nil || sn.Name == nil {
					continue
				}
				key := vnetID + "/" + strings.ToLower(*sn.Name)
				known[key] = true
				if sn.Properties != nil && sn.Properties.NetworkSecurityGroup != nil {
					secured[key] = true
				}
			}
		}
	}
	offenders, total := []string{}, 0
	managed := 0
	for _, w := range spaces {
		vnetID := w.customVNetID()
		if vnetID == "" {
			// A Databricks-managed network puts the subnets in a resource
			// group we do not own and cannot read. 2.1.1 already fails such a
			// workspace; failing it twice would double-count one finding.
			managed++
			continue
		}
		subnets := w.customSubnets()
		if len(subnets) == 0 {
			offenders = append(offenders, w.name+" (no subnet names recorded)")
			total++
			continue
		}
		for _, sn := range subnets {
			key := strings.ToLower(vnetID) + "/" + strings.ToLower(sn)
			if !known[key] {
				// The subnet is not in any network this subscription can see,
				// so nothing was measured for it. Saying so beats passing.
				offenders = append(offenders, fmt.Sprintf("%s/%s (subnet not visible)", w.name, sn))
				total++
				continue
			}
			total++
			if !secured[key] {
				offenders = append(offenders, fmt.Sprintf("%s/%s", w.name, sn))
			}
		}
	}
	if total == 0 {
		base.Status = StatusPass
		base.Priority = PriorityInfo
		base.Evidence = fmt.Sprintf("All %d workspace(s) are on the Databricks-managed network, whose subnets this "+
			"subscription cannot read; 2.1.1 is the recommendation that covers them", managed)
		return base
	}
	base = netVerdict(base, "Databricks subnet(s)", offenders, total)
	if managed > 0 {
		base.Evidence += fmt.Sprintf("; %d further workspace(s) are on the Databricks-managed network and are covered by 2.1.1", managed)
	}
	return base
}

func (c *CISDatabricksChecks) diagnosticLogDelivery(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-2.1.7",
		Name:        "Databricks Diagnostic Log Delivery Configured",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Add a diagnostic setting on each workspace and send the logs to a workspace, storage account or event hub",
		RemediationDetail: `az monitor diagnostic-settings create \
  --name databricks-logs \
  --resource <workspace-resource-id> \
  --workspace <log-analytics-workspace-id> \
  --logs '[{"categoryGroup":"allLogs","enabled":true}]'

Without it the account, cluster and notebook activity is visible only inside
the workspace and only for a short window, so there is nothing to show an
assessor after the fact.`,
		ScreenshotGuide: "Azure Databricks -> each workspace -> Monitoring -> Diagnostic settings -> Screenshot the setting and its destination",
		ConsoleURL:      databricksConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "2.1.7", "SOC2": "CC7.2", "PCI-DSS": "10.2.1"},
	}
	spaces, err := c.gather(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list Databricks workspaces: %v", err)
		return base
	}
	if len(spaces) == 0 {
		base.Status = StatusPass
		base.Evidence = "No Azure Databricks workspaces exist in this subscription"
		base.Priority = PriorityInfo
		return base
	}
	if c.diagnostics == nil {
		base.Status = StatusError
		base.Evidence = "Diagnostic settings client not configured"
		return base
	}
	offenders, total := []string{}, 0
	for _, w := range spaces {
		if w.id == "" {
			continue
		}
		total++
		enabled := false
		pager := c.diagnostics.NewListPager(w.id, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, ds := range page.Value {
				if ds == nil || ds.Properties == nil {
					continue
				}
				for _, l := range ds.Properties.Logs {
					if l != nil && l.Enabled != nil && *l.Enabled {
						enabled = true
					}
				}
			}
		}
		if !enabled {
			offenders = append(offenders, w.name)
		}
	}
	return dbVerdict(base, offenders, total)
}

func (c *CISDatabricksChecks) noPublicIP(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-2.1.9",
		Name:        "Databricks Secure Cluster Connectivity Enabled",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Deploy the workspace with secure cluster connectivity so cluster nodes have no public IP",
		RemediationDetail: `Secure cluster connectivity is set at creation and cannot be turned on
afterwards; the workspace has to be recreated.

az databricks workspace create \
  --name <workspace> --resource-group <resource-group> --location <region> \
  --sku premium --enable-no-public-ip true \
  --vnet <virtual-network-id> \
  --private-subnet <private-subnet> --public-subnet <public-subnet>

Without it every cluster node gets a public IP, so the nodes are reachable from
the internet and the network controls around the workspace are bypassed.`,
		ScreenshotGuide: "Azure Databricks -> each workspace -> Networking -> Screenshot 'Secure Cluster Connectivity (No Public IP)' set to Enabled",
		ConsoleURL:      databricksConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "2.1.9", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
	}
	spaces, err := c.gather(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list Databricks workspaces: %v", err)
		return base
	}
	offenders := []string{}
	for _, w := range spaces {
		if w.props == nil || w.props.Parameters == nil || w.props.Parameters.EnableNoPublicIP == nil ||
			w.props.Parameters.EnableNoPublicIP.Value == nil || !*w.props.Parameters.EnableNoPublicIP.Value {
			offenders = append(offenders, w.name)
		}
	}
	return dbVerdict(base, offenders, len(spaces))
}

func (c *CISDatabricksChecks) publicNetworkAccess(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-2.1.10",
		Name:        "Databricks Public Network Access Disabled",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Set public network access to Disabled and reach the workspace through a private endpoint",
		RemediationDetail: `az databricks workspace update \
  --name <workspace> --resource-group <resource-group> \
  --public-network-access Disabled

Disable this before the private endpoint is in place and the workspace becomes
unreachable, so create the endpoint first - 2.1.11 is the same change from the
other side.`,
		ScreenshotGuide: "Azure Databricks -> each workspace -> Networking -> Screenshot public network access set to Disabled",
		ConsoleURL:      databricksConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "2.1.10", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
	}
	spaces, err := c.gather(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list Databricks workspaces: %v", err)
		return base
	}
	offenders := []string{}
	for _, w := range spaces {
		if w.props == nil || w.props.PublicNetworkAccess == nil ||
			*w.props.PublicNetworkAccess != armdatabricks.PublicNetworkAccessDisabled {
			offenders = append(offenders, w.name)
		}
	}
	return dbVerdict(base, offenders, len(spaces))
}

func (c *CISDatabricksChecks) privateEndpoints(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-2.1.11",
		Name:        "Private Endpoints Used to Access Databricks",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Create an approved private endpoint for each workspace",
		RemediationDetail: `az network private-endpoint create \
  --name <endpoint> --resource-group <resource-group> \
  --vnet-name <virtual-network> --subnet <subnet> \
  --private-connection-resource-id <workspace-resource-id> \
  --group-id databricks_ui_api \
  --connection-name <connection>

An endpoint left in the Pending state carries no traffic, so it is counted only
once approved.`,
		ScreenshotGuide: "Azure Databricks -> each workspace -> Networking -> Private endpoint connections -> Screenshot the approved connections",
		ConsoleURL:      databricksConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "2.1.11", "SOC2": "CC6.6"},
	}
	spaces, err := c.gather(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list Databricks workspaces: %v", err)
		return base
	}
	offenders := []string{}
	for _, w := range spaces {
		if !hasApprovedPrivateEndpoint(w.props) {
			offenders = append(offenders, w.name)
		}
	}
	return dbVerdict(base, offenders, len(spaces))
}

// hasApprovedPrivateEndpoint requires the connection to be approved. A pending
// or rejected endpoint exists as a resource and carries no traffic, so
// counting the list length would pass a workspace nothing can reach privately.
func hasApprovedPrivateEndpoint(p *armdatabricks.WorkspaceProperties) bool {
	if p == nil {
		return false
	}
	for _, pe := range p.PrivateEndpointConnections {
		if pe == nil || pe.Properties == nil || pe.Properties.PrivateLinkServiceConnectionState == nil {
			continue
		}
		status := pe.Properties.PrivateLinkServiceConnectionState.Status
		if status != nil && *status == armdatabricks.PrivateLinkServiceConnectionStatusApproved {
			return true
		}
	}
	return false
}
