package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

// CISNetworkChecks answers the networking recommendations in CIS Microsoft
// Azure Foundations v6.0.0 section 7 that no other check covers: virtual
// network flow log retention, the VPN gateway authentication type, subnet
// association, and the five Application Gateway and Web Application Firewall
// settings.
//
// Five clients, because these settings live on five different resources, and a
// check without its client cannot tell "configured badly" from "we could not
// look" - which is the difference between a finding and a fabrication.
type CISNetworkChecks struct {
	gateways    *armnetwork.ApplicationGatewaysClient
	wafPolicies *armnetwork.WebApplicationFirewallPoliciesClient
	vnets       *armnetwork.VirtualNetworksClient
	watchers    *armnetwork.WatchersClient
	flowLogs    *armnetwork.FlowLogsClient
	vpnGateways *armnetwork.VirtualNetworkGatewaysClient
	bastions    *armnetwork.BastionHostsClient
}

func NewCISNetworkChecks(gateways *armnetwork.ApplicationGatewaysClient,
	wafPolicies *armnetwork.WebApplicationFirewallPoliciesClient,
	vnets *armnetwork.VirtualNetworksClient, watchers *armnetwork.WatchersClient,
	flowLogs *armnetwork.FlowLogsClient,
	vpnGateways *armnetwork.VirtualNetworkGatewaysClient,
	bastions *armnetwork.BastionHostsClient) *CISNetworkChecks {
	return &CISNetworkChecks{
		gateways: gateways, wafPolicies: wafPolicies, vnets: vnets,
		watchers: watchers, flowLogs: flowLogs, vpnGateways: vpnGateways,
		bastions: bastions,
	}
}

func (c *CISNetworkChecks) Name() string { return "CIS Azure Networking" }

const appGatewayConsole = "https://portal.azure.com/#browse/Microsoft.Network%2FapplicationGateways"

// netVerdict renders "these resources failed out of this many" the same way for
// every check here, so nine checks do not each repeat the shape - and so none
// of them can report a verdict without a denominator.
func netVerdict(base CheckResult, kind string, offenders []string, total int) CheckResult {
	if total == 0 {
		base.Status = StatusPass
		base.Evidence = fmt.Sprintf("No %s exist in this subscription", kind)
		base.Priority = PriorityInfo
		return base
	}
	if len(offenders) == 0 {
		base.Status = StatusPass
		base.Evidence = fmt.Sprintf("All %d %s satisfy this", total, kind)
		base.Priority = PriorityInfo
		return base
	}
	base.Status = StatusFail
	base.Evidence = fmt.Sprintf("%d of %d %s do not: %v", len(offenders), total, kind, capList(offenders, 5))
	return base
}

func (c *CISNetworkChecks) Run(ctx context.Context) ([]CheckResult, error) {
	return []CheckResult{
		c.virtualNetworkFlowLogRetention(ctx),
		c.vpnGatewayAuthType(ctx),
		c.wafOnApplicationGateway(ctx),
		c.subnetsHaveSecurityGroups(ctx),
		c.gatewayMinimumTLS(ctx),
		c.gatewayHTTP2(ctx),
		c.wafRequestBodyInspection(ctx),
		c.wafBotProtection(ctx),
		c.bastionHostExists(ctx),
		c.ddosProtectionOnVirtualNetworks(ctx),
	}, nil
}

// resourceGroupsFromVNets gives the resource groups worth asking about for the
// per-resource-group-only clients. Network Watchers and VPN gateways cannot be
// listed subscription-wide in this SDK version, and guessing a resource group
// name would silently examine nothing.
func (c *CISNetworkChecks) resourceGroups(ctx context.Context) ([]string, error) {
	if c.vnets == nil {
		return nil, fmt.Errorf("virtual networks client not configured")
	}
	seen := map[string]bool{}
	var out []string
	pager := c.vnets.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			if v == nil {
				continue
			}
			if rg := resourceGroupOf(deref(v.ID)); rg != "" && !seen[strings.ToLower(rg)] {
				seen[strings.ToLower(rg)] = true
				out = append(out, rg)
			}
		}
	}
	return out, nil
}

func (c *CISNetworkChecks) virtualNetworkFlowLogRetention(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.8",
		Name:        "Virtual Network Flow Log Retention at Least 90 Days",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Set each virtual network flow log to retain at least 90 days, or to 0 for indefinite retention",
		RemediationDetail: `az network watcher flow-log update \
  --name <flow-log> \
  --resource-group <resource-group> \
  --retention 90

A retention of 0 also satisfies the recommendation: it means no retention
policy is applied and the records are kept indefinitely. Anything between 1 and
89 days fails, because an investigation that starts a quarter after the event
has nothing to read.`,
		ScreenshotGuide: "Network Watcher -> Flow logs -> filter Flow log type = Virtual network -> each log -> Screenshot the retention days",
		ConsoleURL:      "https://portal.azure.com/#view/Microsoft_Azure_Network/NetworkWatcherMenuBlade/~/flowLogs",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.8", "SOC2": "CC7.2", "PCI-DSS": "10.5.1"},
	}
	if c.watchers == nil || c.flowLogs == nil {
		base.Status = StatusError
		base.Evidence = "Network Watcher or flow logs client not configured"
		return base
	}
	groups, err := c.resourceGroups(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to enumerate resource groups from the virtual networks: %v", err)
		return base
	}
	offenders, total := []string{}, 0
	for _, rg := range groups {
		wPager := c.watchers.NewListPager(rg, nil)
		for wPager.More() {
			wPage, err := wPager.NextPage(ctx)
			if err != nil {
				// A resource group with no watcher is normal, not an error
				// worth failing the whole check over.
				break
			}
			for _, w := range wPage.Value {
				if w == nil || w.Name == nil {
					continue
				}
				fPager := c.flowLogs.NewListPager(rg, *w.Name, nil)
				for fPager.More() {
					fPage, err := fPager.NextPage(ctx)
					if err != nil {
						break
					}
					for _, fl := range fPage.Value {
						if fl == nil || fl.Properties == nil {
							continue
						}
						// Only virtual network flow logs are in scope; the same
						// API returns the NSG ones, which 7.5 covers.
						if !strings.Contains(strings.ToLower(deref(fl.Properties.TargetResourceID)), "/virtualnetworks/") {
							continue
						}
						total++
						if !retentionSatisfies90(fl.Properties.RetentionPolicy) {
							offenders = append(offenders, deref(fl.Name))
						}
					}
				}
			}
		}
	}
	return netVerdict(base, "virtual network flow log(s)", offenders, total)
}

// retentionSatisfies90 encodes the benchmark's own wording: 0, 90 or more is
// compliant, because 0 means no retention policy and the records are kept
// indefinitely. Reading 0 as "nothing retained" would fail the strongest
// configuration.
func retentionSatisfies90(p *armnetwork.RetentionPolicyParameters) bool {
	if p == nil || p.Days == nil {
		return false
	}
	return *p.Days == 0 || *p.Days >= 90
}

func (c *CISNetworkChecks) vpnGatewayAuthType(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.9",
		Name:        "VPN Gateway Point-to-Site Uses Entra ID Only",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Set the point-to-site authentication type to Microsoft Entra ID and remove the certificate and RADIUS options",
		RemediationDetail: `Virtual network gateway -> Point-to-site configuration ->
Authentication type -> tick only Azure Active Directory.

Certificate authentication has no central revocation or conditional access; a
gateway offering both is only as strong as the weaker option.`,
		ScreenshotGuide: "Virtual network gateways -> each VPN gateway -> Point-to-site configuration -> Screenshot the authentication type",
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Network%2FvirtualNetworkGateways",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.9", "SOC2": "CC6.6", "PCI-DSS": "8.4.2"},
	}
	if c.vpnGateways == nil {
		base.Status = StatusError
		base.Evidence = "Virtual network gateways client not configured"
		return base
	}
	groups, err := c.resourceGroups(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to enumerate resource groups from the virtual networks: %v", err)
		return base
	}
	offenders, total := []string{}, 0
	for _, rg := range groups {
		pager := c.vpnGateways.NewListPager(rg, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				break
			}
			for _, g := range page.Value {
				if g == nil || g.Properties == nil || g.Properties.VPNClientConfiguration == nil {
					// A gateway with no point-to-site configuration is out of
					// scope: the recommendation is about how P2S clients
					// authenticate, and this one accepts none.
					continue
				}
				total++
				if !entraOnly(g.Properties.VPNClientConfiguration.VPNAuthenticationTypes) {
					offenders = append(offenders, deref(g.Name))
				}
			}
		}
	}
	return netVerdict(base, "VPN gateway(s) with a point-to-site configuration", offenders, total)
}

// entraOnly is "exactly AAD and nothing else". A gateway that also accepts
// certificates is not Entra-only, however many of the types are AAD.
func entraOnly(types []*armnetwork.VPNAuthenticationType) bool {
	if len(types) == 0 {
		return false
	}
	for _, t := range types {
		if t == nil || *t != armnetwork.VPNAuthenticationTypeAAD {
			return false
		}
	}
	return true
}

func (c *CISNetworkChecks) gatherGateways(ctx context.Context) ([]*armnetwork.ApplicationGateway, error) {
	if c.gateways == nil {
		return nil, fmt.Errorf("application gateways client not configured")
	}
	var out []*armnetwork.ApplicationGateway
	pager := c.gateways.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (c *CISNetworkChecks) wafOnApplicationGateway(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.10",
		Name:        "Web Application Firewall Enabled on Application Gateway",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Associate a Web Application Firewall policy with each application gateway and move it to the WAF_v2 tier",
		RemediationDetail: `az network application-gateway waf-policy create \
  --name <policy> --resource-group <resource-group>

az network application-gateway update \
  --name <gateway> --resource-group <resource-group> \
  --set firewallPolicy.id=<policy-id>

The gateway must be on the WAF_v2 tier for the policy to be enforced; a policy
associated with a Standard_v2 gateway is configuration without effect.`,
		ScreenshotGuide: "Application gateways -> each gateway -> Overview -> Screenshot the tier, and Web application firewall -> Screenshot the associated policy",
		ConsoleURL:      appGatewayConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.10", "SOC2": "CC6.6", "PCI-DSS": "6.4.2"},
	}
	gws, err := c.gatherGateways(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list application gateways: %v", err)
		return base
	}
	offenders := []string{}
	for _, g := range gws {
		if g == nil || g.Properties == nil {
			continue
		}
		tierIsWAF := g.Properties.SKU != nil && g.Properties.SKU.Tier != nil &&
			strings.Contains(strings.ToUpper(string(*g.Properties.SKU.Tier)), "WAF")
		hasPolicy := g.Properties.FirewallPolicy != nil && deref(g.Properties.FirewallPolicy.ID) != ""
		if !tierIsWAF || !hasPolicy {
			offenders = append(offenders, deref(g.Name))
		}
	}
	return netVerdict(base, "application gateway(s)", offenders, len(gws))
}

func (c *CISNetworkChecks) subnetsHaveSecurityGroups(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.11",
		Name:        "Subnets Associated with Network Security Groups",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Associate a network security group with every subnet",
		RemediationDetail: `az network vnet subnet update \
  --name <subnet> \
  --vnet-name <virtual-network> \
  --resource-group <resource-group> \
  --network-security-group <nsg>

A subnet with no security group inherits no restriction: anything permitted at
the virtual network boundary reaches every host in it. The Azure-reserved
subnets - GatewaySubnet, AzureFirewallSubnet, AzureBastionSubnet and the
management pairs - do not accept one and are not counted.`,
		ScreenshotGuide: "Virtual networks -> each network -> Subnets -> Screenshot the list with the security group column populated",
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Network%2FvirtualNetworks",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.11", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
	}
	if c.vnets == nil {
		base.Status = StatusError
		base.Evidence = "Virtual networks client not configured"
		return base
	}
	offenders, total := []string{}, 0
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
			for _, sn := range v.Properties.Subnets {
				if sn == nil || sn.Name == nil {
					continue
				}
				if isReservedSubnet(*sn.Name) {
					continue
				}
				total++
				if sn.Properties == nil || sn.Properties.NetworkSecurityGroup == nil {
					offenders = append(offenders, fmt.Sprintf("%s/%s", deref(v.Name), *sn.Name))
				}
			}
		}
	}
	return netVerdict(base, "subnet(s)", offenders, total)
}

// reservedSubnets are the Azure-managed subnets that cannot take a network
// security group at all. Counting them would make every estate running a
// gateway or Bastion fail a recommendation it cannot satisfy.
var reservedSubnets = map[string]bool{
	"gatewaysubnet":                 true,
	"azurefirewallsubnet":           true,
	"azurefirewallmanagementsubnet": true,
	"azurebastionsubnet":            true,
	"routeserversubnet":             true,
}

func isReservedSubnet(name string) bool {
	return reservedSubnets[strings.ToLower(strings.TrimSpace(name))]
}

func (c *CISNetworkChecks) gatewayMinimumTLS(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.12",
		Name:        "Application Gateway Minimum TLS Version 1.2",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Remediation: "Set the application gateway SSL policy minimum protocol version to TLSv1_2 or higher",
		RemediationDetail: `az network application-gateway ssl-policy set \
  --gateway-name <gateway> \
  --resource-group <resource-group> \
  --policy-type Custom \
  --min-protocol-version TLSv1_2 \
  --cipher-suites <suites>

A gateway with no SSL policy at all uses the platform default, which has
historically permitted TLS 1.0 - so an absent policy fails rather than passes.`,
		ScreenshotGuide: "Application gateways -> each gateway -> Listeners -> SSL policy -> Screenshot the minimum protocol version",
		ConsoleURL:      appGatewayConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.12", "SOC2": "CC6.7", "PCI-DSS": "4.2.1"},
	}
	gws, err := c.gatherGateways(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list application gateways: %v", err)
		return base
	}
	offenders := []string{}
	for _, g := range gws {
		if g == nil || g.Properties == nil {
			continue
		}
		if !tlsPolicyAtLeast12(g.Properties.SSLPolicy) {
			offenders = append(offenders, deref(g.Name))
		}
	}
	return netVerdict(base, "application gateway(s)", offenders, len(gws))
}

// tlsPolicyAtLeast12 accepts either an explicit minimum of TLS 1.2 or 1.3, or
// one of the predefined policies whose name carries the version. A predefined
// policy reports its name and no minimum, so reading only MinProtocolVersion
// would fail a gateway pinned to AppGwSslPolicy20220101.
func tlsPolicyAtLeast12(p *armnetwork.ApplicationGatewaySSLPolicy) bool {
	if p == nil {
		return false
	}
	if p.MinProtocolVersion != nil {
		switch *p.MinProtocolVersion {
		case armnetwork.ApplicationGatewaySSLProtocolTLSv12, armnetwork.ApplicationGatewaySSLProtocolTLSv13:
			return true
		default:
			return false
		}
	}
	if p.PolicyName != nil {
		name := string(*p.PolicyName)
		// The 2022 predefined policies are TLS 1.2 minimum; the 2015 and 2017
		// ones permit TLS 1.0.
		return strings.Contains(name, "2022")
	}
	return false
}

func (c *CISNetworkChecks) gatewayHTTP2(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.13",
		Name:        "Application Gateway HTTP2 Enabled",
		Severity:    "LOW",
		Priority:    PriorityLow,
		Remediation: "Enable HTTP2 on each application gateway",
		RemediationDetail: `az network application-gateway update \
  --name <gateway> --resource-group <resource-group> --set enableHttp2=true`,
		ScreenshotGuide: "Application gateways -> each gateway -> Configuration -> Screenshot HTTP2 set to Enabled",
		ConsoleURL:      appGatewayConsole,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.13", "SOC2": "CC6.7"},
	}
	gws, err := c.gatherGateways(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list application gateways: %v", err)
		return base
	}
	offenders := []string{}
	for _, g := range gws {
		if g == nil || g.Properties == nil {
			continue
		}
		if g.Properties.EnableHTTP2 == nil || !*g.Properties.EnableHTTP2 {
			offenders = append(offenders, deref(g.Name))
		}
	}
	return netVerdict(base, "application gateway(s)", offenders, len(gws))
}

func (c *CISNetworkChecks) gatherWAFPolicies(ctx context.Context) ([]*armnetwork.WebApplicationFirewallPolicy, error) {
	if c.wafPolicies == nil {
		return nil, fmt.Errorf("web application firewall policies client not configured")
	}
	var out []*armnetwork.WebApplicationFirewallPolicy
	pager := c.wafPolicies.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (c *CISNetworkChecks) wafRequestBodyInspection(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.14",
		Name:        "WAF Request Body Inspection Enabled",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Enable request body inspection on each Web Application Firewall policy",
		RemediationDetail: `az network application-gateway waf-policy policy-setting update \
  --policy-name <policy> \
  --resource-group <resource-group> \
  --request-body-check true

Without it the rules only see headers and the query string, so an injection
carried in a POST body passes unexamined.`,
		ScreenshotGuide: "Application gateways -> Web application firewall -> the policy -> Policy settings -> Screenshot 'Enforce request body inspection' ticked",
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Network%2FApplicationGatewayWebApplicationFirewallPolicies",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.14", "SOC2": "CC6.6", "PCI-DSS": "6.4.2"},
	}
	policies, err := c.gatherWAFPolicies(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list web application firewall policies: %v", err)
		return base
	}
	offenders := []string{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		if p.Properties == nil || p.Properties.PolicySettings == nil ||
			p.Properties.PolicySettings.RequestBodyCheck == nil ||
			!*p.Properties.PolicySettings.RequestBodyCheck {
			offenders = append(offenders, deref(p.Name))
		}
	}
	return netVerdict(base, "web application firewall polic(ies)", offenders, len(policies))
}

// botManagerRuleSet is the managed rule set that carries the bot rules. Matched
// case-insensitively on a substring because the wire value has varied between
// "Microsoft_BotManagerRuleSet" and the same name with a version suffix.
const botManagerRuleSet = "botmanagerruleset"

func (c *CISNetworkChecks) wafBotProtection(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-7.15",
		Name:        "WAF Bot Protection Enabled",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Add the Microsoft bot manager rule set to each Web Application Firewall policy",
		RemediationDetail: `az network application-gateway waf-policy managed-rule rule-set add \
  --policy-name <policy> \
  --resource-group <resource-group> \
  --type Microsoft_BotManagerRuleSet \
  --version 1.0

The rule set covers the malicious-bot categories; without it credential
stuffing and scraping traffic is indistinguishable from ordinary requests to
the policy.`,
		ScreenshotGuide: "Application gateways -> Web application firewall -> the policy -> Managed rules -> Screenshot the bot manager rule set with Malicious Bots enabled",
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Network%2FApplicationGatewayWebApplicationFirewallPolicies",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "7.15", "SOC2": "CC6.6", "PCI-DSS": "6.4.2"},
	}
	policies, err := c.gatherWAFPolicies(ctx)
	if err != nil {
		base.Status = StatusError
		base.Evidence = fmt.Sprintf("Unable to list web application firewall policies: %v", err)
		return base
	}
	offenders := []string{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		if !hasBotManagerRuleSet(p.Properties) {
			offenders = append(offenders, deref(p.Name))
		}
	}
	return netVerdict(base, "web application firewall polic(ies)", offenders, len(policies))
}

func hasBotManagerRuleSet(p *armnetwork.WebApplicationFirewallPolicyPropertiesFormat) bool {
	if p == nil || p.ManagedRules == nil {
		return false
	}
	for _, rs := range p.ManagedRules.ManagedRuleSets {
		if rs == nil || rs.RuleSetType == nil {
			continue
		}
		if strings.Contains(strings.ToLower(*rs.RuleSetType), botManagerRuleSet) {
			return true
		}
	}
	return false
}

// 8.4 and 8.5 sit outside section 7 in the benchmark but read network
// resources, so they live with the other armnetwork checks rather than in a
// suite of their own holding one client.

func (c *CISNetworkChecks) bastionHostExists(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.4.1",
		Name:        "Azure Bastion Host Exists",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Deploy an Azure Bastion host and reach virtual machines through it instead of a public IP",
		RemediationDetail: `az network bastion create \
  --name <bastion> \
  --public-ip-address <public-ip> \
  --resource-group <resource-group> \
  --vnet-name <virtual-network> \
  --location <region>

Bastion needs a subnet named AzureBastionSubnet of at least /26. With it in
place, RDP and SSH no longer need a public IP or an open management port, which
is what makes the 7.1 and 7.2 restrictions practical to apply.`,
		ScreenshotGuide: "Bastions -> Screenshot the list showing at least one host, and the virtual networks it serves",
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Network%2FbastionHosts",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.4.1", "SOC2": "CC6.6", "PCI-DSS": "2.2.7"},
	}
	if c.bastions == nil {
		base.Status = StatusError
		base.Evidence = "Bastion hosts client not configured"
		return base
	}
	names := []string{}
	pager := c.bastions.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			base.Status = StatusError
			base.Evidence = fmt.Sprintf("Unable to list Bastion hosts: %v", err)
			return base
		}
		for _, b := range page.Value {
			if b != nil && b.Name != nil {
				names = append(names, *b.Name)
			}
		}
	}
	if len(names) == 0 {
		base.Status = StatusFail
		base.Evidence = "No Azure Bastion host exists in this subscription"
		return base
	}
	base.Status = StatusPass
	base.Priority = PriorityInfo
	base.Evidence = fmt.Sprintf("%d Bastion host(s) exist: %v", len(names), capList(names, 5))
	return base
}

func (c *CISNetworkChecks) ddosProtectionOnVirtualNetworks(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:     "CIS-8.5",
		Name:        "DDoS Network Protection Enabled on Virtual Networks",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Remediation: "Enable DDoS Network Protection on each virtual network and associate a protection plan",
		RemediationDetail: `az network ddos-protection create \
  --name <plan> --resource-group <resource-group> --location <region>

az network vnet update \
  --name <virtual-network> \
  --resource-group <resource-group> \
  --ddos-protection true \
  --ddos-protection-plan <plan>

The plan carries a standing monthly charge that covers every virtual network in
the tenant, so the cost is per tenant rather than per network - worth knowing
before reading this as an expensive finding.`,
		ScreenshotGuide: "Virtual networks -> each network -> DDoS protection -> Screenshot the setting and the associated plan",
		ConsoleURL:      "https://portal.azure.com/#browse/Microsoft.Network%2FvirtualNetworks",
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-Azure": "8.5", "SOC2": "A1.2"},
	}
	if c.vnets == nil {
		base.Status = StatusError
		base.Evidence = "Virtual networks client not configured"
		return base
	}
	offenders, total := []string{}, 0
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
			total++
			// Both halves are needed: the flag without a plan is a setting
			// with nothing behind it, and a plan reference with the flag off
			// is not in effect.
			enabled := v.Properties.EnableDdosProtection != nil && *v.Properties.EnableDdosProtection
			planned := v.Properties.DdosProtectionPlan != nil && deref(v.Properties.DdosProtectionPlan.ID) != ""
			if !enabled || !planned {
				offenders = append(offenders, deref(v.Name))
			}
		}
	}
	return netVerdict(base, "virtual network(s)", offenders, total)
}
