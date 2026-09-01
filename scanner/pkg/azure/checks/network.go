package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

type NetworkChecks struct {
	client *armnetwork.SecurityGroupsClient
}

func NewNetworkChecks(client *armnetwork.SecurityGroupsClient) *NetworkChecks {
	return &NetworkChecks{client: client}
}

func (c *NetworkChecks) Name() string {
	return "Azure Network Security"
}

func (c *NetworkChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS 7.1: RDP access from internet
	results = append(results, c.CheckRDPAccess(ctx)...)

	// CIS 7.2: SSH access from internet
	results = append(results, c.CheckSSHAccess(ctx)...)

	// CIS 7.3: UDP access from internet
	results = append(results, c.CheckUDPAccess(ctx)...)

	// CIS 7.4: HTTP(S) access evaluation
	results = append(results, c.CheckHTTPAccess(ctx)...)

	// CIS 7.5: NSG Flow Log retention
	results = append(results, c.CheckFlowLogRetention(ctx)...)

	// CIS 7.6: Network Watcher enabled
	results = append(results, c.CheckNetworkWatcher(ctx)...)

	// CIS 7.7: Public IP evaluation
	results = append(results, c.CheckPublicIPs(ctx)...)

	// Legacy comprehensive check (covers multiple)
	results = append(results, c.CheckOpenPorts(ctx)...)

	return results, nil
}

func (c *NetworkChecks) CheckRDPAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListAllPager(nil)

	rdpFromInternet := []string{}
	totalNSGs := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return append(results, CheckResult{
				Control:    "CIS-7.1",
				Name:       "[CIS Azure 7.1] RDP Access from Internet",
				Status:     "ERROR",
				Evidence:   fmt.Sprintf("Unable to check NSGs: %v", err),
				Priority:   PriorityHigh,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("NSG_RULES"),
			})
		}

		for _, nsg := range page.Value {
			totalNSGs++

			if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
				for _, rule := range nsg.Properties.SecurityRules {
					if rule.Properties != nil &&
						rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound &&
						rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {

						// Check if RDP (3389) is open from internet
						isRDP := false
						if rule.Properties.DestinationPortRange != nil {
							port := *rule.Properties.DestinationPortRange
							if port == "3389" || port == "*" {
								isRDP = true
							}
						}

						if isRDP {
							// Check source
							if rule.Properties.SourceAddressPrefix != nil {
								source := *rule.Properties.SourceAddressPrefix
								if source == "*" || source == "0.0.0.0/0" || source == "Internet" || source == "<nw>/0" || source == "/0" {
									rdpFromInternet = append(rdpFromInternet, fmt.Sprintf("%s (rule: %s)", *nsg.Name, *rule.Name))
								}
							}
						}
					}
				}
			}
		}
	}

	if len(rdpFromInternet) > 0 {
		displayRules := rdpFromInternet
		if len(rdpFromInternet) > 3 {
			displayRules = rdpFromInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-7.1",
			Name:        "[CIS Azure 7.1] RDP Access from Internet",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CIS 7.1: %d NSG rules allow RDP (3389) from internet: %s", len(rdpFromInternet), strings.Join(displayRules, ", ")),
			Remediation: "Remove RDP access from internet, use Azure Bastion",
			RemediationDetail: `CIS Azure 7.1: Ensure that RDP access from the Internet is evaluated and restricted

CRITICAL: RDP exposed to internet is a primary attack vector.

Remediation steps:
1. Delete NSG rules allowing 0.0.0.0/0 → port 3389
2. Deploy Azure Bastion for secure RDP access
3. Or restrict source to specific corporate IPs only

Azure CLI (delete rule):
az network nsg rule delete \
  --name <rule-name> \
  --nsg-name <nsg-name> \
  --resource-group <rg>

Azure Bastion deployment:
az network bastion create \
  --name <bastion-name> \
  --public-ip-address <pip> \
  --resource-group <rg> \
  --vnet-name <vnet>`,
			ScreenshotGuide: "NSG → Inbound security rules → Screenshot showing:\n- No rules with Source=Any/Internet AND Destination Port=3389\n- OR Azure Bastion deployment in VNet",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("NSG_RULES"),
		})
	} else if totalNSGs > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-7.1",
			Name:       "[CIS Azure 7.1] RDP Access from Internet",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 7.1: All %d NSGs properly restrict RDP access from internet", totalNSGs),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("NSG_RULES"),
		})
	}

	return results
}

func (c *NetworkChecks) CheckSSHAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListAllPager(nil)

	sshFromInternet := []string{}
	totalNSGs := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, nsg := range page.Value {
			totalNSGs++

			if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
				for _, rule := range nsg.Properties.SecurityRules {
					if rule.Properties != nil &&
						rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound &&
						rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {

						// Check if SSH (22) is open from internet
						isSSH := false
						if rule.Properties.DestinationPortRange != nil {
							port := *rule.Properties.DestinationPortRange
							if port == "22" || port == "*" {
								isSSH = true
							}
						}

						if isSSH {
							if rule.Properties.SourceAddressPrefix != nil {
								source := *rule.Properties.SourceAddressPrefix
								if source == "*" || source == "0.0.0.0/0" || source == "Internet" || source == "<nw>/0" || source == "/0" {
									sshFromInternet = append(sshFromInternet, fmt.Sprintf("%s (rule: %s)", *nsg.Name, *rule.Name))
								}
							}
						}
					}
				}
			}
		}
	}

	if len(sshFromInternet) > 0 {
		displayRules := sshFromInternet
		if len(sshFromInternet) > 3 {
			displayRules = sshFromInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-7.2",
			Name:        "[CIS Azure 7.2] SSH Access from Internet",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CIS 7.2: %d NSG rules allow SSH (22) from internet: %s", len(sshFromInternet), strings.Join(displayRules, ", ")),
			Remediation: "Remove SSH access from internet, use Azure Bastion or VPN",
			RemediationDetail: `CIS Azure 7.2: Ensure that SSH access from the Internet is evaluated and restricted

CRITICAL: SSH exposed to internet faces constant brute force attacks.

Remediation:
1. Delete NSG rules allowing 0.0.0.0/0 → port 22
2. Use Azure Bastion for SSH access
3. Or configure site-to-site VPN
4. Or restrict to specific corporate IPs with strong authentication

Best practice: Combine Azure Bastion + disable password authentication + use SSH keys only.`,
			ScreenshotGuide: "NSG → Inbound security rules → Screenshot showing:\n- No rules with Source=Any/Internet AND Destination Port=22\n- Azure Bastion or VPN gateway deployment",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("NSG_RULES"),
		})
	} else if totalNSGs > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-7.2",
			Name:       "[CIS Azure 7.2] SSH Access from Internet",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 7.2: All %d NSGs properly restrict SSH access from internet", totalNSGs),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("NSG_RULES"),
		})
	}

	return results
}

func (c *NetworkChecks) CheckUDPAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListAllPager(nil)

	udpFromInternet := []string{}
	totalNSGs := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, nsg := range page.Value {
			totalNSGs++

			if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
				for _, rule := range nsg.Properties.SecurityRules {
					if rule.Properties != nil &&
						rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound &&
						rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {

						// Check if UDP is allowed from internet
						isUDP := false
						if rule.Properties.Protocol != nil {
							protocol := *rule.Properties.Protocol
							if protocol == armnetwork.SecurityRuleProtocolUDP || protocol == armnetwork.SecurityRuleProtocolAsterisk {
								isUDP = true
							}
						}

						if isUDP {
							if rule.Properties.SourceAddressPrefix != nil {
								source := *rule.Properties.SourceAddressPrefix
								if source == "*" || source == "0.0.0.0/0" || source == "Internet" {
									port := "any"
									if rule.Properties.DestinationPortRange != nil {
										port = *rule.Properties.DestinationPortRange
									}
									udpFromInternet = append(udpFromInternet, fmt.Sprintf("%s (UDP port %s)", *nsg.Name, port))
								}
							}
						}
					}
				}
			}
		}
	}

	if len(udpFromInternet) > 0 {
		displayRules := udpFromInternet
		if len(udpFromInternet) > 3 {
			displayRules = udpFromInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-7.3",
			Name:        "[CIS Azure 7.3] UDP Access from Internet",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 7.3: %d NSG rules allow UDP from internet: %s", len(udpFromInternet), strings.Join(displayRules, ", ")),
			Remediation: "Evaluate and restrict UDP access from internet",
			RemediationDetail: `CIS Azure 7.3: Ensure that UDP access from the Internet is evaluated and restricted

UDP services commonly attacked:
- DNS (53) - amplification attacks
- SNMP (161) - reconnaissance  
- NTP (123) - amplification attacks
- Any UDP - can be used for DDoS amplification

Review each UDP rule and ensure business justification exists.
Restrict to specific source IPs where possible.`,
			ScreenshotGuide: "NSG → Inbound security rules → Screenshot showing:\n- No UDP rules with Source=Any/Internet\n- OR documented business justification for each UDP rule",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("NSG_RULES"),
		})
	} else if totalNSGs > 0 {
		results = append(results, CheckResult{
			Control:    "CIS-7.3",
			Name:       "[CIS Azure 7.3] UDP Access from Internet",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("CIS 7.3: All %d NSGs properly restrict UDP access from internet", totalNSGs),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("NSG_RULES"),
		})
	}

	return results
}

func (c *NetworkChecks) CheckHTTPAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListAllPager(nil)

	httpFromInternet := []string{}
	httpsFromInternet := []string{}
	totalNSGs := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, nsg := range page.Value {
			totalNSGs++

			if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
				for _, rule := range nsg.Properties.SecurityRules {
					if rule.Properties != nil &&
						rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound &&
						rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {

						if rule.Properties.SourceAddressPrefix != nil {
							source := *rule.Properties.SourceAddressPrefix
							if source == "*" || source == "0.0.0.0/0" || source == "Internet" {
								if rule.Properties.DestinationPortRange != nil {
									port := *rule.Properties.DestinationPortRange
									if port == "80" {
										httpFromInternet = append(httpFromInternet, *nsg.Name)
									} else if port == "443" {
										httpsFromInternet = append(httpsFromInternet, *nsg.Name)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(httpFromInternet) > 0 || len(httpsFromInternet) > 0 {
		evidence := []string{}
		if len(httpFromInternet) > 0 {
			evidence = append(evidence, fmt.Sprintf("%d HTTP (port 80)", len(httpFromInternet)))
		}
		if len(httpsFromInternet) > 0 {
			evidence = append(evidence, fmt.Sprintf("%d HTTPS (port 443)", len(httpsFromInternet)))
		}

		results = append(results, CheckResult{
			Control:     "CIS-7.4",
			Name:        "[CIS Azure 7.4] HTTP(S) Access from Internet",
			Status:      "INFO",
			Evidence:    fmt.Sprintf("CIS 7.4: Found NSG rules allowing HTTP(S) from internet: %s - Verify these are for web applications only", strings.Join(evidence, ", ")),
			Remediation: "Evaluate HTTP(S) exposure and use Application Gateway/Front Door for web apps",
			RemediationDetail: `CIS Azure 7.4: Ensure that HTTP(S) access from the Internet is evaluated and restricted

HTTP(S) internet exposure considerations:
- Port 80 (HTTP): Redirect to HTTPS, don't serve content unencrypted
- Port 443 (HTTPS): Acceptable for public web applications

Best practices:
1. Use Azure Application Gateway or Front Door for web apps (provides WAF)
2. Don't expose HTTP/HTTPS for non-web workloads
3. For web apps: Enforce HTTPS only, redirect HTTP to HTTPS
4. Consider using Azure CDN for public content

Document business justification for each HTTP/HTTPS rule.`,
			ScreenshotGuide: "NSG → Inbound security rules → Screenshot showing:\n- HTTP/HTTPS rules with documented justification\n- Application Gateway or Front Door deployment (preferred)\n- OR list of public web applications requiring internet access",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("NSG_RULES"),
		})
	}

	return results
}

func (c *NetworkChecks) CheckFlowLogRetention(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// NSG Flow Log retention requires Network Watcher API
	// This is marked as INFO for manual verification

	results = append(results, CheckResult{
		Control:     "CIS-7.5",
		Name:        "[CIS Azure 7.5] NSG Flow Log Retention",
		Status:      "INFO",
		Evidence:    "CIS 7.5: MANUAL CHECK - Verify NSG flow log retention period is greater than 90 days",
		Remediation: "Configure flow log retention >= 90 days",
		RemediationDetail: `CIS Azure 7.5: Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'

Requirements:
- NSG flow logs enabled for all NSGs
- Storage account retention >= 90 days
- Flow logs version 2 (includes more details)

Azure CLI:
az network watcher flow-log create \
  --location <region> \
  --name <flow-log-name> \
  --nsg <nsg-id> \
  --storage-account <storage-id> \
  --retention 90

Best practice: Use 365 days for compliance and incident investigation.`,
		ScreenshotGuide: "Network Watcher → NSG flow logs → Screenshot showing:\n- All NSGs with flow logs enabled\n- Retention days >= 90\n- Storage account configured",
		ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Network/NetworkWatcherMenuBlade/flowLogs",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("NSG_FLOW_LOGS"),
	})

	return results
}

func (c *NetworkChecks) CheckNetworkWatcher(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Network Watcher status requires separate API

	results = append(results, CheckResult{
		Control:     "CIS-7.6",
		Name:        "[CIS Azure 7.6] Network Watcher Enabled",
		Status:      "INFO",
		Evidence:    "CIS 7.6: MANUAL CHECK - Verify Network Watcher is enabled for Azure Regions that are in use",
		Remediation: "Enable Network Watcher in all active regions",
		RemediationDetail: `CIS Azure 7.6: Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use

Network Watcher provides network monitoring and diagnostic tools:
- NSG flow logs
- Connection monitor
- Network diagnostics
- Packet capture
- VPN troubleshooting

Enable in all regions:
Azure Portal → Network Watcher → Overview → Verify enabled in each region with resources

Azure CLI:
az network watcher configure \
  --locations <region> \
  --enabled true`,
		ScreenshotGuide: "Network Watcher → Overview → Screenshot showing enabled status in all regions containing Azure resources",
		ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Network/NetworkWatcherMenuBlade/overview",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("NETWORK_WATCHER"),
	})

	return results
}

func (c *NetworkChecks) CheckPublicIPs(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Public IP evaluation

	results = append(results, CheckResult{
		Control:     "CIS-7.7",
		Name:        "[CIS Azure 7.7] Public IP Address Evaluation",
		Status:      "INFO",
		Evidence:    "CIS 7.7: MANUAL CHECK - Ensure Public IP addresses are evaluated on a periodic basis",
		Remediation: "Review public IPs monthly and remove unused ones",
		RemediationDetail: `CIS Azure 7.7: Ensure that Public IP addresses are Evaluated on a Periodic Basis

Public IP addresses increase attack surface and incur costs.

Monthly review process:
1. List all public IPs: az network public-ip list
2. Identify unattached IPs
3. Verify business justification for each public IP
4. Remove unused public IPs
5. Document why each public IP is required

Azure CLI (list public IPs):
az network public-ip list --output table

Consider:
- Use Private Link instead of public IPs where possible
- Use NAT Gateway for outbound connectivity
- Use Application Gateway/Front Door for inbound web traffic`,
		ScreenshotGuide: "Public IP addresses → Screenshot showing:\n- List of all public IPs\n- Association status (attached/unattached)\n- Business justification documented for each\n- Removal of any unused IPs",
		ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FpublicIPAddresses",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("NSG_RULES"),
	})

	return results
}

func (c *NetworkChecks) CheckOpenPorts(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	pager := c.client.NewListAllPager(nil)

	openToInternet := []string{}
	totalNSGs := 0
	dangerousPorts := map[string]string{
		"22":   "SSH",
		"3389": "RDP",
		"1433": "SQL Server",
		"3306": "MySQL",
		"5432": "PostgreSQL",
		"445":  "SMB",
		"135":  "RPC",
		"21":   "FTP",
		"23":   "Telnet",
		"5985": "WinRM HTTP",
		"5986": "WinRM HTTPS",
	}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}

		for _, nsg := range page.Value {
			totalNSGs++
			nsgName := *nsg.Name

			if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
				for _, rule := range nsg.Properties.SecurityRules {
					if rule.Properties != nil {
						if rule.Properties.Direction != nil && *rule.Properties.Direction == armnetwork.SecurityRuleDirectionInbound {
							if rule.Properties.Access != nil && *rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {
								isInternet := false
								if rule.Properties.SourceAddressPrefix != nil {
									source := *rule.Properties.SourceAddressPrefix
									if source == "*" || source == "0.0.0.0/0" || source == "Internet" {
										isInternet = true
									}
								}

								if isInternet {
									if rule.Properties.DestinationPortRange != nil {
										port := *rule.Properties.DestinationPortRange
										if port == "*" {
											openToInternet = append(openToInternet, fmt.Sprintf("%s (ALL PORTS!)", nsgName))
										} else if serviceName, isDangerous := dangerousPorts[port]; isDangerous {
											openToInternet = append(openToInternet, fmt.Sprintf("%s (%s port %s)", nsgName, serviceName, port))
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(openToInternet) > 0 {
		displayNSGs := openToInternet
		if len(openToInternet) > 3 {
			displayNSGs = openToInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-6.1",
			Name:        "[CIS Azure 6.1-6.3] Dangerous Open Ports",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CIS 6.1-6.3: %d NSG rules expose dangerous ports to internet: %s", len(openToInternet), strings.Join(displayNSGs, ", ")),
			Remediation: "Remove internet access to management and database ports",
			RemediationDetail: `Multiple CIS Azure 6.x controls violated - dangerous ports exposed to internet.

Immediate action required:
1. Remove all rules allowing 0.0.0.0/0 access to management ports (SSH, RDP)
2. Remove internet access to database ports (SQL, MySQL, PostgreSQL)
3. Deploy Azure Bastion for secure VM access
4. Use Private Link for database connectivity

This is a critical security vulnerability enabling:
- Brute force attacks on management ports
- Direct database attacks
- Malware/ransomware deployment`,
			ScreenshotGuide: "NSG → Inbound rules → Screenshot showing all dangerous ports blocked from internet + Azure Bastion deployment",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FNetworkSecurityGroups",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("NSG_RULES"),
		})
	}

	return results
}
