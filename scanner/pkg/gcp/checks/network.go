package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"
)

// NetworkChecks handles GCP VPC and firewall security checks
type NetworkChecks struct {
	service   *compute.Service
	projectID string
}

// NewNetworkChecks creates a new network checker
func NewNetworkChecks(service *compute.Service, projectID string) *NetworkChecks {
	return &NetworkChecks{
		service:   service,
		projectID: projectID,
	}
}

// Run executes all network security checks
func (c *NetworkChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Existing checks
	results = append(results, c.CheckFirewallRules(ctx)...)
	results = append(results, c.CheckDefaultNetwork(ctx)...)
	results = append(results, c.CheckPrivateGoogleAccess(ctx)...)

	// NEW CIS checks
	results = append(results, c.CheckVPCFlowLogs(ctx)...)
	results = append(results, c.CheckDNSSEC(ctx)...)
	results = append(results, c.CheckLoadBalancerLogging(ctx)...)
	results = append(results, c.CheckLegacyNetworks(ctx)...)
	results = append(results, c.CheckSSHFromInternet(ctx)...)
	results = append(results, c.CheckRDPFromInternet(ctx)...)
	results = append(results, c.CheckHTTPSForwarding(ctx)...)
	results = append(results, c.CheckTLSVersions(ctx)...)

	return results, nil
}

// CheckFirewallRules checks for overly permissive firewall rules
func (c *NetworkChecks) CheckFirewallRules(ctx context.Context) []CheckResult {
	var results []CheckResult

	firewallList, err := c.service.Firewalls.List(c.projectID).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CC6.6",
			Name:        "VPC Firewall Rules Check",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Unable to check firewall rules: %v", err),
			Remediation: "Verify Compute Engine API is enabled and credentials have compute.firewalls.list permission",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
		return results
	}

	dangerousPorts := map[string]string{
		"22":    "SSH",
		"3389":  "RDP",
		"3306":  "MySQL",
		"5432":  "PostgreSQL",
		"1433":  "MSSQL",
		"27017": "MongoDB",
		"6379":  "Redis",
	}

	openToInternet := []string{}
	totalRules := len(firewallList.Items)

	for _, rule := range firewallList.Items {
		// Skip egress rules
		if rule.Direction == "EGRESS" {
			continue
		}

		// Check if rule allows traffic from 0.0.0.0/0
		isOpenToInternet := false
		for _, sourceRange := range rule.SourceRanges {
			if sourceRange == "0.0.0.0/0" {
				isOpenToInternet = true
				break
			}
		}

		if !isOpenToInternet {
			continue
		}

		// Check if rule allows dangerous ports
		for _, allowed := range rule.Allowed {
			if allowed.Ports == nil || len(allowed.Ports) == 0 {
				// No ports specified means all ports
				openToInternet = append(openToInternet, fmt.Sprintf("%s (ALL PORTS - %s)", rule.Name, allowed.IPProtocol))
				continue
			}

			for _, portRange := range allowed.Ports {
				for port, service := range dangerousPorts {
					if strings.Contains(portRange, port) || portRange == port {
						openToInternet = append(openToInternet, fmt.Sprintf("%s (%s on port %s)", rule.Name, service, port))
					}
				}
			}
		}
	}

	if len(openToInternet) > 0 {
		displayRules := openToInternet
		if len(openToInternet) > 3 {
			displayRules = openToInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.6",
			Name:        "VPC Firewall Rules - Open to Internet",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CRITICAL: %d firewall rules allow dangerous services from 0.0.0.0/0: %s | Violates PCI DSS 1.2.1, 1.3.1", len(openToInternet), strings.Join(displayRules, ", ")),
			Remediation: "Restrict firewall rules to specific IP ranges",
			RemediationDetail: fmt.Sprintf(`# Delete overly permissive rule
gcloud compute firewall-rules delete %s

# Create restricted rule
gcloud compute firewall-rules create restricted-ssh \
  --network=default \
  --allow=tcp:22 \
  --source-ranges=YOUR_OFFICE_IP/32 \
  --description="SSH access from office only"`, strings.Split(openToInternet[0], " ")[0]),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: fmt.Sprintf("Google Cloud Console → VPC Network → Firewall → Screenshot of %s showing source IP ranges", strings.Split(openToInternet[0], " ")[0]),
			ConsoleURL:      "https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/list",
			Frameworks:      GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
	} else if totalRules > 0 {
		results = append(results, CheckResult{
			Control:    "CC6.6",
			Name:       "VPC Firewall Rules - Open to Internet",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d firewall rules have appropriate source restrictions | Meets SOC2 CC6.6, PCI DSS 1.2.1", totalRules),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CC6.6",
			Name:       "VPC Firewall Rules Check",
			Status:     "INFO",
			Evidence:   "No firewall rules found in project",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
	}

	return results
}

// CheckDefaultNetwork checks if default network is still in use
func (c *NetworkChecks) CheckDefaultNetwork(ctx context.Context) []CheckResult {
	var results []CheckResult

	networkList, err := c.service.Networks.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	hasDefaultNetwork := false
	instancesInDefault := 0

	for _, network := range networkList.Items {
		if network.Name == "default" {
			hasDefaultNetwork = true

			// Check how many instances use default network
			zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
			if err != nil {
				continue
			}

			for _, zone := range zones.Items {
				instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
				if err != nil {
					continue
				}

				for _, instance := range instances.Items {
					for _, networkInterface := range instance.NetworkInterfaces {
						if strings.Contains(networkInterface.Network, "/default") {
							instancesInDefault++
						}
					}
				}
			}
			break
		}
	}

	if hasDefaultNetwork && instancesInDefault > 0 {
		results = append(results, CheckResult{
			Control:     "CIS-3.1",
			Name:        "[CIS GCP 3.1] Default VPC Network Deleted",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("%d instances using default VPC network | Violates CIS GCP 3.1 (default networks have overly permissive firewall rules)", instancesInDefault),
			Remediation: "Delete the default VPC network and migrate to custom VPC",
			RemediationDetail: fmt.Sprintf(`# WARNING: This is a destructive operation!
# Ensure no resources are using the default VPC before deletion

# Step 1: List resources in default VPC
gcloud compute instances list --filter="networkInterfaces.network:default" --project=%s
gcloud compute forwarding-rules list --filter="network:default" --project=%s

# Step 2: Create custom VPC (example)
gcloud compute networks create custom-vpc --subnet-mode=custom --project=%s

# Create custom subnets
gcloud compute networks subnets create custom-subnet-us-central1 \
  --network=custom-vpc \
  --range=10.0.0.0/24 \
  --region=us-central1 \
  --project=%s

# Step 3: Migrate instances to custom VPC (requires recreating instances)
# Step 4: Delete default VPC firewall rules first
gcloud compute firewall-rules delete default-allow-icmp --quiet --project=%s
gcloud compute firewall-rules delete default-allow-internal --quiet --project=%s
gcloud compute firewall-rules delete default-allow-rdp --quiet --project=%s
gcloud compute firewall-rules delete default-allow-ssh --quiet --project=%s

# Step 5: Delete default VPC
gcloud compute networks delete default --quiet --project=%s`, c.projectID, c.projectID, c.projectID, c.projectID, c.projectID, c.projectID, c.projectID, c.projectID, c.projectID),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: fmt.Sprintf("VPC Console → https://console.cloud.google.com/networking/networks/list?project=%s → Screenshot showing 'default' network exists with instances", c.projectID),
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/networking/networks/list?project=%s", c.projectID),
			Frameworks:      GetFrameworkMappings("VPC_DEFAULT_NETWORK"),
		})
	} else if hasDefaultNetwork && instancesInDefault == 0 {
		results = append(results, CheckResult{
			Control:     "CIS-3.1",
			Name:        "[CIS GCP 3.1] Default VPC Network Deleted",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    "Default VPC network still exists (no instances using it) | Violates CIS GCP 3.1",
			Remediation: "Delete the default VPC network",
			RemediationDetail: fmt.Sprintf(`# Delete default VPC firewall rules first
gcloud compute firewall-rules delete default-allow-icmp --quiet --project=%s
gcloud compute firewall-rules delete default-allow-internal --quiet --project=%s
gcloud compute firewall-rules delete default-allow-rdp --quiet --project=%s
gcloud compute firewall-rules delete default-allow-ssh --quiet --project=%s

# Delete default VPC
gcloud compute networks delete default --quiet --project=%s`, c.projectID, c.projectID, c.projectID, c.projectID, c.projectID),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: fmt.Sprintf("VPC Console → https://console.cloud.google.com/networking/networks/list?project=%s → Screenshot showing 'default' network exists", c.projectID),
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/networking/networks/list?project=%s", c.projectID),
			Frameworks:      GetFrameworkMappings("VPC_DEFAULT_NETWORK"),
		})
	} else if !hasDefaultNetwork {
		results = append(results, CheckResult{
			Control:    "CIS-3.1",
			Name:       "[CIS GCP 3.1] Default VPC Network Deleted",
			Status:     "PASS",
			Evidence:   "Default VPC network has been deleted | Meets CIS GCP 3.1 (network isolation and custom firewall rules)",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("VPC_DEFAULT_NETWORK"),
		})
	}

	return results
}

// CheckPrivateGoogleAccess verifies Private Google Access is enabled
func (c *NetworkChecks) CheckPrivateGoogleAccess(ctx context.Context) []CheckResult {
	var results []CheckResult

	regions, err := c.service.Regions.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	subnetsWithoutPGA := []string{}
	totalSubnets := 0

	for _, region := range regions.Items {
		subnetList, err := c.service.Subnetworks.List(c.projectID, region.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, subnet := range subnetList.Items {
			totalSubnets++

			if !subnet.PrivateIpGoogleAccess {
				subnetsWithoutPGA = append(subnetsWithoutPGA, subnet.Name)
			}
		}
	}

	if len(subnetsWithoutPGA) > 0 {
		displaySubnets := subnetsWithoutPGA
		if len(subnetsWithoutPGA) > 3 {
			displaySubnets = subnetsWithoutPGA[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Private Google Access",
			Status:      "INFO",
			Severity:    "LOW",
			Evidence:    fmt.Sprintf("%d subnets do not have Private Google Access enabled: %s", len(subnetsWithoutPGA), strings.Join(displaySubnets, ", ")),
			Remediation: "Enable Private Google Access for secure communication with Google APIs",
			RemediationDetail: fmt.Sprintf(`gcloud compute networks subnets update %s \
  --region=REGION \
  --enable-private-ip-google-access`, subnetsWithoutPGA[0]),
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "VPC Network → VPC networks → Subnets → Screenshot showing 'Private Google access: On'",
			ConsoleURL:      "https://console.cloud.google.com/networking/networks/list",
			Frameworks:      GetFrameworkMappings("VPC_PRIVATE_GOOGLE_ACCESS"),
		})
	} else if totalSubnets > 0 {
		results = append(results, CheckResult{
			Control:    "CC6.1",
			Name:       "Private Google Access",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d subnets have Private Google Access enabled | Meets SOC2 CC6.1", totalSubnets),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("VPC_PRIVATE_GOOGLE_ACCESS"),
		})
	}

	return results
}

// NEW CIS CHECKS BELOW

// CheckVPCFlowLogs verifies VPC Flow Logs are enabled (CIS 3.9)
func (c *NetworkChecks) CheckVPCFlowLogs(ctx context.Context) []CheckResult {
	var results []CheckResult

	regions, err := c.service.Regions.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	subnetsWithoutFlowLogs := []string{}
	totalSubnets := 0

	for _, region := range regions.Items {
		subnetList, err := c.service.Subnetworks.List(c.projectID, region.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, subnet := range subnetList.Items {
			totalSubnets++

			// Check if flow logs are enabled
			if !subnet.EnableFlowLogs {
				subnetsWithoutFlowLogs = append(subnetsWithoutFlowLogs, fmt.Sprintf("%s (region: %s)", subnet.Name, region.Name))
			}
		}
	}

	if len(subnetsWithoutFlowLogs) > 0 {
		displaySubnets := subnetsWithoutFlowLogs
		if len(subnetsWithoutFlowLogs) > 3 {
			displaySubnets = subnetsWithoutFlowLogs[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 3.9",
			Name:        "[CIS GCP 3.9] VPC Flow Logs",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 3.9: %d subnets do not have VPC Flow Logs enabled: %s | Required for network monitoring and incident response", len(subnetsWithoutFlowLogs), strings.Join(displaySubnets, ", ")),
			Remediation: "Enable VPC Flow Logs on all subnets for network traffic visibility",
			RemediationDetail: fmt.Sprintf(`gcloud compute networks subnets update %s \
  --region=REGION \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=0.5 \
  --logging-metadata=include-all`, strings.Split(subnetsWithoutFlowLogs[0], " ")[0]),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "VPC Network → Subnets → Flow logs column showing 'On' for all subnets",
			ConsoleURL:      "https://console.cloud.google.com/networking/networks/list",
			Frameworks:      GetFrameworkMappings("VPC_FLOW_LOGS"),
		})
	} else if totalSubnets > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 3.9",
			Name:       "[CIS GCP 3.9] VPC Flow Logs",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d subnets have VPC Flow Logs enabled | Meets CIS 3.9", totalSubnets),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("VPC_FLOW_LOGS"),
		})
	}

	return results
}

// CheckDNSSEC checks if DNSSEC is enabled (CIS 3.3)
func (c *NetworkChecks) CheckDNSSEC(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Cloud DNS DNSSEC requires DNS API which isn't in compute service
	results = append(results, CheckResult{
		Control:           "CIS GCP 3.3",
		Name:              "[CIS GCP 3.3] DNSSEC on Cloud DNS",
		Status:            "MANUAL",
		Severity:          "MEDIUM",
		Evidence:          "MANUAL CHECK: Verify DNSSEC is enabled on Cloud DNS managed zones",
		Remediation:       "Enable DNSSEC for DNS security",
		RemediationDetail: `gcloud dns managed-zones update ZONE_NAME --dnssec-state=on`,
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		ScreenshotGuide:   "Network Services → Cloud DNS → DNSSEC column showing 'On'",
		ConsoleURL:        "https://console.cloud.google.com/net-services/dns/zones",
		Frameworks:        GetFrameworkMappings("DNSSEC_ENABLED"),
	})

	return results
}

// CheckLoadBalancerLogging checks if load balancer logging is enabled (CIS 3.10)
func (c *NetworkChecks) CheckLoadBalancerLogging(ctx context.Context) []CheckResult {
	var results []CheckResult

	results = append(results, CheckResult{
		Control:     "CIS GCP 3.10",
		Name:        "[CIS GCP 3.10] Load Balancer Logging",
		Status:      "MANUAL",
		Severity:    "MEDIUM",
		Evidence:    "MANUAL CHECK: Verify HTTP(S) load balancers have request logging enabled",
		Remediation: "Enable logging on all load balancers for traffic analysis",
		RemediationDetail: `# Enable logging on backend service
gcloud compute backend-services update BACKEND_SERVICE \
  --global \
  --enable-logging \
  --logging-sample-rate=1.0`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Network Services → Load balancing → Backend configuration → Logging enabled",
		ConsoleURL:      "https://console.cloud.google.com/net-services/loadbalancing/list",
		Frameworks:      GetFrameworkMappings("LOAD_BALANCER_LOGGING"),
	})

	return results
}

// CheckLegacyNetworks checks if legacy networks exist (CIS 3.2)
func (c *NetworkChecks) CheckLegacyNetworks(ctx context.Context) []CheckResult {
	var results []CheckResult

	networkList, err := c.service.Networks.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	legacyNetworks := []string{}

	for _, network := range networkList.Items {
		// Legacy networks have IPv4Range set (not using subnets)
		// Custom/auto mode networks have AutoCreateSubnetworks field and no IPv4Range
		if network.IPv4Range != "" {
			legacyNetworks = append(legacyNetworks, network.Name)
		}
	}

	if len(legacyNetworks) > 0 {
		results = append(results, CheckResult{
			Control:     "CIS GCP 3.2",
			Name:        "[CIS GCP 3.2] Legacy Networks",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d legacy networks found: %s | Violates CIS GCP 3.2 (legacy networks lack modern features)", len(legacyNetworks), strings.Join(legacyNetworks, ", ")),
			Remediation: "Migrate from legacy networks to subnet-mode (auto or custom) networks",
			RemediationDetail: fmt.Sprintf(`# Legacy networks cannot be converted - must migrate
# Step 1: Create new subnet-mode network
gcloud compute networks create new-vpc --subnet-mode=custom --project=%s

# Step 2: Create subnets
gcloud compute networks subnets create subnet-us-central1 \
  --network=new-vpc \
  --range=10.0.0.0/24 \
  --region=us-central1 \
  --project=%s

# Step 3: Migrate resources to new network (requires recreating instances)
# Step 4: Delete legacy network
gcloud compute networks delete %s --project=%s`, c.projectID, c.projectID, legacyNetworks[0], c.projectID),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "VPC Network → Screenshot showing all networks in 'Subnet creation mode: Auto' or 'Custom'",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/networking/networks/list?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "3.2", "SOC2": "CC6.1"},
		})
	} else if len(networkList.Items) > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 3.2",
			Name:       "[CIS GCP 3.2] Legacy Networks",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d networks are subnet-mode (no legacy networks) | Meets CIS GCP 3.2", len(networkList.Items)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "3.2", "SOC2": "CC6.1"},
		})
	}

	return results
}

// CheckSSHFromInternet checks if SSH is restricted from internet (CIS 3.4)
func (c *NetworkChecks) CheckSSHFromInternet(ctx context.Context) []CheckResult {
	var results []CheckResult

	firewallList, err := c.service.Firewalls.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	sshRulesFromInternet := []string{}

	for _, rule := range firewallList.Items {
		// Skip egress rules
		if rule.Direction == "EGRESS" {
			continue
		}

		// Check if rule allows traffic from 0.0.0.0/0
		isOpenToInternet := false
		for _, sourceRange := range rule.SourceRanges {
			if sourceRange == "0.0.0.0/0" {
				isOpenToInternet = true
				break
			}
		}

		if !isOpenToInternet {
			continue
		}

		// Check if rule allows SSH (port 22)
		for _, allowed := range rule.Allowed {
			if allowed.IPProtocol == "tcp" {
				if allowed.Ports == nil || len(allowed.Ports) == 0 {
					// All ports allowed
					sshRulesFromInternet = append(sshRulesFromInternet, fmt.Sprintf("%s (all ports)", rule.Name))
				} else {
					for _, portRange := range allowed.Ports {
						if portRange == "22" || strings.Contains(portRange, "22") {
							sshRulesFromInternet = append(sshRulesFromInternet, rule.Name)
							break
						}
					}
				}
			}
		}
	}

	if len(sshRulesFromInternet) > 0 {
		displayRules := sshRulesFromInternet
		if len(sshRulesFromInternet) > 3 {
			displayRules = sshRulesFromInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 3.4",
			Name:        "[CIS GCP 3.4] SSH Access from Internet",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CRITICAL: %d firewall rules allow SSH (port 22) from 0.0.0.0/0: %s | Violates CIS GCP 3.4", len(sshRulesFromInternet), strings.Join(displayRules, ", ")),
			Remediation: fmt.Sprintf("Remove or restrict firewall rule: %s", sshRulesFromInternet[0]),
			RemediationDetail: fmt.Sprintf(`# Option 1: Delete the overly permissive rule
gcloud compute firewall-rules delete %s --project=%s

# Option 2: Update to restrict source IP ranges
gcloud compute firewall-rules update %s \
  --source-ranges=YOUR_OFFICE_IP/32,YOUR_VPN_IP/32 \
  --project=%s

# Best practice: Use Cloud IAP for SSH instead
gcloud compute firewall-rules create allow-ssh-iap \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 \
  --project=%s`, sshRulesFromInternet[0], c.projectID, sshRulesFromInternet[0], c.projectID, c.projectID),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: fmt.Sprintf("VPC Network → Firewall → Screenshot showing %s with restricted source ranges (NOT 0.0.0.0/0)", sshRulesFromInternet[0]),
			ConsoleURL:      "https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/list",
			Frameworks:      map[string]string{"CIS-GCP": "3.4", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 3.4",
			Name:       "[CIS GCP 3.4] SSH Access from Internet",
			Status:     "PASS",
			Evidence:   "SSH access (port 22) is not allowed from 0.0.0.0/0 | Meets CIS GCP 3.4",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "3.4", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
		})
	}

	return results
}

// CheckRDPFromInternet checks if RDP is restricted from internet (CIS 3.5)
func (c *NetworkChecks) CheckRDPFromInternet(ctx context.Context) []CheckResult {
	var results []CheckResult

	firewallList, err := c.service.Firewalls.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	rdpRulesFromInternet := []string{}

	for _, rule := range firewallList.Items {
		// Skip egress rules
		if rule.Direction == "EGRESS" {
			continue
		}

		// Check if rule allows traffic from 0.0.0.0/0
		isOpenToInternet := false
		for _, sourceRange := range rule.SourceRanges {
			if sourceRange == "0.0.0.0/0" {
				isOpenToInternet = true
				break
			}
		}

		if !isOpenToInternet {
			continue
		}

		// Check if rule allows RDP (port 3389)
		for _, allowed := range rule.Allowed {
			if allowed.IPProtocol == "tcp" {
				if allowed.Ports == nil || len(allowed.Ports) == 0 {
					// All ports allowed
					rdpRulesFromInternet = append(rdpRulesFromInternet, fmt.Sprintf("%s (all ports)", rule.Name))
				} else {
					for _, portRange := range allowed.Ports {
						if portRange == "3389" || strings.Contains(portRange, "3389") {
							rdpRulesFromInternet = append(rdpRulesFromInternet, rule.Name)
							break
						}
					}
				}
			}
		}
	}

	if len(rdpRulesFromInternet) > 0 {
		displayRules := rdpRulesFromInternet
		if len(rdpRulesFromInternet) > 3 {
			displayRules = rdpRulesFromInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 3.5",
			Name:        "[CIS GCP 3.5] RDP Access from Internet",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CRITICAL: %d firewall rules allow RDP (port 3389) from 0.0.0.0/0: %s | Violates CIS GCP 3.5", len(rdpRulesFromInternet), strings.Join(displayRules, ", ")),
			Remediation: fmt.Sprintf("Remove or restrict firewall rule: %s", rdpRulesFromInternet[0]),
			RemediationDetail: fmt.Sprintf(`# Option 1: Delete the overly permissive rule
gcloud compute firewall-rules delete %s --project=%s

# Option 2: Update to restrict source IP ranges
gcloud compute firewall-rules update %s \
  --source-ranges=YOUR_OFFICE_IP/32,YOUR_VPN_IP/32 \
  --project=%s

# Best practice: Use Cloud IAP for RDP instead
gcloud compute firewall-rules create allow-rdp-iap \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:3389 \
  --source-ranges=35.235.240.0/20 \
  --project=%s`, rdpRulesFromInternet[0], c.projectID, rdpRulesFromInternet[0], c.projectID, c.projectID),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: fmt.Sprintf("VPC Network → Firewall → Screenshot showing %s with restricted source ranges (NOT 0.0.0.0/0)", rdpRulesFromInternet[0]),
			ConsoleURL:      "https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/list",
			Frameworks:      map[string]string{"CIS-GCP": "3.5", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 3.5",
			Name:       "[CIS GCP 3.5] RDP Access from Internet",
			Status:     "PASS",
			Evidence:   "RDP access (port 3389) is not allowed from 0.0.0.0/0 | Meets CIS GCP 3.5",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "3.5", "SOC2": "CC6.6", "PCI-DSS": "1.3.1"},
		})
	}

	return results
}

// CheckHTTPSForwarding verifies that load balancers use HTTPS instead of HTTP (CIS 3.6)
func (c *NetworkChecks) CheckHTTPSForwarding(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Check URL Maps for HTTP to HTTPS redirects
	urlMaps, err := c.service.UrlMaps.List(c.projectID).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CIS GCP 3.6",
			Name:        "[CIS GCP 3.6] HTTPS Load Balancer Configuration",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Unable to check URL maps: %v", err),
			Remediation: "Verify Compute Engine API is enabled and permissions are correct",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("HTTPS_FORWARDING"),
		})
		return results
	}

	if len(urlMaps.Items) == 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 3.6",
			Name:       "[CIS GCP 3.6] HTTPS Load Balancer Configuration",
			Status:     "PASS",
			Evidence:   "No URL maps configured (no HTTP load balancers to check)",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("HTTPS_FORWARDING"),
		})
		return results
	}

	// This is a manual check because detailed URL map rules inspection
	// requires analyzing redirects and backend service configurations
	results = append(results, CheckResult{
		Control:     "CIS GCP 3.6",
		Name:        "[CIS GCP 3.6] HTTPS Load Balancer Configuration",
		Status:      "INFO",
		Severity:    "HIGH",
		Evidence:    fmt.Sprintf("%d URL maps found | Requires manual verification that all HTTP traffic is redirected to HTTPS", len(urlMaps.Items)),
		Remediation: "Configure HTTP to HTTPS redirects on all load balancers",
		RemediationDetail: `# Create URL map with HTTPS redirect
gcloud compute url-maps create https-redirect \
    --default-service=BACKEND_SERVICE

# Add HTTP to HTTPS redirect
gcloud compute url-maps add-path-matcher https-redirect \
    --path-matcher-name=redirect \
    --default-url-redirect-https

# Update target HTTP proxy to use redirect URL map
gcloud compute target-http-proxies update HTTP_PROXY_NAME \
    --url-map=https-redirect`,
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Google Cloud Console → Network services → Load balancing → Select load balancer → Frontend configuration → Screenshot showing HTTPS protocol and HTTP→HTTPS redirect",
		ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/net-services/loadbalancing/list/loadBalancers?project=%s", c.projectID),
		Frameworks:      GetFrameworkMappings("HTTPS_FORWARDING"),
	})

	return results
}

// CheckTLSVersions verifies that SSL policies enforce modern TLS versions (CIS 3.7)
func (c *NetworkChecks) CheckTLSVersions(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Check SSL policies
	sslPolicies, err := c.service.SslPolicies.List(c.projectID).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CIS GCP 3.7",
			Name:        "[CIS GCP 3.7] SSL Policy TLS Version",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Unable to check SSL policies: %v", err),
			Remediation: "Verify Compute Engine API is enabled and permissions are correct",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("TLS_VERSION"),
		})
		return results
	}

	if len(sslPolicies.Items) == 0 {
		results = append(results, CheckResult{
			Control:     "CIS GCP 3.7",
			Name:        "[CIS GCP 3.7] SSL Policy TLS Version",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    "No SSL policies configured | Load balancers may be using default TLS settings which could allow older, insecure TLS versions",
			Remediation: "Create SSL policy with minimum TLS 1.2",
			RemediationDetail: `# Create SSL policy with TLS 1.2 minimum
gcloud compute ssl-policies create modern-tls \
    --profile=MODERN \
    --min-tls-version=1.2

# Apply to target HTTPS proxy
gcloud compute target-https-proxies update HTTPS_PROXY_NAME \
    --ssl-policy=modern-tls

# Or use RESTRICTED profile for TLS 1.3
gcloud compute ssl-policies create restricted-tls \
    --profile=RESTRICTED \
    --min-tls-version=1.3`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → Network security → SSL policies → Screenshot showing policy with TLS 1.2+ minimum",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/net-security/sslpolicies/list?project=%s", c.projectID),
			Frameworks:      GetFrameworkMappings("TLS_VERSION"),
		})
		return results
	}

	// Check each SSL policy
	weakPolicies := []string{}
	for _, policy := range sslPolicies.Items {
		// Check minimum TLS version (should be TLS 1.2 or higher)
		if policy.MinTlsVersion == "TLS_1_0" || policy.MinTlsVersion == "TLS_1_1" {
			weakPolicies = append(weakPolicies, fmt.Sprintf("%s (min: %s)", policy.Name, policy.MinTlsVersion))
		}
	}

	if len(weakPolicies) > 0 {
		results = append(results, CheckResult{
			Control:     "CIS GCP 3.7",
			Name:        "[CIS GCP 3.7] SSL Policy TLS Version",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d SSL policies allow weak TLS versions: %s | Violates CIS GCP 3.7 (TLS 1.0/1.1 have known vulnerabilities)", len(weakPolicies), strings.Join(weakPolicies, ", ")),
			Remediation: "Update SSL policies to enforce TLS 1.2 or higher",
			RemediationDetail: fmt.Sprintf(`# Update SSL policy to TLS 1.2 minimum
gcloud compute ssl-policies update %s \
    --min-tls-version=1.2

# Recommended: Use MODERN or RESTRICTED profile
gcloud compute ssl-policies update %s \
    --profile=MODERN \
    --min-tls-version=1.2`, weakPolicies[0], weakPolicies[0]),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → Network security → SSL policies → Select policy → Screenshot showing TLS 1.2+ minimum version",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/net-security/sslpolicies/details/%s?project=%s", sslPolicies.Items[0].Name, c.projectID),
			Frameworks:      GetFrameworkMappings("TLS_VERSION"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 3.7",
			Name:       "[CIS GCP 3.7] SSL Policy TLS Version",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d SSL policies enforce TLS 1.2 or higher | Meets CIS GCP 3.7", len(sslPolicies.Items)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("TLS_VERSION"),
		})
	}

	return results
}
