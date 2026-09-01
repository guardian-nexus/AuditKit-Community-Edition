package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
)

type NetworkFirewallChecks struct {
	nfwClient *networkfirewall.Client
	ec2Client *ec2.Client
}

func NewNetworkFirewallChecks(nfwClient *networkfirewall.Client, ec2Client *ec2.Client) *NetworkFirewallChecks {
	return &NetworkFirewallChecks{
		nfwClient: nfwClient,
		ec2Client: ec2Client,
	}
}

func (c *NetworkFirewallChecks) Name() string {
	return "Network Firewall Configuration"
}

func (c *NetworkFirewallChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 5 - Network Firewall controls (5.15-5.17)
	if result, err := c.CheckNetworkFirewallSubnetPlacement(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckNetworkFirewallPolicyRules(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckNetworkFirewallLogging(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CIS 5.15 - Ensure Network Firewall is deployed in each AZ
func (c *NetworkFirewallChecks) CheckNetworkFirewallSubnetPlacement(ctx context.Context) (CheckResult, error) {
	// List all firewalls
	firewalls, err := c.nfwClient.ListFirewalls(ctx, &networkfirewall.ListFirewallsInput{})
	if err != nil {
		return CheckResult{
			Control:    "[CIS-5.15]",
			Name:       "Network Firewall AZ Deployment",
			Status:     "PASS",
			Evidence:   "No Network Firewalls deployed | CIS 5.15 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.15"},
		}, nil
	}

	if len(firewalls.Firewalls) == 0 {
		return CheckResult{
			Control:    "[CIS-5.15]",
			Name:       "Network Firewall AZ Deployment",
			Status:     "INFO",
			Evidence:   "No Network Firewalls deployed | Consider deploying for enhanced network security",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.15"},
		}, nil
	}

	firewallsWithMissingAZs := []string{}

	for _, fw := range firewalls.Firewalls {
		// Get firewall details
		fwDetails, err := c.nfwClient.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{
			FirewallArn: fw.FirewallArn,
		})
		if err != nil {
			continue
		}

		// Get VPC details to check available AZs
		if fwDetails.Firewall.VpcId != nil {
			vpcId := *fwDetails.Firewall.VpcId

			// List subnets in the VPC
			subnets, err := c.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
				Filters: []ec2types.Filter{
					{
						Name:   stringPtr("vpc-id"),
						Values: []string{vpcId},
					},
				},
			})
			if err != nil {
				continue
			}

			// Get unique AZs in VPC
			vpcAZs := make(map[string]bool)
			for _, subnet := range subnets.Subnets {
				if subnet.AvailabilityZone != nil {
					vpcAZs[*subnet.AvailabilityZone] = true
				}
			}

			// Get AZs where firewall is deployed
			fwAZs := make(map[string]bool)
			if fwDetails.Firewall.SubnetMappings != nil {
				for _, mapping := range fwDetails.Firewall.SubnetMappings {
					// Get subnet AZ
					subnetDetails, err := c.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
						SubnetIds: []string{*mapping.SubnetId},
					})
					if err == nil && len(subnetDetails.Subnets) > 0 {
						if subnetDetails.Subnets[0].AvailabilityZone != nil {
							fwAZs[*subnetDetails.Subnets[0].AvailabilityZone] = true
						}
					}
				}
			}

			// Check if firewall is in all VPC AZs
			if len(fwAZs) < len(vpcAZs) {
				firewallsWithMissingAZs = append(firewallsWithMissingAZs, *fw.FirewallName)
			}
		}
	}

	if len(firewallsWithMissingAZs) > 0 {
		return CheckResult{
			Control:     "[CIS-5.15]",
			Name:        "Network Firewall AZ Deployment",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d/%d firewalls not deployed in all AZs: %v | CIS 5.15", len(firewallsWithMissingAZs), len(firewalls.Firewalls), firewallsWithMissingAZs),
			Remediation: "Deploy Network Firewall in all availability zones",
			RemediationDetail: `# Update firewall subnet mappings to include all AZs:
aws network-firewall update-subnet-change-protection \
  --firewall-name FIREWALL_NAME \
  --subnet-change-protection ENABLED

aws network-firewall associate-subnets \
  --firewall-name FIREWALL_NAME \
  --subnet-mappings SubnetId=subnet-xxx`,
			ScreenshotGuide: "Network Firewall Console → Firewalls → Subnets → Screenshot showing subnet in each AZ",
			ConsoleURL:      "https://console.aws.amazon.com/vpc/home#NetworkFirewalls",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "5.15", "SOC2": "CC6.6"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.15]",
		Name:       "Network Firewall AZ Deployment",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Network Firewalls are deployed across all AZs | Meets CIS 5.15", len(firewalls.Firewalls)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "5.15"},
	}, nil
}

// CIS 5.16 - Ensure Network Firewall policy has stateful rule groups
func (c *NetworkFirewallChecks) CheckNetworkFirewallPolicyRules(ctx context.Context) (CheckResult, error) {
	// List all firewall policies
	policies, err := c.nfwClient.ListFirewallPolicies(ctx, &networkfirewall.ListFirewallPoliciesInput{})
	if err != nil {
		return CheckResult{
			Control:    "[CIS-5.16]",
			Name:       "Network Firewall Policy Rules",
			Status:     "PASS",
			Evidence:   "No Network Firewall policies found | CIS 5.16 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.16"},
		}, nil
	}

	if len(policies.FirewallPolicies) == 0 {
		return CheckResult{
			Control:    "[CIS-5.16]",
			Name:       "Network Firewall Policy Rules",
			Status:     "INFO",
			Evidence:   "No Network Firewall policies found | Consider creating firewall policies",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.16"},
		}, nil
	}

	policiesWithoutRules := []string{}

	for _, policy := range policies.FirewallPolicies {
		// Get policy details
		policyDetails, err := c.nfwClient.DescribeFirewallPolicy(ctx, &networkfirewall.DescribeFirewallPolicyInput{
			FirewallPolicyArn: policy.Arn,
		})
		if err != nil {
			continue
		}

		hasStatefulRules := false

		if policyDetails.FirewallPolicy != nil {
			// Check for stateful rule groups
			if policyDetails.FirewallPolicy.StatefulRuleGroupReferences != nil &&
				len(policyDetails.FirewallPolicy.StatefulRuleGroupReferences) > 0 {
				hasStatefulRules = true
			}
		}

		// Policy should have at least stateful rules for proper inspection
		if !hasStatefulRules {
			policiesWithoutRules = append(policiesWithoutRules, *policy.Name)
		}
	}

	if len(policiesWithoutRules) > 0 {
		displayPolicies := policiesWithoutRules
		if len(policiesWithoutRules) > 5 {
			displayPolicies = policiesWithoutRules[:5]
		}

		return CheckResult{
			Control:     "[CIS-5.16]",
			Name:        "Network Firewall Policy Rules",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d policies without stateful rule groups: %v | CIS 5.16", len(policiesWithoutRules), len(policies.FirewallPolicies), displayPolicies),
			Remediation: "Add stateful rule groups to Network Firewall policies",
			RemediationDetail: `# Create a stateful rule group:
aws network-firewall create-rule-group \
  --rule-group-name my-stateful-rules \
  --type STATEFUL \
  --rules-source '{"rulesSourceList":{"targetTypes":["HTTP_HOST"],"targets":["example.com"],"generatedRulesType":"DENYLIST"}}'

# Associate with policy:
aws network-firewall update-firewall-policy \
  --firewall-policy-name POLICY_NAME \
  --firewall-policy StatefulRuleGroupReferences='[{"ResourceArn":"arn:aws:network-firewall:..."}]'`,
			ScreenshotGuide: "Network Firewall Console → Firewall policies → Rule groups → Screenshot showing stateful rules",
			ConsoleURL:      "https://console.aws.amazon.com/vpc/home#FirewallPolicies",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "5.16", "SOC2": "CC6.1", "PCI-DSS": "1.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.16]",
		Name:       "Network Firewall Policy Rules",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Network Firewall policies have stateful rule groups | Meets CIS 5.16", len(policies.FirewallPolicies)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "5.16"},
	}, nil
}

// CIS 5.17 - Ensure Network Firewall logging is enabled
func (c *NetworkFirewallChecks) CheckNetworkFirewallLogging(ctx context.Context) (CheckResult, error) {
	// List all firewalls
	firewalls, err := c.nfwClient.ListFirewalls(ctx, &networkfirewall.ListFirewallsInput{})
	if err != nil {
		return CheckResult{
			Control:    "[CIS-5.17]",
			Name:       "Network Firewall Logging",
			Status:     "PASS",
			Evidence:   "No Network Firewalls found | CIS 5.17 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.17"},
		}, nil
	}

	if len(firewalls.Firewalls) == 0 {
		return CheckResult{
			Control:    "[CIS-5.17]",
			Name:       "Network Firewall Logging",
			Status:     "INFO",
			Evidence:   "No Network Firewalls deployed | CIS 5.17 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.17"},
		}, nil
	}

	firewallsWithoutLogging := []string{}

	for _, fw := range firewalls.Firewalls {
		// Describe logging configuration
		loggingConfig, err := c.nfwClient.DescribeLoggingConfiguration(ctx, &networkfirewall.DescribeLoggingConfigurationInput{
			FirewallArn: fw.FirewallArn,
		})
		if err != nil {
			// If error, likely no logging configured
			firewallsWithoutLogging = append(firewallsWithoutLogging, *fw.FirewallName)
			continue
		}

		hasLogging := false
		if loggingConfig.LoggingConfiguration != nil &&
			loggingConfig.LoggingConfiguration.LogDestinationConfigs != nil &&
			len(loggingConfig.LoggingConfiguration.LogDestinationConfigs) > 0 {
			hasLogging = true
		}

		if !hasLogging {
			firewallsWithoutLogging = append(firewallsWithoutLogging, *fw.FirewallName)
		}
	}

	if len(firewallsWithoutLogging) > 0 {
		displayFirewalls := firewallsWithoutLogging
		if len(firewallsWithoutLogging) > 5 {
			displayFirewalls = firewallsWithoutLogging[:5]
		}

		return CheckResult{
			Control:     "[CIS-5.17]",
			Name:        "Network Firewall Logging",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d firewalls without logging enabled: %v | CIS 5.17", len(firewallsWithoutLogging), len(firewalls.Firewalls), displayFirewalls),
			Remediation: "Enable logging for Network Firewalls",
			RemediationDetail: `# Configure logging to CloudWatch:
aws network-firewall update-logging-configuration \
  --firewall-name FIREWALL_NAME \
  --logging-configuration '{
    "LogDestinationConfigs": [{
      "LogType": "ALERT",
      "LogDestinationType": "CloudWatchLogs",
      "LogDestination": {"logGroup": "/aws/networkfirewall/alerts"}
    },
    {
      "LogType": "FLOW",
      "LogDestinationType": "CloudWatchLogs",
      "LogDestination": {"logGroup": "/aws/networkfirewall/flow"}
    }]
  }'`,
			ScreenshotGuide: "Network Firewall Console → Firewalls → Logging → Screenshot showing logging enabled",
			ConsoleURL:      "https://console.aws.amazon.com/vpc/home#NetworkFirewalls",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "5.17", "SOC2": "CC7.2", "PCI-DSS": "10.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.17]",
		Name:       "Network Firewall Logging",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Network Firewalls have logging enabled | Meets CIS 5.17", len(firewalls.Firewalls)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "5.17"},
	}, nil
}

func stringPtr(s string) *string {
	return &s
}
