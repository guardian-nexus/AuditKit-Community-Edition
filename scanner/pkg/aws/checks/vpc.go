package checks

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"time"
)

type VPCChecks struct {
	client *ec2.Client
}

func NewVPCChecks(client *ec2.Client) *VPCChecks {
	return &VPCChecks{client: client}
}

func (c *VPCChecks) Name() string {
	return "VPC Network Security"
}

func (c *VPCChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Existing check
	if result, err := c.CheckVPCFlowLogs(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS checks
	if result, err := c.CheckDefaultVPC(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckVPCPeering(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 5.7-5.8: VPC Endpoints
	if result, err := c.CheckVPCEndpoints(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 5.9-5.12: NACL restrictions
	results = append(results, c.CheckNACLRestrictions(ctx)...)

	// CIS 5.13: Admin port security
	if result, err := c.CheckAdminPortSecurity(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 5.14: EC2 subnet placement
	if result, err := c.CheckEC2SubnetPlacement(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 5.18: Unused security groups
	if result, err := c.CheckUnusedSecurityGroups(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS controls - v0.7.0 additions
	results = append(results, c.CheckVPCPeeringRouting(ctx))
	results = append(results, c.CheckVPCEndpointsForS3(ctx))

	return results, nil
}

func (c *VPCChecks) CheckVPCFlowLogs(ctx context.Context) (CheckResult, error) {
	// Get all VPCs
	vpcs, err := c.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	// Get flow logs
	flowLogs, err := c.client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	// Map flow logs to VPCs
	vpcWithFlowLogs := make(map[string]bool)
	for _, flowLog := range flowLogs.FlowLogs {
		if flowLog.ResourceId != nil {
			vpcWithFlowLogs[*flowLog.ResourceId] = true
		}
	}

	// Check which VPCs don't have flow logs
	vpcsWithoutFlowLogs := []string{}
	for _, vpc := range vpcs.Vpcs {
		if !vpcWithFlowLogs[*vpc.VpcId] {
			vpcsWithoutFlowLogs = append(vpcsWithoutFlowLogs, *vpc.VpcId)
		}
	}

	if len(vpcsWithoutFlowLogs) > 0 {
		return CheckResult{
			Control:           "CIS-3.9, CC7.1",
			Name:              "VPC Flow Logs",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d VPCs don't have Flow Logs enabled: %v | Network traffic not audited | Violates CIS-3.9", len(vpcsWithoutFlowLogs), vpcsWithoutFlowLogs),
			Remediation:       "Enable VPC Flow Logs immediately",
			RemediationDetail: fmt.Sprintf("aws ec2 create-flow-logs --resource-type VPC --resource-ids %s --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs", vpcsWithoutFlowLogs[0]),
			ScreenshotGuide:   "VPC Console → Select VPC → Flow logs tab → Screenshot showing 'Active' flow logs",
			ConsoleURL:        "https://console.aws.amazon.com/vpc/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("VPC_FLOW_LOGS"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-3.9, CC7.1",
		Name:       "VPC Flow Logs",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d VPCs have Flow Logs enabled | Meets CIS-3.9", len(vpcs.Vpcs)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("VPC_FLOW_LOGS"),
	}, nil
}

// CIS 5.1 - Ensure no default VPC is in use
func (c *VPCChecks) CheckDefaultVPC(ctx context.Context) (CheckResult, error) {
	vpcs, err := c.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("isDefault"),
				Values: []string{"true"},
			},
		},
	})
	if err != nil {
		return CheckResult{}, err
	}

	// Check if default VPC has any resources
	defaultVPCsInUse := []string{}
	for _, vpc := range vpcs.Vpcs {
		// Check for instances in default VPC
		instances, err := c.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*vpc.VpcId},
				},
			},
		})

		hasInstances := false
		if err == nil {
			for _, reservation := range instances.Reservations {
				if len(reservation.Instances) > 0 {
					hasInstances = true
					break
				}
			}
		}

		if hasInstances {
			defaultVPCsInUse = append(defaultVPCsInUse, *vpc.VpcId)
		}
	}

	if len(defaultVPCsInUse) > 0 {
		return CheckResult{
			Control:           "[CIS-5.1]",
			Name:              "Default VPC in Use",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d default VPC(s) have resources: %v | Default VPCs lack security controls", len(defaultVPCsInUse), defaultVPCsInUse),
			Remediation:       "Move resources to custom VPCs with proper security controls",
			RemediationDetail: "1. Create custom VPC with proper CIDR and subnets\n2. Migrate instances to custom VPC\n3. Delete default VPC after migration",
			ScreenshotGuide:   "VPC Console → Show only custom VPCs in use (no default VPC resources)",
			ConsoleURL:        "https://console.aws.amazon.com/vpc/",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("DEFAULT_VPC"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.1]",
		Name:       "Default VPC in Use",
		Status:     "PASS",
		Evidence:   "No resources using default VPC",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("DEFAULT_VPC"),
	}, nil
}

// CIS 5.5 - Ensure routing tables for VPC peering are least access
func (c *VPCChecks) CheckVPCPeering(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "[CIS-5.5]",
		Name:              "VPC Peering Routing",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Review VPC peering connections for least privilege routing",
		Remediation:       "Ensure VPC peering route tables use specific CIDR blocks, not 0.0.0.0/0",
		RemediationDetail: "1. Review all VPC peering connections\n2. Check route tables for peering connections\n3. Ensure routes use specific CIDR blocks\n4. Remove any overly permissive routes (0.0.0.0/0)",
		ScreenshotGuide:   "VPC Console → Peering Connections → Route Tables → Screenshot showing specific CIDR routes (no 0.0.0.0/0)",
		ConsoleURL:        "https://console.aws.amazon.com/vpc/home#PeeringConnections:",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("VPC_PEERING"),
	}, nil
}

// CIS 5.7-5.8 - Ensure VPC endpoints are used for AWS services
func (c *VPCChecks) CheckVPCEndpoints(ctx context.Context) (CheckResult, error) {
	vpcs, err := c.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	endpoints, err := c.client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	// Map endpoints by VPC
	vpcEndpoints := make(map[string][]string)
	for _, endpoint := range endpoints.VpcEndpoints {
		if endpoint.VpcId != nil && endpoint.ServiceName != nil {
			vpcEndpoints[*endpoint.VpcId] = append(vpcEndpoints[*endpoint.VpcId], *endpoint.ServiceName)
		}
	}

	vpcsWithoutS3 := []string{}
	vpcsWithoutDynamoDB := []string{}

	for _, vpc := range vpcs.Vpcs {
		if vpc.IsDefault != nil && *vpc.IsDefault {
			continue // Skip default VPCs
		}

		services := vpcEndpoints[*vpc.VpcId]
		hasS3 := false
		hasDynamoDB := false

		for _, service := range services {
			if contains(service, ".s3.") || contains(service, ".s3-global.") {
				hasS3 = true
			}
			if contains(service, ".dynamodb.") {
				hasDynamoDB = true
			}
		}

		if !hasS3 {
			vpcsWithoutS3 = append(vpcsWithoutS3, *vpc.VpcId)
		}
		if !hasDynamoDB {
			vpcsWithoutDynamoDB = append(vpcsWithoutDynamoDB, *vpc.VpcId)
		}
	}

	if len(vpcsWithoutS3) > 0 || len(vpcsWithoutDynamoDB) > 0 {
		evidence := fmt.Sprintf("VPCs without S3 endpoint: %d | VPCs without DynamoDB endpoint: %d | CIS 5.7-5.8",
			len(vpcsWithoutS3), len(vpcsWithoutDynamoDB))

		return CheckResult{
			Control:     "[CIS-5.7, 5.8]",
			Name:        "VPC Endpoints for AWS Services",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    evidence,
			Remediation: "Create VPC endpoints for S3 and DynamoDB to avoid internet traffic",
			RemediationDetail: `# Create S3 endpoint
aws ec2 create-vpc-endpoint --vpc-id VPC_ID --service-name com.amazonaws.REGION.s3 --route-table-ids RTB_ID

# Create DynamoDB endpoint
aws ec2 create-vpc-endpoint --vpc-id VPC_ID --service-name com.amazonaws.REGION.dynamodb --route-table-ids RTB_ID`,
			ScreenshotGuide: "VPC Console → Endpoints → Screenshot showing S3 and DynamoDB endpoints for each VPC",
			ConsoleURL:      "https://console.aws.amazon.com/vpc/home#Endpoints:",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "5.7, 5.8"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.7, 5.8]",
		Name:       "VPC Endpoints for AWS Services",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d VPCs have appropriate endpoints | CIS 5.7-5.8", len(vpcs.Vpcs)-countDefaultVPCs(vpcs.Vpcs)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "5.7, 5.8"},
	}, nil
}

// CIS 5.9-5.12 - Ensure Network ACLs restrict admin access from internet
func (c *VPCChecks) CheckNACLRestrictions(ctx context.Context) []CheckResult {
	var results []CheckResult

	nacls, err := c.client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return results
	}

	naclsAllowingSSH := []string{}
	naclsAllowingRDP := []string{}
	naclsAllowingSSHv6 := []string{}
	naclsAllowingRDPv6 := []string{}

	for _, nacl := range nacls.NetworkAcls {
		allowsSSH := false
		allowsRDP := false
		allowsSSHv6 := false
		allowsRDPv6 := false

		for _, entry := range nacl.Entries {
			if entry.Egress != nil && *entry.Egress {
				continue // Skip egress rules
			}

			if entry.RuleAction != types.RuleActionAllow {
				continue
			}

			// Check for SSH (port 22)
			if isPortInRangeStruct(22, entry.PortRange) {
				if entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0" {
					allowsSSH = true
				}
				if entry.Ipv6CidrBlock != nil && *entry.Ipv6CidrBlock == "::/0" {
					allowsSSHv6 = true
				}
			}

			// Check for RDP (port 3389)
			if isPortInRangeStruct(3389, entry.PortRange) {
				if entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0" {
					allowsRDP = true
				}
				if entry.Ipv6CidrBlock != nil && *entry.Ipv6CidrBlock == "::/0" {
					allowsRDPv6 = true
				}
			}
		}

		if allowsSSH {
			naclsAllowingSSH = append(naclsAllowingSSH, *nacl.NetworkAclId)
		}
		if allowsRDP {
			naclsAllowingRDP = append(naclsAllowingRDP, *nacl.NetworkAclId)
		}
		if allowsSSHv6 {
			naclsAllowingSSHv6 = append(naclsAllowingSSHv6, *nacl.NetworkAclId)
		}
		if allowsRDPv6 {
			naclsAllowingRDPv6 = append(naclsAllowingRDPv6, *nacl.NetworkAclId)
		}
	}

	// CIS 5.9
	if len(naclsAllowingSSH) > 0 {
		results = append(results, CheckResult{
			Control:           "[CIS-5.9]",
			Name:              "NACL Restricts SSH from Internet",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d NACLs allow SSH (port 22) from 0.0.0.0/0: %v | CIS 5.9", len(naclsAllowingSSH), truncateList(naclsAllowingSSH, 3)),
			Remediation:       "Remove NACL rules allowing SSH from 0.0.0.0/0",
			RemediationDetail: `aws ec2 delete-network-acl-entry --network-acl-id NACL_ID --ingress --rule-number RULE_NUM`,
			ScreenshotGuide:   "VPC Console → Network ACLs → Inbound Rules → Screenshot showing no rules for port 22 from 0.0.0.0/0",
			ConsoleURL:        "https://console.aws.amazon.com/vpc/home#acls:",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "5.9", "PCI-DSS": "1.2.1", "SOC2": "CC6.6"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "[CIS-5.9]",
			Name:       "NACL Restricts SSH from Internet",
			Status:     "PASS",
			Evidence:   "No NACLs allow SSH from internet | CIS 5.9",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.9"},
		})
	}

	// CIS 5.10
	if len(naclsAllowingRDP) > 0 {
		results = append(results, CheckResult{
			Control:           "[CIS-5.10]",
			Name:              "NACL Restricts RDP from Internet",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d NACLs allow RDP (port 3389) from 0.0.0.0/0: %v | CIS 5.10", len(naclsAllowingRDP), truncateList(naclsAllowingRDP, 3)),
			Remediation:       "Remove NACL rules allowing RDP from 0.0.0.0/0",
			RemediationDetail: `aws ec2 delete-network-acl-entry --network-acl-id NACL_ID --ingress --rule-number RULE_NUM`,
			ScreenshotGuide:   "VPC Console → Network ACLs → Inbound Rules → Screenshot showing no rules for port 3389 from 0.0.0.0/0",
			ConsoleURL:        "https://console.aws.amazon.com/vpc/home#acls:",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "5.10", "PCI-DSS": "1.2.1", "SOC2": "CC6.6"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "[CIS-5.10]",
			Name:       "NACL Restricts RDP from Internet",
			Status:     "PASS",
			Evidence:   "No NACLs allow RDP from internet | CIS 5.10",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.10"},
		})
	}

	// CIS 5.11
	if len(naclsAllowingSSHv6) > 0 {
		results = append(results, CheckResult{
			Control:           "[CIS-5.11]",
			Name:              "NACL Restricts SSH from Internet (IPv6)",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d NACLs allow SSH from ::/0: %v | CIS 5.11", len(naclsAllowingSSHv6), truncateList(naclsAllowingSSHv6, 3)),
			Remediation:       "Remove NACL rules allowing SSH from ::/0",
			RemediationDetail: `aws ec2 delete-network-acl-entry --network-acl-id NACL_ID --ingress --rule-number RULE_NUM`,
			ScreenshotGuide:   "VPC Console → Network ACLs → Inbound Rules → Screenshot showing no IPv6 rules for port 22",
			ConsoleURL:        "https://console.aws.amazon.com/vpc/home#acls:",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "5.11"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "[CIS-5.11]",
			Name:       "NACL Restricts SSH from Internet (IPv6)",
			Status:     "PASS",
			Evidence:   "No NACLs allow SSH from ::/0 | CIS 5.11",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.11"},
		})
	}

	// CIS 5.12
	if len(naclsAllowingRDPv6) > 0 {
		results = append(results, CheckResult{
			Control:           "[CIS-5.12]",
			Name:              "NACL Restricts RDP from Internet (IPv6)",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d NACLs allow RDP from ::/0: %v | CIS 5.12", len(naclsAllowingRDPv6), truncateList(naclsAllowingRDPv6, 3)),
			Remediation:       "Remove NACL rules allowing RDP from ::/0",
			RemediationDetail: `aws ec2 delete-network-acl-entry --network-acl-id NACL_ID --ingress --rule-number RULE_NUM`,
			ScreenshotGuide:   "VPC Console → Network ACLs → Inbound Rules → Screenshot showing no IPv6 rules for port 3389",
			ConsoleURL:        "https://console.aws.amazon.com/vpc/home#acls:",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "5.12"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "[CIS-5.12]",
			Name:       "NACL Restricts RDP from Internet (IPv6)",
			Status:     "PASS",
			Evidence:   "No NACLs allow RDP from ::/0 | CIS 5.12",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "5.12"},
		})
	}

	return results
}

// CIS 5.13 - Security groups restrict admin access
func (c *VPCChecks) CheckAdminPortSecurity(ctx context.Context) (CheckResult, error) {
	secGroups, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	violatingSGs := []string{}
	adminPorts := []int32{22, 3389, 5985, 5986} // SSH, RDP, WinRM

	for _, sg := range secGroups.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, port := range adminPorts {
				if isPortInRange(port, perm.FromPort, perm.ToPort) {
					for _, ipRange := range perm.IpRanges {
						if ipRange.CidrIp != nil && (*ipRange.CidrIp == "0.0.0.0/0" || *ipRange.CidrIp == "::/0") {
							violatingSGs = append(violatingSGs, fmt.Sprintf("%s (port %d)", *sg.GroupId, port))
						}
					}
					for _, ipv6Range := range perm.Ipv6Ranges {
						if ipv6Range.CidrIpv6 != nil && *ipv6Range.CidrIpv6 == "::/0" {
							violatingSGs = append(violatingSGs, fmt.Sprintf("%s (port %d IPv6)", *sg.GroupId, port))
						}
					}
				}
			}
		}
	}

	if len(violatingSGs) > 0 {
		return CheckResult{
			Control:     "[CIS-5.13]",
			Name:        "Security Groups Restrict Admin Ports",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("%d security group rules allow admin ports from internet: %v | CIS 5.13", len(violatingSGs), truncateList(violatingSGs, 5)),
			Remediation: "Restrict admin port access to specific IP ranges",
			RemediationDetail: `aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id SG_ID --protocol tcp --port 22 --cidr YOUR_IP/32`,
			ScreenshotGuide: "EC2 Console → Security Groups → Inbound Rules → Screenshot showing admin ports restricted to specific IPs",
			ConsoleURL:      "https://console.aws.amazon.com/ec2/home#SecurityGroups:",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "5.13", "PCI-DSS": "1.2.1", "SOC2": "CC6.6"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.13]",
		Name:       "Security Groups Restrict Admin Ports",
		Status:     "PASS",
		Evidence:   "Security groups properly restrict admin port access | CIS 5.13",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "5.13"},
	}, nil
}

// CIS 5.14 - Ensure EC2 instances are in custom VPC subnets
func (c *VPCChecks) CheckEC2SubnetPlacement(ctx context.Context) (CheckResult, error) {
	// Get default VPCs
	defaultVPCs, err := c.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []types.Filter{{Name: aws.String("isDefault"), Values: []string{"true"}}},
	})
	if err != nil {
		return CheckResult{}, err
	}

	defaultVPCIds := make(map[string]bool)
	for _, vpc := range defaultVPCs.Vpcs {
		defaultVPCIds[*vpc.VpcId] = true
	}

	// Check instances
	instances, err := c.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	instancesInDefault := []string{}
	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			if instance.VpcId != nil && defaultVPCIds[*instance.VpcId] {
				instancesInDefault = append(instancesInDefault, *instance.InstanceId)
			}
		}
	}

	if len(instancesInDefault) > 0 {
		return CheckResult{
			Control:           "[CIS-5.14]",
			Name:              "EC2 Instances in Custom VPC",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d instances in default VPC: %v | CIS 5.14", len(instancesInDefault), truncateList(instancesInDefault, 3)),
			Remediation:       "Launch instances in custom VPCs with proper network controls",
			RemediationDetail: "1. Create custom VPC\n2. Migrate instances to custom VPC\n3. Terminate instances in default VPC",
			ScreenshotGuide:   "EC2 Console → Instances → VPC column → Screenshot showing all instances in custom VPCs",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/home#Instances:",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "5.14"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.14]",
		Name:       "EC2 Instances in Custom VPC",
		Status:     "PASS",
		Evidence:   "All instances in custom VPCs | CIS 5.14",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "5.14"},
	}, nil
}

// CIS 5.18 - Ensure unused security groups are removed
func (c *VPCChecks) CheckUnusedSecurityGroups(ctx context.Context) (CheckResult, error) {
	secGroups, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	// Get all ENIs
	enis, err := c.client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	usedSGs := make(map[string]bool)
	for _, eni := range enis.NetworkInterfaces {
		for _, sg := range eni.Groups {
			usedSGs[*sg.GroupId] = true
		}
	}

	unusedSGs := []string{}
	for _, sg := range secGroups.SecurityGroups {
		// Skip default security groups
		if sg.GroupName != nil && *sg.GroupName == "default" {
			continue
		}

		if !usedSGs[*sg.GroupId] {
			unusedSGs = append(unusedSGs, *sg.GroupId)
		}
	}

	if len(unusedSGs) > 0 {
		return CheckResult{
			Control:           "[CIS-5.18]",
			Name:              "Unused Security Groups Removed",
			Status:            "FAIL",
			Severity:          "LOW",
			Evidence:          fmt.Sprintf("%d unused security groups found: %v | CIS 5.18", len(unusedSGs), truncateList(unusedSGs, 5)),
			Remediation:       "Remove unused security groups to reduce attack surface",
			RemediationDetail: `aws ec2 delete-security-group --group-id SG_ID`,
			ScreenshotGuide:   "EC2 Console → Security Groups → Screenshot showing only security groups in use",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/home#SecurityGroups:",
			Priority:          PriorityLow,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"CIS-AWS": "5.18"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.18]",
		Name:       "Unused Security Groups Removed",
		Status:     "PASS",
		Evidence:   "No unused security groups | CIS 5.18",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "5.18"},
	}, nil
}

// Helper functions
func countDefaultVPCs(vpcs []types.Vpc) int {
	count := 0
	for _, vpc := range vpcs {
		if vpc.IsDefault != nil && *vpc.IsDefault {
			count++
		}
	}
	return count
}

func isPortInRangeStruct(port int32, portRange *types.PortRange) bool {
	if portRange == nil {
		return true // No port restriction means all ports
	}
	if portRange.From == nil || portRange.To == nil {
		return true // All ports
	}
	return port >= *portRange.From && port <= *portRange.To
}

func isPortInRange(port int32, from, to *int32) bool {
	if from == nil && to == nil {
		return false
	}
	if from == nil || to == nil {
		return true // -1 means all ports
	}
	return port >= *from && port <= *to
}

func truncateList(list []string, maxLen int) []string {
	if len(list) <= maxLen {
		return list
	}
	return list[:maxLen]
}

// CIS-5.8 - Ensure routing tables for VPC peering are "least access"
func (c *VPCChecks) CheckVPCPeeringRouting(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "CIS-5.8",
		Name:        "VPC Peering Routing Least Access",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Verify VPC peering route tables follow least privilege",
		Remediation: "Review and restrict VPC peering routes to specific CIDR blocks",
		RemediationDetail: `1. List VPC peering connections:
   aws ec2 describe-vpc-peering-connections

2. For each peering connection, check route tables:
   aws ec2 describe-route-tables

3. Verify routes:
   - Routes should point to specific CIDR blocks, not 0.0.0.0/0
   - Avoid overly permissive routes that grant more access than needed
   - Document the business justification for each peering route

4. Screenshot showing:
   - VPC peering connections
   - Associated route tables
   - Specific CIDR blocks (not 0.0.0.0/0)`,
		ScreenshotGuide: "VPC Console → Peering Connections → Route Tables → Screenshot showing specific CIDR routes (not 0.0.0.0/0)",
		ConsoleURL:      "https://console.aws.amazon.com/vpc/home#PeeringConnections:",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("VPC_PEERING_ROUTING"),
	}
}

// CIS-5.20 - Ensure VPC endpoints are used for S3
func (c *VPCChecks) CheckVPCEndpointsForS3(ctx context.Context) CheckResult {
	return CheckResult{
		Control:     "CIS-5.20",
		Name:        "VPC Endpoints for S3",
		Status:      "MANUAL",
		Evidence:    "MANUAL CHECK: Verify S3 VPC endpoints are configured for private S3 access",
		Remediation: "Create VPC endpoints for S3 to avoid internet traffic",
		RemediationDetail: `1. Create S3 VPC endpoint:
   aws ec2 create-vpc-endpoint \
     --vpc-id vpc-XXXXX \
     --service-name com.amazonaws.REGION.s3 \
     --route-table-ids rtb-XXXXX

2. Verify endpoint is active:
   aws ec2 describe-vpc-endpoints

3. Update S3 bucket policies to require VPC endpoint access:
   {
     "Condition": {
       "StringNotEquals": {
         "aws:sourceVpce": "vpce-XXXXX"
       }
     },
     "Effect": "Deny",
     "Principal": "*",
     "Action": "s3:*",
     "Resource": ["arn:aws:s3:::bucket/*"]
   }

4. Screenshot showing:
   - VPC endpoints configured for S3
   - Route tables associated with endpoints
   - S3 bucket policies enforcing VPC endpoint access`,
		ScreenshotGuide: "VPC Console → Endpoints → Screenshot showing active S3 endpoint(s) + associated route tables",
		ConsoleURL:      "https://console.aws.amazon.com/vpc/home#Endpoints:",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("VPC_S3_ENDPOINTS"),
	}
}
