package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EC2Checks struct {
	client *ec2.Client
}

func NewEC2Checks(client *ec2.Client) *EC2Checks {
	return &EC2Checks{client: client}
}

func (c *EC2Checks) Name() string {
	return "EC2 Security Configuration"
}

func (c *EC2Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Existing checks
	if result, err := c.CheckOpenSecurityGroups(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckUnencryptedVolumes(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckPublicInstances(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckOldAMIs(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS checks
	if result, err := c.CheckSecurityGroupSSH(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckSecurityGroupRDP(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckDefaultSecurityGroup(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckIMDSv2(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEBSPublicSnapshots(ctx); err == nil {
		results = append(results, result)
	}

	// Additional CIS AWS controls
	if result, err := c.CheckInstanceIAMRoles(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *EC2Checks) CheckOpenSecurityGroups(ctx context.Context) (CheckResult, error) {
	sgs, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "Open Security Groups",
			Status:     "FAIL",
			Evidence:   "Unable to check security groups",
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPEN_SECURITY_GROUPS"),
		}, err
	}

	openGroups := []string{}
	criticalPorts := map[int32]string{
		22:    "SSH",
		3389:  "RDP",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		1433:  "MSSQL",
		27017: "MongoDB",
	}

	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			// Check if rule allows access from anywhere (0.0.0.0/0)
			hasOpenAccess := false
			openPort := int32(0)

			for _, ipRange := range rule.IpRanges {
				if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
					hasOpenAccess = true
					if rule.FromPort != nil {
						openPort = aws.ToInt32(rule.FromPort)
					}
					break
				}
			}

			if hasOpenAccess {
				if portName, isCritical := criticalPorts[openPort]; isCritical {
					openGroups = append(openGroups, fmt.Sprintf("%s (port %d/%s open to world!)",
						aws.ToString(sg.GroupId), openPort, portName))
				}
			}
		}
	}

	if len(openGroups) > 0 {
		groupList := strings.Join(openGroups[:min(3, len(openGroups))], ", ")
		if len(openGroups) > 3 {
			groupList += fmt.Sprintf(" +%d more", len(openGroups)-3)
		}

		// Extract first SG ID for remediation
		firstSG := openGroups[0]
		sgID := ""
		if idx := strings.Index(firstSG, " "); idx > 0 {
			sgID = firstSG[:idx]
		}

		return CheckResult{
			Control:           "CC6.1",
			Name:              "Network Security - Open Ports",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d security groups have critical ports open to 0.0.0.0/0: %s | Violates PCI DSS 1.4.2 (firewall config)", len(openGroups), groupList),
			Remediation:       fmt.Sprintf("Close open ports on SG: %s\nRun: aws ec2 revoke-security-group-ingress", sgID),
			RemediationDetail: fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port 22 --cidr 0.0.0.0/0", sgID),
			ScreenshotGuide:   "1. Go to EC2 → Security Groups\n2. Click on the flagged security group\n3. Go to 'Inbound rules' tab\n4. Screenshot showing NO rules with Source '0.0.0.0/0' for ports 22, 3389, or databases\n5. Critical: SSH/RDP must never be open to internet\n6. For PCI DSS: Document business justification for any public access",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPEN_SECURITY_GROUPS"),
		}, nil
	}

	return CheckResult{
		Control:         "CC6.1",
		Name:            "Network Security - Open Ports",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d security groups properly restrict access | Meets SOC2 CC6.1, PCI DSS 1.4.2, HIPAA 164.312(e)(1)", len(sgs.SecurityGroups)),
		Severity:        "INFO",
		ScreenshotGuide: "1. Go to EC2 → Security Groups\n2. Screenshot the list showing your security groups\n3. Click into 2-3 groups and screenshot inbound rules",
		ConsoleURL:      "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("OPEN_SECURITY_GROUPS"),
	}, nil
}

func (c *EC2Checks) CheckUnencryptedVolumes(ctx context.Context) (CheckResult, error) {
	volumes, err := c.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unencryptedVolumes := []string{}
	totalVolumes := len(volumes.Volumes)

	for _, volume := range volumes.Volumes {
		if !aws.ToBool(volume.Encrypted) {
			volId := aws.ToString(volume.VolumeId)
			// Check if it's attached to an instance
			if len(volume.Attachments) > 0 {
				instanceId := aws.ToString(volume.Attachments[0].InstanceId)
				unencryptedVolumes = append(unencryptedVolumes, fmt.Sprintf("%s (attached to %s)", volId, instanceId))
			} else {
				unencryptedVolumes = append(unencryptedVolumes, fmt.Sprintf("%s (unattached)", volId))
			}
		}
	}

	if len(unencryptedVolumes) > 0 {
		volList := strings.Join(unencryptedVolumes[:min(3, len(unencryptedVolumes))], ", ")
		if len(unencryptedVolumes) > 3 {
			volList += fmt.Sprintf(" +%d more", len(unencryptedVolumes)-3)
		}

		return CheckResult{
			Control:           "CC6.3",
			Name:              "EBS Volume Encryption",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d EBS volumes are NOT encrypted: %s | Violates PCI DSS 3.5.1 (encrypt stored data) & HIPAA 164.312(a)(2)(iv)", len(unencryptedVolumes), totalVolumes, volList),
			Remediation:       "Create encrypted snapshots and migrate",
			RemediationDetail: "1. Create snapshot: aws ec2 create-snapshot --volume-id VOL_ID\n2. Copy with encryption: aws ec2 copy-snapshot --source-snapshot-id SNAP_ID --encrypted\n3. Create new volume from encrypted snapshot",
			ScreenshotGuide:   "1. Go to EC2 → Volumes\n2. Screenshot the list showing 'Encryption' column\n3. All volumes should show 'Encrypted'\n4. For any unencrypted, document migration plan\n5. For HIPAA: Document encryption algorithm used",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#Volumes",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("EBS_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "EBS Volume Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d EBS volumes are encrypted | Meets SOC2 CC6.3, PCI DSS 3.5.1, HIPAA 164.312(a)(2)(iv)", totalVolumes),
		Severity:   "INFO",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("EBS_ENCRYPTION"),
	}, nil
}

func (c *EC2Checks) CheckPublicInstances(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	publicInstances := []string{}
	totalInstances := 0

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances
			if instance.State.Name == types.InstanceStateNameTerminated {
				continue
			}

			totalInstances++

			// Check if instance has public IP
			if instance.PublicIpAddress != nil && *instance.PublicIpAddress != "" {
				name := "unnamed"
				for _, tag := range instance.Tags {
					if aws.ToString(tag.Key) == "Name" {
						name = aws.ToString(tag.Value)
						break
					}
				}
				publicInstances = append(publicInstances, fmt.Sprintf("%s (%s)", name, aws.ToString(instance.InstanceId)))
			}
		}
	}

	if len(publicInstances) > 5 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "Public EC2 Instances",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d EC2 instances have public IPs | PCI DSS 1.4.2 requires DMZ for public systems", len(publicInstances)),
			Remediation:       "Move instances to private subnets",
			RemediationDetail: "Move instances to private subnets and use bastion hosts or VPN for access",
			ScreenshotGuide:   "1. Go to EC2 → Instances\n2. Screenshot showing instance list\n3. Document why each public instance needs external access\n4. For PCI DSS: Show network segmentation",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#Instances",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("PUBLIC_INSTANCES"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "Public EC2 Instances",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("%d/%d instances properly use private IPs | Meets PCI DSS 1.4.2 network segmentation", totalInstances-len(publicInstances), totalInstances),
		Severity:   "INFO",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("PUBLIC_INSTANCES"),
	}, nil
}

func (c *EC2Checks) CheckOldAMIs(ctx context.Context) (CheckResult, error) {
	// Check for old AMIs (>180 days)
	images, err := c.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return CheckResult{}, err
	}

	oldAMIs := []string{}
	for _, image := range images.Images {
		// Parse creation date
		if image.CreationDate != nil {
			creationTime, err := time.Parse(time.RFC3339, *image.CreationDate)
			if err == nil {
				age := time.Since(creationTime)
				days := int(age.Hours() / 24)

				if days > 180 {
					oldAMIs = append(oldAMIs, fmt.Sprintf("%s (%d days old)",
						aws.ToString(image.ImageId), days))
				}
			}
		}
	}

	if len(oldAMIs) > 0 {
		return CheckResult{
			Control:           "CC7.2",
			Name:              "AMI Age and Patching",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d AMIs are older than 180 days | PCI DSS 6.3.3 requires timely patching", len(oldAMIs)),
			Remediation:       "Create new AMIs with latest patches",
			RemediationDetail: "Create new AMIs with latest patches and deregister old ones using: aws ec2 deregister-image --image-id AMI_ID",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OLD_AMIS"),
			ScreenshotGuide:   "1. Go to EC2 → AMIs\n2. Screenshot showing AMI creation dates\n3. Document patching schedule for PCI DSS",
		}, nil
	}

	return CheckResult{
		Control:    "CC7.2",
		Name:       "AMI Age and Patching",
		Status:     "PASS",
		Evidence:   "All AMIs are recent and likely patched | Meets PCI DSS 6.3.3 patch management",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OLD_AMIS"),
	}, nil
}

// NEW CIS-SPECIFIC CHECKS

// CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
func (c *EC2Checks) CheckSecurityGroupSSH(ctx context.Context) (CheckResult, error) {
	sgs, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	sshOpenGroups := []string{}

	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			// Check for SSH (port 22)
			if rule.FromPort != nil && *rule.FromPort == 22 {
				for _, ipRange := range rule.IpRanges {
					if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
						sshOpenGroups = append(sshOpenGroups, aws.ToString(sg.GroupId))
						break
					}
				}
			}
		}
	}

	if len(sshOpenGroups) > 0 {
		return CheckResult{
			Control:           "[CIS-5.2]",
			Name:              "SSH Access from Internet",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d security groups allow SSH (port 22) from 0.0.0.0/0: %v", len(sshOpenGroups), sshOpenGroups),
			Remediation:       "Restrict SSH access to specific IP addresses",
			RemediationDetail: fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port 22 --cidr 0.0.0.0/0", sshOpenGroups[0]),
			ScreenshotGuide:   "EC2 → Security Groups → Screenshot showing NO rules allowing 0.0.0.0/0 access to port 22",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SECURITY_GROUP_UNRESTRICTED"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.2]",
		Name:       "SSH Access from Internet",
		Status:     "PASS",
		Evidence:   "No security groups allow unrestricted SSH access",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SECURITY_GROUP_UNRESTRICTED"),
	}, nil
}

// CIS 5.3 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
func (c *EC2Checks) CheckSecurityGroupRDP(ctx context.Context) (CheckResult, error) {
	sgs, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	rdpOpenGroups := []string{}

	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			// Check for RDP (port 3389)
			if rule.FromPort != nil && *rule.FromPort == 3389 {
				for _, ipRange := range rule.IpRanges {
					if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
						rdpOpenGroups = append(rdpOpenGroups, aws.ToString(sg.GroupId))
						break
					}
				}
			}
		}
	}

	if len(rdpOpenGroups) > 0 {
		return CheckResult{
			Control:           "[CIS-5.3]",
			Name:              "RDP Access from Internet",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d security groups allow RDP (port 3389) from 0.0.0.0/0: %v", len(rdpOpenGroups), rdpOpenGroups),
			Remediation:       "Restrict RDP access to specific IP addresses",
			RemediationDetail: fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port 3389 --cidr 0.0.0.0/0", rdpOpenGroups[0]),
			ScreenshotGuide:   "EC2 → Security Groups → Screenshot showing NO rules allowing 0.0.0.0/0 access to port 3389",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("SECURITY_GROUP_UNRESTRICTED"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.3]",
		Name:       "RDP Access from Internet",
		Status:     "PASS",
		Evidence:   "No security groups allow unrestricted RDP access",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("SECURITY_GROUP_UNRESTRICTED"),
	}, nil
}

// CIS 5.4 - Ensure default security group restricts all traffic
func (c *EC2Checks) CheckDefaultSecurityGroup(ctx context.Context) (CheckResult, error) {
	vpcs, err := c.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	openDefaultSGs := []string{}

	for _, vpc := range vpcs.Vpcs {
		sgs, err := c.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{*vpc.VpcId},
				},
				{
					Name:   aws.String("group-name"),
					Values: []string{"default"},
				},
			},
		})

		if err == nil && len(sgs.SecurityGroups) > 0 {
			sg := sgs.SecurityGroups[0]
			// Check if default SG has any rules
			if len(sg.IpPermissions) > 0 || len(sg.IpPermissionsEgress) > 1 {
				openDefaultSGs = append(openDefaultSGs, fmt.Sprintf("%s (VPC: %s)", aws.ToString(sg.GroupId), aws.ToString(vpc.VpcId)))
			}
		}
	}

	if len(openDefaultSGs) > 0 {
		return CheckResult{
			Control:           "[CIS-5.4]",
			Name:              "Default Security Group",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d default security groups allow traffic: %v", len(openDefaultSGs), openDefaultSGs),
			Remediation:       "Remove all rules from default security groups",
			RemediationDetail: "1. Don't use default security groups\n2. Remove all inbound/outbound rules from default SGs\n3. Create custom security groups for your resources",
			ScreenshotGuide:   "EC2 → Security Groups → Default groups → Screenshot showing NO inbound/outbound rules",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("DEFAULT_VPC"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.4]",
		Name:       "Default Security Group",
		Status:     "PASS",
		Evidence:   "All default security groups properly restrict traffic",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("DEFAULT_VPC"),
	}, nil
}

// CIS 5.6 - Ensure EC2 instances use IMDSv2
func (c *EC2Checks) CheckIMDSv2(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	imdsV1Instances := []string{}

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			// Skip terminated instances
			if instance.State.Name == types.InstanceStateNameTerminated {
				continue
			}

			// Check IMDSv2 requirement
			if instance.MetadataOptions == nil ||
				instance.MetadataOptions.HttpTokens != types.HttpTokensStateRequired {
				imdsV1Instances = append(imdsV1Instances, aws.ToString(instance.InstanceId))
			}
		}
	}

	if len(imdsV1Instances) > 0 {
		return CheckResult{
			Control:           "[CIS-5.6]",
			Name:              "EC2 IMDSv2",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d EC2 instances not using IMDSv2: %v", len(imdsV1Instances), imdsV1Instances),
			Remediation:       "Require IMDSv2 on all EC2 instances",
			RemediationDetail: fmt.Sprintf("aws ec2 modify-instance-metadata-options --instance-id %s --http-tokens required --http-endpoint enabled", imdsV1Instances[0]),
			ScreenshotGuide:   "EC2 → Instances → Instance details → Screenshot showing 'IMDSv2: Required'",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#Instances",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("IMDS_V2"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-5.6]",
		Name:       "EC2 IMDSv2",
		Status:     "PASS",
		Evidence:   "All EC2 instances require IMDSv2",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("IMDS_V2"),
	}, nil
}

// CIS 2.2.2 - Ensure EBS volume snapshots are not publicly accessible
func (c *EC2Checks) CheckEBSPublicSnapshots(ctx context.Context) (CheckResult, error) {
	snapshots, err := c.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	if err != nil {
		return CheckResult{}, err
	}

	publicSnapshots := []string{}

	for _, snapshot := range snapshots.Snapshots {
		attrs, err := c.client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
			SnapshotId: snapshot.SnapshotId,
			Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
		})

		if err == nil {
			for _, perm := range attrs.CreateVolumePermissions {
				if perm.Group == "all" {
					publicSnapshots = append(publicSnapshots, aws.ToString(snapshot.SnapshotId))
					break
				}
			}
		}
	}

	if len(publicSnapshots) > 0 {
		return CheckResult{
			Control:           "[CIS-2.2.2]",
			Name:              "EBS Public Snapshots",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d EBS snapshots are publicly accessible: %v", len(publicSnapshots), publicSnapshots),
			Remediation:       "Make snapshots private immediately",
			RemediationDetail: fmt.Sprintf("aws ec2 modify-snapshot-attribute --snapshot-id %s --create-volume-permission Remove=[{Group=all}]", publicSnapshots[0]),
			ScreenshotGuide:   "EC2 → Snapshots → Permissions → Screenshot showing NO 'Public' access",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#Snapshots",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("EBS_PUBLIC_SNAPSHOTS"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-2.2.2]",
		Name:       "EBS Public Snapshots",
		Status:     "PASS",
		Evidence:   "No EBS snapshots are publicly accessible",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("EBS_PUBLIC_SNAPSHOTS"),
	}, nil
}

// CheckInstanceIAMRoles verifies EC2 instances use IAM roles (CIS 1.18)
func (c *EC2Checks) CheckInstanceIAMRoles(ctx context.Context) (CheckResult, error) {
	result, err := c.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return CheckResult{
			Control:    "[CIS-1.18]",
			Name:       "EC2 Instance IAM Roles",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check EC2 instances: %v", err),
			Severity:   "MEDIUM",
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "1.18", "SOC2": "CC6.1"},
		}, nil
	}

	instancesWithoutRoles := []string{}
	totalRunningInstances := 0

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			// Only check running instances
			if instance.State.Name != types.InstanceStateNameRunning {
				continue
			}

			totalRunningInstances++

			// Check if instance has IAM instance profile
			if instance.IamInstanceProfile == nil || instance.IamInstanceProfile.Arn == nil {
				instanceID := aws.ToString(instance.InstanceId)
				instancesWithoutRoles = append(instancesWithoutRoles, instanceID)
			}
		}
	}

	if len(instancesWithoutRoles) > 0 {
		displayInstances := instancesWithoutRoles
		if len(instancesWithoutRoles) > 5 {
			displayInstances = instancesWithoutRoles[:5]
		}

		return CheckResult{
			Control:     "[CIS-1.18]",
			Name:        "EC2 Instance IAM Roles",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d/%d running EC2 instances do not use IAM roles: %s | Violates CIS 1.18 (may use embedded credentials)", len(instancesWithoutRoles), totalRunningInstances, strings.Join(displayInstances, ", ")),
			Remediation: "Attach IAM instance profiles to EC2 instances",
			RemediationDetail: fmt.Sprintf(`# Create IAM role for EC2
aws iam create-role --role-name EC2-App-Role --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

# Attach policies to role
aws iam attach-role-policy --role-name EC2-App-Role --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Create instance profile
aws iam create-instance-profile --instance-profile-name EC2-App-Profile

# Add role to instance profile
aws iam add-role-to-instance-profile --instance-profile-name EC2-App-Profile --role-name EC2-App-Role

# Attach instance profile to EC2 instance
aws ec2 associate-iam-instance-profile --instance-id %s --iam-instance-profile Name=EC2-App-Profile

# Remove any embedded credentials from instance after testing role works`, instancesWithoutRoles[0]),
			ScreenshotGuide: "EC2 → Instances → Select instance → Security tab → Screenshot showing 'IAM Role' assigned",
			ConsoleURL:      "https://console.aws.amazon.com/ec2/v2/home#Instances",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "1.18", "SOC2": "CC6.1", "PCI-DSS": "7.2.1"},
		}, nil
	}

	if totalRunningInstances == 0 {
		return CheckResult{
			Control:    "[CIS-1.18]",
			Name:       "EC2 Instance IAM Roles",
			Status:     "INFO",
			Evidence:   "No running EC2 instances found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "1.18", "SOC2": "CC6.1"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-1.18]",
		Name:       "EC2 Instance IAM Roles",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d running EC2 instances use IAM roles | Meets CIS 1.18", totalRunningInstances),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "1.18", "SOC2": "CC6.1", "PCI-DSS": "7.2.1"},
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
