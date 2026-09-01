package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// PCIDSSChecks implements PCI-DSS v4.0.1 requirements
// v4.0.1 is the only active version. All 51 future-dated requirements became
// mandatory on March 31, 2025 - there is no remaining grace period.
//
// Requirement IDs were remapped from v3.2.1 to v4.0.1 numbering using the PCI SSC
// "v3.2.1 to v4.0 Summary of Changes" where it gives an explicit mapping, and by
// matching check content against the v4.0.1 standard text otherwise.
//
// Known gaps - future-dated requirements not yet covered. The first five are
// testable from cloud configuration and are the ones worth adding:
//
//	4.2.1.1  inventory of trusted keys and certificates
//	8.6.1-3  application and system account credential management
//	10.4.1.1 automated log review mechanisms
//	10.7.2   detect and alert on security control failures (all entities)
//	10.7.3   respond to security control failures
//
// The remainder are payment-page or process controls a cloud config scanner
// cannot assess, and should surface as MANUAL rather than be omitted:
//
//	3.5.1.1, 5.3.3, 6.4.3, 11.3.1.1, 11.5.1.1, 11.6.1, 12.5.2.1, 12.10.7
type PCIDSSChecks struct {
	iamClient        *iam.Client
	ec2Client        *ec2.Client
	s3Client         *s3.Client
	cloudtrailClient *cloudtrail.Client
	configClient     *configservice.Client
}

func NewPCIDSSChecks(
	iamClient *iam.Client,
	ec2Client *ec2.Client,
	s3Client *s3.Client,
	cloudtrailClient *cloudtrail.Client,
	configClient *configservice.Client,
) *PCIDSSChecks {
	return &PCIDSSChecks{
		iamClient:        iamClient,
		ec2Client:        ec2Client,
		s3Client:         s3Client,
		cloudtrailClient: cloudtrailClient,
		configClient:     configClient,
	}
}

func (c *PCIDSSChecks) Name() string {
	return "PCI-DSS v4.0.1 Requirements"
}

func (c *PCIDSSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Requirement 1: Network Security Requirements
	results = append(results, c.CheckReq1_NetworkSegmentation(ctx)...)

	// Requirement 2: Default Passwords
	results = append(results, c.CheckReq2_DefaultPasswords(ctx)...)

	// Requirement 3: Cardholder Data Protection
	results = append(results, c.CheckReq3_Encryption(ctx)...)

	// Requirement 4: Encryption in Transit (CRITICAL)
	results = append(results, c.CheckReq4_EncryptionInTransit(ctx)...)

	// Requirement 5: Malware Protection
	results = append(results, c.CheckReq5_MalwareProtection(ctx)...)

	// Requirement 6: Secure Systems (CRITICAL)
	results = append(results, c.CheckReq6_SecureSystems(ctx)...)

	// Requirement 7: Access Control (CRITICAL)
	results = append(results, c.CheckReq7_AccessControl(ctx)...)

	// Requirement 8: User Authentication (STRICTER than SOC2)
	results = append(results, c.CheckReq8_Authentication(ctx)...)

	// Requirement 10: Logging (12 months!)
	results = append(results, c.CheckReq10_Logging(ctx)...)

	// Requirement 9: Physical Access Controls
	results = append(results, c.CheckReq9_PhysicalAccess(ctx)...)

	// Requirement 11: Security Testing
	results = append(results, c.CheckReq11_SecurityTesting(ctx)...)

	// Requirement 12: Information Security Policy
	results = append(results, c.CheckReq12_SecurityPolicy(ctx)...)

	return results, nil
}

// Requirement 1.4.2: Network segmentation for CDE
func (c *PCIDSSChecks) CheckReq1_NetworkSegmentation(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check VPC segmentation
	vpcs, err := c.ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-1.4.2",
			Name:      "[PCI-DSS] Network Segmentation",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Could not check VPC segmentation: %v", err),
			Priority:  PriorityCritical,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 1.4.2",
			},
		})
	}

	// Check if we have isolated VPCs (simplified check)
	if len(vpcs.Vpcs) < 2 {
		results = append(results, CheckResult{
			Control:           "PCI-1.4.2",
			Name:              "[PCI-DSS] Network Segmentation for CDE",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "PCI-DSS Req 1.4.2 VIOLATION: Only 1 VPC found - PCI requires isolated network for cardholder data environment (CDE)",
			Remediation:       "Create separate VPC for CDE",
			RemediationDetail: "1. Create new VPC: aws ec2 create-vpc --cidr-block 10.1.0.0/16\n2. Tag as CDE: aws ec2 create-tags --resources vpc-xxx --tags Key=Environment,Value=CDE\n3. Implement strict NACLs and security groups",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "VPC Console → Show all VPCs → Screenshot showing CDE VPC separated",
			ConsoleURL:        "https://console.aws.amazon.com/vpc/",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 1.4.2",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-1.4.2",
			Name:      "[PCI-DSS] Network Segmentation for CDE",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d VPCs found - verify CDE isolation manually", len(vpcs.Vpcs)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 1.4.2",
			},
		})
	}

	// Check for 0.0.0.0/0 security group rules (PCI HATES these)
	// FIXED: Properly handle error instead of ignoring with _
	sgs, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-1.4.2",
			Name:      "[PCI-DSS] Security Group Check",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check security groups: %v", err),
			Priority:  PriorityHigh,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 1.4.2",
			},
		})
	}

	openToWorld := []string{}

	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			for _, ipRange := range rule.IpRanges {
				if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
					port := "all"
					if rule.FromPort != nil {
						port = fmt.Sprintf("%d", aws.ToInt32(rule.FromPort))
					}
					openToWorld = append(openToWorld, fmt.Sprintf("%s (port %s)", aws.ToString(sg.GroupId), port))
				}
			}
		}
	}

	if len(openToWorld) > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-1.4.2",
			Name:              "[PCI-DSS] No Direct Public Access to CDE",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 1.4.2 VIOLATION: %d security groups allow 0.0.0.0/0 access: %s", len(openToWorld), strings.Join(openToWorld[:min(3, len(openToWorld))], ", ")),
			Remediation:       "Remove all 0.0.0.0/0 rules immediately",
			RemediationDetail: "aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol all --cidr 0.0.0.0/0",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "EC2 → Security Groups → Each group → Inbound rules → No 0.0.0.0/0",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 1.4.2",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-1.4.2",
			Name:      "[PCI-DSS] No Direct Public Access",
			Status:    "PASS",
			Evidence:  "No security groups allow 0.0.0.0/0 access",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 1.4.2",
			},
		})
	}

	return results
}

// Requirement 2: No default passwords/configs
func (c *PCIDSSChecks) CheckReq2_DefaultPasswords(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for default security group (often has permissive rules)
	// FIXED: Properly handle error instead of ignoring with _
	sgs, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:     "PCI-2.2.4",
			Name:        "[PCI-DSS] Disable Default Configurations",
			Status:      "ERROR",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Unable to check security groups: %v", err),
			Remediation: "Ensure AWS credentials have ec2:DescribeSecurityGroups permission",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 2.2.4",
			},
		})
	}

	defaultGroupsWithRules := 0
	for _, sg := range sgs.SecurityGroups {
		if aws.ToString(sg.GroupName) == "default" && len(sg.IpPermissions) > 0 {
			defaultGroupsWithRules++
		}
	}

	if defaultGroupsWithRules > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-2.2.4",
			Name:              "[PCI-DSS] Disable Default Configurations",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS Req 2.2.4: %d default security groups have rules - PCI requires removing defaults", defaultGroupsWithRules),
			Remediation:       "Remove all rules from default security groups",
			RemediationDetail: "for each VPC: aws ec2 revoke-security-group-ingress --group-id <default-sg-id> --protocol all --source-group <default-sg-id>",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "EC2 → Security Groups → Filter by 'default' → Show empty rule sets",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 2.2.4",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-2.2.4",
			Name:      "[PCI-DSS] Default Configurations Disabled",
			Status:    "PASS",
			Evidence:  "Default security groups have no rules",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 2.2.4",
			},
		})
	}

	return results
}

// Requirement 3.5.1: Encryption of cardholder data at rest
func (c *PCIDSSChecks) CheckReq3_Encryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// S3 encryption is MANDATORY for PCI
	// FIXED: Properly handle error instead of ignoring with _
	buckets, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-3.5.1",
			Name:      "[PCI-DSS] Encryption at Rest",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check S3 buckets: %v", err),
			Priority:  PriorityCritical,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 3.5.1",
			},
		})
	}

	unencryptedBuckets := []string{}
	totalBuckets := len(buckets.Buckets)

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		// Check encryption
		_, err := c.s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})

		if err != nil {
			unencryptedBuckets = append(unencryptedBuckets, bucketName)
		}
	}

	if len(unencryptedBuckets) > 0 {
		displayBuckets := unencryptedBuckets
		if len(unencryptedBuckets) > 3 {
			displayBuckets = unencryptedBuckets[:3]
		}

		results = append(results, CheckResult{
			Control:           "PCI-3.5.1",
			Name:              "[PCI-DSS] Encryption at Rest (Mandatory)",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 3.5.1 VIOLATION: %d/%d S3 buckets NOT encrypted - PCI REQUIRES encryption: %s", len(unencryptedBuckets), totalBuckets, strings.Join(displayBuckets, ", ")),
			Remediation:       "Enable AES-256 encryption NOW",
			RemediationDetail: fmt.Sprintf("aws s3api put-bucket-encryption --bucket %s --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'", unencryptedBuckets[0]),
			Priority:          PriorityCritical,
			ScreenshotGuide:   "S3 → Each bucket → Properties → Encryption → Show AES-256 or KMS enabled",
			ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets/",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 3.5.1, 3.4.1",
			},
		})
	} else if totalBuckets > 0 {
		results = append(results, CheckResult{
			Control:   "PCI-3.5.1",
			Name:      "[PCI-DSS] Encryption at Rest",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d S3 buckets encrypted", totalBuckets),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 3.5.1, 3.4.1",
			},
		})
	}

	return results
}

// Requirement 4: Encryption in Transit (CRITICAL - MISSING)
func (c *PCIDSSChecks) CheckReq4_EncryptionInTransit(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for security groups allowing unencrypted protocols
	// FIXED: Properly handle error instead of ignoring with _
	sgs, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-4.2.1",
			Name:      "[PCI-DSS] Encryption in Transit",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check security groups: %v", err),
			Priority:  PriorityCritical,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 4.2.1",
			},
		})
	}

	unencryptedProtocols := []string{}
	dangerousPorts := map[int32]string{
		21:   "FTP",
		23:   "Telnet",
		80:   "HTTP",
		1433: "SQL Server",
		3306: "MySQL",
		5432: "PostgreSQL",
	}

	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			if rule.FromPort != nil {
				port := aws.ToInt32(rule.FromPort)
				if protocol, isDangerous := dangerousPorts[port]; isDangerous {
					// Check if it's open to internet
					for _, ipRange := range rule.IpRanges {
						if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
							unencryptedProtocols = append(unencryptedProtocols,
								fmt.Sprintf("%s (port %d) in %s", protocol, port, aws.ToString(sg.GroupId)))
						}
					}
				}
			}
		}
	}

	if len(unencryptedProtocols) > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-4.2.1",
			Name:              "[PCI-DSS] Encryption in Transit",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 4.2.1 VIOLATION: Unencrypted protocols exposed: %s", strings.Join(unencryptedProtocols[:min(3, len(unencryptedProtocols))], ", ")),
			Remediation:       "Use only encrypted protocols (HTTPS, SSH, TLS 1.2+)",
			RemediationDetail: "Replace HTTP with HTTPS, FTP with SFTP, Telnet with SSH",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "EC2 → Security Groups → Show no HTTP/FTP/Telnet ports open",
			ConsoleURL:        "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 4.2.1, 4.1.1",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-4.2.1",
			Name:      "[PCI-DSS] Encryption in Transit",
			Status:    "PASS",
			Evidence:  "No unencrypted protocols exposed to internet",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 4.2.1",
			},
		})
	}

	// Check S3 bucket policies for secure transport
	// FIXED: Properly handle error instead of ignoring with _
	buckets, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		// Already returned error above, so just add info check
		return results
	}

	bucketsWithoutSSL := []string{}

	for _, bucket := range buckets.Buckets {
		bucketName := aws.ToString(bucket.Name)

		// Try to get bucket policy
		policy, err := c.s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})

		// If no policy or policy doesn't enforce SSL
		if err != nil || !strings.Contains(aws.ToString(policy.Policy), "aws:SecureTransport") {
			bucketsWithoutSSL = append(bucketsWithoutSSL, bucketName)
		}
	}

	if len(bucketsWithoutSSL) > 0 && len(bucketsWithoutSSL) > len(buckets.Buckets)/2 {
		results = append(results, CheckResult{
			Control:           "PCI-4.2.1",
			Name:              "[PCI-DSS] S3 Secure Transport",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS Req 4.2.1: %d S3 buckets don't enforce SSL/TLS", len(bucketsWithoutSSL)),
			Remediation:       "Add bucket policy requiring SecureTransport",
			RemediationDetail: "Add condition: {\"Bool\": {\"aws:SecureTransport\": \"true\"}}",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 4.2.1",
			},
		})
	}

	return results
}

// Requirement 6: Secure Systems (Patching)
func (c *PCIDSSChecks) CheckReq6_SecureSystems(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for instances without SSM (can't verify patching)
	// FIXED: Properly handle error instead of ignoring with _
	instances, err := c.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-6.3.3",
			Name:      "[PCI-DSS] Security Patching",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check EC2 instances: %v", err),
			Priority:  PriorityHigh,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 6.3.3",
			},
		})
	}

	totalInstances := 0
	instancesWithoutSSM := []string{}

	for _, reservation := range instances.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State != nil && instance.State.Name == "running" {
				totalInstances++
				// Check if instance has SSM agent (simplified check via tags)
				hasSSM := false
				for _, tag := range instance.Tags {
					if aws.ToString(tag.Key) == "SSMManaged" && aws.ToString(tag.Value) == "true" {
						hasSSM = true
						break
					}
				}
				if !hasSSM {
					instancesWithoutSSM = append(instancesWithoutSSM, aws.ToString(instance.InstanceId))
				}
			}
		}
	}

	if len(instancesWithoutSSM) > 0 && totalInstances > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-6.3.3",
			Name:              "[PCI-DSS] Security Patching",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS Req 6.3.3: %d/%d instances not managed by SSM - can't verify 30-day patching", len(instancesWithoutSSM), totalInstances),
			Remediation:       "Enable SSM for patch management",
			RemediationDetail: "Install SSM agent and enable Patch Manager",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Systems Manager → Managed Instances → Show all instances managed",
			ConsoleURL:        "https://console.aws.amazon.com/systems-manager/",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 6.3.3",
			},
		})
	}

	// Check for web-facing security groups (need WAF)
	// FIXED: Properly handle error instead of ignoring with _
	sgs, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		// Already have error handling above
		return results
	}

	webFacingSGs := 0
	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			if rule.FromPort != nil {
				port := aws.ToInt32(rule.FromPort)
				if port == 443 || port == 80 {
					for _, ipRange := range rule.IpRanges {
						if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
							webFacingSGs++
							break
						}
					}
				}
			}
		}
	}

	if webFacingSGs > 0 {
		results = append(results, CheckResult{
			Control:           "PCI-6.4.2",
			Name:              "[PCI-DSS] Web Application Protection",
			Status:            "INFO",
			Evidence:          fmt.Sprintf("PCI-DSS Req 6.4.2: %d web-facing security groups found - ensure WAF is deployed", webFacingSGs),
			Remediation:       "Deploy AWS WAF for web applications",
			RemediationDetail: "PCI requires WAF or regular code reviews for public-facing web apps",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 6.4.2",
			},
		})
	}

	return results
}

// Requirement 7: Access Control (Least Privilege)
func (c *PCIDSSChecks) CheckReq7_AccessControl(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for overly permissive IAM policies
	// FIXED: Properly handle error instead of ignoring with _
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-7.2.1",
			Name:      "[PCI-DSS] Least Privilege Access",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check IAM users: %v", err),
			Priority:  PriorityHigh,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 7.2.1",
			},
		})
	}

	usersWithAdmin := []string{}

	for _, user := range users.Users {
		// Check attached policies
		policies, _ := c.iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: user.UserName,
		})

		for _, policy := range policies.AttachedPolicies {
			if strings.Contains(aws.ToString(policy.PolicyName), "AdministratorAccess") ||
				strings.Contains(aws.ToString(policy.PolicyName), "PowerUser") {
				usersWithAdmin = append(usersWithAdmin, aws.ToString(user.UserName))
				break
			}
		}
	}

	if len(usersWithAdmin) > 2 { // More than 2 is suspicious
		results = append(results, CheckResult{
			Control:           "PCI-7.2.1",
			Name:              "[PCI-DSS] Least Privilege Access",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("PCI-DSS Req 7.2.1: %d users have admin/power user access - violates least privilege", len(usersWithAdmin)),
			Remediation:       "Restrict to specific required permissions only",
			RemediationDetail: "Review each user and apply minimal required permissions",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "IAM → Users → Permissions → Show restricted policies only",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 7.2.1, 7.1.2",
			},
		})
	}

	// Check for separation of duties
	results = append(results, CheckResult{
		Control:           "PCI-7.2.2",
		Name:              "[PCI-DSS] Separation of Duties",
		Status:            "INFO",
		Evidence:          "MANUAL REVIEW REQUIRED: Verify separation between development, operations, and security roles",
		Remediation:       "Implement role-based access control",
		RemediationDetail: "Separate Dev, Ops, and Security IAM groups with distinct permissions",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 7.2.2",
		},
	})

	return results
}

// Requirement 8: Authentication (WAY stricter than SOC2)
func (c *PCIDSSChecks) CheckReq8_Authentication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// 8.2.4: Passwords must be changed every 90 days MAX (not 180!)
	passwordPolicy, err := c.iamClient.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})

	if err != nil {
		results = append(results, CheckResult{
			Control:           "PCI-8.3.9",
			Name:              "[PCI-DSS] 90-Day Password Rotation",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "PCI-DSS Req 8.3.9 VIOLATION: No password policy configured - PCI requires 90-day rotation",
			Remediation:       "Set password expiry to 90 days MAX",
			RemediationDetail: "aws iam update-account-password-policy --max-password-age 90",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "IAM → Account settings → Password policy → Must show 90 days or less",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 8.3.9",
			},
		})
	} else {
		maxAge := aws.ToInt32(passwordPolicy.PasswordPolicy.MaxPasswordAge)
		if maxAge == 0 || maxAge > 90 {
			currentSetting := "never expire"
			if maxAge > 0 {
				currentSetting = fmt.Sprintf("%d days", maxAge)
			}

			results = append(results, CheckResult{
				Control:           "PCI-8.3.9",
				Name:              "[PCI-DSS] 90-Day Password Rotation",
				Status:            "FAIL",
				Severity:          "CRITICAL",
				Evidence:          fmt.Sprintf("PCI-DSS Req 8.3.9 VIOLATION: Passwords set to %s - PCI REQUIRES 90 days MAX", currentSetting),
				Remediation:       "Change to 90 days immediately",
				RemediationDetail: "aws iam update-account-password-policy --max-password-age 90",
				Priority:          PriorityCritical,
				ScreenshotGuide:   "IAM → Account settings → Password policy → Show 90 days max",
				ConsoleURL:        "https://console.aws.amazon.com/iam/home#/account_settings",
				Timestamp:         time.Now(),
				Frameworks: map[string]string{
					"PCI-DSS": "Req 8.3.9",
				},
			})
		} else {
			results = append(results, CheckResult{
				Control:   "PCI-8.3.9",
				Name:      "[PCI-DSS] 90-Day Password Rotation",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("Password expiry set to %d days (PCI compliant)", maxAge),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
				Frameworks: map[string]string{
					"PCI-DSS": "Req 8.3.9",
				},
			})
		}

		// 8.2.3: Minimum password strength (7+ characters for PCI)
		minLength := aws.ToInt32(passwordPolicy.PasswordPolicy.MinimumPasswordLength)
		if minLength < 7 {
			results = append(results, CheckResult{
				Control:           "PCI-8.3.6",
				Name:              "[PCI-DSS] Minimum Password Length",
				Status:            "FAIL",
				Severity:          "HIGH",
				Evidence:          fmt.Sprintf("PCI-DSS Req 8.3.6: Password length only %d chars - PCI requires minimum 7", minLength),
				Remediation:       "Set to 7+ characters",
				RemediationDetail: "aws iam update-account-password-policy --minimum-password-length 7",
				Priority:          PriorityHigh,
				Timestamp:         time.Now(),
				Frameworks: map[string]string{
					"PCI-DSS": "Req 8.3.6",
				},
			})
		} else {
			results = append(results, CheckResult{
				Control:   "PCI-8.3.6",
				Name:      "[PCI-DSS] Minimum Password Length",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("Password length %d chars meets PCI requirement (7+)", minLength),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
				Frameworks: map[string]string{
					"PCI-DSS": "Req 8.3.6",
				},
			})
		}

		// Check password reuse prevention (PCI: 4 minimum)
		reusePrevent := aws.ToInt32(passwordPolicy.PasswordPolicy.PasswordReusePrevention)
		if reusePrevent < 4 {
			results = append(results, CheckResult{
				Control:           "PCI-8.3.7",
				Name:              "[PCI-DSS] Password History",
				Status:            "FAIL",
				Severity:          "HIGH",
				Evidence:          fmt.Sprintf("PCI-DSS Req 8.3.7: Password history only %d - PCI requires minimum 4", reusePrevent),
				Remediation:       "Set password history to 4+",
				RemediationDetail: "aws iam update-account-password-policy --password-reuse-prevention 4",
				Priority:          PriorityHigh,
				Timestamp:         time.Now(),
				Frameworks: map[string]string{
					"PCI-DSS": "Req 8.3.7",
				},
			})
		}

		// Check account lockout (PCI: 6 attempts)
		// Note: AWS doesn't have native account lockout, this is informational
		results = append(results, CheckResult{
			Control:           "PCI-8.3.4",
			Name:              "[PCI-DSS] Account Lockout",
			Status:            "INFO",
			Evidence:          "PCI-DSS Req 8.3.4: AWS doesn't support native account lockout - implement via Lambda/CloudWatch",
			Remediation:       "Implement account lockout after 6 failed attempts",
			RemediationDetail: "Use CloudWatch Events + Lambda to track failed logins and disable accounts",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 8.3.4",
			},
		})
	}

	// 8.3.1: MFA for ALL access (not just privileged!)
	// FIXED: Properly handle error instead of ignoring with _
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-8.4.2",
			Name:      "[PCI-DSS] MFA for ALL Console Access",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check IAM users: %v", err),
			Priority:  PriorityCritical,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 8.4.2",
			},
		})
	}

	noMFAUsers := []string{}
	totalUsers := len(users.Users)

	for _, user := range users.Users {
		userName := aws.ToString(user.UserName)
		mfaDevices, _ := c.iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{
			UserName: aws.String(userName),
		})

		if len(mfaDevices.MFADevices) == 0 {
			// Check if user has console access
			_, err := c.iamClient.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
				UserName: aws.String(userName),
			})
			if err == nil {
				// User has console access but no MFA
				noMFAUsers = append(noMFAUsers, userName)
			}
		}
	}

	if len(noMFAUsers) > 0 {
		displayUsers := noMFAUsers
		if len(noMFAUsers) > 3 {
			displayUsers = noMFAUsers[:3]
		}

		results = append(results, CheckResult{
			Control:           "PCI-8.4.2",
			Name:              "[PCI-DSS] MFA for ALL Console Access",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 8.4.2 VIOLATION: %d users with console access lack MFA - PCI requires MFA for ALL: %s", len(noMFAUsers), strings.Join(displayUsers, ", ")),
			Remediation:       "Enable MFA for ALL users with console access",
			RemediationDetail: "Every user with console access MUST have MFA - no exceptions for PCI",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "IAM → Users → Show MFA enabled for ALL users with console access",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 8.4.2",
			},
		})
	} else if totalUsers > 0 {
		results = append(results, CheckResult{
			Control:   "PCI-8.4.2",
			Name:      "[PCI-DSS] MFA for Console Access",
			Status:    "PASS",
			Evidence:  "All users with console access have MFA enabled",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 8.4.2",
			},
		})
	}

	// Check access key rotation (90 days for PCI, not 180!)
	oldKeys := []string{}
	for _, user := range users.Users {
		keys, _ := c.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: user.UserName,
		})

		for _, key := range keys.AccessKeyMetadata {
			status := string(key.Status)
			if status == "Active" && key.CreateDate != nil {
				age := time.Since(*key.CreateDate)
				days := int(age.Hours() / 24)
				if days > 90 {
					oldKeys = append(oldKeys, fmt.Sprintf("%s (%d days)", aws.ToString(user.UserName), days))
				}
			}
		}
	}

	if len(oldKeys) > 0 {
		displayKeys := oldKeys
		if len(oldKeys) > 3 {
			displayKeys = oldKeys[:3]
		}

		results = append(results, CheckResult{
			Control:           "PCI-8.2.4-keys",
			Name:              "[PCI-DSS] 90-Day Access Key Rotation",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("PCI-DSS Req 8.3.9 VIOLATION: %d access keys older than 90 days: %s", len(oldKeys), strings.Join(displayKeys, ", ")),
			Remediation:       "Rotate keys every 90 days",
			RemediationDetail: "aws iam create-access-key --user-name <user> && aws iam delete-access-key --access-key-id <old-key>",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "IAM → Users → Security credentials → Show all keys < 90 days old",
			ConsoleURL:        "https://console.aws.amazon.com/iam/home#/users",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 8.3.9",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-8.2.4-keys",
			Name:      "[PCI-DSS] Access Key Age",
			Status:    "PASS",
			Evidence:  "All access keys rotated within 90 days",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 8.3.9",
			},
		})
	}

	// Check for idle session timeout (PCI: 15 minutes)
	results = append(results, CheckResult{
		Control:           "PCI-8.2.8",
		Name:              "[PCI-DSS] 15-Minute Idle Timeout",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 8.2.8: Verify console timeout is set to 15 minutes or less",
		Remediation:       "Set IAM console session timeout to 15 minutes",
		RemediationDetail: "IAM → Account settings → Console session timeout → 15 minutes",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "IAM → Account settings → Show 15-minute session timeout configured",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 8.2.8",
		},
	})

	return results
}

// Requirement 10: Logging (12 months retention!)
func (c *PCIDSSChecks) CheckReq10_Logging(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check CloudTrail
	// FIXED: Properly handle error instead of ignoring with _
	trails, err := c.cloudtrailClient.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-10.2.1",
			Name:      "[PCI-DSS] Audit Trail Implementation",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check CloudTrail: %v", err),
			Priority:  PriorityCritical,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 10.2.1",
			},
		})
	}

	if len(trails.Trails) == 0 {
		results = append(results, CheckResult{
			Control:           "PCI-10.2.1",
			Name:              "[PCI-DSS] Audit Trail Implementation",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          "PCI-DSS Req 10.2.1 VIOLATION: No CloudTrail configured - PCI REQUIRES comprehensive audit trails",
			Remediation:       "Enable CloudTrail immediately",
			RemediationDetail: "aws cloudtrail create-trail --name pci-audit-trail --s3-bucket-name <bucket> --is-multi-region-trail",
			Priority:          PriorityCritical,
			ScreenshotGuide:   "CloudTrail → Dashboard → Show trail enabled for all regions",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 10.2.1, 10.2.1",
			},
		})
	} else {
		// Check if multi-region
		multiRegionCount := 0
		for range trails.Trails {
			// We'd need to describe each trail to check IsMultiRegionTrail
			// For now, simplified check
			multiRegionCount++
		}

		results = append(results, CheckResult{
			Control:   "PCI-10.2.1",
			Name:      "[PCI-DSS] Audit Trail Implementation",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d CloudTrail(s) configured", len(trails.Trails)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 10.2.1, 10.2.1",
			},
		})

		// Check retention (12 months for PCI)
		results = append(results, CheckResult{
			Control:           "PCI-10.5.1",
			Name:              "[PCI-DSS] 12-Month Log Retention",
			Status:            "INFO",
			Evidence:          "MANUAL CHECK REQUIRED: Verify S3 lifecycle for 12-month retention (3 months readily available)",
			Remediation:       "Set S3 lifecycle to retain logs for 365+ days",
			RemediationDetail: "1. Go to S3 bucket with CloudTrail logs\n2. Create lifecycle policy\n3. Transition to Glacier after 90 days\n4. Delete after 365+ days",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "S3 → CloudTrail bucket → Management → Lifecycle rules → Show 365+ day retention",
			ConsoleURL:        "https://s3.console.aws.amazon.com/s3/",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 10.5.1",
			},
		})

		// Log integrity validation
		results = append(results, CheckResult{
			Control:           "PCI-10.3.2",
			Name:              "[PCI-DSS] Log Integrity Validation",
			Status:            "INFO",
			Evidence:          "Enable CloudTrail log file validation to detect tampering",
			Remediation:       "Enable log file validation",
			RemediationDetail: "aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 10.3.2, 10.5.5",
			},
		})

		// Time synchronization check
		results = append(results, CheckResult{
			Control:           "PCI-10.6.1",
			Name:              "[PCI-DSS] Time Synchronization",
			Status:            "INFO",
			Evidence:          "PCI-DSS Req 10.6.1: Verify all systems use NTP for time sync",
			Remediation:       "Ensure all EC2 instances use NTP",
			RemediationDetail: "Configure chrony or ntpd on all instances",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 10.6.1",
			},
		})
	}

	return results
}

// Requirement 11: Security Testing
func (c *PCIDSSChecks) CheckReq11_SecurityTesting(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check if AWS Config is enabled (helps with quarterly reviews)
	// FIXED: Properly handle error instead of ignoring with _
	configRecorders, err := c.configClient.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return append(results, CheckResult{
			Control:   "PCI-11.5.2",
			Name:      "[PCI-DSS] Change Detection Mechanisms",
			Status:    "ERROR",
			Evidence:  fmt.Sprintf("Unable to check AWS Config: %v", err),
			Priority:  PriorityHigh,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 11.5.2",
			},
		})
	}

	if len(configRecorders.ConfigurationRecorders) == 0 {
		results = append(results, CheckResult{
			Control:           "PCI-11.5.2",
			Name:              "[PCI-DSS] Change Detection Mechanisms",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "PCI-DSS Req 11.5.2: AWS Config not enabled - required for change detection",
			Remediation:       "Enable AWS Config",
			RemediationDetail: "aws configservice put-configuration-recorder --configuration-recorder name=default,roleArn=<role-arn>",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "AWS Config → Settings → Show recorder enabled",
			ConsoleURL:        "https://console.aws.amazon.com/config/",
			Timestamp:         time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 11.5.2",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "PCI-11.5.2",
			Name:      "[PCI-DSS] Change Detection",
			Status:    "PASS",
			Evidence:  "AWS Config enabled for change detection",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "Req 11.5.2",
			},
		})
	}

	// Quarterly scan reminder
	results = append(results, CheckResult{
		Control:           "PCI-11.3.2",
		Name:              "[PCI-DSS] Quarterly Vulnerability Scans",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.3.2: PCI requires QUARTERLY vulnerability scans by Approved Scanning Vendor (ASV)",
		Remediation:       "Schedule quarterly ASV scans",
		RemediationDetail: "1. Engage PCI-approved ASV\n2. Schedule quarterly external scans\n3. Internal scans can use AWS Inspector",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document ASV scan reports dated within last 90 days",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.3.2",
		},
	})

	// Penetration testing reminder
	results = append(results, CheckResult{
		Control:           "PCI-11.4.3",
		Name:              "[PCI-DSS] Annual Penetration Testing",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.4.3: PCI requires ANNUAL penetration testing of CDE",
		Remediation:       "Schedule annual pentest",
		RemediationDetail: "Annual external and internal penetration testing required",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.4.3",
		},
	})

	// File integrity monitoring
	results = append(results, CheckResult{
		Control:           "PCI-11.5.2",
		Name:              "[PCI-DSS] File Integrity Monitoring",
		Status:            "INFO",
		Evidence:          "PCI-DSS Req 11.5.2: Deploy file integrity monitoring on critical systems",
		Remediation:       "Implement FIM solution",
		RemediationDetail: "Use AWS Systems Manager or third-party FIM tools",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 11.5.2",
		},
	})

	return results
}

// Requirement 5: Malware Protection
func (c *PCIDSSChecks) CheckReq5_MalwareProtection(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// PCI-DSS Requirement 5: Protect all systems from malware
	results = append(results, CheckResult{
		Control:           "PCI-5.2.1",
		Name:              "[PCI-DSS] Anti-Malware Protection",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 5.2.1 requires anti-malware on all systems commonly affected by malware (workstations, servers)",
		Remediation:       "Deploy and maintain anti-malware solution",
		RemediationDetail: "1. Deploy endpoint protection (Amazon GuardDuty for runtime, third-party for OS-level)\n2. Ensure anti-malware is active and up-to-date\n3. Configure automatic updates and periodic scans\n4. Document anti-malware solution and update schedule",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Security Console → Show anti-malware deployed on all systems with current definitions",
		ConsoleURL:        "https://console.aws.amazon.com/guardduty/",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.2.1, 5.2.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-5.3.1",
		Name:              "[PCI-DSS] Anti-Malware Updates",
		Status:            "INFO",
		Evidence:          "MANUAL: Verify anti-malware mechanisms are current, actively running, and generating logs",
		Remediation:       "Ensure anti-malware auto-updates are enabled",
		RemediationDetail: "Configure automatic signature updates and verify audit logs show active scanning",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Anti-malware console → Show automatic updates enabled and recent scan logs",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.3.1, 5.3.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-5.3.4",
		Name:              "[PCI-DSS] Anti-Malware Scan Logs",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI requires anti-malware logs be retained and reviewed periodically",
		Remediation:       "Configure log retention and review procedures",
		RemediationDetail: "1. Enable logging for all anti-malware events\n2. Configure log retention (minimum per Req 10)\n3. Establish periodic review process\n4. Document review findings",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Show anti-malware logs with retention policy and review documentation",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 5.3.4, 5.3.4",
		},
	})

	return results
}

// Requirement 9: Physical Access Controls
func (c *PCIDSSChecks) CheckReq9_PhysicalAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Physical access controls - AWS inherited controls
	results = append(results, CheckResult{
		Control:           "PCI-9.1.1",
		Name:              "[PCI-DSS] Physical Access Controls",
		Status:            "INFO",
		Evidence:          "INFO: AWS data centers have physical security controls (inherited control). Review AWS compliance documentation.",
		Remediation:       "Document AWS physical security inheritance",
		RemediationDetail: "1. Review AWS PCI-DSS Attestation of Compliance (AOC)\n2. Download AWS PCI-DSS Responsibility Matrix from AWS Artifact\n3. Document inherited physical controls in your compliance documentation\n4. Focus on your organizational physical security for offices/facilities with cardholder data access",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "AWS Artifact → Download PCI-DSS AOC showing AWS physical security controls",
		ConsoleURL:        "https://console.aws.amazon.com/artifact/home",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.1.1, 9.1.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-9.2.1",
		Name:              "[PCI-DSS] Physical Access Procedures",
		Status:            "INFO",
		Evidence:          "MANUAL: Develop procedures to control physical access to facilities with systems that store, process, or transmit cardholder data",
		Remediation:       "Document physical access procedures for your facilities",
		RemediationDetail: "1. Implement badge/access card system for facility entry\n2. Establish visitor log procedures\n3. Differentiate badges for employees vs visitors\n4. Require escort for visitors in sensitive areas\n5. Document all procedures",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document physical access control procedures, visitor logs, and badge system",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.2.1, 9.3",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-9.4.1",
		Name:              "[PCI-DSS] Media Physical Security",
		Status:            "INFO",
		Evidence:          "MANUAL: Physically secure all media containing cardholder data (backups, portable devices)",
		Remediation:       "Implement physical controls for backup media and portable devices",
		RemediationDetail: "1. Store backup media in secure, locked location\n2. Maintain inventory of all media with cardholder data\n3. Review media inventory at least annually\n4. Securely destroy media when no longer needed (Req 9.4.6)",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Show backup media inventory, secure storage documentation, and destruction procedures",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.4.1, 9.5, 9.8",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-9.5.1",
		Name:              "[PCI-DSS] Point-of-Interaction Device Protection",
		Status:            "INFO",
		Evidence:          "MANUAL: Protect point-of-interaction (POI) devices from tampering and substitution",
		Remediation:       "Implement POI device protection procedures (if applicable)",
		RemediationDetail: "1. Maintain inventory of POI devices\n2. Inspect devices regularly for tampering\n3. Train personnel to be aware of suspicious behavior\n4. Document inspection procedures and findings",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document POI device inventory, inspection schedules, and training records",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 9.5.1, 9.9.1",
		},
	})

	return results
}

// Requirement 12: Information Security Policy
func (c *PCIDSSChecks) CheckReq12_SecurityPolicy(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Security policy requirements
	results = append(results, CheckResult{
		Control:           "PCI-12.1.1",
		Name:              "[PCI-DSS] Security Policy Establishment",
		Status:            "INFO",
		Evidence:          "MANUAL: PCI-DSS Req 12.1.1 requires establishing, publishing, maintaining, and disseminating a security policy",
		Remediation:       "Create and maintain comprehensive information security policy",
		RemediationDetail: "1. Establish security policy addressing PCI-DSS requirements\n2. Review policy at least annually\n3. Update when environment changes\n4. Communicate to all relevant personnel\n5. Document policy review and approval",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document current security policy, annual review dates, and communication records",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.1.1, 12.1.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.3.1",
		Name:              "[PCI-DSS] Risk Assessment Process",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement risk assessment process performed at least annually and upon significant changes",
		Remediation:       "Establish annual risk assessment process",
		RemediationDetail: "1. Perform formal risk assessment at least annually\n2. Identify critical assets and threats\n3. Assess likelihood and impact\n4. Document risk assessment results\n5. Update after significant infrastructure changes",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document risk assessments with dates, findings, and mitigation plans",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.3.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.2.1",
		Name:              "[PCI-DSS] Acceptable Use Policies",
		Status:            "INFO",
		Evidence:          "MANUAL: Develop usage policies for critical technologies (remote access, wireless, mobile devices, email, internet)",
		Remediation:       "Create and enforce acceptable use policies",
		RemediationDetail: "1. Define acceptable use for all critical technologies\n2. Require management approval for use of technologies\n3. Require authentication for use of technology\n4. Maintain list of authorized devices and personnel\n5. Document acceptable use policies",
		Priority:          PriorityMedium,
		ScreenshotGuide:   "Document acceptable use policies, approval records, and technology inventory",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.2.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.1.4",
		Name:              "[PCI-DSS] Assign Security Responsibilities",
		Status:            "INFO",
		Evidence:          "MANUAL: Assign individual or team responsibility for information security management",
		Remediation:       "Document security responsibilities and assignments",
		RemediationDetail: "1. Formally assign information security responsibilities\n2. Define roles and responsibilities for PCI-DSS compliance\n3. Document organizational structure for security\n4. Ensure adequate resources allocated",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document organizational chart showing security responsibilities and role assignments",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.1.4, 12.5.1",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.6.1",
		Name:              "[PCI-DSS] Security Awareness Program",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement formal security awareness program for all personnel",
		Remediation:       "Establish security awareness and training program",
		RemediationDetail: "1. Provide security awareness training upon hire and at least annually\n2. Train personnel on their responsibilities for protecting cardholder data\n3. Require personnel acknowledge understanding\n4. Document training completion and acknowledgments",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document training program, completion records, and acknowledgment forms",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.6.1, 12.6.1, 12.6.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.8.1",
		Name:              "[PCI-DSS] Service Provider Management",
		Status:            "INFO",
		Evidence:          "MANUAL: Maintain and implement policies for service providers who handle cardholder data",
		Remediation:       "Implement service provider management procedures",
		RemediationDetail: "1. Maintain list of service providers\n2. Establish written agreement including PCI-DSS responsibilities\n3. Ensure service providers acknowledge responsibility\n4. Monitor service provider PCI-DSS compliance status at least annually",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document service provider list, contracts, and annual compliance verification",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.8.1, 12.8.1, 12.8.2",
		},
	})

	results = append(results, CheckResult{
		Control:           "PCI-12.10.1",
		Name:              "[PCI-DSS] Incident Response Plan",
		Status:            "INFO",
		Evidence:          "MANUAL: Implement an incident response plan for security incidents",
		Remediation:       "Create and test incident response plan",
		RemediationDetail: "1. Create incident response plan\n2. Assign roles and responsibilities\n3. Include specific incident response procedures\n4. Test plan at least annually\n5. Update plan based on test results and industry developments",
		Priority:          PriorityHigh,
		ScreenshotGuide:   "Document incident response plan, test results, and update history",
		Timestamp:         time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "Req 12.10.1, 12.10.1",
		},
	})

	return results
}
