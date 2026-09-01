package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// CC6: Logical and Physical Access Controls (8 criteria)
// This is the meat of SOC2 - access control

type CC6Checks struct {
	iamClient        *iam.Client
	ec2Client        *ec2.Client
	s3Client         *s3.Client
	cloudtrailClient *cloudtrail.Client
}

func NewCC6Checks(iamClient *iam.Client, ec2Client *ec2.Client, s3Client *s3.Client, cloudtrailClient *cloudtrail.Client) *CC6Checks {
	return &CC6Checks{
		iamClient:        iamClient,
		ec2Client:        ec2Client,
		s3Client:         s3Client,
		cloudtrailClient: cloudtrailClient,
	}
}

func (c *CC6Checks) Name() string {
	return "SOC2 CC6 Checks"
}

func (c *CC6Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC6.1: Logical and Physical Access Controls
	results = append(results, c.CheckCC6_1_AccessControls(ctx)...)

	// CC6.2: Prior to Issuing System Credentials
	results = append(results, c.CheckCC6_2_CredentialIssuance(ctx)...)

	// CC6.3: Manages Points of Access
	results = append(results, c.CheckCC6_3_AccessPoints(ctx)...)

	// CC6.4: Restricts Access to Information Assets
	results = append(results, c.CheckCC6_4_AssetAccess(ctx)...)

	// CC6.5: Discontinues Logical and Physical Protections
	results = append(results, c.CheckCC6_5_AccessRemoval(ctx)...)

	// CC6.6: Prevents Unauthorized Access
	results = append(results, c.CheckCC6_6_UnauthorizedPrevention(ctx)...)

	// CC6.7: Authenticates Users
	results = append(results, c.CheckCC6_7_Authentication(ctx)...)

	// CC6.8: Prevents Unauthorized Modification
	results = append(results, c.CheckCC6_8_ModificationPrevention(ctx)...)

	return results, nil
}

func (c *CC6Checks) CheckCC6_1_AccessControls(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check security groups for network access control
	sgs, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil || sgs == nil {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "Network Access Controls",
			Status:    "ERROR",
			Evidence:  "Unable to check security groups",
			Priority:  PriorityHigh,
			Timestamp: time.Now(),
		})
		return results
	}

	openToWorld := 0
	adminPortsOpen := 0

	for _, sg := range sgs.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			for _, ipRange := range rule.IpRanges {
				if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
					openToWorld++

					// Check for admin ports
					if rule.FromPort != nil {
						port := aws.ToInt32(rule.FromPort)
						if port == 22 || port == 3389 || port == 3306 || port == 5432 {
							adminPortsOpen++
						}
					}
				}
			}
		}
	}

	if adminPortsOpen > 0 {
		results = append(results, CheckResult{
			Control:         "CC6.1",
			Name:            "Network Access Controls - Admin Ports",
			Status:          "FAIL",
			Severity:        "CRITICAL",
			Evidence:        fmt.Sprintf("CRITICAL: %d security groups with admin ports open to internet", adminPortsOpen),
			Remediation:     "Restrict SSH/RDP/database ports to specific IPs only",
			ScreenshotGuide: "1. Go to EC2 → Security Groups\n2. Review inbound rules\n3. Remove 0.0.0.0/0 from ports 22, 3389, 3306",
			ConsoleURL:      "https://console.aws.amazon.com/ec2/v2/home#SecurityGroups",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
		})
	} else if openToWorld > 5 {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Network Access Controls",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d security group rules open to 0.0.0.0/0", openToWorld),
			Remediation: "Review and restrict security group rules",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "Network Access Controls",
			Status:    "PASS",
			Evidence:  "Security groups properly restrict network access",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results
}

func (c *CC6Checks) CheckCC6_2_CredentialIssuance(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check IAM user creation and onboarding
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		results = append(results, CheckResult{
			Control:   "CC6.2",
			Name:      "User Credential Issuance Process",
			Status:    "ERROR",
			Evidence:  "Unable to check IAM users",
			Priority:  PriorityHigh,
			Timestamp: time.Now(),
		})
		return results
	}

	if users != nil && users.Users != nil {
		recentUsers := 0
		for _, user := range users.Users {
			if user.CreateDate != nil {
				age := time.Since(*user.CreateDate)
				if age.Hours()/24 < 30 { // Users created in last 30 days
					recentUsers++
				}
			}
		}

		if recentUsers > 0 {
			results = append(results, CheckResult{
				Control:   "CC6.2",
				Name:      "User Credential Issuance Process",
				Status:    "INFO",
				Evidence:  fmt.Sprintf("%d users created in last 30 days - verify approval process", recentUsers),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}

		// Check for service accounts with long-lived credentials
		serviceAccounts := 0
		for _, user := range users.Users {
			name := strings.ToLower(aws.ToString(user.UserName))
			if strings.Contains(name, "service") || strings.Contains(name, "bot") || strings.Contains(name, "app") {
				serviceAccounts++
			}
		}

		if serviceAccounts > 5 {
			results = append(results, CheckResult{
				Control:     "CC6.2",
				Name:        "Service Account Management",
				Status:      "FAIL",
				Severity:    "MEDIUM",
				Evidence:    fmt.Sprintf("%d service accounts detected - consider using IAM roles instead", serviceAccounts),
				Remediation: "Replace service account users with IAM roles for applications",
				Priority:    PriorityMedium,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

func (c *CC6Checks) CheckCC6_3_AccessPoints(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check VPC endpoints (secure access points)
	vpcs, _ := c.ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	endpoints, _ := c.ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})

	if vpcs != nil && len(vpcs.Vpcs) > 0 {
		if endpoints == nil || len(endpoints.VpcEndpoints) == 0 {
			results = append(results, CheckResult{
				Control:         "CC6.3",
				Name:            "Secure Access Points",
				Status:          "FAIL",
				Severity:        "MEDIUM",
				Evidence:        fmt.Sprintf("%d VPCs but no VPC endpoints - traffic goes over public internet", len(vpcs.Vpcs)),
				Remediation:     "Create VPC endpoints for AWS services (S3, DynamoDB, etc.)",
				ScreenshotGuide: "1. Go to VPC → Endpoints\n2. Create endpoints for S3, DynamoDB\n3. Route table associations",
				Priority:        PriorityMedium,
				Timestamp:       time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:   "CC6.3",
				Name:      "Secure Access Points",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%d VPC endpoints configured for secure service access", len(endpoints.VpcEndpoints)),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	}

	return results
}

func (c *CC6Checks) CheckCC6_4_AssetAccess(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check S3 bucket public access
	buckets, _ := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if buckets != nil && buckets.Buckets != nil {
		publicBuckets := 0
		for _, bucket := range buckets.Buckets {
			acl, _ := c.s3Client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
				Bucket: bucket.Name,
			})
			if acl != nil {
				for _, grant := range acl.Grants {
					if grant.Grantee != nil && grant.Grantee.URI != nil {
						uri := aws.ToString(grant.Grantee.URI)
						if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
							publicBuckets++
							break
						}
					}
				}
			}
		}

		if publicBuckets > 0 {
			results = append(results, CheckResult{
				Control:     "CC6.4",
				Name:        "Asset Access Restrictions",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    fmt.Sprintf("[HIGH] %d S3 buckets with public access", publicBuckets),
				Remediation: "Remove public access from S3 buckets unless absolutely necessary",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:   "CC6.4",
				Name:      "Asset Access Restrictions",
				Status:    "PASS",
				Evidence:  "All S3 buckets properly restrict public access",
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	}

	return results
}

func (c *CC6Checks) CheckCC6_5_AccessRemoval(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for inactive users that should be removed
	users, err := c.iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		results = append(results, CheckResult{
			Control:   "CC6.5",
			Name:      "Access Removal Process",
			Status:    "ERROR",
			Evidence:  "Unable to check IAM users for inactive accounts",
			Priority:  PriorityMedium,
			Timestamp: time.Now(),
		})
		return results
	}

	inactiveUsers := 0

	if users != nil && users.Users != nil {
		for _, user := range users.Users {
			// Get user's last activity
			accessKeys, _ := c.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: user.UserName,
			})

			hasOldKey := false
			if accessKeys != nil && accessKeys.AccessKeyMetadata != nil {
				for _, key := range accessKeys.AccessKeyMetadata {
					if key.CreateDate != nil {
						age := time.Since(*key.CreateDate)
						if age.Hours()/24 > 90 { // Keys older than 90 days
							hasOldKey = true
							break
						}
					}
				}
			}

			if hasOldKey {
				inactiveUsers++
			}
		}
	}

	if inactiveUsers > 0 {
		results = append(results, CheckResult{
			Control:     "CC6.5",
			Name:        "Access Removal - Inactive Users",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d users with access keys older than 90 days", inactiveUsers),
			Remediation: "Review and rotate old access keys or remove inactive users",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.5",
			Name:      "Access Removal Process",
			Status:    "PASS",
			Evidence:  "No inactive users with old credentials detected",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results
}

func (c *CC6Checks) CheckCC6_6_UnauthorizedPrevention(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check CloudTrail for unauthorized access monitoring
	trails, _ := c.cloudtrailClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if trails == nil || trails.TrailList == nil || len(trails.TrailList) == 0 {
		results = append(results, CheckResult{
			Control:     "CC6.6",
			Name:        "Unauthorized Access Prevention",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    "No CloudTrail configured - cannot detect unauthorized access",
			Remediation: "Enable CloudTrail for all regions",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
		})
	} else {
		multiRegionTrail := false
		for _, trail := range trails.TrailList {
			if trail.IsMultiRegionTrail != nil && *trail.IsMultiRegionTrail {
				multiRegionTrail = true
				break
			}
		}

		if !multiRegionTrail {
			results = append(results, CheckResult{
				Control:     "CC6.6",
				Name:        "Unauthorized Access Prevention",
				Status:      "FAIL",
				Severity:    "MEDIUM",
				Evidence:    "CloudTrail not enabled for all regions",
				Remediation: "Enable multi-region CloudTrail",
				Priority:    PriorityMedium,
				Timestamp:   time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:   "CC6.6",
				Name:      "Unauthorized Access Prevention",
				Status:    "PASS",
				Evidence:  "Multi-region CloudTrail enabled for unauthorized access detection",
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	}

	return results
}

func (c *CC6Checks) CheckCC6_7_Authentication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check IAM password policy
	policy, err := c.iamClient.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil || policy == nil || policy.PasswordPolicy == nil {
		results = append(results, CheckResult{
			Control:     "CC6.7",
			Name:        "Authentication Requirements",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    "No password policy configured",
			Remediation: "Configure strong IAM password policy",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
		})
		return results
	}

	weakPolicy := false
	minLength := int32(14)

	if policy.PasswordPolicy.MinimumPasswordLength != nil {
		if *policy.PasswordPolicy.MinimumPasswordLength < minLength {
			weakPolicy = true
		}
	} else {
		weakPolicy = true
	}

	if !policy.PasswordPolicy.RequireUppercaseCharacters {
		weakPolicy = true
	}

	if !policy.PasswordPolicy.RequireLowercaseCharacters {
		weakPolicy = true
	}

	if !policy.PasswordPolicy.RequireNumbers {
		weakPolicy = true
	}

	if weakPolicy {
		results = append(results, CheckResult{
			Control:     "CC6.7",
			Name:        "Password Policy Strength",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    "Password policy does not meet minimum requirements",
			Remediation: fmt.Sprintf("Set minimum %d characters with complexity requirements", minLength),
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
		})
	} else {
		minLengthValue := int32(8)
		if policy.PasswordPolicy.MinimumPasswordLength != nil {
			minLengthValue = *policy.PasswordPolicy.MinimumPasswordLength
		}
		results = append(results, CheckResult{
			Control:   "CC6.7",
			Name:      "Password Policy Strength",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("Password policy requires %d+ characters with complexity", minLengthValue),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results
}

func (c *CC6Checks) CheckCC6_8_ModificationPrevention(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check S3 versioning for data modification tracking
	buckets, _ := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if buckets != nil && buckets.Buckets != nil && len(buckets.Buckets) > 0 {
		versionedBuckets := 0
		for _, bucket := range buckets.Buckets {
			versioning, _ := c.s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
				Bucket: bucket.Name,
			})
			if versioning != nil && versioning.Status == "Enabled" {
				versionedBuckets++
			}
		}

		percentage := float64(versionedBuckets) / float64(len(buckets.Buckets)) * 100

		if percentage < 50 {
			results = append(results, CheckResult{
				Control:     "CC6.8",
				Name:        "Data Modification Prevention",
				Status:      "FAIL",
				Severity:    "MEDIUM",
				Evidence:    fmt.Sprintf("Only %.0f%% of S3 buckets have versioning enabled", percentage),
				Remediation: "Enable versioning on all S3 buckets",
				Priority:    PriorityMedium,
				Timestamp:   time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:   "CC6.8",
				Name:      "Data Modification Prevention",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%.0f%% of S3 buckets have versioning for modification tracking", percentage),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.8",
			Name:      "Data Modification Prevention",
			Status:    "INFO",
			Evidence:  "No S3 buckets to check",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results
}

// CC7: System Operations (4 criteria)
// How the system is monitored and maintained

type CC7Checks struct {
	cloudtrailClient *cloudtrail.Client
	ssmClient        *ssm.Client
	lambdaClient     *lambda.Client
}

func NewCC7Checks(cloudtrailClient *cloudtrail.Client, ssmClient *ssm.Client, lambdaClient *lambda.Client) *CC7Checks {
	return &CC7Checks{
		cloudtrailClient: cloudtrailClient,
		ssmClient:        ssmClient,
		lambdaClient:     lambdaClient,
	}
}

func (c *CC7Checks) Name() string {
	return "SOC2 CC7 Checks"
}

func (c *CC7Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC7.1: Monitors the System
	results = append(results, c.CheckCC7_1_Monitoring(ctx)...)

	// CC7.2: Monitors Anomalies
	results = append(results, c.CheckCC7_2_AnomalyDetection(ctx)...)

	// CC7.3: Evaluates Security Events
	results = append(results, c.CheckCC7_3_SecurityEvents(ctx)...)

	// CC7.4: Responds to Anomalies and Security Events
	results = append(results, c.CheckCC7_4_IncidentResponse(ctx)...)

	return results, nil
}

func (c *CC7Checks) CheckCC7_1_Monitoring(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check CloudTrail logging
	trails, _ := c.cloudtrailClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if trails != nil && trails.TrailList != nil && len(trails.TrailList) > 0 {
		enabledTrails := 0
		for _, trail := range trails.TrailList {
			status, _ := c.cloudtrailClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
				Name: trail.Name,
			})
			if status != nil && status.IsLogging != nil && *status.IsLogging {
				enabledTrails++
			}
		}

		if enabledTrails == 0 {
			results = append(results, CheckResult{
				Control:     "CC7.1",
				Name:        "System Monitoring",
				Status:      "FAIL",
				Severity:    "CRITICAL",
				Evidence:    "CloudTrail exists but logging is disabled",
				Remediation: "Enable CloudTrail logging immediately",
				Priority:    PriorityCritical,
				Timestamp:   time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:   "CC7.1",
				Name:      "System Monitoring",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%d CloudTrail(s) actively logging", enabledTrails),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	} else {
		results = append(results, CheckResult{
			Control:     "CC7.1",
			Name:        "System Monitoring",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    "No CloudTrail configured",
			Remediation: "Enable CloudTrail for comprehensive logging",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
		})
	}

	return results
}

func (c *CC7Checks) CheckCC7_2_AnomalyDetection(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check if Lambda functions exist for anomaly detection
	functions, _ := c.lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{})
	anomalyFunctions := 0

	if functions != nil && functions.Functions != nil {
		for _, fn := range functions.Functions {
			name := strings.ToLower(aws.ToString(fn.FunctionName))
			if strings.Contains(name, "anomaly") || strings.Contains(name, "detect") || strings.Contains(name, "alert") {
				anomalyFunctions++
			}
		}
	}

	if anomalyFunctions > 0 {
		results = append(results, CheckResult{
			Control:   "CC7.2",
			Name:      "Anomaly Detection",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d Lambda functions potentially for anomaly detection", anomalyFunctions),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:     "CC7.2",
			Name:        "Anomaly Detection",
			Status:      "INFO",
			Evidence:    "No automated anomaly detection functions found",
			Remediation: "Consider implementing Lambda-based anomaly detection",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
		})
	}

	return results
}

func (c *CC7Checks) CheckCC7_3_SecurityEvents(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check SSM for security patching
	if c.ssmClient != nil {
		patches, _ := c.ssmClient.DescribePatchGroups(ctx, &ssm.DescribePatchGroupsInput{})

		if patches != nil && patches.Mappings != nil && len(patches.Mappings) > 0 {
			results = append(results, CheckResult{
				Control:   "CC7.3",
				Name:      "Security Event Management",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%d patch groups configured for security updates", len(patches.Mappings)),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:     "CC7.3",
				Name:        "Security Event Management - Patching",
				Status:      "FAIL",
				Severity:    "MEDIUM",
				Evidence:    "No patch groups configured in Systems Manager",
				Remediation: "Configure SSM Patch Manager for automated security patching",
				Priority:    PriorityMedium,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

func (c *CC7Checks) CheckCC7_4_IncidentResponse(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// In AWS context, we rely on AWS's physical security
	results = append(results, CheckResult{
		Control:   "CC7.4",
		Name:      "Incident Response Planning",
		Status:    "INFO",
		Evidence:  "Manual review required: Verify incident response procedures are documented",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	})

	return results
}

// CC8: Change Management (1 criteria)
// How changes are controlled

type CC8Checks struct {
	lambdaClient *lambda.Client
	ec2Client    *ec2.Client
}

func NewCC8Checks(lambdaClient *lambda.Client, ec2Client *ec2.Client) *CC8Checks {
	return &CC8Checks{
		lambdaClient: lambdaClient,
		ec2Client:    ec2Client,
	}
}

func (c *CC8Checks) Name() string {
	return "SOC2 CC8 Checks"
}

func (c *CC8Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC8.1: Authorizes, Designs, Develops, Configures, Documents, Tests, Approves, and Implements Changes
	results = append(results, c.CheckCC8_1_ChangeManagement(ctx)...)

	return results, nil
}

func (c *CC8Checks) CheckCC8_1_ChangeManagement(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check Lambda function versioning (change tracking)
	if c.lambdaClient != nil {
		functions, _ := c.lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{})

		if functions != nil && functions.Functions != nil && len(functions.Functions) > 0 {
			versionedFunctions := 0
			for _, fn := range functions.Functions {
				versions, _ := c.lambdaClient.ListVersionsByFunction(ctx, &lambda.ListVersionsByFunctionInput{
					FunctionName: fn.FunctionName,
				})
				if versions != nil && versions.Versions != nil && len(versions.Versions) > 1 {
					versionedFunctions++
				}
			}

			percentage := float64(versionedFunctions) / float64(len(functions.Functions)) * 100

			if percentage < 50 {
				results = append(results, CheckResult{
					Control:     "CC8.1",
					Name:        "Change Management - Function Versioning",
					Status:      "FAIL",
					Severity:    "MEDIUM",
					Evidence:    fmt.Sprintf("Only %.0f%% of Lambda functions have version tracking", percentage),
					Remediation: "Enable versioning for all Lambda functions",
					Priority:    PriorityMedium,
					Timestamp:   time.Now(),
				})
			} else {
				results = append(results, CheckResult{
					Control:   "CC8.1",
					Name:      "Change Management - Function Versioning",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("%.0f%% of Lambda functions have proper version tracking", percentage),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			}
		}
	}

	// Check EC2 AMIs for image management
	images, _ := c.ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})

	if images != nil && images.Images != nil && len(images.Images) > 0 {
		results = append(results, CheckResult{
			Control:   "CC8.1",
			Name:      "Change Management - AMI Management",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("%d AMIs maintained for change control", len(images.Images)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	} else {
		results = append(results, CheckResult{
			Control:     "CC8.1",
			Name:        "Change Management - AMI Management",
			Status:      "INFO",
			Evidence:    "No custom AMIs found - consider creating golden images",
			Remediation: "Create and maintain AMIs for consistent deployments",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
		})
	}

	return results
}

// CC9: Risk Mitigation (1 criteria)
// Ensuring risks are properly addressed

type CC9Checks struct {
	rdsClient *rds.Client
	s3Client  *s3.Client
}

func NewCC9Checks(rdsClient *rds.Client, s3Client *s3.Client) *CC9Checks {
	return &CC9Checks{
		rdsClient: rdsClient,
		s3Client:  s3Client,
	}
}

func (c *CC9Checks) Name() string {
	return "SOC2 CC9 Checks"
}

func (c *CC9Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC9.1: Identifies and Assesses Risk from Vendors and Business Partners
	results = append(results, c.CheckCC9_1_VendorRisk(ctx)...)

	// CC9.2: Assesses and Manages Risk Associated with Vendors and Business Partners
	results = append(results, c.CheckCC9_2_VendorManagement(ctx)...)

	return results, nil
}

func (c *CC9Checks) CheckCC9_1_VendorRisk(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check RDS for database encryption (data at rest protection)
	databases, _ := c.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if databases != nil && databases.DBInstances != nil && len(databases.DBInstances) > 0 {
		encryptedDBs := 0
		for _, db := range databases.DBInstances {
			if db.StorageEncrypted != nil && *db.StorageEncrypted {
				encryptedDBs++
			}
		}

		percentage := float64(encryptedDBs) / float64(len(databases.DBInstances)) * 100

		if percentage < 100 {
			results = append(results, CheckResult{
				Control:     "CC9.1",
				Name:        "Data Protection - Database Encryption",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    fmt.Sprintf("Only %.0f%% of RDS instances are encrypted", percentage),
				Remediation: "Enable encryption for all RDS databases",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:   "CC9.1",
				Name:      "Data Protection - Database Encryption",
				Status:    "PASS",
				Evidence:  "All RDS databases are encrypted at rest",
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	}

	return results
}

func (c *CC9Checks) CheckCC9_2_VendorManagement(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check S3 for encryption (vendor data protection)
	buckets, _ := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if buckets != nil && buckets.Buckets != nil && len(buckets.Buckets) > 0 {
		encryptedBuckets := 0
		for _, bucket := range buckets.Buckets {
			encryption, _ := c.s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
				Bucket: bucket.Name,
			})
			if encryption != nil && encryption.ServerSideEncryptionConfiguration != nil {
				encryptedBuckets++
			}
		}

		percentage := float64(encryptedBuckets) / float64(len(buckets.Buckets)) * 100

		if percentage < 100 {
			results = append(results, CheckResult{
				Control:     "CC9.2",
				Name:        "Vendor Data Management - S3 Encryption",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    fmt.Sprintf("Only %.0f%% of S3 buckets have encryption enabled", percentage),
				Remediation: "Enable default encryption for all S3 buckets",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:   "CC9.2",
				Name:      "Vendor Data Management - S3 Encryption",
				Status:    "PASS",
				Evidence:  "All S3 buckets have encryption enabled",
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	}

	return results
}
