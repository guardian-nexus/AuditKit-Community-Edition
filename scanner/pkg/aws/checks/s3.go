package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Checks struct {
	client *s3.Client
}

func NewS3Checks(client *s3.Client) *S3Checks {
	return &S3Checks{client: client}
}

func (c *S3Checks) Name() string {
	return "S3 Bucket Security"
}

func (c *S3Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Existing checks
	if result, err := c.CheckPublicAccess(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckVersioning(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckLogging(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS checks
	if result, err := c.CheckMFADelete(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckServerAccessLogging(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckObjectLock(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckS3LifecyclePolicy(ctx); err == nil {
		results = append(results, result)
	}

	// Additional CIS AWS controls
	if result, err := c.CheckAccountPublicAccessBlock(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *S3Checks) CheckPublicAccess(ctx context.Context) (CheckResult, error) {
	resp, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.2",
			Name:       "S3 Public Access Block",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check S3 buckets: %v", err),
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("S3_PUBLIC_ACCESS"),
		}, err
	}

	if len(resp.Buckets) == 0 {
		return CheckResult{
			Control:    "CC6.2",
			Name:       "S3 Public Access Block",
			Status:     "PASS",
			Evidence:   "No S3 buckets found",
			Severity:   "INFO",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("S3_PUBLIC_ACCESS"),
		}, nil
	}

	publicBuckets := []string{}
	checkedCount := 0

	for _, bucket := range resp.Buckets {
		checkedCount++
		pab, err := c.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})

		isPublic := false
		if err != nil {
			// No public access block configured = potentially public
			isPublic = true
		} else if pab.PublicAccessBlockConfiguration == nil {
			isPublic = true
		} else {
			cfg := pab.PublicAccessBlockConfiguration
			if !aws.ToBool(cfg.BlockPublicAcls) ||
				!aws.ToBool(cfg.BlockPublicPolicy) ||
				!aws.ToBool(cfg.IgnorePublicAcls) ||
				!aws.ToBool(cfg.RestrictPublicBuckets) {
				isPublic = true
			}
		}

		if isPublic {
			publicBuckets = append(publicBuckets, *bucket.Name)
		}
	}

	if len(publicBuckets) > 0 {
		bucketList := strings.Join(publicBuckets, ", ")
		if len(publicBuckets) > 3 {
			bucketList = strings.Join(publicBuckets[:3], ", ") + fmt.Sprintf(" +%d more", len(publicBuckets)-3)
		}

		return CheckResult{
			Control:           "CC6.2",
			Name:              "S3 Public Access Block",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d/%d S3 buckets allow public access: %s | Violates PCI DSS 1.4.2 (no direct public access to cardholder data)", len(publicBuckets), checkedCount, bucketList),
			Remediation:       fmt.Sprintf("Block public access on bucket: %s\nRun: aws s3api put-public-access-block", publicBuckets[0]),
			RemediationDetail: fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", publicBuckets[0]),
			ScreenshotGuide:   "1. Open S3 Console\n2. Click on bucket '" + publicBuckets[0] + "'\n3. Go to 'Permissions' tab\n4. Screenshot 'Block public access' section\n5. All 4 options must show 'On'\n6. For PCI DSS: Document that cardholder data is NOT stored here",
			ConsoleURL:        fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s?tab=permissions", publicBuckets[0]),
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("S3_PUBLIC_ACCESS"),
		}, nil
	}

	return CheckResult{
		Control:         "CC6.2",
		Name:            "S3 Public Access Block",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("All %d S3 buckets block public access | Meets SOC2 CC6.2, PCI DSS 1.4.2, HIPAA 164.312(a)(1)", checkedCount),
		Severity:        "INFO",
		ScreenshotGuide: "1. Open S3 Console\n2. Click any bucket\n3. Go to 'Permissions' tab\n4. Screenshot showing all 'Block public access' settings ON",
		ConsoleURL:      "https://s3.console.aws.amazon.com/s3/buckets",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("S3_PUBLIC_ACCESS"),
	}, nil
}

func (c *S3Checks) CheckEncryption(ctx context.Context) (CheckResult, error) {
	resp, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unencryptedBuckets := []string{}
	checkedCount := 0

	for _, bucket := range resp.Buckets {
		checkedCount++
		_, err := c.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})

		if err != nil {
			// Error usually means no encryption configured
			unencryptedBuckets = append(unencryptedBuckets, *bucket.Name)
		}
	}

	if len(unencryptedBuckets) > 0 {
		bucketList := strings.Join(unencryptedBuckets, ", ")
		if len(unencryptedBuckets) > 3 {
			bucketList = strings.Join(unencryptedBuckets[:3], ", ") + fmt.Sprintf(" +%d more", len(unencryptedBuckets)-3)
		}

		return CheckResult{
			Control:           "CC6.3",
			Name:              "S3 Encryption at Rest",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d/%d S3 buckets lack encryption: %s | Violates PCI DSS 3.5.1 (encrypt stored cardholder data) & HIPAA 164.312(a)(2)(iv)", len(unencryptedBuckets), checkedCount, bucketList),
			Remediation:       fmt.Sprintf("Enable encryption on: %s\nRun: aws s3api put-bucket-encryption", unencryptedBuckets[0]),
			RemediationDetail: fmt.Sprintf("aws s3api put-bucket-encryption --bucket %s --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'", unencryptedBuckets[0]),
			ScreenshotGuide:   "1. Open S3 Console\n2. Click bucket '" + unencryptedBuckets[0] + "'\n3. Go to 'Properties' tab\n4. Scroll to 'Default encryption'\n5. Screenshot showing 'Server-side encryption: Enabled'\n6. For HIPAA: Note encryption algorithm (AES-256)",
			ConsoleURL:        fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s?tab=properties", unencryptedBuckets[0]),
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("S3_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "S3 Encryption at Rest",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d S3 buckets have encryption enabled | Meets SOC2 CC6.3, PCI DSS 3.5.1, HIPAA 164.312(a)(2)(iv)", checkedCount),
		Severity:   "INFO",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("S3_ENCRYPTION"),
	}, nil
}

func (c *S3Checks) CheckVersioning(ctx context.Context) (CheckResult, error) {
	resp, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noVersioning := []string{}

	for _, bucket := range resp.Buckets {
		versioning, err := c.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucket.Name,
		})

		if err != nil || versioning.Status != "Enabled" {
			noVersioning = append(noVersioning, *bucket.Name)
		}
	}

	if len(noVersioning) > 0 {
		firstBucket := noVersioning[0]
		return CheckResult{
			Control:           "A1.2",
			Name:              "S3 Versioning for Backup",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d buckets lack versioning (needed for data recovery) | Required for PCI DSS 10.3.4 (secure audit trails)", len(noVersioning)),
			Remediation:       fmt.Sprintf("Enable versioning on: %s", firstBucket),
			RemediationDetail: fmt.Sprintf("aws s3api put-bucket-versioning --bucket %s --versioning-configuration Status=Enabled", firstBucket),
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("S3_VERSIONING"),
			ScreenshotGuide:   "1. Open S3 Console\n2. Click bucket '" + firstBucket + "'\n3. Go to 'Properties' tab\n4. Screenshot 'Bucket Versioning' showing 'Enabled'",
			ConsoleURL:        fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s?tab=properties", firstBucket),
		}, nil
	}

	return CheckResult{
		Control:    "A1.2",
		Name:       "S3 Versioning for Backup",
		Status:     "PASS",
		Evidence:   "All buckets have versioning enabled | Meets SOC2 A1.2, PCI DSS 10.3.4, HIPAA 164.312(c)(1)",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("S3_VERSIONING"),
	}, nil
}

func (c *S3Checks) CheckLogging(ctx context.Context) (CheckResult, error) {
	resp, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC7.1",
			Name:       "S3 Access Logging",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check S3 buckets: %v", err),
			Severity:   "HIGH",
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("S3_LOGGING"),
		}, err
	}

	if len(resp.Buckets) == 0 {
		return CheckResult{
			Control:    "CC7.1",
			Name:       "S3 Access Logging",
			Status:     "PASS",
			Evidence:   "No S3 buckets found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("S3_LOGGING"),
		}, nil
	}

	bucketsWithoutLogging := []string{}
	checkedCount := 0

	for _, bucket := range resp.Buckets {
		checkedCount++
		logging, err := c.client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: bucket.Name,
		})

		// If error or no logging enabled, add to list
		if err != nil || logging.LoggingEnabled == nil {
			bucketsWithoutLogging = append(bucketsWithoutLogging, *bucket.Name)
		}
	}

	if len(bucketsWithoutLogging) > 0 {
		bucketList := strings.Join(bucketsWithoutLogging, ", ")
		if len(bucketsWithoutLogging) > 3 {
			bucketList = strings.Join(bucketsWithoutLogging[:3], ", ") + fmt.Sprintf(" +%d more", len(bucketsWithoutLogging)-3)
		}

		return CheckResult{
			Control:           "CC7.1",
			Name:              "S3 Access Logging",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d/%d S3 buckets lack access logging: %s | Violates PCI DSS 10.2.1 (audit trail requirements)", len(bucketsWithoutLogging), checkedCount, bucketList),
			Remediation:       fmt.Sprintf("Enable server access logging on bucket: %s", bucketsWithoutLogging[0]),
			RemediationDetail: fmt.Sprintf("aws s3api put-bucket-logging --bucket %s --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"my-log-bucket\",\"TargetPrefix\":\"%s/\"}}'", bucketsWithoutLogging[0], bucketsWithoutLogging[0]),
			ScreenshotGuide:   "1. Open S3 Console\n2. Click bucket '" + bucketsWithoutLogging[0] + "'\n3. Go to 'Properties' tab\n4. Scroll to 'Server access logging'\n5. Screenshot showing 'Server access logging: Enabled'\n6. For PCI DSS: Document log retention period",
			ConsoleURL:        fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s?tab=properties", bucketsWithoutLogging[0]),
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("S3_LOGGING"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.1",
		Name:       "S3 Access Logging",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d S3 buckets have access logging enabled | Meets SOC2 CC7.1, PCI DSS 10.2.1", checkedCount),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("S3_LOGGING"),
	}, nil
}

// NEW CIS-SPECIFIC CHECKS

// CIS 2.1.2 - Ensure S3 Bucket has MFA Delete enabled
func (c *S3Checks) CheckMFADelete(ctx context.Context) (CheckResult, error) {
	resp, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	bucketsWithoutMFADelete := []string{}

	for _, bucket := range resp.Buckets {
		versioning, err := c.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucket.Name,
		})

		if err != nil || versioning.MFADelete != "Enabled" {
			bucketsWithoutMFADelete = append(bucketsWithoutMFADelete, *bucket.Name)
		}
	}

	if len(bucketsWithoutMFADelete) > 0 {
		return CheckResult{
			Control:           "[CIS-2.1.2]",
			Name:              "S3 MFA Delete",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d S3 buckets lack MFA Delete protection", len(bucketsWithoutMFADelete)),
			Remediation:       "Enable MFA Delete on critical S3 buckets",
			RemediationDetail: "1. MFA Delete can only be enabled by root account\n2. Sign in as root with MFA\n3. Run: aws s3api put-bucket-versioning --bucket [BUCKET] --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::ACCOUNT:mfa/root-account-mfa-device MFACODE'",
			ScreenshotGuide:   "S3 Console → Bucket → Properties → Bucket Versioning → Screenshot showing 'MFA delete: Enabled'",
			ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("S3_MFA_DELETE"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-2.1.2]",
		Name:       "S3 MFA Delete",
		Status:     "PASS",
		Evidence:   "All S3 buckets have MFA Delete enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("S3_MFA_DELETE"),
	}, nil
}

// CIS 2.1.4 - Ensure S3 bucket logging is enabled
func (c *S3Checks) CheckServerAccessLogging(ctx context.Context) (CheckResult, error) {
	resp, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	bucketsWithoutLogging := []string{}

	for _, bucket := range resp.Buckets {
		_, err := c.client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: bucket.Name,
		})

		if err != nil {
			bucketsWithoutLogging = append(bucketsWithoutLogging, *bucket.Name)
		}
	}

	if len(bucketsWithoutLogging) > 0 {
		firstBucket := bucketsWithoutLogging[0]
		return CheckResult{
			Control:           "[CIS-2.1.4]",
			Name:              "S3 Server Access Logging",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d S3 buckets don't have access logging enabled: %s", len(bucketsWithoutLogging), firstBucket),
			Remediation:       "Enable S3 server access logging",
			RemediationDetail: fmt.Sprintf("aws s3api put-bucket-logging --bucket %s --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"my-log-bucket\",\"TargetPrefix\":\"%s/\"}}'", firstBucket, firstBucket),
			ScreenshotGuide:   "S3 Console → Bucket → Properties → Server access logging → Screenshot showing 'Enabled'",
			ConsoleURL:        fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s?tab=properties", firstBucket),
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("S3_LOGGING"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-2.1.4]",
		Name:       "S3 Server Access Logging",
		Status:     "PASS",
		Evidence:   "All S3 buckets have server access logging enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("S3_LOGGING"),
	}, nil
}

// CIS 2.1.6 - Ensure S3 bucket has Object Lock enabled (for compliance)
func (c *S3Checks) CheckObjectLock(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "[CIS-2.1.6]",
		Name:              "S3 Object Lock",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify S3 Object Lock is enabled for buckets storing compliance data",
		Remediation:       "Enable Object Lock on S3 buckets that require WORM (write-once-read-many) protection",
		RemediationDetail: "1. Object Lock can only be enabled during bucket creation\n2. Create new bucket with: aws s3api create-bucket --bucket [NAME] --object-lock-enabled-for-bucket\n3. Configure retention: aws s3api put-object-lock-configuration --bucket [NAME] --object-lock-configuration ...",
		ScreenshotGuide:   "S3 Console → Bucket → Properties → Object Lock → Screenshot showing 'Enabled' with retention configuration",
		ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets",
		Priority:          PriorityLow,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("S3_OBJECT_LOCK"),
	}, nil
}

// S3 Lifecycle Policies (informational)
func (c *S3Checks) CheckS3LifecyclePolicy(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "INFO",
		Name:              "S3 Lifecycle Policies",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify S3 buckets have appropriate lifecycle policies for data retention",
		Remediation:       "Configure lifecycle policies for data retention and cost optimization",
		RemediationDetail: "1. Identify buckets needing lifecycle management\n2. Create lifecycle policy based on retention requirements\n3. Configure transitions to IA/Glacier for cost savings\n4. Set expiration rules for compliance",
		ScreenshotGuide:   "S3 Console → Bucket → Management → Lifecycle rules → Screenshot showing configured lifecycle policies",
		ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("S3_LIFECYCLE"),
	}, nil
}

// CheckAccountPublicAccessBlock verifies S3 Block Public Access is enabled at account level (CIS 2.1.7)
func (c *S3Checks) CheckAccountPublicAccessBlock(ctx context.Context) (CheckResult, error) {
	// Get account-level public access block configuration
	config, err := c.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{})
	if err != nil {
		// If error is "NoSuchPublicAccessBlockConfiguration", it means it's not configured
		if strings.Contains(err.Error(), "NoSuchPublicAccessBlockConfiguration") {
			return CheckResult{
				Control:     "[CIS-2.1.7]",
				Name:        "S3 Account Public Access Block",
				Status:      "FAIL",
				Severity:    "CRITICAL",
				Evidence:    "S3 Block Public Access is NOT configured at account level | Violates CIS 2.1.7 (account-wide protection missing)",
				Remediation: "Enable S3 Block Public Access for the entire AWS account",
				RemediationDetail: `# Enable S3 Block Public Access at account level
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# This protects all S3 buckets in the account from public access`,
				ScreenshotGuide: "S3 Console → Block Public Access settings for this account → Screenshot showing ALL 4 settings enabled",
				ConsoleURL:      "https://s3.console.aws.amazon.com/s3/settings",
				Priority:        PriorityCritical,
				Timestamp:       time.Now(),
				Frameworks:      map[string]string{"CIS-AWS": "2.1.7", "SOC2": "CC6.1", "PCI-DSS": "1.4.2"},
			}, nil
		}

		return CheckResult{
			Control:    "[CIS-2.1.7]",
			Name:       "S3 Account Public Access Block",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check account-level public access block: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "2.1.7", "SOC2": "CC6.1"},
		}, nil
	}

	// Check if all 4 settings are enabled
	pab := config.PublicAccessBlockConfiguration
	allEnabled := pab.BlockPublicAcls != nil && *pab.BlockPublicAcls &&
		pab.IgnorePublicAcls != nil && *pab.IgnorePublicAcls &&
		pab.BlockPublicPolicy != nil && *pab.BlockPublicPolicy &&
		pab.RestrictPublicBuckets != nil && *pab.RestrictPublicBuckets

	if !allEnabled {
		settings := []string{}
		if pab.BlockPublicAcls == nil || !*pab.BlockPublicAcls {
			settings = append(settings, "BlockPublicAcls=false")
		}
		if pab.IgnorePublicAcls == nil || !*pab.IgnorePublicAcls {
			settings = append(settings, "IgnorePublicAcls=false")
		}
		if pab.BlockPublicPolicy == nil || !*pab.BlockPublicPolicy {
			settings = append(settings, "BlockPublicPolicy=false")
		}
		if pab.RestrictPublicBuckets == nil || !*pab.RestrictPublicBuckets {
			settings = append(settings, "RestrictPublicBuckets=false")
		}

		return CheckResult{
			Control:     "[CIS-2.1.7]",
			Name:        "S3 Account Public Access Block",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("S3 Block Public Access not fully enabled: %s | Violates CIS 2.1.7", strings.Join(settings, ", ")),
			Remediation: "Enable all 4 Block Public Access settings at account level",
			RemediationDetail: `aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
			ScreenshotGuide: "S3 Console → Block Public Access settings → Screenshot showing ALL 4 checkboxes enabled",
			ConsoleURL:      "https://s3.console.aws.amazon.com/s3/settings",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "2.1.7", "SOC2": "CC6.1", "PCI-DSS": "1.4.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-2.1.7]",
		Name:       "S3 Account Public Access Block",
		Status:     "PASS",
		Evidence:   "S3 Block Public Access is enabled at account level (all 4 settings) | Meets CIS 2.1.7",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "2.1.7", "SOC2": "CC6.1", "PCI-DSS": "1.4.2"},
	}, nil
}
