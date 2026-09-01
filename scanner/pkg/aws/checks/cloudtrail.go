package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

type CloudTrailChecks struct {
	client *cloudtrail.Client
}

func NewCloudTrailChecks(client *cloudtrail.Client) *CloudTrailChecks {
	return &CloudTrailChecks{client: client}
}

func (c *CloudTrailChecks) Name() string {
	return "CloudTrail Logging"
}

func (c *CloudTrailChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Existing checks
	if result, err := c.CheckTrailEnabled(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckMultiRegion(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckLogFileValidation(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS checks
	if result, err := c.CheckCloudTrailEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckCloudTrailLogIntegration(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckS3BucketAccessLogging(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckCloudTrailLogValidation(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckCloudTrailS3BucketPolicy(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckCloudTrailKMSKey(ctx); err == nil {
		results = append(results, result)
	}

	// Additional CIS AWS controls
	if result, err := c.CheckS3ObjectLevelLoggingWrite(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckS3ObjectLevelLoggingRead(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *CloudTrailChecks) CheckTrailEnabled(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC7.1",
			Name:       "CloudTrail Logging Enabled",
			Status:     "FAIL",
			Evidence:   "Unable to check CloudTrail status",
			Severity:   "CRITICAL",
			Priority:   PriorityCritical,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
		}, err
	}

	if len(trails.Trails) == 0 {
		return CheckResult{
			Control:         "CC7.1",
			Name:            "CloudTrail Logging Enabled",
			Status:          "FAIL",
			Severity:        "CRITICAL",
			Evidence:        "CRITICAL: NO CloudTrail configured! Zero audit logging | Violates PCI DSS 10.2.1 (implement audit trails) & HIPAA 164.312(b)",
			Remediation:     "aws cloudtrail create-trail --name audit-trail --s3-bucket-name YOUR_BUCKET && aws cloudtrail start-logging --name audit-trail",
			ScreenshotGuide: "1. Go to CloudTrail Console\n2. Click 'Create trail'\n3. Enable for all regions\n4. Screenshot showing trail is 'Logging' status\n5. This is MANDATORY for SOC2, PCI, and HIPAA!",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
		}, nil
	}

	// Check if at least one trail is logging
	activeTrails := 0
	for _, trail := range trails.Trails {
		status, err := c.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err == nil && aws.ToBool(status.IsLogging) {
			activeTrails++
		}
	}

	if activeTrails == 0 {
		return CheckResult{
			Control:         "CC7.1",
			Name:            "CloudTrail Logging Enabled",
			Status:          "FAIL",
			Severity:        "CRITICAL",
			Evidence:        fmt.Sprintf("CloudTrail exists but is NOT logging! (%d trails configured, 0 active) | Fails PCI DSS 10.2.1.1", len(trails.Trails)),
			Remediation:     "aws cloudtrail start-logging --name YOUR_TRAIL_NAME",
			ScreenshotGuide: "1. Go to CloudTrail → Trails\n2. Click on your trail\n3. Click 'Start logging'\n4. Screenshot showing 'Logging: ON'\n5. For PCI: Document log retention period (90+ days required)",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
		}, nil
	}

	return CheckResult{
		Control:         "CC7.1",
		Name:            "CloudTrail Logging Enabled",
		Status:          "PASS",
		Evidence:        fmt.Sprintf("%d CloudTrail(s) actively logging API calls | Meets SOC2 CC7.1, PCI DSS 10.2.1, HIPAA 164.312(b)", activeTrails),
		Severity:        "INFO",
		ScreenshotGuide: "1. Go to CloudTrail → Trails\n2. Screenshot showing your trail(s) with 'Logging: ON'\n3. Click into trail and screenshot configuration\n4. For PCI: Show retention settings",
		ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
		Priority:        PriorityInfo,
		Timestamp:       time.Now(),
		Frameworks:      GetFrameworkMappings("CLOUDTRAIL_ENABLED"),
	}, nil
}

func (c *CloudTrailChecks) CheckMultiRegion(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	multiRegionTrails := 0
	for _, trail := range trails.Trails {
		// Get trail details
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if aws.ToBool(details.TrailList[0].IsMultiRegionTrail) {
				multiRegionTrails++
			}
		}
	}

	if multiRegionTrails == 0 {
		return CheckResult{
			Control:         "CIS-3.1, CC7.1",
			Name:            "Multi-Region CloudTrail",
			Status:          "FAIL",
			Severity:        "HIGH",
			Evidence:        "CloudTrail only logs current region - missing activity in other regions | Violates CIS-3.1, PCI DSS 10.2.1.1 requires all system activity logged",
			Remediation:     "aws cloudtrail update-trail --name YOUR_TRAIL --is-multi-region-trail",
			ScreenshotGuide: "1. Go to CloudTrail → Trails\n2. Click your trail\n3. Screenshot showing 'Multi-region trail: Yes'\n4. This catches attackers using other regions",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_MULTIREGION"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-3.1, CC7.1",
		Name:       "Multi-Region CloudTrail",
		Status:     "PASS",
		Evidence:   "CloudTrail configured to log all regions | Meets CIS-3.1, PCI DSS 10.2.1.1 comprehensive logging",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CLOUDTRAIL_MULTIREGION"),
	}, nil
}

func (c *CloudTrailChecks) CheckLogFileValidation(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	validationEnabled := 0
	for _, trail := range trails.Trails {
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if aws.ToBool(details.TrailList[0].LogFileValidationEnabled) {
				validationEnabled++
			}
		}
	}

	if validationEnabled == 0 {
		return CheckResult{
			Control:         "CC7.1",
			Name:            "CloudTrail Log Integrity",
			Status:          "FAIL",
			Severity:        "MEDIUM",
			Evidence:        "Log file validation disabled - logs could be tampered with | PCI DSS 10.3.2 requires tamper protection",
			Remediation:     "aws cloudtrail update-trail --name YOUR_TRAIL --enable-log-file-validation",
			ScreenshotGuide: "1. Go to CloudTrail → Trails → Your Trail\n2. Screenshot showing 'Log file validation: Enabled'\n3. For HIPAA: Document integrity controls",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("CLOUDTRAIL_INTEGRITY"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.1",
		Name:       "CloudTrail Log Integrity",
		Status:     "PASS",
		Evidence:   "Log file validation enabled to prevent tampering | Meets PCI DSS 10.3.2 & HIPAA 164.312(c)(1)",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CLOUDTRAIL_INTEGRITY"),
	}, nil
}

// NEW CIS-SPECIFIC CHECKS

// CIS 3.7 - Ensure CloudTrail logs are encrypted at rest using KMS CMKs
func (c *CloudTrailChecks) CheckCloudTrailEncryption(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	unencryptedTrails := []string{}
	for _, trail := range trails.Trails {
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if details.TrailList[0].KmsKeyId == nil || *details.TrailList[0].KmsKeyId == "" {
				unencryptedTrails = append(unencryptedTrails, aws.ToString(trail.Name))
			}
		}
	}

	if len(unencryptedTrails) > 0 {
		return CheckResult{
			Control:           "[CIS-3.7]",
			Name:              "CloudTrail Encryption at Rest",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d CloudTrail(s) not encrypted with KMS: %v", len(unencryptedTrails), unencryptedTrails),
			Remediation:       "Enable KMS encryption for CloudTrail logs",
			RemediationDetail: "1. Create KMS key: aws kms create-key\n2. Update trail: aws cloudtrail update-trail --name [TRAIL] --kms-key-id [KEY_ARN]",
			ScreenshotGuide:   "CloudTrail → Trail → General details → Screenshot showing 'SSE-KMS encryption: Enabled' with KMS key ARN",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("CLOUDTRAIL_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-3.7]",
		Name:       "CloudTrail Encryption at Rest",
		Status:     "PASS",
		Evidence:   "All CloudTrail logs encrypted with KMS CMKs",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CLOUDTRAIL_ENCRYPTION"),
	}, nil
}

// CIS 3.3 - Ensure CloudWatch Logs integration is enabled
func (c *CloudTrailChecks) CheckCloudTrailLogIntegration(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	trailsWithoutCWL := []string{}
	for _, trail := range trails.Trails {
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if details.TrailList[0].CloudWatchLogsLogGroupArn == nil || *details.TrailList[0].CloudWatchLogsLogGroupArn == "" {
				trailsWithoutCWL = append(trailsWithoutCWL, aws.ToString(trail.Name))
			}
		}
	}

	if len(trailsWithoutCWL) > 0 {
		return CheckResult{
			Control:           "[CIS-3.3]",
			Name:              "CloudTrail CloudWatch Logs Integration",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d CloudTrail(s) not integrated with CloudWatch Logs: %v", len(trailsWithoutCWL), trailsWithoutCWL),
			Remediation:       "Enable CloudWatch Logs integration for real-time monitoring",
			RemediationDetail: "1. Create CloudWatch log group\n2. Create IAM role for CloudTrail\n3. Update trail: aws cloudtrail update-trail --name [TRAIL] --cloud-watch-logs-log-group-arn [ARN] --cloud-watch-logs-role-arn [ROLE_ARN]",
			ScreenshotGuide:   "CloudTrail → Trail → CloudWatch Logs → Screenshot showing log group ARN configured",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("CLOUDWATCH_LOG_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-3.3]",
		Name:       "CloudTrail CloudWatch Logs Integration",
		Status:     "PASS",
		Evidence:   "All CloudTrail logs integrated with CloudWatch Logs",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CLOUDWATCH_LOG_ENCRYPTION"),
	}, nil
}

// CIS 3.6 - Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket
func (c *CloudTrailChecks) CheckS3BucketAccessLogging(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "[CIS-3.6]",
		Name:              "CloudTrail S3 Bucket Logging",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify S3 bucket used by CloudTrail has access logging enabled",
		Remediation:       "Enable S3 server access logging on CloudTrail bucket",
		RemediationDetail: "1. Identify CloudTrail S3 bucket\n2. Enable access logging: aws s3api put-bucket-logging --bucket [CLOUDTRAIL_BUCKET] --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"[LOG_BUCKET]\",\"TargetPrefix\":\"cloudtrail-bucket-logs/\"}}'",
		ScreenshotGuide:   "S3 Console → CloudTrail bucket → Properties → Server access logging → Screenshot showing 'Enabled'",
		ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("CLOUDTRAIL_S3_LOGGING"),
	}, nil
}

// CIS 3.2 - Ensure CloudTrail log file validation is enabled (duplicate but with CIS label)
func (c *CloudTrailChecks) CheckCloudTrailLogValidation(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil || len(trails.Trails) == 0 {
		return CheckResult{}, err
	}

	trailsWithoutValidation := []string{}
	for _, trail := range trails.Trails {
		details, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			TrailNameList: []string{aws.ToString(trail.TrailARN)},
		})
		if err == nil && len(details.TrailList) > 0 {
			if !aws.ToBool(details.TrailList[0].LogFileValidationEnabled) {
				trailsWithoutValidation = append(trailsWithoutValidation, aws.ToString(trail.Name))
			}
		}
	}

	if len(trailsWithoutValidation) > 0 {
		return CheckResult{
			Control:           "[CIS-3.2]",
			Name:              "CloudTrail Log File Validation",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d CloudTrail(s) without log file validation: %v", len(trailsWithoutValidation), trailsWithoutValidation),
			Remediation:       "Enable log file validation to detect tampering",
			RemediationDetail: "aws cloudtrail update-trail --name [TRAIL_NAME] --enable-log-file-validation",
			ScreenshotGuide:   "CloudTrail → Trail → General details → Screenshot showing 'Log file validation: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("CLOUDTRAIL_VALIDATION"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-3.2]",
		Name:       "CloudTrail Log File Validation",
		Status:     "PASS",
		Evidence:   "All CloudTrail logs have file validation enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("CLOUDTRAIL_VALIDATION"),
	}, nil
}

// CIS 3.4 - Ensure CloudTrail S3 bucket policy prevents public access
func (c *CloudTrailChecks) CheckCloudTrailS3BucketPolicy(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "[CIS-3.4]",
		Name:              "CloudTrail S3 Bucket Policy",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify CloudTrail S3 bucket denies public access and has proper policy",
		Remediation:       "Ensure CloudTrail S3 bucket blocks all public access",
		RemediationDetail: "1. Go to S3 Console\n2. Find CloudTrail bucket\n3. Block Public Access settings: All ON\n4. Bucket policy: Should only allow CloudTrail service access\n5. No 'Principal': '*' unless properly restricted",
		ScreenshotGuide:   "S3 Console → CloudTrail bucket → Permissions → Screenshot showing 'Block all public access: On' and bucket policy limiting access",
		ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("S3_CLOUDTRAIL_BUCKET"),
	}, nil
}

// CIS 3.8 - Ensure KMS key rotation is enabled for CloudTrail encryption keys
func (c *CloudTrailChecks) CheckCloudTrailKMSKey(ctx context.Context) (CheckResult, error) {
	return CheckResult{
		Control:           "[CIS-3.8]",
		Name:              "CloudTrail KMS Key Rotation",
		Status:            "INFO",
		Evidence:          "MANUAL CHECK: Verify KMS keys used for CloudTrail encryption have automatic rotation enabled",
		Remediation:       "Enable automatic key rotation for KMS keys",
		RemediationDetail: "1. Go to KMS Console\n2. Find key used by CloudTrail\n3. Enable automatic key rotation\n4. Verify rotation is enabled: aws kms get-key-rotation-status --key-id [KEY_ID]",
		ScreenshotGuide:   "KMS Console → Customer managed keys → CloudTrail key → Key rotation → Screenshot showing 'Automatically rotate this KMS key every year: Enabled'",
		ConsoleURL:        "https://console.aws.amazon.com/kms/home#/kms/keys",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		Frameworks:        GetFrameworkMappings("KMS_KEY_ROTATION"),
	}, nil
}

// CheckS3ObjectLevelLoggingWrite verifies S3 object-level logging for write events (CIS 3.10)
func (c *CloudTrailChecks) CheckS3ObjectLevelLoggingWrite(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		return CheckResult{
			Control:    "[CIS-3.10]",
			Name:       "S3 Object-Level Logging (Write)",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check CloudTrail configuration: %v", err),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "3.10", "SOC2": "CC7.2"},
		}, nil
	}

	if len(trails.Trails) == 0 {
		return CheckResult{
			Control:     "[CIS-3.10]",
			Name:        "S3 Object-Level Logging (Write)",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    "No CloudTrail trails configured | Cannot log S3 object-level events | Violates CIS 3.10",
			Remediation: "Configure CloudTrail with S3 data events for write operations",
			RemediationDetail: `# Create event selector for S3 write events
aws cloudtrail put-event-selectors --trail-name [TRAIL_NAME] --event-selectors '[{
  "ReadWriteType": "WriteOnly",
  "IncludeManagementEvents": false,
  "DataResources": [{
    "Type": "AWS::S3::Object",
    "Values": ["arn:aws:s3:::[BUCKET_NAME]/*"]
  }]
}]'

# Or enable for all S3 buckets:
aws cloudtrail put-event-selectors --trail-name [TRAIL_NAME] --event-selectors '[{
  "ReadWriteType": "WriteOnly",
  "IncludeManagementEvents": false,
  "DataResources": [{
    "Type": "AWS::S3::Object",
    "Values": ["arn:aws:s3:::*/*"]
  }]
}]'`,
			ScreenshotGuide: "CloudTrail → Trails → Data events → Screenshot showing S3 'Write' events logging enabled",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "3.10", "SOC2": "CC7.2", "PCI-DSS": "10.2.1"},
		}, nil
	}

	// Check each trail for S3 data event selectors
	trailsWithS3WriteLogging := []string{}
	for _, trail := range trails.Trails {
		trailName := aws.ToString(trail.Name)

		// Get event selectors for this trail
		eventSelectors, err := c.client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.Name,
		})
		if err != nil {
			continue
		}

		// Check if trail has S3 data events for write
		for _, selector := range eventSelectors.EventSelectors {
			for _, resource := range selector.DataResources {
				if aws.ToString(resource.Type) == "AWS::S3::Object" {
					// Check if it includes write events
					readWriteType := string(selector.ReadWriteType)
					if readWriteType == "WriteOnly" || readWriteType == "All" {
						trailsWithS3WriteLogging = append(trailsWithS3WriteLogging, trailName)
						break
					}
				}
			}
		}
	}

	if len(trailsWithS3WriteLogging) == 0 {
		return CheckResult{
			Control:     "[CIS-3.10]",
			Name:        "S3 Object-Level Logging (Write)",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d CloudTrail trails found, but NONE log S3 write events | Violates CIS 3.10", len(trails.Trails)),
			Remediation: "Enable S3 data event logging for write operations on at least one trail",
			RemediationDetail: `aws cloudtrail put-event-selectors --trail-name [TRAIL_NAME] --event-selectors '[{
  "ReadWriteType": "WriteOnly",
  "IncludeManagementEvents": false,
  "DataResources": [{
    "Type": "AWS::S3::Object",
    "Values": ["arn:aws:s3:::*/*"]
  }]
}]'`,
			ScreenshotGuide: "CloudTrail → Trails → Data events → Screenshot showing S3 'Write' events enabled",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "3.10", "SOC2": "CC7.2", "PCI-DSS": "10.2.1"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-3.10]",
		Name:       "S3 Object-Level Logging (Write)",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("%d trail(s) logging S3 write events: %s | Meets CIS 3.10", len(trailsWithS3WriteLogging), trailsWithS3WriteLogging[0]),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "3.10", "SOC2": "CC7.2", "PCI-DSS": "10.2.1"},
	}, nil
}

// CheckS3ObjectLevelLoggingRead verifies S3 object-level logging for read events (CIS 3.11)
func (c *CloudTrailChecks) CheckS3ObjectLevelLoggingRead(ctx context.Context) (CheckResult, error) {
	trails, err := c.client.ListTrails(ctx, &cloudtrail.ListTrailsInput{})
	if err != nil {
		return CheckResult{
			Control:    "[CIS-3.11]",
			Name:       "S3 Object-Level Logging (Read)",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check CloudTrail configuration: %v", err),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "3.11", "SOC2": "CC7.2"},
		}, nil
	}

	if len(trails.Trails) == 0 {
		return CheckResult{
			Control:     "[CIS-3.11]",
			Name:        "S3 Object-Level Logging (Read)",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    "No CloudTrail trails configured | Cannot log S3 object-level events | Violates CIS 3.11",
			Remediation: "Configure CloudTrail with S3 data events for read operations",
			RemediationDetail: `# Create event selector for S3 read events
aws cloudtrail put-event-selectors --trail-name [TRAIL_NAME] --event-selectors '[{
  "ReadWriteType": "ReadOnly",
  "IncludeManagementEvents": false,
  "DataResources": [{
    "Type": "AWS::S3::Object",
    "Values": ["arn:aws:s3:::*/*"]
  }]
}]'

# Or enable both read and write:
aws cloudtrail put-event-selectors --trail-name [TRAIL_NAME] --event-selectors '[{
  "ReadWriteType": "All",
  "IncludeManagementEvents": false,
  "DataResources": [{
    "Type": "AWS::S3::Object",
    "Values": ["arn:aws:s3:::*/*"]
  }]
}]'`,
			ScreenshotGuide: "CloudTrail → Trails → Data events → Screenshot showing S3 'Read' events logging enabled",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "3.11", "SOC2": "CC7.2", "PCI-DSS": "10.2.1"},
		}, nil
	}

	// Check each trail for S3 data event selectors
	trailsWithS3ReadLogging := []string{}
	for _, trail := range trails.Trails {
		trailName := aws.ToString(trail.Name)

		// Get event selectors for this trail
		eventSelectors, err := c.client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.Name,
		})
		if err != nil {
			continue
		}

		// Check if trail has S3 data events for read
		for _, selector := range eventSelectors.EventSelectors {
			for _, resource := range selector.DataResources {
				if aws.ToString(resource.Type) == "AWS::S3::Object" {
					// Check if it includes read events
					readWriteType := string(selector.ReadWriteType)
					if readWriteType == "ReadOnly" || readWriteType == "All" {
						trailsWithS3ReadLogging = append(trailsWithS3ReadLogging, trailName)
						break
					}
				}
			}
		}
	}

	if len(trailsWithS3ReadLogging) == 0 {
		return CheckResult{
			Control:     "[CIS-3.11]",
			Name:        "S3 Object-Level Logging (Read)",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d CloudTrail trails found, but NONE log S3 read events | Violates CIS 3.11", len(trails.Trails)),
			Remediation: "Enable S3 data event logging for read operations on at least one trail",
			RemediationDetail: `aws cloudtrail put-event-selectors --trail-name [TRAIL_NAME] --event-selectors '[{
  "ReadWriteType": "ReadOnly",
  "IncludeManagementEvents": false,
  "DataResources": [{
    "Type": "AWS::S3::Object",
    "Values": ["arn:aws:s3:::*/*"]
  }]
}]'`,
			ScreenshotGuide: "CloudTrail → Trails → Data events → Screenshot showing S3 'Read' events enabled",
			ConsoleURL:      "https://console.aws.amazon.com/cloudtrail/home#/trails",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "3.11", "SOC2": "CC7.2", "PCI-DSS": "10.2.1"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-3.11]",
		Name:       "S3 Object-Level Logging (Read)",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("%d trail(s) logging S3 read events: %s | Meets CIS 3.11", len(trailsWithS3ReadLogging), trailsWithS3ReadLogging[0]),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "3.11", "SOC2": "CC7.2", "PCI-DSS": "10.2.1"},
	}, nil
}
