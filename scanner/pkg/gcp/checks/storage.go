package checks

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// StorageChecks handles GCS bucket security checks
type StorageChecks struct {
	client    *storage.Client
	projectID string
}

// NewStorageChecks creates a new storage checker
func NewStorageChecks(client *storage.Client, projectID string) *StorageChecks {
	return &StorageChecks{
		client:    client,
		projectID: projectID,
	}
}

// Run executes all storage security checks
func (c *StorageChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	results = append(results, c.CheckBucketPublicAccess(ctx)...)
	results = append(results, c.CheckBucketEncryption(ctx)...)
	results = append(results, c.CheckBucketVersioning(ctx)...)
	results = append(results, c.CheckBucketLogging(ctx)...)
	results = append(results, c.CheckUniformBucketLevelAccess(ctx)...)
	results = append(results, c.CheckBucketRetentionPolicy(ctx)...)

	return results, nil
}

// CheckBucketPublicAccess verifies no buckets are publicly accessible
func (c *StorageChecks) CheckBucketPublicAccess(ctx context.Context) []CheckResult {
	var results []CheckResult

	it := c.client.Buckets(ctx, c.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CC6.1",
				Name:        "GCS Bucket Public Access Check",
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check bucket public access: %v", err),
				Remediation: "Verify Cloud Storage API is enabled and credentials have storage.buckets.list permission",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("GCS_BUCKET_PUBLIC"),
			})
			break
		}

		bucket := c.client.Bucket(attrs.Name)
		policy, err := bucket.IAM().V3().Policy(ctx)
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CC6.1",
				Name:        fmt.Sprintf("GCS Bucket Public Access - %s", attrs.Name),
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check IAM policy for bucket %s: %v", attrs.Name, err),
				Remediation: "Verify storage.buckets.getIamPolicy permission",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("GCS_BUCKET_PUBLIC"),
			})
			continue
		}

		// Check for allUsers or allAuthenticatedUsers
		isPublic := false
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					isPublic = true
					break
				}
			}
			if isPublic {
				break
			}
		}

		if isPublic {
			results = append(results, CheckResult{
				Control:     "CC6.1",
				Name:        fmt.Sprintf("GCS Bucket Public Access - %s", attrs.Name),
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Bucket %s is publicly accessible", attrs.Name),
				Remediation: "Remove allUsers and allAuthenticatedUsers from bucket IAM policy",
				RemediationDetail: fmt.Sprintf(`gcloud storage buckets remove-iam-policy-binding gs://%s \
  --member=allUsers --role=roles/storage.objectViewer

gcloud storage buckets remove-iam-policy-binding gs://%s \
  --member=allAuthenticatedUsers --role=roles/storage.objectViewer`, attrs.Name, attrs.Name),
				Priority:        PriorityCritical,
				Timestamp:       time.Now(),
				ScreenshotGuide: fmt.Sprintf("Google Cloud Console → Storage → Browser → %s → Permissions → Screenshot showing allUsers/allAuthenticatedUsers", attrs.Name),
				ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/storage/browser/%s", attrs.Name),
				Frameworks:      GetFrameworkMappings("GCS_BUCKET_PUBLIC"),
			})
		} else {
			results = append(results, CheckResult{
				Control:    "CC6.1",
				Name:       fmt.Sprintf("GCS Bucket Public Access - %s", attrs.Name),
				Status:     "PASS",
				Evidence:   fmt.Sprintf("Bucket %s is not publicly accessible", attrs.Name),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("GCS_BUCKET_PUBLIC"),
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:    "CC6.1",
			Name:       "GCS Bucket Public Access Check",
			Status:     "INFO",
			Evidence:   "No GCS buckets found in project",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCS_BUCKET_PUBLIC"),
		})
	}

	return results
}

// CheckBucketEncryption verifies buckets use encryption
func (c *StorageChecks) CheckBucketEncryption(ctx context.Context) []CheckResult {
	var results []CheckResult

	it := c.client.Buckets(ctx, c.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CC6.7",
				Name:        "GCS Bucket Encryption Check",
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check bucket encryption: %v", err),
				Remediation: "Verify Cloud Storage API is enabled",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("GCS_BUCKET_ENCRYPTION"),
			})
			break
		}

		bucket := c.client.Bucket(attrs.Name)
		bucketAttrs, err := bucket.Attrs(ctx)
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CC6.7",
				Name:        fmt.Sprintf("GCS Bucket Encryption - %s", attrs.Name),
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check encryption for bucket %s: %v", attrs.Name, err),
				Remediation: "Verify storage.buckets.get permission",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("GCS_BUCKET_ENCRYPTION"),
			})
			continue
		}

		// Check for CMEK (Customer-Managed Encryption Key)
		if bucketAttrs.Encryption == nil || bucketAttrs.Encryption.DefaultKMSKeyName == "" {
			results = append(results, CheckResult{
				Control:     "CC6.7",
				Name:        fmt.Sprintf("GCS Bucket Encryption - %s", attrs.Name),
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Bucket %s uses Google-managed encryption instead of customer-managed keys", attrs.Name),
				Remediation: "Enable customer-managed encryption keys (CMEK) for sensitive data",
				RemediationDetail: fmt.Sprintf(`gcloud storage buckets update gs://%s \
  --default-encryption-key=projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY`, attrs.Name),
				Priority:        PriorityMedium,
				Timestamp:       time.Now(),
				ScreenshotGuide: fmt.Sprintf("Google Cloud Console → Storage → Browser → %s → Configuration → Encryption", attrs.Name),
				ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/storage/browser/%s", attrs.Name),
				Frameworks:      GetFrameworkMappings("GCS_BUCKET_ENCRYPTION"),
			})
		} else {
			results = append(results, CheckResult{
				Control:    "CC6.7",
				Name:       fmt.Sprintf("GCS Bucket Encryption - %s", attrs.Name),
				Status:     "PASS",
				Evidence:   fmt.Sprintf("Bucket %s uses customer-managed encryption: %s", attrs.Name, bucketAttrs.Encryption.DefaultKMSKeyName),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("GCS_BUCKET_ENCRYPTION"),
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:    "CC6.7",
			Name:       "GCS Bucket Encryption Check",
			Status:     "INFO",
			Evidence:   "No GCS buckets found in project",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCS_BUCKET_ENCRYPTION"),
		})
	}

	return results
}

// CheckBucketVersioning verifies versioning is enabled for data protection
func (c *StorageChecks) CheckBucketVersioning(ctx context.Context) []CheckResult {
	var results []CheckResult

	it := c.client.Buckets(ctx, c.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "A1.2",
				Name:        "GCS Bucket Versioning Check",
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check bucket versioning: %v", err),
				Severity:    "HIGH",
				Remediation: "Verify Cloud Storage API is enabled",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("GCS_BUCKET_VERSIONING"),
			})
			break
		}

		bucket := c.client.Bucket(attrs.Name)
		bucketAttrs, err := bucket.Attrs(ctx)
		if err != nil {
			continue
		}

		if !bucketAttrs.VersioningEnabled {
			results = append(results, CheckResult{
				Control:           "A1.2",
				Name:              fmt.Sprintf("GCS Bucket Versioning - %s", attrs.Name),
				Status:            "FAIL",
				Severity:          "MEDIUM",
				Evidence:          fmt.Sprintf("Bucket %s does not have versioning enabled for data recovery", attrs.Name),
				Remediation:       "Enable versioning for accidental deletion protection",
				RemediationDetail: fmt.Sprintf(`gcloud storage buckets update gs://%s --versioning`, attrs.Name),
				Priority:          PriorityMedium,
				Timestamp:         time.Now(),
				ScreenshotGuide:   fmt.Sprintf("Google Cloud Console → Storage → Browser → %s → Protection tab → Screenshot versioning status", attrs.Name),
				ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/storage/browser/%s", attrs.Name),
				Frameworks:        GetFrameworkMappings("GCS_BUCKET_VERSIONING"),
			})
		} else {
			results = append(results, CheckResult{
				Control:    "A1.2",
				Name:       fmt.Sprintf("GCS Bucket Versioning - %s", attrs.Name),
				Status:     "PASS",
				Evidence:   fmt.Sprintf("Bucket %s has versioning enabled", attrs.Name),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("GCS_BUCKET_VERSIONING"),
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:    "A1.2",
			Name:       "GCS Bucket Versioning Check",
			Status:     "INFO",
			Evidence:   "No GCS buckets found in project",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCS_BUCKET_VERSIONING"),
		})
	}

	return results
}

// CheckBucketLogging verifies access logging is enabled
func (c *StorageChecks) CheckBucketLogging(ctx context.Context) []CheckResult {
	var results []CheckResult

	it := c.client.Buckets(ctx, c.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CC7.2",
				Name:        "GCS Bucket Logging Check",
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check bucket logging: %v", err),
				Severity:    "HIGH",
				Remediation: "Verify Cloud Storage API is enabled",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("GCS_BUCKET_LOGGING"),
			})
			break
		}

		bucket := c.client.Bucket(attrs.Name)
		bucketAttrs, err := bucket.Attrs(ctx)
		if err != nil {
			continue
		}

		if bucketAttrs.Logging == nil {
			results = append(results, CheckResult{
				Control:     "CC7.2",
				Name:        fmt.Sprintf("GCS Bucket Logging - %s", attrs.Name),
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    fmt.Sprintf("Bucket %s does not have access logging enabled", attrs.Name),
				Remediation: "Enable access logging for audit trail",
				RemediationDetail: fmt.Sprintf(`gcloud storage buckets update gs://%s \
  --log-bucket=gs://LOGGING_BUCKET \
  --log-object-prefix=%s/`, attrs.Name, attrs.Name),
				Priority:        PriorityHigh,
				Timestamp:       time.Now(),
				ScreenshotGuide: fmt.Sprintf("Google Cloud Console → Storage → Browser → %s → Protection tab → Access logs section", attrs.Name),
				ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/storage/browser/%s", attrs.Name),
				Frameworks:      GetFrameworkMappings("GCS_BUCKET_LOGGING"),
			})
		} else {
			results = append(results, CheckResult{
				Control:    "CC7.2",
				Name:       fmt.Sprintf("GCS Bucket Logging - %s", attrs.Name),
				Status:     "PASS",
				Evidence:   fmt.Sprintf("Bucket %s has access logging enabled to %s", attrs.Name, bucketAttrs.Logging.LogBucket),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("GCS_BUCKET_LOGGING"),
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:    "CC7.2",
			Name:       "GCS Bucket Logging Check",
			Status:     "INFO",
			Evidence:   "No GCS buckets found in project",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCS_BUCKET_LOGGING"),
		})
	}

	return results
}

// CheckUniformBucketLevelAccess verifies uniform bucket-level access is enabled (CIS 5.2)
func (c *StorageChecks) CheckUniformBucketLevelAccess(ctx context.Context) []CheckResult {
	var results []CheckResult

	it := c.client.Buckets(ctx, c.projectID)
	bucketsWithACLs := []string{}
	totalBuckets := 0

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CIS GCP 5.2",
				Name:        "GCS Uniform Bucket-Level Access",
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check uniform bucket-level access: %v", err),
				Remediation: "Verify Cloud Storage API is enabled",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("GCS_UNIFORM_ACCESS"),
			})
			break
		}

		totalBuckets++
		bucket := c.client.Bucket(attrs.Name)
		bucketAttrs, err := bucket.Attrs(ctx)
		if err != nil {
			continue
		}

		// Check if Uniform Bucket-Level Access is NOT enabled
		if !bucketAttrs.UniformBucketLevelAccess.Enabled {
			bucketsWithACLs = append(bucketsWithACLs, attrs.Name)
		}
	}

	if len(bucketsWithACLs) > 0 {
		displayBuckets := bucketsWithACLs
		if len(bucketsWithACLs) > 3 {
			displayBuckets = bucketsWithACLs[:3]
		}

		results = append(results, CheckResult{
			Control:           "CIS GCP 5.2",
			Name:              "GCS Uniform Bucket-Level Access",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("CIS 5.2: %d buckets use legacy ACLs instead of uniform bucket-level access: %v", len(bucketsWithACLs), displayBuckets),
			Remediation:       "Enable uniform bucket-level access to simplify IAM management",
			RemediationDetail: fmt.Sprintf(`gcloud storage buckets update gs://%s --uniform-bucket-level-access`, bucketsWithACLs[0]),
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			ScreenshotGuide:   fmt.Sprintf("Storage → Browser → %s → Permissions → Screenshot showing 'Uniform' access enabled", bucketsWithACLs[0]),
			ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/storage/browser/%s", bucketsWithACLs[0]),
			Frameworks:        GetFrameworkMappings("GCS_UNIFORM_ACCESS"),
		})
	} else if totalBuckets > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 5.2",
			Name:       "GCS Uniform Bucket-Level Access",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d buckets use uniform bucket-level access | Meets CIS 5.2", totalBuckets),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCS_UNIFORM_ACCESS"),
		})
	}

	return results
}

// CheckBucketRetentionPolicy verifies retention policies are set (CIS 5.1)
func (c *StorageChecks) CheckBucketRetentionPolicy(ctx context.Context) []CheckResult {
	var results []CheckResult

	it := c.client.Buckets(ctx, c.projectID)
	bucketsWithoutRetention := []string{}
	totalBuckets := 0

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		totalBuckets++
		bucket := c.client.Bucket(attrs.Name)
		bucketAttrs, err := bucket.Attrs(ctx)
		if err != nil {
			continue
		}

		// Check if retention policy is set
		if bucketAttrs.RetentionPolicy == nil {
			bucketsWithoutRetention = append(bucketsWithoutRetention, attrs.Name)
		}
	}

	if len(bucketsWithoutRetention) > 0 {
		displayBuckets := bucketsWithoutRetention
		if len(bucketsWithoutRetention) > 3 {
			displayBuckets = bucketsWithoutRetention[:3]
		}

		results = append(results, CheckResult{
			Control:           "CIS GCP 5.1",
			Name:              "GCS Bucket Retention Policy",
			Status:            "INFO",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("CIS 5.1: %d buckets do not have retention policies configured: %v", len(bucketsWithoutRetention), displayBuckets),
			Remediation:       "Configure retention policies for compliance and data retention requirements",
			RemediationDetail: fmt.Sprintf(`gcloud storage buckets update gs://%s --retention-period=90d`, bucketsWithoutRetention[0]),
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			ScreenshotGuide:   fmt.Sprintf("Storage → Browser → %s → Retention policy tab → Screenshot retention settings", bucketsWithoutRetention[0]),
			ConsoleURL:        fmt.Sprintf("https://console.cloud.google.com/storage/browser/%s", bucketsWithoutRetention[0]),
			Frameworks:        GetFrameworkMappings("GCS_RETENTION_POLICY"),
		})
	} else if totalBuckets > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 5.1",
			Name:       "GCS Bucket Retention Policy",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d buckets have retention policies configured | Meets CIS 5.1", totalBuckets),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCS_RETENTION_POLICY"),
		})
	}

	return results
}
