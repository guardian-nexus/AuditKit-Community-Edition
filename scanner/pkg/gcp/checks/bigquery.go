package checks

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
)

type BigQueryChecks struct {
	projectID string
}

func NewBigQueryChecks(projectID string) *BigQueryChecks {
	return &BigQueryChecks{projectID: projectID}
}

func (c *BigQueryChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Initialize BigQuery service
	bqService, err := bigquery.NewService(ctx, option.WithScopes(bigquery.CloudPlatformReadOnlyScope))
	if err != nil {
		return results, err
	}

	results = append(results, c.CheckPublicDatasets(ctx, bqService)...)
	results = append(results, c.CheckDatasetEncryption(ctx, bqService)...)

	return results, nil
}

// CheckPublicDatasets verifies BigQuery datasets are not publicly accessible (CIS 7.1, 7.2)
func (c *BigQueryChecks) CheckPublicDatasets(ctx context.Context, bqService *bigquery.Service) []CheckResult {
	datasetList, err := bqService.Datasets.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 7.1",
			Name:        "[CIS GCP 7.1] BigQuery Datasets Not Public",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to check BigQuery datasets: %v", err),
			Remediation: "Verify BigQuery API is enabled",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BIGQUERY_PUBLIC_DATASETS"),
		}}
	}

	if datasetList.Datasets == nil || len(datasetList.Datasets) == 0 {
		return []CheckResult{{
			Control:    "CIS GCP 7.1",
			Name:       "[CIS GCP 7.1] BigQuery Datasets Not Public",
			Status:     "INFO",
			Evidence:   "No BigQuery datasets found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("BIGQUERY_PUBLIC_DATASETS"),
		}}
	}

	publicDatasets := []string{}

	for _, dataset := range datasetList.Datasets {
		// Get full dataset details to check access controls
		ds, err := bqService.Datasets.Get(c.projectID, dataset.DatasetReference.DatasetId).Context(ctx).Do()
		if err != nil {
			continue
		}

		// Check for public access
		if ds.Access != nil {
			for _, access := range ds.Access {
				if access.IamMember == "allUsers" || access.IamMember == "allAuthenticatedUsers" {
					publicDatasets = append(publicDatasets, dataset.DatasetReference.DatasetId)
					break
				}
			}
		}
	}

	if len(publicDatasets) > 0 {
		displayDatasets := publicDatasets
		if len(publicDatasets) > 3 {
			displayDatasets = publicDatasets[:3]
		}

		return []CheckResult{{
			Control:     "CIS GCP 7.1",
			Name:        "[CIS GCP 7.1] BigQuery Datasets Not Public",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CRITICAL: %d BigQuery datasets are publicly accessible: %v | Violates CIS GCP 7.1 (data exposure risk)", len(publicDatasets), displayDatasets),
			Remediation: fmt.Sprintf("Remove public access from dataset: %s", publicDatasets[0]),
			RemediationDetail: fmt.Sprintf(`# Remove all public access from BigQuery dataset
bq update --remove_all_authenticated_users %s:%s
bq update --remove_all_users %s:%s

# Alternative: Use console
1. Open BigQuery console
2. Select dataset '%s'
3. Click 'Sharing' → 'Permissions'
4. Remove 'allUsers' and 'allAuthenticatedUsers' entries`, c.projectID, publicDatasets[0], c.projectID, publicDatasets[0], publicDatasets[0]),
			ScreenshotGuide: fmt.Sprintf("BigQuery → Select dataset '%s' → Sharing → Screenshot showing NO public access", publicDatasets[0]),
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/bigquery?project=%s", c.projectID),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("BIGQUERY_PUBLIC_DATASETS"),
		}}
	}

	return []CheckResult{{
		Control:    "CIS GCP 7.1",
		Name:       "[CIS GCP 7.1] BigQuery Datasets Not Public",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d BigQuery datasets are private | Meets CIS GCP 7.1", len(datasetList.Datasets)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("BIGQUERY_PUBLIC_DATASETS"),
	}}
}

// CheckDatasetEncryption verifies BigQuery datasets/tables use CMEK (CIS 7.2, 7.3)
func (c *BigQueryChecks) CheckDatasetEncryption(ctx context.Context, bqService *bigquery.Service) []CheckResult {
	datasetList, err := bqService.Datasets.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 7.2",
			Name:        "[CIS GCP 7.2/7.3] BigQuery CMEK Encryption",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to check BigQuery encryption: %v", err),
			Remediation: "Verify BigQuery API is enabled",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BIGQUERY_ENCRYPTION"),
		}}
	}

	if datasetList.Datasets == nil || len(datasetList.Datasets) == 0 {
		return []CheckResult{{
			Control:    "CIS GCP 7.2",
			Name:       "[CIS GCP 7.2/7.3] BigQuery CMEK Encryption",
			Status:     "INFO",
			Evidence:   "No BigQuery datasets found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("BIGQUERY_ENCRYPTION"),
		}}
	}

	datasetsWithoutCMEK := []string{}

	for _, dataset := range datasetList.Datasets {
		ds, err := bqService.Datasets.Get(c.projectID, dataset.DatasetReference.DatasetId).Context(ctx).Do()
		if err != nil {
			continue
		}

		// Check if dataset has default encryption (no CMEK)
		if ds.DefaultEncryptionConfiguration == nil || ds.DefaultEncryptionConfiguration.KmsKeyName == "" {
			datasetsWithoutCMEK = append(datasetsWithoutCMEK, dataset.DatasetReference.DatasetId)
		}
	}

	if len(datasetsWithoutCMEK) > 0 {
		displayDatasets := datasetsWithoutCMEK
		if len(datasetsWithoutCMEK) > 3 {
			displayDatasets = datasetsWithoutCMEK[:3]
		}

		return []CheckResult{{
			Control:     "CIS GCP 7.2",
			Name:        "[CIS GCP 7.2/7.3] BigQuery CMEK Encryption",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d BigQuery datasets use Google-managed keys instead of customer-managed keys (CMEK): %v | Violates CIS GCP 7.2", len(datasetsWithoutCMEK), displayDatasets),
			Remediation: "Enable customer-managed encryption keys (CMEK) for sensitive datasets",
			RemediationDetail: fmt.Sprintf(`# Create KMS key first
gcloud kms keys create bigquery-key \
  --location=us \
  --keyring=bigquery-keyring \
  --purpose=encryption

# Update dataset to use CMEK
bq update --default_kms_key \
  projects/%s/locations/us/keyRings/bigquery-keyring/cryptoKeys/bigquery-key \
  %s:%s

Note: Existing tables must be copied to new tables with CMEK`, c.projectID, c.projectID, datasetsWithoutCMEK[0]),
			ScreenshotGuide: fmt.Sprintf("BigQuery → Dataset '%s' → Details → Screenshot showing Customer-managed key configured", datasetsWithoutCMEK[0]),
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/bigquery?project=%s", c.projectID),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			Frameworks:      GetFrameworkMappings("BIGQUERY_ENCRYPTION"),
		}}
	}

	return []CheckResult{{
		Control:    "CIS GCP 7.2",
		Name:       "[CIS GCP 7.2/7.3] BigQuery CMEK Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d BigQuery datasets use customer-managed encryption (CMEK) | Meets CIS GCP 7.2, 7.3", len(datasetList.Datasets)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("BIGQUERY_ENCRYPTION"),
	}}
}
