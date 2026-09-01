package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/sqladmin/v1"
)

// GCPAvailabilityConfidentialityChecks covers the SOC 2 Availability and
// Confidentiality criteria for GCP. See the AWS module of the same name for why
// Processing Integrity and Privacy are out of scope.
type GCPAvailabilityConfidentialityChecks struct {
	storageClient *storage.Client
	sqlService    *sqladmin.Service
	projectID     string
}

func NewGCPAvailabilityConfidentialityChecks(storageClient *storage.Client, sqlService *sqladmin.Service, projectID string) *GCPAvailabilityConfidentialityChecks {
	return &GCPAvailabilityConfidentialityChecks{storageClient: storageClient, sqlService: sqlService, projectID: projectID}
}

func (c *GCPAvailabilityConfidentialityChecks) Name() string {
	return "GCP SOC2 Availability and Confidentiality"
}

func (c *GCPAvailabilityConfidentialityChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}
	results = append(results, c.checkRecoveryTesting(ctx))
	results = append(results, c.checkBucketClassification(ctx)...)
	return results, nil
}

// A1.3 - recovery plan testing. A backup that has never been restored is
// untested, so the check reports whether there is anything to restore from.
func (c *GCPAvailabilityConfidentialityChecks) checkRecoveryTesting(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:         "A1.3",
		Name:            "Recovery Plan Testing",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Dated restore test records, showing what was restored and how long it took",
		Frameworks:      map[string]string{"SOC2": "A1.3"},
	}

	list, err := c.sqlService.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		base.Status = "INFO"
		base.Evidence = "SOC2 A1.3: document and retain evidence of recovery plan testing"
		base.Remediation = "Perform and record a restore test"
		base.RemediationDetail = "1. Restore a backup into an isolated project\n2. Record the date, what was restored and the elapsed time\n3. Repeat at the frequency your policy defines"
		return base
	}

	noBackup := []string{}
	for _, inst := range list.Items {
		if inst.Settings == nil || inst.Settings.BackupConfiguration == nil || !inst.Settings.BackupConfiguration.Enabled {
			noBackup = append(noBackup, inst.Name)
		}
	}

	if len(noBackup) > 0 {
		shown := noBackup
		if len(shown) > 3 {
			shown = shown[:3]
		}
		base.Status = "FAIL"
		base.Severity = "HIGH"
		base.Evidence = fmt.Sprintf("SOC2 A1.3: %d Cloud SQL instance(s) have backups disabled, so there is nothing to test a recovery against: %s", len(noBackup), strings.Join(shown, ", "))
		base.Remediation = "Enable automated backups, then test a restore"
		base.RemediationDetail = "1. gcloud sql instances patch INSTANCE --backup-start-time=03:00\n2. Restore into an isolated project and record the result"
		base.ConsoleURL = "https://console.cloud.google.com/sql/instances"
		return base
	}

	base.Status = "INFO"
	base.Evidence = fmt.Sprintf("SOC2 A1.3: %d Cloud SQL instance(s) have automated backups. Recovery testing itself must be evidenced separately - a backup that has never been restored is untested", len(list.Items))
	base.Remediation = "Record a restore test"
	base.RemediationDetail = "Restore a backup into an isolated project, record the date, scope and elapsed time, and repeat at the frequency your policy defines."
	return base
}

// C1.1 and C1.2 - identification and disposal of confidential information.
// Labels record what a bucket holds; lifecycle rules enforce disposal.
func (c *GCPAvailabilityConfidentialityChecks) checkBucketClassification(ctx context.Context) []CheckResult {
	unlabelled := []string{}
	noLifecycle := []string{}
	total := 0

	it := c.storageClient.Buckets(ctx, c.projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return []CheckResult{
				{
					Control:           "C1.1",
					Name:              "Confidential Data Identification",
					Status:            "INFO",
					Evidence:          fmt.Sprintf("SOC2 C1.1: unable to list buckets (%v). Identify and maintain a record of which resources hold confidential information", err),
					Remediation:       "Label data-bearing resources with a classification",
					RemediationDetail: "Apply a classification label to each bucket and keep an inventory of what each holds.",
					Priority:          PriorityMedium,
					Timestamp:         time.Now(),
					Frameworks:        map[string]string{"SOC2": "C1.1"},
				},
			}
		}
		total++
		classified := false
		for k := range attrs.Labels {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "classification") || strings.Contains(lk, "sensitivity") || strings.Contains(lk, "dataclass") {
				classified = true
				break
			}
		}
		if !classified {
			unlabelled = append(unlabelled, attrs.Name)
		}
		if len(attrs.Lifecycle.Rules) == 0 {
			noLifecycle = append(noLifecycle, attrs.Name)
		}
	}

	trim := func(v []string) string {
		if len(v) > 3 {
			v = v[:3]
		}
		return strings.Join(v, ", ")
	}

	results := []CheckResult{}
	if len(unlabelled) > 0 {
		results = append(results, CheckResult{
			Control:           "C1.1",
			Name:              "Confidential Data Identification",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("SOC2 C1.1: %d of %d bucket(s) carry no data classification label: %s", len(unlabelled), total, trim(unlabelled)),
			Remediation:       "Label buckets with a data classification",
			RemediationDetail: "1. Agree a classification scheme, for example public, internal, confidential\n2. gsutil label ch -l dataclassification:confidential gs://BUCKET\n3. Keep the inventory current as buckets are created",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "Bucket labels showing a classification value, plus the classification scheme itself",
			ConsoleURL:        "https://console.cloud.google.com/storage/browser",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "C1.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "C1.1",
			Name:       "Confidential Data Identification",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("SOC2 C1.1: all %d bucket(s) carry a data classification label", total),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "C1.1"},
		})
	}

	if len(noLifecycle) > 0 {
		results = append(results, CheckResult{
			Control:           "C1.2",
			Name:              "Confidential Data Disposal",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("SOC2 C1.2: %d of %d bucket(s) have no lifecycle rule, so nothing enforces disposal at the end of retention: %s", len(noLifecycle), total, trim(noLifecycle)),
			Remediation:       "Apply lifecycle rules that delete data at end of retention",
			RemediationDetail: "1. Agree a retention period per classification\n2. gsutil lifecycle set rules.json gs://BUCKET\n3. Include noncurrent version deletion where versioning is enabled",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "Bucket lifecycle rules showing deletion matching your retention policy",
			ConsoleURL:        "https://console.cloud.google.com/storage/browser",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "C1.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "C1.2",
			Name:       "Confidential Data Disposal",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("SOC2 C1.2: all %d bucket(s) have lifecycle rules governing disposal", total),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "C1.2"},
		})
	}
	return results
}
