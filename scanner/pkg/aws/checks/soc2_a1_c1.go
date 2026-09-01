package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AvailabilityConfidentialityChecks covers the SOC 2 Availability and
// Confidentiality criteria that the Common Criteria modules do not.
//
// Coverage before this module was CC1.1 through CC9.2 in full, plus A1.1 and
// A1.2 emitted incidentally by the service checks. A1.3, C1.1 and C1.2 were
// absent, so an organisation whose report scope included the Availability or
// Confidentiality categories saw nothing for them.
//
// Processing Integrity (PI1.x) and Privacy (P1 through P8) remain out of scope.
// Both are properties of an application and its data handling rather than of
// cloud configuration, and inferring them from infrastructure would produce
// findings that cannot be substantiated.
type AvailabilityConfidentialityChecks struct {
	s3Client  *s3.Client
	rdsClient *rds.Client
}

func NewAvailabilityConfidentialityChecks(s3Client *s3.Client, rdsClient *rds.Client) *AvailabilityConfidentialityChecks {
	return &AvailabilityConfidentialityChecks{s3Client: s3Client, rdsClient: rdsClient}
}

func (c *AvailabilityConfidentialityChecks) Name() string {
	return "SOC2 Availability and Confidentiality"
}

func (c *AvailabilityConfidentialityChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}
	results = append(results, c.checkRecoveryTesting(ctx))
	results = append(results, c.checkDataClassification(ctx)...)
	results = append(results, c.checkDataDisposal(ctx)...)
	return results, nil
}

// A1.3 - the entity tests recovery plan procedures. Whether a test happened is
// not visible from configuration, but whether there is anything to recover from
// is, and a recovery test is meaningless without backups.
func (c *AvailabilityConfidentialityChecks) checkRecoveryTesting(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:         "A1.3",
		Name:            "Recovery Plan Testing",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Dated restore test records, showing what was restored and how long it took",
		Frameworks:      map[string]string{FrameworkSOC2: "A1.3"},
	}

	instances, err := c.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		base.Status = "INFO"
		base.Evidence = "SOC2 A1.3: document and retain evidence of recovery plan testing"
		base.Remediation = "Perform and record a restore test"
		base.RemediationDetail = "1. Restore a backup into an isolated environment\n2. Record the date, what was restored and the elapsed time\n3. Repeat at the frequency your policy defines"
		return base
	}

	noBackup := []string{}
	for _, db := range instances.DBInstances {
		if db.BackupRetentionPeriod == nil || *db.BackupRetentionPeriod == 0 {
			noBackup = append(noBackup, aws.ToString(db.DBInstanceIdentifier))
		}
	}

	if len(noBackup) > 0 {
		shown := noBackup
		if len(shown) > 3 {
			shown = shown[:3]
		}
		base.Status = "FAIL"
		base.Severity = "HIGH"
		base.Evidence = fmt.Sprintf("SOC2 A1.3: %d database(s) have no automated backups, so there is nothing to test a recovery against: %s", len(noBackup), strings.Join(shown, ", "))
		base.Remediation = "Enable automated backups, then test a restore"
		base.RemediationDetail = "1. aws rds modify-db-instance --db-instance-identifier ID --backup-retention-period 7 --apply-immediately\n2. Restore into an isolated environment and record the result"
		base.ConsoleURL = "https://console.aws.amazon.com/rds/home#databases:"
		return base
	}

	base.Status = "INFO"
	base.Evidence = fmt.Sprintf("SOC2 A1.3: %d database(s) have automated backups. Recovery testing itself must be evidenced separately - a backup that has never been restored is untested", len(instances.DBInstances))
	base.Remediation = "Record a restore test"
	base.RemediationDetail = "Restore a backup into an isolated environment, record the date, scope and elapsed time, and repeat at the frequency your policy defines."
	return base
}

// C1.1 - confidential information is identified and maintained. Tagging is the
// mechanism AWS provides for recording which resources hold confidential data.
func (c *AvailabilityConfidentialityChecks) checkDataClassification(ctx context.Context) []CheckResult {
	buckets, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return []CheckResult{{
			Control:           "C1.1",
			Name:              "Confidential Data Identification",
			Status:            "INFO",
			Evidence:          "SOC2 C1.1: identify and maintain a record of which resources hold confidential information",
			Remediation:       "Classify data-bearing resources",
			RemediationDetail: "Tag buckets and databases with a classification, and keep an inventory of what each holds.",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{FrameworkSOC2: "C1.1"},
		}}
	}

	if len(buckets.Buckets) == 0 {
		return []CheckResult{noResources("C1.1", "Confidential Data Identification", "S3 bucket", "C1.1")}
	}

	untagged := []string{}
	for _, b := range buckets.Buckets {
		name := aws.ToString(b.Name)
		tags, err := c.s3Client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(name)})
		classified := false
		if err == nil {
			for _, t := range tags.TagSet {
				key := strings.ToLower(aws.ToString(t.Key))
				if strings.Contains(key, "classification") || strings.Contains(key, "sensitivity") || strings.Contains(key, "dataclass") {
					classified = true
					break
				}
			}
		}
		if !classified {
			untagged = append(untagged, name)
		}
	}

	if len(untagged) > 0 {
		shown := untagged
		if len(shown) > 3 {
			shown = shown[:3]
		}
		return []CheckResult{{
			Control:           "C1.1",
			Name:              "Confidential Data Identification",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("SOC2 C1.1: %d of %d bucket(s) carry no data classification tag: %s", len(untagged), len(buckets.Buckets), strings.Join(shown, ", ")),
			Remediation:       "Tag buckets with a data classification",
			RemediationDetail: "1. Agree a classification scheme, for example public, internal, confidential\n2. aws s3api put-bucket-tagging --bucket NAME --tagging 'TagSet=[{Key=DataClassification,Value=Confidential}]'\n3. Keep the inventory current as buckets are created",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "Bucket tag sets showing a classification value, plus the classification scheme itself",
			ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{FrameworkSOC2: "C1.1"},
		}}
	}

	return []CheckResult{{
		Control:    "C1.1",
		Name:       "Confidential Data Identification",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("SOC2 C1.1: all %d bucket(s) carry a data classification tag", len(buckets.Buckets)),
		Priority:   PriorityMedium,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{FrameworkSOC2: "C1.1"},
	}}
}

// C1.2 - confidential information is disposed of when no longer needed.
// Lifecycle rules are how that disposal is actually enforced.
func (c *AvailabilityConfidentialityChecks) checkDataDisposal(ctx context.Context) []CheckResult {
	buckets, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return []CheckResult{{
			Control:           "C1.2",
			Name:              "Confidential Data Disposal",
			Status:            "INFO",
			Evidence:          "SOC2 C1.2: dispose of confidential information once it is no longer needed",
			Remediation:       "Define retention and disposal rules",
			RemediationDetail: "Apply lifecycle rules that expire objects at the end of their retention period.",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{FrameworkSOC2: "C1.2"},
		}}
	}

	if len(buckets.Buckets) == 0 {
		return []CheckResult{noResources("C1.2", "Confidential Data Disposal", "S3 bucket", "C1.2")}
	}

	noLifecycle := []string{}
	unreadable := []string{}
	for _, b := range buckets.Buckets {
		name := aws.ToString(b.Name)
		lc, err := c.s3Client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(name)})
		if err != nil {
			// AWS returns NoSuchLifecycleConfiguration for a bucket with no
			// rules, which is a real finding, but AccessDenied and
			// PermanentRedirect are not: reporting those as a failure would
			// blame the customer for our own lack of permission.
			if strings.Contains(err.Error(), "NoSuchLifecycleConfiguration") {
				noLifecycle = append(noLifecycle, name)
			} else {
				unreadable = append(unreadable, name)
			}
			continue
		}
		if lc == nil || len(lc.Rules) == 0 {
			noLifecycle = append(noLifecycle, name)
		}
	}

	if len(noLifecycle) == 0 && len(unreadable) > 0 {
		return []CheckResult{{
			Control:           "C1.2",
			Name:              "Confidential Data Disposal",
			Status:            StatusError,
			Evidence:          fmt.Sprintf("SOC2 C1.2: could not read the lifecycle configuration of %d bucket(s), so disposal could not be assessed: %s", len(unreadable), strings.Join(unreadable[:min(3, len(unreadable))], ", ")),
			Remediation:       "Grant s3:GetLifecycleConfiguration and re-run",
			RemediationDetail: "The scanner needs s3:GetLifecycleConfiguration on each bucket to determine whether disposal is enforced.",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{FrameworkSOC2: "C1.2"},
		}}
	}

	if len(noLifecycle) > 0 {
		shown := noLifecycle
		if len(shown) > 3 {
			shown = shown[:3]
		}
		return []CheckResult{{
			Control:           "C1.2",
			Name:              "Confidential Data Disposal",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("SOC2 C1.2: %d of %d bucket(s) have no lifecycle rule, so nothing enforces disposal at the end of retention: %s", len(noLifecycle), len(buckets.Buckets), strings.Join(shown, ", ")),
			Remediation:       "Apply lifecycle rules that expire data",
			RemediationDetail: "1. Agree a retention period per classification\n2. aws s3api put-bucket-lifecycle-configuration --bucket NAME --lifecycle-configuration file://rules.json\n3. Include noncurrent version expiration where versioning is enabled",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "Bucket lifecycle rules showing expiration matching your retention policy",
			ConsoleURL:        "https://s3.console.aws.amazon.com/s3/buckets",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{FrameworkSOC2: "C1.2"},
		}}
	}

	return []CheckResult{{
		Control:    "C1.2",
		Name:       "Confidential Data Disposal",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("SOC2 C1.2: all %d bucket(s) have lifecycle rules governing disposal", len(buckets.Buckets)),
		Priority:   PriorityMedium,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{FrameworkSOC2: "C1.2"},
	}}
}

// noResources reports that a control could not be assessed because the account
// holds nothing of the relevant type. This is deliberately INFO rather than
// PASS: "all 0 buckets are tagged" is not evidence of anything, and scoring it
// as a pass inflates the compliance score for an empty account.
func noResources(control, name, resource, framework string) CheckResult {
	return CheckResult{
		Control:           control,
		Name:              name,
		Status:            StatusInfo,
		Evidence:          fmt.Sprintf("SOC2 %s: no %s found in this account, so there was nothing to assess", framework, resource),
		Remediation:       "No action while no such resources exist",
		RemediationDetail: "Re-run once resources of this type are in scope.",
		Priority:          PriorityInfo,
		Timestamp:         time.Now(),
		Frameworks:        map[string]string{FrameworkSOC2: framework},
	}
}
