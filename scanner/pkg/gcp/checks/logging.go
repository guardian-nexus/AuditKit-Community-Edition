package checks

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/api/iterator"
)

type LoggingChecks struct {
	client    *logging.ConfigClient
	projectID string
}

func NewLoggingChecks(client *logging.ConfigClient, projectID string) *LoggingChecks {
	return &LoggingChecks{
		client:    client,
		projectID: projectID,
	}
}

func (c *LoggingChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	results = append(results, c.CheckCloudAuditLogs(ctx)...)
	results = append(results, c.CheckLogSinks(ctx)...)
	results = append(results, c.CheckLogRetention(ctx)...)
	results = append(results, c.CheckDNSLogging(ctx)...)

	return results, nil
}

// CheckCloudAuditLogs verifies Cloud Audit Logs are properly configured (CIS 2.1)
func (c *LoggingChecks) CheckCloudAuditLogs(ctx context.Context) []CheckResult {
	var results []CheckResult

	// For CIS 2.1, we need to verify audit logging is enabled
	// In GCP, Admin Activity logs are always enabled and can't be disabled
	// Data Access logs need to be explicitly enabled for sensitive operations

	// This is a manual check because audit log configuration requires
	// checking IAM audit config at the project level via Resource Manager API
	results = append(results, CheckResult{
		Control:     "CIS GCP 2.1",
		Name:        "[CIS GCP 2.1] Cloud Audit Logs Enabled",
		Status:      "INFO",
		Severity:    "CRITICAL",
		Evidence:    "Cloud Audit Logging configuration requires manual verification | Admin Activity logs are enabled by default (cannot be disabled), but Data Access logs must be explicitly enabled",
		Remediation: "Enable Data Access audit logs for all services",
		RemediationDetail: `# Enable Data Access logs for all services (requires Owner/Security Admin role)
# Via Console: IAM & Admin → Audit Logs → Select services → Enable Data Read/Write logs

# Via gcloud (example for Cloud Storage):
cat > audit_config.yaml <<EOF
auditConfigs:
- auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_READ
  - logType: DATA_WRITE
  service: storage.googleapis.com
EOF

gcloud projects set-iam-policy PROJECT_ID audit_config.yaml

# Verify audit logs:
gcloud logging read "protoPayload.serviceName=storage.googleapis.com" --limit 10`,
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Google Cloud Console → IAM & Admin → Audit Logs → Screenshot showing Data Access logs enabled for key services (Cloud Storage, BigQuery, Cloud SQL)",
		ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/audit?project=%s", c.projectID),
		Frameworks:      GetFrameworkMappings("CLOUD_AUDIT_LOGS"),
	})

	return results
}

// CheckLogSinks verifies log sinks are configured (CIS 2.2)
func (c *LoggingChecks) CheckLogSinks(ctx context.Context) []CheckResult {
	var results []CheckResult

	req := &loggingpb.ListSinksRequest{
		Parent: fmt.Sprintf("projects/%s", c.projectID),
	}

	it := c.client.ListSinks(ctx, req)
	sinkCount := 0
	sinks := []string{}

	for {
		sink, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CIS GCP 2.2",
				Name:        "[CIS GCP 2.2] Log Sinks Configured",
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check log sinks: %v", err),
				Remediation: "Verify Cloud Logging API is enabled and permissions are correct",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("LOG_SINKS"),
			})
			return results
		}

		sinkCount++
		sinks = append(sinks, sink.Name)
	}

	if sinkCount == 0 {
		results = append(results, CheckResult{
			Control:     "CIS GCP 2.2",
			Name:        "[CIS GCP 2.2] Log Sinks Configured",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    "CIS 2.2: No log sinks configured | Logs should be exported to long-term storage for security analysis",
			Remediation: "Configure log sinks to export logs to Cloud Storage, BigQuery, or Pub/Sub",
			RemediationDetail: `# Create log sink to Cloud Storage
gcloud logging sinks create security-logs-sink \
  storage.googleapis.com/BUCKET_NAME \
  --log-filter='severity >= ERROR'

# Or export all audit logs
gcloud logging sinks create audit-logs-sink \
  storage.googleapis.com/BUCKET_NAME \
  --log-filter='logName:"cloudaudit.googleapis.com"'`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Logging → Log Router → Sinks tab → Screenshot showing configured sinks",
			ConsoleURL:      "https://console.cloud.google.com/logs/router",
			Frameworks:      GetFrameworkMappings("LOG_SINKS"),
		})
	} else {
		displaySinks := sinks
		if len(sinks) > 3 {
			displaySinks = sinks[:3]
		}

		results = append(results, CheckResult{
			Control:    "CIS GCP 2.2",
			Name:       "[CIS GCP 2.2] Log Sinks Configured",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("%d log sinks configured: %v | Meets CIS 2.2", sinkCount, displaySinks),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("LOG_SINKS"),
		})
	}

	return results
}

// CheckLogRetention verifies log retention meets requirements (CIS 2.3)
func (c *LoggingChecks) CheckLogRetention(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Note: Log retention is configured at bucket level in Cloud Logging
	// This requires checking bucket settings which is complex
	// Providing manual check with guidance

	req := &loggingpb.ListBucketsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", c.projectID),
	}

	it := c.client.ListBuckets(ctx, req)
	bucketsWithShortRetention := []string{}
	totalBuckets := 0

	for {
		bucket, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CIS GCP 2.3",
				Name:        "[CIS GCP 2.3] Log Retention Period",
				Status:      "FAIL",
				Evidence:    fmt.Sprintf("Unable to check log retention: %v", err),
				Remediation: "Verify Cloud Logging API is enabled",
				Priority:    PriorityMedium,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("LOG_RETENTION"),
			})
			return results
		}

		totalBuckets++

		// Check retention period (should be at least 90 days, recommend 365)
		// Default is 30 days
		if bucket.RetentionDays < 90 {
			bucketsWithShortRetention = append(bucketsWithShortRetention,
				fmt.Sprintf("%s (%d days)", bucket.Name, bucket.RetentionDays))
		}
	}

	if len(bucketsWithShortRetention) > 0 {
		displayBuckets := bucketsWithShortRetention
		if len(bucketsWithShortRetention) > 3 {
			displayBuckets = bucketsWithShortRetention[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 2.3",
			Name:        "[CIS GCP 2.3] Log Retention Period",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 2.3: %d log buckets have retention < 90 days: %v | PCI requires 90 days minimum", len(bucketsWithShortRetention), displayBuckets),
			Remediation: "Set log retention to at least 90 days (365 days recommended for security analysis)",
			RemediationDetail: `gcloud logging buckets update BUCKET_ID \
  --location=LOCATION \
  --retention-days=365`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Logging → Log Storage → Buckets → Screenshot showing retention days >= 90",
			ConsoleURL:      "https://console.cloud.google.com/logs/storage",
			Frameworks:      GetFrameworkMappings("LOG_RETENTION"),
		})
	} else if totalBuckets > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 2.3",
			Name:       "[CIS GCP 2.3] Log Retention Period",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d log buckets have retention >= 90 days | Meets CIS 2.3", totalBuckets),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("LOG_RETENTION"),
		})
	} else {
		results = append(results, CheckResult{
			Control:     "CIS GCP 2.3",
			Name:        "[CIS GCP 2.3] Log Retention Period",
			Status:      "INFO",
			Evidence:    "Default log bucket found. Verify retention settings.",
			Remediation: "Configure log retention to at least 90 days",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("LOG_RETENTION"),
		})
	}

	return results
}

// CheckDNSLogging verifies DNS logging is enabled (CIS 2.13)
func (c *LoggingChecks) CheckDNSLogging(ctx context.Context) []CheckResult {
	var results []CheckResult

	// DNS logging configuration is in Cloud DNS, not directly in logging API
	// Providing manual check with guidance
	results = append(results, CheckResult{
		Control:     "CIS GCP 2.13",
		Name:        "[CIS GCP 2.13] DNS Logging Enabled",
		Status:      "MANUAL",
		Severity:    "MEDIUM",
		Evidence:    "MANUAL CHECK: Verify DNS query logging is enabled for all VPC networks",
		Remediation: "Enable DNS logging for all VPC networks",
		RemediationDetail: `# Enable DNS logging for a VPC network
gcloud compute networks update NETWORK_NAME \
  --enable-cloud-dns-logging

# Or enable for specific DNS policy
gcloud dns policies update POLICY_NAME \
  --enable-logging`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "VPC Network → Select network → DNS → Cloud DNS logging = Enabled",
		ConsoleURL:      "https://console.cloud.google.com/networking/networks/list",
		Frameworks:      GetFrameworkMappings("DNS_LOGGING"),
	})

	return results
}
