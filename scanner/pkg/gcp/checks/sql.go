package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/sqladmin/v1"
)

type SQLChecks struct {
	service   *sqladmin.Service
	projectID string
}

func NewSQLChecks(service *sqladmin.Service, projectID string) *SQLChecks {
	return &SQLChecks{service: service, projectID: projectID}
}

func (c *SQLChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	results = append(results, c.CheckPublicIP(ctx)...)
	results = append(results, c.CheckBackupEnabled(ctx)...)
	results = append(results, c.CheckBackupRetention(ctx)...)
	results = append(results, c.CheckSSLRequired(ctx)...)

	// CIS database flag checks
	results = append(results, c.CheckPostgreSQLLogCheckpoints(ctx)...)
	results = append(results, c.CheckPostgreSQLLogConnections(ctx)...)
	results = append(results, c.CheckPostgreSQLLogDisconnections(ctx)...)
	results = append(results, c.CheckPostgreSQLLogDuration(ctx)...)
	results = append(results, c.CheckMySQLSkipShowDatabase(ctx)...)
	results = append(results, c.CheckSQLServerTraceFlag(ctx)...)

	// Database flags. Ported from Pro: these eight were reported by neither
	// edition under an identifier that exists in v5.0.0.
	results = append(results, c.CheckPostgreSQLLogErrorVerbosity(ctx)...)
	results = append(results, c.CheckPostgreSQLLogStatement(ctx)...)
	results = append(results, c.CheckPostgreSQLLogMinErrorStatement(ctx)...)
	results = append(results, c.CheckSQLServerCrossDBOwnership(ctx)...)
	results = append(results, c.CheckSQLServerContainedDBAuth(ctx)...)
	results = append(results, c.CheckMySQLLocalInfile(ctx)...)
	results = append(results, c.CheckSQLServerRemoteAccess(ctx)...)
	results = append(results, c.CheckPostgreSQLLogLockWaits(ctx)...)
	// The flag recommendations the original checks did not cover, plus 6.5.
	results = append(results, c.CheckPostgreSQLLogMinMessages(ctx)...)
	results = append(results, c.CheckPostgreSQLPgAudit(ctx)...)
	results = append(results, c.CheckSQLServerExternalScripts(ctx)...)
	results = append(results, c.CheckSQLServerUserConnections(ctx)...)
	results = append(results, c.CheckSQLServerUserOptions(ctx)...)
	results = append(results, c.CheckSQLAuthorizedNetworks(ctx)...)
	return results, nil
}

func (c *SQLChecks) CheckPublicIP(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	publicInstances := []string{}
	for _, instance := range instanceList.Items {
		if instance.Settings != nil && instance.Settings.IpConfiguration != nil {
			if instance.Settings.IpConfiguration.Ipv4Enabled {
				publicInstances = append(publicInstances, instance.Name)
			}
		}
	}

	if len(publicInstances) > 0 {
		results = append(results, CheckResult{
			Control:           "CC6.6",
			Name:              "Cloud SQL - Public IP",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("CRITICAL: %d Cloud SQL instances have public IPs: %s | Violates PCI DSS 1.4.2", len(publicInstances), strings.Join(publicInstances, ", ")),
			Remediation:       "Disable public IP and use private IP or Cloud SQL Proxy",
			RemediationDetail: "gcloud sql instances patch INSTANCE_NAME --no-assign-ip",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "SQL → Connections → Public IP address = Not enabled",
			ConsoleURL:        "https://console.cloud.google.com/sql/instances",
			Frameworks:        GetFrameworkMappings("SQL_PUBLIC_IP"),
		})
	} else if len(instanceList.Items) > 0 {
		results = append(results, CheckResult{
			Control:    "CC6.6",
			Name:       "Cloud SQL - Public IP",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d SQL instances use private IPs | Meets PCI DSS 1.4.2", len(instanceList.Items)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_PUBLIC_IP"),
		})
	}

	return results
}

func (c *SQLChecks) CheckBackupEnabled(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	noBackup := []string{}
	for _, instance := range instanceList.Items {
		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			if !instance.Settings.BackupConfiguration.Enabled {
				noBackup = append(noBackup, instance.Name)
			}
		} else {
			noBackup = append(noBackup, instance.Name)
		}
	}

	if len(noBackup) > 0 {
		results = append(results, CheckResult{
			Control:           "A1.2",
			Name:              "Cloud SQL - Automated Backups",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d SQL instances without automated backups: %s | Violates PCI DSS 9.5.1", len(noBackup), strings.Join(noBackup, ", ")),
			Remediation:       "Enable automated daily backups",
			RemediationDetail: "gcloud sql instances patch INSTANCE_NAME --backup-start-time=03:00",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "SQL → Backups → Automated backups enabled",
			ConsoleURL:        "https://console.cloud.google.com/sql/instances",
			Frameworks:        GetFrameworkMappings("SQL_BACKUP_ENABLED"),
		})
	} else if len(instanceList.Items) > 0 {
		results = append(results, CheckResult{
			Control:    "A1.2",
			Name:       "Cloud SQL - Automated Backups",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d SQL instances have automated backups | Meets PCI DSS 9.5.1", len(instanceList.Items)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_BACKUP_ENABLED"),
		})
	}

	return results
}

// CheckBackupRetention verifies SQL instances have proper backup retention configured (CIS 6.8)
func (c *SQLChecks) CheckBackupRetention(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	if len(instanceList.Items) == 0 {
		results = append(results, CheckResult{
			Control:    "CIS-GCP-6.8",
			Name:       "[CIS-GCP-6.8] SQL Backup Retention",
			Status:     "PASS",
			Evidence:   "No SQL instances configured",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "6.8", "SOC2": "A1.2"},
		})
		return results
	}

	lowRetention := []string{}
	noPointInTime := []string{}

	for _, instance := range instanceList.Items {
		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			backupConfig := instance.Settings.BackupConfiguration

			// Check backup retention (recommended: 7+ days for CIS)
			if backupConfig.BackupRetentionSettings != nil {
				retainedBackups := backupConfig.BackupRetentionSettings.RetainedBackups
				if retainedBackups < 7 {
					lowRetention = append(lowRetention, fmt.Sprintf("%s (retention: %d backups)", instance.Name, retainedBackups))
				}
			}

			// Check point-in-time recovery (binary logging)
			if !backupConfig.BinaryLogEnabled && !backupConfig.PointInTimeRecoveryEnabled {
				noPointInTime = append(noPointInTime, instance.Name)
			}
		}
	}

	if len(lowRetention) > 0 || len(noPointInTime) > 0 {
		evidenceParts := []string{}
		if len(lowRetention) > 0 {
			evidenceParts = append(evidenceParts, fmt.Sprintf("%d instances with low backup retention (<7 days): %s", len(lowRetention), strings.Join(lowRetention, ", ")))
		}
		if len(noPointInTime) > 0 {
			evidenceParts = append(evidenceParts, fmt.Sprintf("%d instances without point-in-time recovery: %s", len(noPointInTime), strings.Join(noPointInTime, ", ")))
		}

		results = append(results, CheckResult{
			Control:     "CIS-GCP-6.8",
			Name:        "[CIS-GCP-6.8] SQL Backup Retention",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    strings.Join(evidenceParts, " | ") + " | Violates CIS GCP 6.8 (backup retention and recovery requirements)",
			Remediation: "Configure backup retention to 7+ days and enable point-in-time recovery",
			RemediationDetail: `# Set backup retention to 7 days
gcloud sql instances patch INSTANCE_NAME \
    --retained-backups-count=7

# Enable point-in-time recovery (binary logging)
gcloud sql instances patch INSTANCE_NAME \
    --backup-start-time=03:00 \
    --enable-bin-log`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → SQL → Select instance → Backups → Screenshot showing backup retention ≥7 days and point-in-time recovery enabled",
			ConsoleURL:      "https://console.cloud.google.com/sql/instances",
			Frameworks:      map[string]string{"CIS-GCP": "6.8", "SOC2": "A1.2", "PCI-DSS": "3.2.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS-GCP-6.8",
			Name:       "[CIS-GCP-6.8] SQL Backup Retention",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d SQL instances have adequate backup retention (≥7 days) and point-in-time recovery enabled | Meets CIS GCP 6.8", len(instanceList.Items)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "6.8", "SOC2": "A1.2", "PCI-DSS": "3.2.1"},
		})
	}

	return results
}

func (c *SQLChecks) CheckSSLRequired(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	noSSL := []string{}
	for _, instance := range instanceList.Items {
		if instance.Settings != nil && instance.Settings.IpConfiguration != nil {
			if !instance.Settings.IpConfiguration.RequireSsl {
				noSSL = append(noSSL, instance.Name)
			}
		}
	}

	if len(noSSL) > 0 {
		results = append(results, CheckResult{
			Control:           "CC6.1",
			Name:              "Cloud SQL - SSL Enforcement",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d SQL instances do not require SSL: %s | Violates PCI DSS 4.2.1", len(noSSL), strings.Join(noSSL, ", ")),
			Remediation:       "Require SSL for all connections",
			RemediationDetail: "gcloud sql instances patch INSTANCE_NAME --require-ssl",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "SQL → Connections → Require SSL = Enabled",
			ConsoleURL:        "https://console.cloud.google.com/sql/instances",
			Frameworks:        GetFrameworkMappings("SQL_SSL_REQUIRED"),
		})
	} else if len(instanceList.Items) > 0 {
		results = append(results, CheckResult{
			Control:    "CC6.1",
			Name:       "Cloud SQL - SSL Enforcement",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d SQL instances require SSL | Meets PCI DSS 4.2.1", len(instanceList.Items)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("SQL_SSL_REQUIRED"),
		})
	}

	return results
}

// CheckPostgreSQLLogCheckpoints checks PostgreSQL log_checkpoints flag
// CIS GCP Foundations Benchmark 6.2.1
func (c *SQLChecks) CheckPostgreSQLLogCheckpoints(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	nonCompliantInstances := []string{}

	for _, instance := range instanceList.Items {
		// Only check PostgreSQL instances
		if !strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
			continue
		}

		// Check database flags
		hasLogCheckpoints := false
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			for _, flag := range instance.Settings.DatabaseFlags {
				if flag.Name == "log_checkpoints" && flag.Value == "on" {
					hasLogCheckpoints = true
					break
				}
			}
		}

		if !hasLogCheckpoints {
			nonCompliantInstances = append(nonCompliantInstances, instance.Name)
		}
	}

	if len(nonCompliantInstances) > 0 {
		displayInstances := nonCompliantInstances
		if len(nonCompliantInstances) > 3 {
			displayInstances = nonCompliantInstances[:3]
		}

		results = append(results, CheckResult{
			Control:     "GCP-SQL-01",
			Name:        "[GCP-SQL-01] PostgreSQL log_checkpoints Flag",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d PostgreSQL instances do not have log_checkpoints enabled: %s (checkpoint logging for recovery)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
			Remediation: "Enable log_checkpoints database flag for PostgreSQL instances",
			RemediationDetail: fmt.Sprintf(`# Enable log_checkpoints for PostgreSQL
gcloud sql instances patch %s \
  --database-flags log_checkpoints=on

# Or add to existing flags (preserve other flags):
gcloud sql instances patch %s \
  --database-flags log_checkpoints=on,other_flag=value`, nonCompliantInstances[0], nonCompliantInstances[0]),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Cloud SQL → Instance → Configuration → Flags → Screenshot showing log_checkpoints=on",
			ConsoleURL:      "https://console.cloud.google.com/sql/instances",
			Frameworks:      map[string]string{"SOC2": "CC7.2"},
		})
	} else {
		// Count PostgreSQL instances to provide meaningful pass message
		postgresCount := 0
		for _, instance := range instanceList.Items {
			if strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
				postgresCount++
			}
		}
		if postgresCount > 0 {
			results = append(results, CheckResult{
				Control:    "GCP-SQL-01",
				Name:       "[GCP-SQL-01] PostgreSQL log_checkpoints Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d PostgreSQL instances have log_checkpoints enabled", postgresCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"SOC2": "CC7.2"},
			})
		}
	}

	return results
}

// CheckPostgreSQLLogConnections checks PostgreSQL log_connections flag
// CIS GCP Foundations Benchmark 6.2.2
func (c *SQLChecks) CheckPostgreSQLLogConnections(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	nonCompliantInstances := []string{}

	for _, instance := range instanceList.Items {
		// Only check PostgreSQL instances
		if !strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
			continue
		}

		// Check database flags
		hasLogConnections := false
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			for _, flag := range instance.Settings.DatabaseFlags {
				if flag.Name == "log_connections" && flag.Value == "on" {
					hasLogConnections = true
					break
				}
			}
		}

		if !hasLogConnections {
			nonCompliantInstances = append(nonCompliantInstances, instance.Name)
		}
	}

	if len(nonCompliantInstances) > 0 {
		displayInstances := nonCompliantInstances
		if len(nonCompliantInstances) > 3 {
			displayInstances = nonCompliantInstances[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-GCP-6.2.2",
			Name:        "[CIS-GCP-6.2.2] PostgreSQL log_connections Flag",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d PostgreSQL instances do not have log_connections enabled: %s | Violates CIS GCP 6.2.2 (connection audit trail)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
			Remediation: "Enable log_connections database flag for PostgreSQL instances",
			RemediationDetail: fmt.Sprintf(`# Enable log_connections for PostgreSQL
gcloud sql instances patch %s \
  --database-flags log_connections=on

# Best practice: Enable both log_connections and log_disconnections
gcloud sql instances patch %s \
  --database-flags log_connections=on,log_disconnections=on`, nonCompliantInstances[0], nonCompliantInstances[0]),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Cloud SQL → Instance → Configuration → Flags → Screenshot showing log_connections=on",
			ConsoleURL:      "https://console.cloud.google.com/sql/instances",
			Frameworks:      map[string]string{"CIS-GCP": "6.2.2", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.5"},
		})
	} else {
		postgresCount := 0
		for _, instance := range instanceList.Items {
			if strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
				postgresCount++
			}
		}
		if postgresCount > 0 {
			results = append(results, CheckResult{
				Control:    "CIS-GCP-6.2.2",
				Name:       "[CIS-GCP-6.2.2] PostgreSQL log_connections Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d PostgreSQL instances have log_connections enabled | Meets CIS GCP 6.2.2", postgresCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.2.2", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.5"},
			})
		}
	}

	return results
}

// CheckMySQLSkipShowDatabase checks MySQL skip_show_database flag
// CIS GCP Foundations Benchmark 6.1.1
func (c *SQLChecks) CheckMySQLSkipShowDatabase(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	nonCompliantInstances := []string{}

	for _, instance := range instanceList.Items {
		// Only check MySQL instances
		if !strings.HasPrefix(instance.DatabaseVersion, "MYSQL") {
			continue
		}

		// Check database flags
		hasSkipShowDatabase := false
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			for _, flag := range instance.Settings.DatabaseFlags {
				if flag.Name == "skip_show_database" && flag.Value == "on" {
					hasSkipShowDatabase = true
					break
				}
			}
		}

		if !hasSkipShowDatabase {
			nonCompliantInstances = append(nonCompliantInstances, instance.Name)
		}
	}

	if len(nonCompliantInstances) > 0 {
		displayInstances := nonCompliantInstances
		if len(nonCompliantInstances) > 3 {
			displayInstances = nonCompliantInstances[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-GCP-6.1.2",
			Name:        "[CIS-GCP-6.1.2] MySQL skip_show_database Flag",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d MySQL instances do not have skip_show_database enabled: %s | Violates CIS GCP 6.1.2 (prevent database enumeration)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
			Remediation: "Enable skip_show_database database flag for MySQL instances",
			RemediationDetail: fmt.Sprintf(`# Enable skip_show_database for MySQL
gcloud sql instances patch %s \
  --database-flags skip_show_database=on

# This prevents users from using SHOW DATABASES to see all databases
# Users can only see databases for which they have privileges`, nonCompliantInstances[0]),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Cloud SQL → Instance → Configuration → Flags → Screenshot showing skip_show_database=on",
			ConsoleURL:      "https://console.cloud.google.com/sql/instances",
			Frameworks:      map[string]string{"CIS-GCP": "6.1.2", "SOC2": "CC6.1"},
		})
	} else {
		mysqlCount := 0
		for _, instance := range instanceList.Items {
			if strings.HasPrefix(instance.DatabaseVersion, "MYSQL") {
				mysqlCount++
			}
		}
		if mysqlCount > 0 {
			results = append(results, CheckResult{
				Control:    "CIS-GCP-6.1.2",
				Name:       "[CIS-GCP-6.1.2] MySQL skip_show_database Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d MySQL instances have skip_show_database enabled | Meets CIS GCP 6.1.2", mysqlCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.1.2", "SOC2": "CC6.1"},
			})
		}
	}

	return results
}

// CheckPostgreSQLLogDisconnections checks PostgreSQL log_disconnections flag
// CIS GCP Foundations Benchmark 6.2.3
func (c *SQLChecks) CheckPostgreSQLLogDisconnections(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	nonCompliantInstances := []string{}

	for _, instance := range instanceList.Items {
		// Only check PostgreSQL instances
		if !strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
			continue
		}

		// Check database flags
		hasLogDisconnections := false
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			for _, flag := range instance.Settings.DatabaseFlags {
				if flag.Name == "log_disconnections" && flag.Value == "on" {
					hasLogDisconnections = true
					break
				}
			}
		}

		if !hasLogDisconnections {
			nonCompliantInstances = append(nonCompliantInstances, instance.Name)
		}
	}

	if len(nonCompliantInstances) > 0 {
		displayInstances := nonCompliantInstances
		if len(nonCompliantInstances) > 3 {
			displayInstances = nonCompliantInstances[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-GCP-6.2.3",
			Name:        "[CIS-GCP-6.2.3] PostgreSQL log_disconnections Flag",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d PostgreSQL instances do not have log_disconnections enabled: %s | Violates CIS GCP 6.2.3 (incomplete session audit trail)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
			Remediation: "Enable log_disconnections database flag for PostgreSQL instances",
			RemediationDetail: fmt.Sprintf(`# Enable log_disconnections for PostgreSQL
gcloud sql instances patch %s \
  --database-flags log_disconnections=on

# Best practice: Enable with log_connections for complete session tracking
gcloud sql instances patch %s \
  --database-flags log_connections=on,log_disconnections=on`, nonCompliantInstances[0], nonCompliantInstances[0]),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Cloud SQL → Instance → Configuration → Flags → Screenshot showing log_disconnections=on",
			ConsoleURL:      "https://console.cloud.google.com/sql/instances",
			Frameworks:      map[string]string{"CIS-GCP": "6.2.3", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.5"},
		})
	} else {
		postgresCount := 0
		for _, instance := range instanceList.Items {
			if strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
				postgresCount++
			}
		}
		if postgresCount > 0 {
			results = append(results, CheckResult{
				Control:    "CIS-GCP-6.2.3",
				Name:       "[CIS-GCP-6.2.3] PostgreSQL log_disconnections Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d PostgreSQL instances have log_disconnections enabled | Meets CIS GCP 6.2.3", postgresCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.2.3", "SOC2": "CC7.2", "PCI-DSS": "10.2.1.5"},
			})
		}
	}

	return results
}

// CheckPostgreSQLLogDuration checks PostgreSQL log_min_duration_statement flag
// CIS GCP Foundations Benchmark 6.2.14
func (c *SQLChecks) CheckPostgreSQLLogDuration(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	nonCompliantInstances := []string{}

	for _, instance := range instanceList.Items {
		// Only check PostgreSQL instances
		if !strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
			continue
		}

		// Check database flags for log_min_duration_statement
		hasLogDuration := false
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			for _, flag := range instance.Settings.DatabaseFlags {
				// Any value >= 0 means logging is enabled (0 = log all statements)
				// -1 means disabled (default)
				if flag.Name == "log_min_duration_statement" && flag.Value != "-1" {
					hasLogDuration = true
					break
				}
			}
		}

		if !hasLogDuration {
			nonCompliantInstances = append(nonCompliantInstances, instance.Name)
		}
	}

	if len(nonCompliantInstances) > 0 {
		displayInstances := nonCompliantInstances
		if len(nonCompliantInstances) > 3 {
			displayInstances = nonCompliantInstances[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-GCP-6.2.7",
			Name:        "[CIS-GCP-6.2.7] PostgreSQL log_min_duration_statement Flag",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d PostgreSQL instances do not have log_min_duration_statement configured: %s | Violates CIS GCP 6.2.7 (no slow query logging)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
			Remediation: "Enable log_min_duration_statement to log slow queries for performance monitoring",
			RemediationDetail: fmt.Sprintf(`# Enable log_min_duration_statement for PostgreSQL
# Log statements taking longer than 1000ms (1 second)
gcloud sql instances patch %s \
  --database-flags log_min_duration_statement=1000

# For stricter monitoring, use lower value (100ms):
gcloud sql instances patch %s \
  --database-flags log_min_duration_statement=100

# Note: Value in milliseconds. -1 = disabled (default)`, nonCompliantInstances[0], nonCompliantInstances[0]),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Cloud SQL → Instance → Configuration → Flags → Screenshot showing log_min_duration_statement set to value >= 0",
			ConsoleURL:      "https://console.cloud.google.com/sql/instances",
			Frameworks:      map[string]string{"CIS-GCP": "6.2.7", "SOC2": "CC7.2"},
		})
	} else {
		postgresCount := 0
		for _, instance := range instanceList.Items {
			if strings.HasPrefix(instance.DatabaseVersion, "POSTGRES") {
				postgresCount++
			}
		}
		if postgresCount > 0 {
			results = append(results, CheckResult{
				Control:    "CIS-GCP-6.2.7",
				Name:       "[CIS-GCP-6.2.7] PostgreSQL log_min_duration_statement Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d PostgreSQL instances have log_min_duration_statement configured | Meets CIS GCP 6.2.7", postgresCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.2.7", "SOC2": "CC7.2"},
			})
		}
	}

	return results
}

// CheckSQLServerTraceFlag checks SQL Server trace flag 3625
// CIS GCP Foundations Benchmark 6.3.1
func (c *SQLChecks) CheckSQLServerTraceFlag(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	nonCompliantInstances := []string{}

	for _, instance := range instanceList.Items {
		// Only check SQL Server instances
		if !strings.HasPrefix(instance.DatabaseVersion, "SQLSERVER") {
			continue
		}

		// Check database flags for trace flag 3625
		hasTraceFlag := false
		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			for _, flag := range instance.Settings.DatabaseFlags {
				if flag.Name == "3625" && flag.Value == "on" {
					hasTraceFlag = true
					break
				}
			}
		}

		if !hasTraceFlag {
			nonCompliantInstances = append(nonCompliantInstances, instance.Name)
		}
	}

	if len(nonCompliantInstances) > 0 {
		displayInstances := nonCompliantInstances
		if len(nonCompliantInstances) > 3 {
			displayInstances = nonCompliantInstances[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS-GCP-6.3.6",
			Name:        "[CIS-GCP-6.3.6] SQL Server Trace Flag 3625",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d SQL Server instances do not have trace flag 3625 enabled: %s | Violates CIS GCP 6.3.6 (error message information disclosure)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
			Remediation: "Enable trace flag 3625 to mask error messages and prevent information disclosure",
			RemediationDetail: fmt.Sprintf(`# Enable trace flag 3625 for SQL Server
gcloud sql instances patch %s \
  --database-flags 3625=on

# Trace flag 3625 masks error messages to prevent disclosure of
# sensitive system information in error responses`, nonCompliantInstances[0]),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Cloud SQL → Instance → Configuration → Flags → Screenshot showing trace flag 3625=on",
			ConsoleURL:      "https://console.cloud.google.com/sql/instances",
			Frameworks:      map[string]string{"CIS-GCP": "6.3.6", "SOC2": "CC6.1"},
		})
	} else {
		sqlServerCount := 0
		for _, instance := range instanceList.Items {
			if strings.HasPrefix(instance.DatabaseVersion, "SQLSERVER") {
				sqlServerCount++
			}
		}
		if sqlServerCount > 0 {
			results = append(results, CheckResult{
				Control:    "CIS-GCP-6.3.6",
				Name:       "[CIS-GCP-6.3.6] SQL Server Trace Flag 3625",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d SQL Server instances have trace flag 3625 enabled | Meets CIS GCP 6.3.6", sqlServerCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.3.6", "SOC2": "CC6.1"},
			})
		}
	}

	return results
}

// Ported from Pro. Eight database-flag recommendations that Community was not
// reporting at all, plus the generic helper they share: the flag name and the
// expected value are the only things that differ between them, so a check
// apiece would be eight copies of one API walk.
// CheckPostgreSQLLogErrorVerbosity verifies log_error_verbosity is set appropriately
func (c *SQLChecks) CheckPostgreSQLLogErrorVerbosity(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "POSTGRES", "log_error_verbosity", "DEFAULT", "CIS-GCP-6.2.1",
		"PostgreSQL Log Error Verbosity",
		"Set log_error_verbosity to DEFAULT or stricter for adequate error logging")
}

// CheckPostgreSQLLogStatement verifies log_statement is set appropriately
func (c *SQLChecks) CheckPostgreSQLLogStatement(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "POSTGRES", "log_statement", "ddl", "CIS-GCP-6.2.4",
		"PostgreSQL Log Statement",
		"Set log_statement to 'ddl' or 'all' to log DDL statements for audit trail")
}

// CheckPostgreSQLLogMinErrorStatement verifies log_min_error_statement is set
func (c *SQLChecks) CheckPostgreSQLLogMinErrorStatement(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "POSTGRES", "log_min_error_statement", "error", "CIS-GCP-6.2.6",
		"PostgreSQL Log Min Error Statement",
		"Set log_min_error_statement to 'error' or stricter for comprehensive error logging")
}

// CheckSQLServerCrossDBOwnership verifies cross db ownership chaining is off
func (c *SQLChecks) CheckSQLServerCrossDBOwnership(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "SQLSERVER", "cross db ownership chaining", "off", "CIS-GCP-6.3.2",
		"SQL Server Cross DB Ownership Chaining",
		"Disable cross db ownership chaining to prevent unauthorized data access")
}

// CheckSQLServerContainedDBAuth verifies contained database authentication is off
func (c *SQLChecks) CheckSQLServerContainedDBAuth(ctx context.Context) []CheckResult {
	return c.checkFlagIfPresent(ctx, "SQLSERVER", "contained database authentication", "off", "CIS-GCP-6.3.7",
		"SQL Server Contained Database Authentication",
		"Disable contained database authentication for centralized authentication management")
}

// CheckMySQLLocalInfile verifies local_infile is set to off
func (c *SQLChecks) CheckMySQLLocalInfile(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "MYSQL", "local_infile", "off", "CIS-GCP-6.1.3",
		"MySQL Local Infile",
		"Disable local_infile to prevent unauthorized file access from client machines")
}

// CheckSQLServerRemoteAccess verifies remote access is set to off
func (c *SQLChecks) CheckSQLServerRemoteAccess(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "SQLSERVER", "remote access", "off", "CIS-GCP-6.3.5",
		"SQL Server Remote Access",
		"Disable remote access unless specifically required for distributed queries")
}

// CheckPostgreSQLLogLockWaits verifies log_lock_waits is enabled
func (c *SQLChecks) CheckPostgreSQLLogLockWaits(ctx context.Context) []CheckResult {
	return c.checkDatabaseFlag(ctx, "POSTGRES", "log_lock_waits", "on", "GCP-SQL-02",
		"PostgreSQL Log Lock Waits",
		"Enable log_lock_waits to identify performance issues and potential deadlocks")
}

// Helper function to check database flags
func (c *SQLChecks) checkDatabaseFlag(ctx context.Context, dbType, flagName, expectedValue, cisControl, checkName, remediation string) []CheckResult {
	var results []CheckResult

	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	violatingInstances := []string{}
	relevantInstanceCount := 0

	for _, instance := range instanceList.Items {
		if instance.DatabaseVersion == "" {
			continue
		}

		// Check if this instance matches the database type
		if !strings.HasPrefix(instance.DatabaseVersion, dbType) {
			continue
		}

		relevantInstanceCount++
		flagValue := ""
		hasFlag := false

		if instance.Settings != nil && instance.Settings.DatabaseFlags != nil {
			for _, flag := range instance.Settings.DatabaseFlags {
				if flag.Name == flagName {
					hasFlag = true
					if flag.Value != "" {
						flagValue = flag.Value
					}
					break
				}
			}
		}

		// Check if flag is missing or has wrong value
		if !hasFlag || (flagValue != expectedValue && !strings.EqualFold(flagValue, expectedValue)) {
			violatingInstances = append(violatingInstances,
				fmt.Sprintf("%s (%s=%s)", instance.Name, flagName, flagValue))
		}
	}

	if len(violatingInstances) > 0 {
		displayInstances := violatingInstances
		if len(violatingInstances) > 5 {
			displayInstances = violatingInstances[:5]
		}

		results = append(results, CheckResult{
			Control:  cisControl,
			Name:     fmt.Sprintf("[%s] %s", cisControl, checkName),
			Status:   "FAIL",
			Severity: "MEDIUM",
			Evidence: fmt.Sprintf("%s: %d/%d %s instances have incorrect '%s' flag: %v",
				cisControl, len(violatingInstances), relevantInstanceCount, dbType, flagName, displayInstances),
			Remediation: remediation,
			RemediationDetail: fmt.Sprintf(`# Set database flag for Cloud SQL instance
gcloud sql instances patch INSTANCE_NAME \
  --database-flags %s=%s

# Or via Console: Cloud SQL → Instance → Edit → Flags → Add %s=%s`,
				flagName, expectedValue, flagName, expectedValue),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: fmt.Sprintf("Cloud SQL → Instance → Edit → Flags → Screenshot showing %s=%s", flagName, expectedValue),
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/sql/instances?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": strings.TrimPrefix(strings.TrimPrefix(cisControl, "CIS-GCP-"), "CIS GCP "), "SOC2": "CC6.1"},
		})
	} else if relevantInstanceCount > 0 {
		results = append(results, CheckResult{
			Control:    cisControl,
			Name:       fmt.Sprintf("[%s] %s", cisControl, checkName),
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d %s instances have '%s' set to '%s' | Meets %s", relevantInstanceCount, dbType, flagName, expectedValue, cisControl),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": strings.TrimPrefix(strings.TrimPrefix(cisControl, "CIS-GCP-"), "CIS GCP "), "SOC2": "CC6.1"},
		})
	}

	return results
}
