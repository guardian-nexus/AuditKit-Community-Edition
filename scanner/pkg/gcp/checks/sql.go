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

// CheckBackupRetention verifies SQL instances have proper backup retention configured (CIS 6.7)
func (c *SQLChecks) CheckBackupRetention(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	if len(instanceList.Items) == 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 6.7",
			Name:       "[CIS GCP 6.7] SQL Backup Retention",
			Status:     "PASS",
			Evidence:   "No SQL instances configured",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "6.7", "SOC2": "A1.2"},
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
			Control:     "CIS GCP 6.7",
			Name:        "[CIS GCP 6.7] SQL Backup Retention",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    strings.Join(evidenceParts, " | ") + " | Violates CIS GCP 6.7 (backup retention and recovery requirements)",
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
			Frameworks:      map[string]string{"CIS-GCP": "6.7", "SOC2": "A1.2", "PCI-DSS": "3.2.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 6.7",
			Name:       "[CIS GCP 6.7] SQL Backup Retention",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d SQL instances have adequate backup retention (≥7 days) and point-in-time recovery enabled | Meets CIS GCP 6.7", len(instanceList.Items)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "6.7", "SOC2": "A1.2", "PCI-DSS": "3.2.1"},
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
			Control:     "CIS GCP 6.2.1",
			Name:        "[CIS GCP 6.2.1] PostgreSQL log_checkpoints Flag",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d PostgreSQL instances do not have log_checkpoints enabled: %s | Violates CIS GCP 6.2.1 (checkpoint logging for recovery)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
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
			Frameworks:      map[string]string{"CIS-GCP": "6.2.1", "SOC2": "CC7.2"},
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
				Control:    "CIS GCP 6.2.1",
				Name:       "[CIS GCP 6.2.1] PostgreSQL log_checkpoints Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d PostgreSQL instances have log_checkpoints enabled | Meets CIS GCP 6.2.1", postgresCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.2.1", "SOC2": "CC7.2"},
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
			Control:     "CIS GCP 6.2.2",
			Name:        "[CIS GCP 6.2.2] PostgreSQL log_connections Flag",
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
				Control:    "CIS GCP 6.2.2",
				Name:       "[CIS GCP 6.2.2] PostgreSQL log_connections Flag",
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
			Control:     "CIS GCP 6.1.1",
			Name:        "[CIS GCP 6.1.1] MySQL skip_show_database Flag",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d MySQL instances do not have skip_show_database enabled: %s | Violates CIS GCP 6.1.1 (prevent database enumeration)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
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
			Frameworks:      map[string]string{"CIS-GCP": "6.1.1", "SOC2": "CC6.1"},
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
				Control:    "CIS GCP 6.1.1",
				Name:       "[CIS GCP 6.1.1] MySQL skip_show_database Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d MySQL instances have skip_show_database enabled | Meets CIS GCP 6.1.1", mysqlCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.1.1", "SOC2": "CC6.1"},
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
			Control:     "CIS GCP 6.2.3",
			Name:        "[CIS GCP 6.2.3] PostgreSQL log_disconnections Flag",
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
				Control:    "CIS GCP 6.2.3",
				Name:       "[CIS GCP 6.2.3] PostgreSQL log_disconnections Flag",
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
			Control:     "CIS GCP 6.2.14",
			Name:        "[CIS GCP 6.2.14] PostgreSQL log_min_duration_statement Flag",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d PostgreSQL instances do not have log_min_duration_statement configured: %s | Violates CIS GCP 6.2.14 (no slow query logging)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
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
			Frameworks:      map[string]string{"CIS-GCP": "6.2.14", "SOC2": "CC7.2"},
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
				Control:    "CIS GCP 6.2.14",
				Name:       "[CIS GCP 6.2.14] PostgreSQL log_min_duration_statement Flag",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d PostgreSQL instances have log_min_duration_statement configured | Meets CIS GCP 6.2.14", postgresCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.2.14", "SOC2": "CC7.2"},
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
			Control:     "CIS GCP 6.3.1",
			Name:        "[CIS GCP 6.3.1] SQL Server Trace Flag 3625",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d SQL Server instances do not have trace flag 3625 enabled: %s | Violates CIS GCP 6.3.1 (error message information disclosure)", len(nonCompliantInstances), strings.Join(displayInstances, ", ")),
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
			Frameworks:      map[string]string{"CIS-GCP": "6.3.1", "SOC2": "CC6.1"},
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
				Control:    "CIS GCP 6.3.1",
				Name:       "[CIS GCP 6.3.1] SQL Server Trace Flag 3625",
				Status:     "PASS",
				Evidence:   fmt.Sprintf("All %d SQL Server instances have trace flag 3625 enabled | Meets CIS GCP 6.3.1", sqlServerCount),
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"CIS-GCP": "6.3.1", "SOC2": "CC6.1"},
			})
		}
	}

	return results
}
