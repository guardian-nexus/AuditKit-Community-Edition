package checks

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"time"
)

type RDSChecks struct {
	client *rds.Client
}

func NewRDSChecks(client *rds.Client) *RDSChecks {
	return &RDSChecks{client: client}
}

func (c *RDSChecks) Name() string {
	return "RDS Database Security"
}

func (c *RDSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Existing checks
	if result, err := c.CheckRDSEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckRDSPublicAccess(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckRDSBackups(ctx); err == nil {
		results = append(results, result)
	}

	// NEW CIS checks
	if result, err := c.CheckRDSMinorVersionUpgrade(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckRDSMultiAZ(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckRDSDeletionProtection(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *RDSChecks) CheckRDSEncryption(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unencrypted := []string{}

	for _, instance := range instances.DBInstances {
		dbName := aws.ToString(instance.DBInstanceIdentifier)
		// Check encryption
		if !aws.ToBool(instance.StorageEncrypted) {
			unencrypted = append(unencrypted, dbName)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:           "CC6.3",
			Name:              "RDS Encryption at Rest",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d RDS instances NOT encrypted: %v", len(unencrypted), unencrypted),
			Remediation:       "Enable RDS encryption (requires snapshot & restore)",
			RemediationDetail: "1. Create snapshot: aws rds create-db-snapshot --db-instance-identifier [DB_ID] --db-snapshot-identifier [SNAP_ID]\n2. Copy with encryption: aws rds copy-db-snapshot --source-db-snapshot-identifier [SNAP_ID] --target-db-snapshot-identifier [ENCRYPTED_SNAP] --kms-key-id [KEY_ID]\n3. Restore from encrypted snapshot",
			ScreenshotGuide:   "RDS Console → Instance → Configuration → Screenshot showing 'Encryption: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/rds/",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("RDS_ENCRYPTION"),
		}, nil
	}

	if len(instances.DBInstances) == 0 {
		return CheckResult{
			Control:    "CC6.3",
			Name:       "RDS Encryption at Rest",
			Status:     StatusInfo,
			Evidence:   "No RDS instances found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("RDS_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "RDS Encryption at Rest",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d RDS instances are encrypted", len(instances.DBInstances)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("RDS_ENCRYPTION"),
	}, nil
}

func (c *RDSChecks) CheckRDSPublicAccess(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	publiclyAccessible := []string{}

	for _, instance := range instances.DBInstances {
		if aws.ToBool(instance.PubliclyAccessible) {
			publiclyAccessible = append(publiclyAccessible, aws.ToString(instance.DBInstanceIdentifier))
		}
	}

	if len(publiclyAccessible) > 0 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "RDS Public Access",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d RDS instances are publicly accessible: %v", len(publiclyAccessible), publiclyAccessible),
			Remediation:       "Disable public access on RDS instances",
			RemediationDetail: fmt.Sprintf("aws rds modify-db-instance --db-instance-identifier %s --no-publicly-accessible --apply-immediately", publiclyAccessible[0]),
			ScreenshotGuide:   "RDS Console → Instance → Connectivity & security → Screenshot showing 'Publicly accessible: No'",
			ConsoleURL:        "https://console.aws.amazon.com/rds/",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("RDS_PUBLIC_ACCESS"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "RDS Public Access",
		Status:     "PASS",
		Evidence:   "No RDS instances are publicly accessible",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("RDS_PUBLIC_ACCESS"),
	}, nil
}

func (c *RDSChecks) CheckRDSBackups(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noBackups := []string{}

	for _, instance := range instances.DBInstances {
		dbName := aws.ToString(instance.DBInstanceIdentifier)
		// Check backup retention (PCI DSS requires 7+ days)
		if aws.ToInt32(instance.BackupRetentionPeriod) < 7 {
			noBackups = append(noBackups, fmt.Sprintf("%s (%d days)", dbName, aws.ToInt32(instance.BackupRetentionPeriod)))
		}
	}

	if len(noBackups) > 0 {
		return CheckResult{
			Control:           "A1.2",
			Name:              "RDS Backup Retention",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d RDS instances have <7 day backup retention: %v", len(noBackups), noBackups),
			Remediation:       "Set backup retention to 7+ days (30 recommended)",
			RemediationDetail: fmt.Sprintf("aws rds modify-db-instance --db-instance-identifier [DB_ID] --backup-retention-period 30 --apply-immediately"),
			ScreenshotGuide:   "RDS Console → Instance → Maintenance & backups → Screenshot showing 'Backup retention period: 7 days or more'",
			ConsoleURL:        "https://console.aws.amazon.com/rds/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("RDS_BACKUP"),
		}, nil
	}

	return CheckResult{
		Control:    "A1.2",
		Name:       "RDS Backup Retention",
		Status:     "PASS",
		Evidence:   "All RDS instances have adequate backup retention",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("RDS_BACKUP"),
	}, nil
}

// NEW CIS-SPECIFIC CHECKS

// CIS 2.3.2 - Ensure RDS instances have automatic minor version upgrade enabled
func (c *RDSChecks) CheckRDSMinorVersionUpgrade(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noAutoUpgrade := []string{}

	for _, instance := range instances.DBInstances {
		if !aws.ToBool(instance.AutoMinorVersionUpgrade) {
			noAutoUpgrade = append(noAutoUpgrade, aws.ToString(instance.DBInstanceIdentifier))
		}
	}

	if len(noAutoUpgrade) > 0 {
		return CheckResult{
			Control:           "[CIS-2.3.2]",
			Name:              "RDS Automatic Minor Version Upgrade",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d RDS instances don't have auto minor version upgrade: %v", len(noAutoUpgrade), noAutoUpgrade),
			Remediation:       "Enable automatic minor version upgrades for security patches",
			RemediationDetail: fmt.Sprintf("aws rds modify-db-instance --db-instance-identifier %s --auto-minor-version-upgrade --apply-immediately", noAutoUpgrade[0]),
			ScreenshotGuide:   "RDS Console → Instance → Maintenance & backups → Screenshot showing 'Auto minor version upgrade: Yes'",
			ConsoleURL:        "https://console.aws.amazon.com/rds/",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("RDS_MINOR_UPGRADE"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-2.3.2]",
		Name:       "RDS Automatic Minor Version Upgrade",
		Status:     "PASS",
		Evidence:   "All RDS instances have automatic minor version upgrade enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("RDS_MINOR_UPGRADE"),
	}, nil
}

// CIS 2.3.4 - Ensure RDS instances are configured with multiple Availability Zones
func (c *RDSChecks) CheckRDSMultiAZ(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noMultiAZ := []string{}

	for _, instance := range instances.DBInstances {
		if !aws.ToBool(instance.MultiAZ) {
			noMultiAZ = append(noMultiAZ, aws.ToString(instance.DBInstanceIdentifier))
		}
	}

	if len(noMultiAZ) > 0 {
		return CheckResult{
			Control:           "[CIS-2.3.4]",
			Name:              "RDS Multi-AZ Deployment",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d RDS instances not using Multi-AZ: %v", len(noMultiAZ), noMultiAZ),
			Remediation:       "Enable Multi-AZ for high availability",
			RemediationDetail: fmt.Sprintf("aws rds modify-db-instance --db-instance-identifier %s --multi-az --apply-immediately", noMultiAZ[0]),
			ScreenshotGuide:   "RDS Console → Instance → Configuration → Screenshot showing 'Multi-AZ: Yes'",
			ConsoleURL:        "https://console.aws.amazon.com/rds/",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("RDS_MULTI_AZ"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-2.3.4]",
		Name:       "RDS Multi-AZ Deployment",
		Status:     "PASS",
		Evidence:   "All RDS instances use Multi-AZ deployment",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("RDS_MULTI_AZ"),
	}, nil
}

// CIS 2.3.5 - Ensure RDS instances have deletion protection enabled
func (c *RDSChecks) CheckRDSDeletionProtection(ctx context.Context) (CheckResult, error) {
	instances, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noDeletionProtection := []string{}

	for _, instance := range instances.DBInstances {
		if !aws.ToBool(instance.DeletionProtection) {
			noDeletionProtection = append(noDeletionProtection, aws.ToString(instance.DBInstanceIdentifier))
		}
	}

	if len(noDeletionProtection) > 0 {
		return CheckResult{
			Control:           "[CIS-2.3.5]",
			Name:              "RDS Deletion Protection",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d RDS instances lack deletion protection: %v", len(noDeletionProtection), noDeletionProtection),
			Remediation:       "Enable deletion protection to prevent accidental deletion",
			RemediationDetail: fmt.Sprintf("aws rds modify-db-instance --db-instance-identifier %s --deletion-protection --apply-immediately", noDeletionProtection[0]),
			ScreenshotGuide:   "RDS Console → Instance → Configuration → Screenshot showing 'Deletion protection: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/rds/",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("RDS_DELETION_PROTECTION"),
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-2.3.5]",
		Name:       "RDS Deletion Protection",
		Status:     "PASS",
		Evidence:   "All RDS instances have deletion protection enabled",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("RDS_DELETION_PROTECTION"),
	}, nil
}
