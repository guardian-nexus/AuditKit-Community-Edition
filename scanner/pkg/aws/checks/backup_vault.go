package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/backup"
)

type BackupVaultChecks struct {
	client *backup.Client
}

func NewBackupVaultChecks(client *backup.Client) *BackupVaultChecks {
	return &BackupVaultChecks{client: client}
}

func (c *BackupVaultChecks) Name() string {
	return "AWS Backup Vault Security Configuration"
}

func (c *BackupVaultChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 10.10 - Backup Vault Encryption
	if result, err := c.CheckBackupVaultEncryption(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.11 - Backup Plan Exists
	if result, err := c.CheckBackupPlanExists(ctx); err == nil {
		results = append(results, result)
	}

	// CIS Section 10.12 - Backup Vault Lock
	if result, err := c.CheckBackupVaultLock(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CheckBackupVaultEncryption - Ensure backup vaults use encryption
func (c *BackupVaultChecks) CheckBackupVaultEncryption(ctx context.Context) (CheckResult, error) {
	vaults, err := c.client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	if err != nil {
		return CheckResult{
			Control:     "AWS-BACKUP-02",
			Name:        "AWS Backup Vault Encryption",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list backup vaults: %v", err),
			Remediation: "Verify AWS Backup access permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BACKUP_VAULT_ENCRYPTION"),
		}, err
	}

	if len(vaults.BackupVaultList) == 0 {
		return CheckResult{
			Control:     "AWS-BACKUP-02",
			Name:        "AWS Backup Vault Encryption",
			Status:      "INFO",
			Evidence:    "No AWS Backup vaults found",
			Remediation: "Create encrypted backup vaults for your resources",
			RemediationDetail: `1. Open AWS Backup console
2. Create backup vault
3. Specify KMS key for encryption (default or custom)
4. All backups stored in vault are automatically encrypted
5. Screenshot showing encrypted vault creation`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Backup → Backup vaults → Screenshot showing no vaults",
			ConsoleURL:      "https://console.aws.amazon.com/backup/home#/backupvaults",
			Frameworks:      GetFrameworkMappings("BACKUP_VAULT_ENCRYPTION"),
		}, nil
	}

	unencryptedVaults := []string{}
	encryptedVaults := 0

	for _, vault := range vaults.BackupVaultList {
		if vault.EncryptionKeyArn != nil && *vault.EncryptionKeyArn != "" {
			encryptedVaults++
		} else {
			unencryptedVaults = append(unencryptedVaults, *vault.BackupVaultName)
		}
	}

	if len(unencryptedVaults) > 0 {
		return CheckResult{
			Control:     "AWS-BACKUP-02",
			Name:        "AWS Backup Vault Encryption",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d backup vaults lack encryption: %v", len(unencryptedVaults), len(vaults.BackupVaultList), unencryptedVaults),
			Remediation: "Create new encrypted backup vaults and migrate backups",
			RemediationDetail: fmt.Sprintf(`1. Open AWS Backup console
2. Create new backup vault with encryption
3. Specify KMS key (custom recommended for compliance)
4. Update backup plans to use new encrypted vault
5. Copy existing backups to encrypted vault
6. Delete old unencrypted vault after migration
7. Unencrypted vaults: %v`, unencryptedVaults),
			Severity:        "CRITICAL",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Backup → Backup vaults → Screenshot showing encrypted vaults",
			ConsoleURL:      "https://console.aws.amazon.com/backup/home#/backupvaults",
			Frameworks:      GetFrameworkMappings("BACKUP_VAULT_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:     "AWS-BACKUP-02",
		Name:        "AWS Backup Vault Encryption",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d backup vaults use KMS encryption", encryptedVaults),
		Remediation: "N/A - All vaults encrypted",
		RemediationDetail: fmt.Sprintf(`All %d backup vaults are encrypted with KMS.
Continue using encryption for all new backup vaults.`, encryptedVaults),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Backup → Backup vaults → Screenshot showing all encrypted",
		ConsoleURL:      "https://console.aws.amazon.com/backup/home#/backupvaults",
		Frameworks:      GetFrameworkMappings("BACKUP_VAULT_ENCRYPTION"),
	}, nil
}

// CheckBackupPlanExists - Ensure backup plans are configured
func (c *BackupVaultChecks) CheckBackupPlanExists(ctx context.Context) (CheckResult, error) {
	plans, err := c.client.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
	if err != nil {
		return CheckResult{
			Control:     "AWS-BACKUP-01",
			Name:        "AWS Backup Plan Configured",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list backup plans: %v", err),
			Remediation: "Verify AWS Backup permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BACKUP_PLAN_EXISTS"),
		}, err
	}

	if len(plans.BackupPlansList) == 0 {
		return CheckResult{
			Control:     "AWS-BACKUP-01",
			Name:        "AWS Backup Plan Configured",
			Status:      "FAIL",
			Evidence:    "No backup plans configured - data loss risk if resources fail",
			Remediation: "Create AWS Backup plans for critical resources",
			RemediationDetail: `1. Open AWS Backup console
2. Create backup plan
3. Define backup frequency (daily/weekly)
4. Set retention period (30+ days recommended)
5. Assign resources using tags or resource IDs
6. Resources to protect:
   - RDS databases
   - EBS volumes
   - EFS file systems
   - DynamoDB tables
   - EC2 instances
7. Screenshot showing configured backup plan`,
			Severity:        "CRITICAL",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Backup → Backup plans → Create plan → Screenshot showing plan configuration",
			ConsoleURL:      "https://console.aws.amazon.com/backup/home#/backupplans",
			Frameworks:      GetFrameworkMappings("BACKUP_PLAN_EXISTS"),
		}, nil
	}

	activePlans := 0
	for _, plan := range plans.BackupPlansList {
		if plan.BackupPlanId != nil {
			activePlans++
		}
	}

	return CheckResult{
		Control:     "AWS-BACKUP-01",
		Name:        "AWS Backup Plan Configured",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("%d backup plan(s) configured for automated backups", activePlans),
		Remediation: "N/A - Backup plans exist",
		RemediationDetail: fmt.Sprintf(`%d backup plan(s) configured.
Regularly verify:
1. Plans are executing successfully
2. Retention policies meet compliance requirements
3. All critical resources are covered`, activePlans),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Backup → Backup plans → Screenshot showing active plans",
		ConsoleURL:      "https://console.aws.amazon.com/backup/home#/backupplans",
		Frameworks:      GetFrameworkMappings("BACKUP_PLAN_EXISTS"),
	}, nil
}

// CheckBackupVaultLock - Ensure backup vaults use vault lock for compliance
func (c *BackupVaultChecks) CheckBackupVaultLock(ctx context.Context) (CheckResult, error) {
	vaults, err := c.client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	if err != nil {
		return CheckResult{
			Control:     "AWS-BACKUP-03",
			Name:        "AWS Backup Vault Lock Enabled",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list vaults: %v", err),
			Remediation: "Verify permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BACKUP_VAULT_LOCK"),
		}, err
	}

	if len(vaults.BackupVaultList) == 0 {
		return CheckResult{
			Control:     "AWS-BACKUP-03",
			Name:        "AWS Backup Vault Lock Enabled",
			Status:      "INFO",
			Evidence:    "No backup vaults found",
			Remediation: "N/A - No vaults to lock",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("BACKUP_VAULT_LOCK"),
		}, nil
	}

	// Check each vault for vault lock configuration
	vaultsWithoutLock := []string{}
	vaultsWithLock := 0

	for _, vault := range vaults.BackupVaultList {
		lockConfig, err := c.client.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{
			BackupVaultName: vault.BackupVaultName,
		})

		if err != nil {
			vaultsWithoutLock = append(vaultsWithoutLock, *vault.BackupVaultName)
			continue
		}

		// Vault lock is indicated by locked flag
		if lockConfig.Locked != nil && *lockConfig.Locked {
			vaultsWithLock++
		} else {
			vaultsWithoutLock = append(vaultsWithoutLock, *vault.BackupVaultName)
		}
	}

	if len(vaultsWithoutLock) > 0 {
		return CheckResult{
			Control:     "AWS-BACKUP-03",
			Name:        "AWS Backup Vault Lock Enabled",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d vaults lack vault lock (WORM protection): %v", len(vaultsWithoutLock), len(vaults.BackupVaultList), vaultsWithoutLock),
			Remediation: "Enable AWS Backup Vault Lock for immutable backups",
			RemediationDetail: fmt.Sprintf(`1. Open AWS Backup console
2. For each vault without lock: %v
3. Select vault → Vault lock configuration
4. Enable vault lock
5. Set minimum retention period (cannot be changed after lock)
6. Set maximum retention period
7. Confirm lock (irreversible!)
8. Screenshot showing vault lock enabled

WARNING: Vault Lock is IRREVERSIBLE once enabled!
Ensure retention policies are correct before enabling.`, vaultsWithoutLock),
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "AWS Backup → Backup vaults → Vault → Vault lock → Screenshot showing lock enabled",
			ConsoleURL:      "https://console.aws.amazon.com/backup/home#/backupvaults",
			Frameworks:      GetFrameworkMappings("BACKUP_VAULT_LOCK"),
		}, nil
	}

	return CheckResult{
		Control:     "AWS-BACKUP-03",
		Name:        "AWS Backup Vault Lock Enabled",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d backup vaults have vault lock enabled (WORM protection)", vaultsWithLock),
		Remediation: "N/A - All vaults locked",
		RemediationDetail: fmt.Sprintf(`All %d vaults use Vault Lock for immutable backups.
This prevents accidental or malicious deletion of backups.`, vaultsWithLock),
		Severity:        "INFO",
		Priority:        PriorityLow,
		Timestamp:       time.Now(),
		ScreenshotGuide: "AWS Backup → Backup vaults → Screenshot showing all vaults locked",
		ConsoleURL:      "https://console.aws.amazon.com/backup/home#/backupvaults",
		Frameworks:      GetFrameworkMappings("BACKUP_VAULT_LOCK"),
	}, nil
}
