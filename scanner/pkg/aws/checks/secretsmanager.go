package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsManagerChecks struct {
	client *secretsmanager.Client
}

func NewSecretsManagerChecks(client *secretsmanager.Client) *SecretsManagerChecks {
	return &SecretsManagerChecks{client: client}
}

func (c *SecretsManagerChecks) Name() string {
	return "AWS Secrets Manager Security Configuration"
}

func (c *SecretsManagerChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS 12.1 - Secret rotation enabled
	if result, err := c.CheckSecretRotation(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 12.2 - Secrets encrypted with KMS
	if result, err := c.CheckSecretEncryption(ctx); err == nil {
		results = append(results, result)
	}

	// CIS 12.3 - Unused secrets removed
	if result, err := c.CheckUnusedSecrets(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *SecretsManagerChecks) CheckSecretRotation(ctx context.Context) (CheckResult, error) {
	secrets, err := c.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return CheckResult{
			Control:     "CIS-12.1",
			Name:        "Secrets Manager Rotation Enabled",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list secrets: %v", err),
			Remediation: "Verify Secrets Manager permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SECRETS_ROTATION"),
		}, err
	}

	if len(secrets.SecretList) == 0 {
		return CheckResult{
			Control:     "CIS-12.1",
			Name:        "Secrets Manager Rotation Enabled",
			Status:      "INFO",
			Evidence:    "No secrets found in Secrets Manager",
			Remediation: "N/A - No secrets to rotate",
			RemediationDetail: `When creating secrets:
1. Open Secrets Manager console
2. Store new secret
3. Enable automatic rotation
4. Select or create Lambda rotation function
5. Set rotation schedule (30-90 days recommended)`,
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Secrets Manager → Secrets → Screenshot showing no secrets",
			ConsoleURL:      "https://console.aws.amazon.com/secretsmanager/home#/secrets",
			Frameworks:      GetFrameworkMappings("SECRETS_ROTATION"),
		}, nil
	}

	withoutRotation := []string{}
	withRotation := 0

	for _, secret := range secrets.SecretList {
		if secret.RotationEnabled != nil && *secret.RotationEnabled {
			withRotation++
		} else {
			withoutRotation = append(withoutRotation, *secret.Name)
		}
	}

	if len(withoutRotation) > 0 {
		return CheckResult{
			Control:     "CIS-12.1",
			Name:        "Secrets Manager Rotation Enabled",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d secrets lack automatic rotation: %v", len(withoutRotation), len(secrets.SecretList), withoutRotation),
			Remediation: "Enable automatic rotation for all secrets",
			RemediationDetail: fmt.Sprintf(`1. Open Secrets Manager console
2. For each secret without rotation: %v
3. Edit secret → Rotation configuration
4. Enable automatic rotation
5. Select rotation Lambda function (or create one)
6. Set rotation interval: 30-90 days
7. Test rotation immediately
8. Screenshot showing rotation enabled`, withoutRotation),
			Severity:        "HIGH",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Secrets Manager → Secret → Rotation configuration → Screenshot showing rotation enabled",
			ConsoleURL:      "https://console.aws.amazon.com/secretsmanager/home#/secrets",
			Frameworks:      GetFrameworkMappings("SECRETS_ROTATION"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-12.1",
		Name:        "Secrets Manager Rotation Enabled",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d secrets have automatic rotation enabled", withRotation),
		Remediation: "N/A - All secrets rotate automatically",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/secretsmanager/home#/secrets",
		Frameworks:  GetFrameworkMappings("SECRETS_ROTATION"),
	}, nil
}

func (c *SecretsManagerChecks) CheckSecretEncryption(ctx context.Context) (CheckResult, error) {
	secrets, err := c.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return CheckResult{
			Control:     "CIS-12.2",
			Name:        "Secrets Manager KMS Encryption",
			Status:      "ERROR",
			Evidence:    fmt.Sprintf("Failed to list secrets: %v", err),
			Remediation: "Verify permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SECRETS_ENCRYPTION"),
		}, err
	}

	if len(secrets.SecretList) == 0 {
		return CheckResult{
			Control:     "CIS-12.2",
			Name:        "Secrets Manager KMS Encryption",
			Status:      "INFO",
			Evidence:    "No secrets found",
			Remediation: "N/A",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SECRETS_ENCRYPTION"),
		}, nil
	}

	withoutCustomKMS := []string{}
	withCustomKMS := 0

	for _, secret := range secrets.SecretList {
		// If KmsKeyId is set, it's using a custom key; otherwise using default AWS managed key
		if secret.KmsKeyId != nil && *secret.KmsKeyId != "" {
			withCustomKMS++
		} else {
			withoutCustomKMS = append(withoutCustomKMS, *secret.Name)
		}
	}

	// All secrets are encrypted, but check if using custom KMS keys (best practice)
	if len(withoutCustomKMS) > 0 {
		return CheckResult{
			Control:     "CIS-12.2",
			Name:        "Secrets Manager KMS Encryption",
			Status:      "PASS",
			Evidence:    fmt.Sprintf("All secrets encrypted. %d using custom KMS keys, %d using AWS managed key (less control)", withCustomKMS, len(withoutCustomKMS)),
			Remediation: "Consider using custom KMS keys for better key management",
			RemediationDetail: fmt.Sprintf(`Secrets using AWS managed key: %v

To use custom KMS keys:
1. Create customer managed KMS key
2. Grant Secrets Manager permissions
3. When creating new secret, specify custom KMS key
4. Existing secrets: Rotate secret to re-encrypt with new key`, withoutCustomKMS),
			Severity:        "INFO",
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Secrets Manager → Secret → Screenshot showing custom KMS key",
			ConsoleURL:      "https://console.aws.amazon.com/secretsmanager/home#/secrets",
			Frameworks:      GetFrameworkMappings("SECRETS_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-12.2",
		Name:        "Secrets Manager KMS Encryption",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d secrets encrypted with custom KMS keys", withCustomKMS),
		Remediation: "N/A - All secrets properly encrypted",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/secretsmanager/home#/secrets",
		Frameworks:  GetFrameworkMappings("SECRETS_ENCRYPTION"),
	}, nil
}

func (c *SecretsManagerChecks) CheckUnusedSecrets(ctx context.Context) (CheckResult, error) {
	secrets, err := c.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return CheckResult{
			Control:     "CIS-12.3",
			Name:        "Unused Secrets Removed",
			Status:      "ERROR",
			Evidence:    "Failed to list secrets",
			Remediation: "Verify permissions",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SECRETS_UNUSED"),
		}, err
	}

	if len(secrets.SecretList) == 0 {
		return CheckResult{
			Control:     "CIS-12.3",
			Name:        "Unused Secrets Removed",
			Status:      "INFO",
			Evidence:    "No secrets found",
			Remediation: "N/A",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("SECRETS_UNUSED"),
		}, nil
	}

	unusedSecrets := []string{}
	activeSecrets := 0
	ninetyDaysAgo := time.Now().AddDate(0, 0, -90)

	for _, secret := range secrets.SecretList {
		// Check last accessed time
		lastAccessed := secret.LastAccessedDate
		if lastAccessed == nil || lastAccessed.Before(ninetyDaysAgo) {
			unusedSecrets = append(unusedSecrets, *secret.Name)
		} else {
			activeSecrets++
		}
	}

	if len(unusedSecrets) > 0 {
		return CheckResult{
			Control:     "CIS-12.3",
			Name:        "Unused Secrets Removed",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d secrets not accessed in 90+ days: %v", len(unusedSecrets), len(secrets.SecretList), unusedSecrets),
			Remediation: "Review and delete unused secrets",
			RemediationDetail: fmt.Sprintf(`1. Open Secrets Manager console
2. For each unused secret: %v
3. Verify secret is truly unused
4. Delete secret (30-day recovery window)
5. If needed later, can restore within 30 days
6. Screenshot showing unused secrets removed

Unused secrets increase:
- Cost ($0.40/secret/month)
- Attack surface
- Management overhead`, unusedSecrets),
			Severity:        "MEDIUM",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Secrets Manager → Secrets → Screenshot showing deleted unused secrets",
			ConsoleURL:      "https://console.aws.amazon.com/secretsmanager/home#/secrets",
			Frameworks:      GetFrameworkMappings("SECRETS_UNUSED"),
		}, nil
	}

	return CheckResult{
		Control:     "CIS-12.3",
		Name:        "Unused Secrets Removed",
		Status:      "PASS",
		Evidence:    fmt.Sprintf("All %d secrets accessed within last 90 days", activeSecrets),
		Remediation: "N/A - No unused secrets",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		ConsoleURL:  "https://console.aws.amazon.com/secretsmanager/home#/secrets",
		Frameworks:  GetFrameworkMappings("SECRETS_UNUSED"),
	}, nil
}
