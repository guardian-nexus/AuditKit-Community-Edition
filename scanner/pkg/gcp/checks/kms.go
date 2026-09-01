package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type KMSChecks struct {
	client    *kms.KeyManagementClient
	projectID string
}

func NewKMSChecks(client *kms.KeyManagementClient, projectID string) *KMSChecks {
	return &KMSChecks{
		client:    client,
		projectID: projectID,
	}
}

func (c *KMSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	results = append(results, c.CheckKMSKeyRotation(ctx)...)
	results = append(results, c.CheckKMSSeparationOfDuties(ctx)...)

	return results, nil
}

// CheckKMSKeyRotation verifies automatic key rotation is enabled (CIS 1.10)
func (c *KMSChecks) CheckKMSKeyRotation(ctx context.Context) []CheckResult {
	var results []CheckResult

	keysWithoutRotation := []string{}
	totalKeys := 0

	// Common locations to check
	locations := []string{"global", "us", "us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1"}

	for _, location := range locations {
		// List key rings
		keyRingsReq := &kmspb.ListKeyRingsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", c.projectID, location),
		}

		keyRingIt := c.client.ListKeyRings(ctx, keyRingsReq)

		for {
			keyRing, err := keyRingIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				continue
			}

			// List crypto keys in this key ring
			keysReq := &kmspb.ListCryptoKeysRequest{
				Parent: keyRing.Name,
			}

			keyIt := c.client.ListCryptoKeys(ctx, keysReq)

			for {
				key, err := keyIt.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					continue
				}

				totalKeys++

				// Check if rotation is enabled
				// Note: KMS key rotation is checked via NextRotationTime
				if key.NextRotationTime == nil {
					keysWithoutRotation = append(keysWithoutRotation, key.Name)
				}
			}
		}
	}

	if len(keysWithoutRotation) > 0 {
		displayKeys := keysWithoutRotation
		if len(keysWithoutRotation) > 3 {
			displayKeys = keysWithoutRotation[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 1.10",
			Name:        "[CIS GCP 1.10] KMS Key Rotation",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("CIS 1.10: %d KMS keys do not have automatic rotation enabled: %v", len(keysWithoutRotation), displayKeys),
			Remediation: "Enable automatic key rotation (recommended: 90 days)",
			RemediationDetail: `gcloud kms keys update KEY_NAME \
  --location=LOCATION \
  --keyring=KEYRING_NAME \
  --rotation-period=90d \
  --next-rotation-time=2025-11-01T00:00:00Z`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Security → Key Management → Select key → Key rotation showing rotation period set",
			ConsoleURL:      "https://console.cloud.google.com/security/kms",
			Frameworks:      GetFrameworkMappings("KMS_ROTATION_ENABLED"),
		})
	} else if totalKeys > 0 {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.10",
			Name:       "[CIS GCP 1.10] KMS Key Rotation",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d KMS keys have automatic rotation enabled | Meets CIS 1.10", totalKeys),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("KMS_ROTATION_ENABLED"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.10",
			Name:       "[CIS GCP 1.10] KMS Key Rotation",
			Status:     "INFO",
			Evidence:   "No KMS keys found in common locations",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("KMS_ROTATION_ENABLED"),
		})
	}

	return results
}

// CheckKMSSeparationOfDuties verifies separation of duties for KMS (CIS 1.9)
func (c *KMSChecks) CheckKMSSeparationOfDuties(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Get project IAM policy
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CIS GCP 1.9",
			Name:        "[CIS GCP 1.9] KMS Separation of Duties",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to check KMS separation of duties: %v", err),
			Remediation: "Verify Cloud Resource Manager API is enabled",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("KMS_SEPARATION_OF_DUTIES"),
		})
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CIS GCP 1.9",
			Name:        "[CIS GCP 1.9] KMS Separation of Duties",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Remediation: "Verify resourcemanager.projects.getIamPolicy permission",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("KMS_SEPARATION_OF_DUTIES"),
		})
		return results
	}

	// Check if same user has both KMS admin and crypto key roles
	userRoles := make(map[string][]string)

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if !strings.HasPrefix(member, "serviceAccount:") {
				userRoles[member] = append(userRoles[member], binding.Role)
			}
		}
	}

	conflictingUsers := []string{}
	for user, roles := range userRoles {
		hasAdmin := false
		hasCryptoKey := false

		for _, role := range roles {
			if role == "roles/cloudkms.admin" {
				hasAdmin = true
			}
			if role == "roles/cloudkms.cryptoKeyEncrypterDecrypter" ||
				role == "roles/cloudkms.cryptoKeyEncrypter" ||
				role == "roles/cloudkms.cryptoKeyDecrypter" {
				hasCryptoKey = true
			}
		}

		if hasAdmin && hasCryptoKey {
			conflictingUsers = append(conflictingUsers, user)
		}
	}

	if len(conflictingUsers) > 0 {
		displayUsers := conflictingUsers
		if len(conflictingUsers) > 3 {
			displayUsers = conflictingUsers[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 1.9",
			Name:        "[CIS GCP 1.9] KMS Separation of Duties",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 1.9: %d users have both KMS admin and crypto key usage roles: %v | Violates separation of duties", len(conflictingUsers), displayUsers),
			Remediation: "Separate KMS administration from key usage - different users should manage keys vs use them",
			RemediationDetail: `# Remove conflicting role
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=USER_MEMBER \
  --role=roles/cloudkms.admin

# Best practice: Key administrators should not use keys for encryption/decryption`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing separation between cloudkms.admin and cryptoKey roles",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      GetFrameworkMappings("KMS_SEPARATION_OF_DUTIES"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.9",
			Name:       "[CIS GCP 1.9] KMS Separation of Duties",
			Status:     "PASS",
			Evidence:   "KMS separation of duties enforced: no users have both admin and usage roles | Meets CIS 1.9",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("KMS_SEPARATION_OF_DUTIES"),
		})
	}

	return results
}
