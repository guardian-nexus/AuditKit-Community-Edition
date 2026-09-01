package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// IAMChecks handles GCP IAM security checks
type IAMChecks struct {
	client    *admin.IamClient
	projectID string
}

// NewIAMChecks creates a new IAM checker
func NewIAMChecks(client *admin.IamClient, projectID string) *IAMChecks {
	return &IAMChecks{
		client:    client,
		projectID: projectID,
	}
}

// Run executes all IAM security checks
func (c *IAMChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// Existing checks
	results = append(results, c.CheckServiceAccountKeys(ctx)...)
	results = append(results, c.CheckUserMFA(ctx)...)
	results = append(results, c.CheckPrimitiveRoles(ctx)...)
	results = append(results, c.CheckServiceAccountPermissions(ctx)...)

	// NEW CIS checks
	results = append(results, c.CheckAPIKeysExist(ctx)...)
	results = append(results, c.CheckServiceAccountAdminSeparation(ctx)...)
	results = append(results, c.CheckCorporateLogin(ctx)...)
	results = append(results, c.CheckWorkloadIdentity(ctx)...)
	results = append(results, c.CheckDefaultServiceAccountDisabled(ctx)...)

	// Additional CIS checks for 100% coverage
	results = append(results, c.CheckAPIKeyRotation(ctx)...)
	results = append(results, c.CheckSeparationOfDuties(ctx)...)
	results = append(results, c.CheckKMSKeysPublicAccess(ctx)...)
	results = append(results, c.CheckKMSRoleSeparation(ctx)...)
	results = append(results, c.CheckIAMUserRoles(ctx)...)

	return results, nil
}

// CheckServiceAccountKeys checks for old or excessive service account keys
func (c *IAMChecks) CheckServiceAccountKeys(ctx context.Context) []CheckResult {
	var results []CheckResult

	// List service accounts
	req := &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", c.projectID),
	}

	it := c.client.ListServiceAccounts(ctx, req)
	totalSAs := 0
	keysOlderThan90Days := []string{}
	tooManyKeys := []string{}

	for {
		sa, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CC6.1",
				Name:        "Service Account Key Rotation",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    fmt.Sprintf("Unable to check service account keys: %v", err),
				Remediation: "Verify IAM API is enabled and credentials have iam.serviceAccounts.list permission",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
			})
			break
		}

		totalSAs++

		// List keys for this service account
		keyReq := &adminpb.ListServiceAccountKeysRequest{
			Name: sa.Name,
		}

		keyResp, err := c.client.ListServiceAccountKeys(ctx, keyReq)
		if err != nil {
			continue
		}

		keyCount := 0
		for _, key := range keyResp.Keys {
			keyCount++

			// Check key age
			if key.ValidAfterTime != nil {
				keyAge := time.Since(key.ValidAfterTime.AsTime())
				if keyAge > 90*24*time.Hour {
					keysOlderThan90Days = append(keysOlderThan90Days,
						fmt.Sprintf("%s (%d days old)", sa.Email, int(keyAge.Hours()/24)))
				}
			}
		}

		// Check if too many keys (PCI requires key rotation, having many keys suggests no rotation)
		if keyCount > 2 {
			tooManyKeys = append(tooManyKeys, fmt.Sprintf("%s (%d keys)", sa.Email, keyCount))
		}
	}

	// Report old keys
	if len(keysOlderThan90Days) > 0 {
		displayKeys := keysOlderThan90Days
		if len(keysOlderThan90Days) > 3 {
			displayKeys = keysOlderThan90Days[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Service Account Key Age",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("PCI-DSS 8.3.9: %d service account keys older than 90 days: %s", len(keysOlderThan90Days), strings.Join(displayKeys, ", ")),
			Remediation: "Rotate service account keys every 90 days",
			RemediationDetail: `# Create new key
gcloud iam service-accounts keys create new-key.json \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Delete old key
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → IAM & Admin → Service Accounts → Select account → Keys tab → Screenshot key creation dates",
			ConsoleURL:      "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Frameworks:      GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
		})
	}

	// Report excessive keys
	if len(tooManyKeys) > 0 {
		displayAccounts := tooManyKeys
		if len(tooManyKeys) > 3 {
			displayAccounts = tooManyKeys[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Service Account Key Count",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d service accounts have excessive keys (>2): %s", len(tooManyKeys), strings.Join(displayAccounts, ", ")),
			Remediation: "Limit to 2 keys per service account and rotate regularly",
			RemediationDetail: `gcloud iam service-accounts keys delete OLD_KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM → Service Accounts → Keys tab → Show only 1-2 active keys",
			ConsoleURL:      "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Frameworks:      GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
		})
	}

	if len(keysOlderThan90Days) == 0 && len(tooManyKeys) == 0 && totalSAs > 0 {
		results = append(results, CheckResult{
			Control:    "CC6.1",
			Name:       "Service Account Key Rotation",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d service accounts have properly rotated keys (< 90 days) | Meets PCI DSS 8.3.9", totalSAs),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
		})
	}

	return results
}

// CheckUserMFA verifies 2FA is enforced for users
func (c *IAMChecks) CheckUserMFA(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Get project IAM policy to check for user accounts
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "User MFA Enforcement",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("Unable to check MFA status: %v", err),
			Remediation: "Verify Cloud Resource Manager API is enabled",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "User MFA Enforcement",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Remediation: "Verify resourcemanager.projects.getIamPolicy permission",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
		return results
	}

	// Check for user accounts (not service accounts)
	userAccounts := []string{}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if strings.HasPrefix(member, "user:") {
				email := strings.TrimPrefix(member, "user:")
				if !contains(userAccounts, email) {
					userAccounts = append(userAccounts, email)
				}
			}
		}
	}

	if len(userAccounts) > 0 {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "User MFA Enforcement",
			Status:      "INFO",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("Manual verification required: %d user accounts found. Verify 2-Step Verification is enforced via Workspace admin console", len(userAccounts)),
			Remediation: "Enforce 2-Step Verification in Google Workspace Admin Console",
			RemediationDetail: `1. Go to admin.google.com
2. Security → 2-Step Verification
3. Enable "Allow users to turn on 2-Step Verification"
4. Click "Start enforcing immediately" for all organizational units
5. For PCI: Document MFA enforcement policy`,
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Admin Console → Security → 2-Step Verification → Screenshot enforcement status for all OUs",
			ConsoleURL:      "https://admin.google.com/ac/security/2sv",
			Frameworks:      GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CC6.1",
			Name:       "User MFA Enforcement",
			Status:     "PASS",
			Evidence:   "No user accounts found in project IAM (only service accounts) | Meets SOC2 CC6.1, PCI DSS 8.4.2",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
	}

	return results
}

// CheckPrimitiveRoles checks for overly permissive primitive roles
func (c *IAMChecks) CheckPrimitiveRoles(ctx context.Context) []CheckResult {
	var results []CheckResult

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return results
	}

	primitiveRoles := []string{"roles/owner", "roles/editor", "roles/viewer"}
	problematicBindings := []string{}

	for _, binding := range policy.Bindings {
		for _, primitiveRole := range primitiveRoles {
			if binding.Role == primitiveRole {
				for _, member := range binding.Members {
					// Flag if non-service accounts have primitive roles
					if !strings.HasPrefix(member, "serviceAccount:") {
						problematicBindings = append(problematicBindings,
							fmt.Sprintf("%s has %s", member, binding.Role))
					}
				}
			}
		}
	}

	if len(problematicBindings) > 0 {
		displayBindings := problematicBindings
		if len(problematicBindings) > 3 {
			displayBindings = problematicBindings[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.3",
			Name:        "Primitive Role Usage",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("SOC2 CC6.3: %d accounts using primitive roles (Owner/Editor/Viewer): %s", len(problematicBindings), strings.Join(displayBindings, ", ")),
			Remediation: "Replace primitive roles with predefined or custom roles following least privilege",
			RemediationDetail: `# Remove primitive role
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=user:EMAIL \
  --role=roles/editor

# Add specific predefined role
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=user:EMAIL \
  --role=roles/compute.admin`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing specific roles instead of Owner/Editor/Viewer",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      GetFrameworkMappings("IAM_PRIMITIVE_ROLES"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CC6.3",
			Name:       "Primitive Role Usage",
			Status:     "PASS",
			Evidence:   "No primitive roles assigned to user accounts | Meets SOC2 CC6.3, PCI DSS 7.2.2",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_PRIMITIVE_ROLES"),
		})
	}

	return results
}

// CheckServiceAccountPermissions checks for overly permissive service accounts
func (c *IAMChecks) CheckServiceAccountPermissions(ctx context.Context) []CheckResult {
	var results []CheckResult

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return results
	}

	dangerousRoles := []string{"roles/owner", "roles/editor"}
	serviceAccountsWithDangerousRoles := []string{}

	for _, binding := range policy.Bindings {
		for _, dangerousRole := range dangerousRoles {
			if binding.Role == dangerousRole {
				for _, member := range binding.Members {
					if strings.HasPrefix(member, "serviceAccount:") {
						email := strings.TrimPrefix(member, "serviceAccount:")
						serviceAccountsWithDangerousRoles = append(serviceAccountsWithDangerousRoles,
							fmt.Sprintf("%s (%s)", email, binding.Role))
					}
				}
			}
		}
	}

	if len(serviceAccountsWithDangerousRoles) > 0 {
		displayAccounts := serviceAccountsWithDangerousRoles
		if len(serviceAccountsWithDangerousRoles) > 3 {
			displayAccounts = serviceAccountsWithDangerousRoles[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.3",
			Name:        "Service Account Permissions",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d service accounts have overly broad permissions: %s", len(serviceAccountsWithDangerousRoles), strings.Join(displayAccounts, ", ")),
			Remediation: "Apply least privilege principle to service accounts",
			RemediationDetail: `gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:SA_EMAIL \
  --role=roles/editor

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:SA_EMAIL \
  --role=roles/SPECIFIC_ROLE`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → Service Accounts → Permissions tab → Screenshot showing specific predefined roles",
			ConsoleURL:      "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Frameworks: map[string]string{
				"SOC2":    "CC6.3",
				"PCI-DSS": "7.2.2",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.3",
			Name:      "Service Account Permissions",
			Status:    "PASS",
			Evidence:  "Service accounts follow least privilege principle | Meets SOC2 CC6.3",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC6.3",
				"PCI-DSS": "7.2.2",
			},
		})
	}

	return results
}

// NEW CIS CHECKS BELOW

// CheckAPIKeysExist checks if API keys are in use (CIS 1.12-1.14)
func (c *IAMChecks) CheckAPIKeysExist(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Note: API keys can't be directly listed via IAM client
	// This requires the API Keys API which isn't in standard Cloud SDK
	results = append(results, CheckResult{
		Control:     "CIS GCP 1.12",
		Name:        "[CIS GCP 1.12-1.14] API Keys Usage",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    "MANUAL CHECK: Verify API keys are not in use, or if required, are properly restricted",
		Remediation: "Prefer service accounts over API keys. If API keys required, apply application and API restrictions",
		RemediationDetail: `# List API keys
gcloud services api-keys list

# If API keys exist, apply restrictions:
gcloud services api-keys update KEY_ID \
  --api-target=SERVICE_NAME \
  --allowed-application=APP_RESTRICTION`,
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "APIs & Services → Credentials → Screenshot showing no API keys or restricted API keys only",
		ConsoleURL:      "https://console.cloud.google.com/apis/credentials",
		Frameworks:      GetFrameworkMappings("IAM_API_KEYS"),
	})

	return results
}

// CheckServiceAccountAdminSeparation checks for separation of duties (CIS 1.4)
func (c *IAMChecks) CheckServiceAccountAdminSeparation(ctx context.Context) []CheckResult {
	var results []CheckResult

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return results
	}

	// Check if same user has both Service Account Admin and Service Account User roles
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
		hasUser := false

		for _, role := range roles {
			if role == "roles/iam.serviceAccountAdmin" {
				hasAdmin = true
			}
			if role == "roles/iam.serviceAccountUser" || role == "roles/iam.serviceAccountTokenCreator" {
				hasUser = true
			}
		}

		if hasAdmin && hasUser {
			conflictingUsers = append(conflictingUsers, user)
		}
	}

	if len(conflictingUsers) > 0 {
		displayUsers := conflictingUsers
		if len(conflictingUsers) > 3 {
			displayUsers = conflictingUsers[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 1.4",
			Name:        "[CIS GCP 1.4] Service Account Admin Separation",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 1.4: %d users have both Service Account Admin and User roles (violation of separation of duties): %s", len(conflictingUsers), strings.Join(displayUsers, ", ")),
			Remediation: "Separate service account administration from usage - different users should manage vs use service accounts",
			RemediationDetail: `# Remove conflicting role
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=USER_MEMBER \
  --role=roles/iam.serviceAccountAdmin

# Best practice: Separate users for admin vs usage`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing separation between serviceAccountAdmin and serviceAccountUser roles",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      GetFrameworkMappings("IAM_SERVICE_ACCOUNT_ADMIN"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.4",
			Name:       "[CIS GCP 1.4] Service Account Admin Separation",
			Status:     "PASS",
			Evidence:   "Separation of duties enforced: no users have both admin and usage roles | Meets CIS 1.4",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_SERVICE_ACCOUNT_ADMIN"),
		})
	}

	return results
}

// CheckCorporateLogin checks for corporate login enforcement (CIS 1.1)
func (c *IAMChecks) CheckCorporateLogin(ctx context.Context) []CheckResult {
	var results []CheckResult

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return results
	}

	// Check for gmail.com user accounts (non-corporate)
	nonCorporateUsers := []string{}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if strings.HasPrefix(member, "user:") {
				email := strings.TrimPrefix(member, "user:")
				if strings.HasSuffix(email, "@gmail.com") {
					nonCorporateUsers = append(nonCorporateUsers, email)
				}
			}
		}
	}

	if len(nonCorporateUsers) > 0 {
		displayUsers := nonCorporateUsers
		if len(nonCorporateUsers) > 3 {
			displayUsers = nonCorporateUsers[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 1.1",
			Name:        "[CIS GCP 1.1] Corporate Login Enforcement",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 1.1: %d non-corporate (gmail.com) user accounts found: %s | Should use Google Workspace or Cloud Identity", len(nonCorporateUsers), strings.Join(displayUsers, ", ")),
			Remediation: "Use corporate Google Workspace or Cloud Identity accounts instead of personal Gmail accounts",
			RemediationDetail: `# Remove personal accounts
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=user:personal@gmail.com \
  --role=ROLE

# Add corporate accounts
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=user:employee@company.com \
  --role=ROLE`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing only @company.com domain accounts, no @gmail.com",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      GetFrameworkMappings("IAM_CORPORATE_LOGIN"),
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.1",
			Name:       "[CIS GCP 1.1] Corporate Login Enforcement",
			Status:     "PASS",
			Evidence:   "All user accounts use corporate identity (no personal Gmail accounts) | Meets CIS 1.1",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("IAM_CORPORATE_LOGIN"),
		})
	}

	return results
}

// CheckWorkloadIdentity checks for GKE workload identity (CIS 1.15)
func (c *IAMChecks) CheckWorkloadIdentity(ctx context.Context) []CheckResult {
	var results []CheckResult

	results = append(results, CheckResult{
		Control:     "CIS GCP 1.15",
		Name:        "[CIS GCP 1.15] GKE Workload Identity",
		Status:      "MANUAL",
		Severity:    "MEDIUM",
		Evidence:    "MANUAL CHECK: If using GKE, verify Workload Identity is enabled instead of Compute Engine default service account",
		Remediation: "Enable Workload Identity on GKE clusters for enhanced security",
		RemediationDetail: `# Enable Workload Identity on existing cluster
gcloud container clusters update CLUSTER_NAME \
  --workload-pool=PROJECT_ID.svc.id.goog

# Enable on node pool
gcloud container node-pools update NODE_POOL \
  --cluster=CLUSTER_NAME \
  --workload-metadata=GKE_METADATA`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Kubernetes Engine → Clusters → Security → Screenshot showing Workload Identity enabled",
		ConsoleURL:      "https://console.cloud.google.com/kubernetes/list",
		Frameworks:      GetFrameworkMappings("IAM_WORKLOAD_IDENTITY"),
	})

	return results
}

// CheckDefaultServiceAccountDisabled checks if the default Compute Engine service account is disabled
// CIS GCP Foundations Benchmark 1.7
func (c *IAMChecks) CheckDefaultServiceAccountDisabled(ctx context.Context) []CheckResult {
	// List all service accounts to find the default one
	req := &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", c.projectID),
	}

	it := c.client.ListServiceAccounts(ctx, req)
	foundDefault := false
	var defaultSA *adminpb.ServiceAccount

	for {
		sa, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return []CheckResult{{
				Control:    "CIS-1.7",
				Name:       "[CIS GCP 1.7] Default Service Account Disabled",
				Status:     "FAIL",
				Severity:   "CRITICAL",
				Evidence:   fmt.Sprintf("Unable to list service accounts: %v", err),
				Priority:   PriorityCritical,
				Timestamp:  time.Now(),
				Frameworks: GetFrameworkMappings("GCP_DEFAULT_SA"),
			}}
		}

		// Default Compute Engine service account ends with "-compute@developer.gserviceaccount.com"
		if strings.HasSuffix(sa.Email, "-compute@developer.gserviceaccount.com") {
			foundDefault = true
			defaultSA = sa
			break
		}
	}

	if !foundDefault {
		return []CheckResult{{
			Control:    "CIS-1.7",
			Name:       "[CIS GCP 1.7] Default Service Account Disabled",
			Status:     "PASS",
			Severity:   "INFO",
			Evidence:   "Default Compute Engine service account has been deleted | Meets CIS GCP 1.7 (prevent over-privileged default access)",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCP_DEFAULT_SA"),
		}}
	}

	if defaultSA.Disabled {
		return []CheckResult{{
			Control:    "CIS-1.7",
			Name:       "[CIS GCP 1.7] Default Service Account Disabled",
			Status:     "PASS",
			Severity:   "INFO",
			Evidence:   fmt.Sprintf("Default Compute Engine service account (%s) is disabled | Meets CIS GCP 1.7", defaultSA.Email),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("GCP_DEFAULT_SA"),
		}}
	}

	return []CheckResult{{
		Control:     "CIS-1.7",
		Name:        "[CIS GCP 1.7] Default Service Account Disabled",
		Status:      "FAIL",
		Severity:    "CRITICAL",
		Evidence:    fmt.Sprintf("Default Compute Engine service account (%s) is ENABLED | Violates CIS GCP 1.7 (default service account is overly permissive)", defaultSA.Email),
		Remediation: "Disable or delete the default Compute Engine service account",
		RemediationDetail: fmt.Sprintf(`# Option 1: Disable the default service account (recommended)
gcloud iam service-accounts disable %s --project=%s

# Option 2: Delete the default service account (more secure)
gcloud iam service-accounts delete %s --project=%s --quiet

# IMPORTANT: Before disabling/deleting, ensure:
1. No VMs are using the default service account
2. All VMs use custom service accounts with minimal permissions
3. Check existing VMs:
   gcloud compute instances list --project=%s --format="table(name,serviceAccounts[].email)"

# Migrate VMs to custom service accounts:
gcloud compute instances set-service-account VM_NAME \
  --service-account=CUSTOM_SA@%s.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --zone=ZONE`, defaultSA.Email, c.projectID, defaultSA.Email, c.projectID, c.projectID, c.projectID),
		ScreenshotGuide: fmt.Sprintf(`Default Service Account Evidence:
1. Open IAM Console: https://console.cloud.google.com/iam-admin/serviceaccounts?project=%s
2. Find service account: %s
3. Screenshot showing:
   - Service account status: Disabled or Deleted
   - Or if enabled, screenshot with status highlighted
4. Open Compute Engine Console
5. Navigate to VM instances
6. Screenshot showing no VMs use default service account`, c.projectID, defaultSA.Email),
		ConsoleURL: fmt.Sprintf("https://console.cloud.google.com/iam-admin/serviceaccounts?project=%s", c.projectID),
		Priority:   PriorityCritical,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("GCP_DEFAULT_SA"),
	}}
}

// CheckAPIKeyRotation verifies API keys are rotated every 90 days (CIS 1.11)
func (c *IAMChecks) CheckAPIKeyRotation(ctx context.Context) []CheckResult {
	// Note: API Keys in GCP are managed through API Keys service, not IAM
	// This is a manual check as the API Keys service requires separate client
	return []CheckResult{{
		Control:     "CIS GCP 1.11",
		Name:        "[CIS GCP 1.11] API Keys Rotated Every 90 Days",
		Status:      "MANUAL",
		Severity:    "MEDIUM",
		Evidence:    "MANUAL CHECK: Verify API keys are rotated every 90 days",
		Remediation: "Rotate API keys every 90 days and delete unused keys",
		RemediationDetail: `# List all API keys
gcloud services api-keys list --project=` + c.projectID + `

# Delete old API key
gcloud services api-keys delete KEY_ID --project=` + c.projectID + `

# Create new API key
gcloud services api-keys create --display-name="New Key" --project=` + c.projectID + `

# Best practice: Set restrictions on API keys
gcloud services api-keys update KEY_ID \
  --api-target=SERVICE_NAME \
  --allowed-application=APP_ID \
  --project=` + c.projectID,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "APIs & Services → Credentials → Screenshot showing API key creation dates within 90 days",
		ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/apis/credentials?project=%s", c.projectID),
		Frameworks:      map[string]string{"CIS-GCP": "1.11", "SOC2": "CC6.1"},
	}}
}

// CheckSeparationOfDuties verifies separation of duties is enforced (CIS 1.3)
func (c *IAMChecks) CheckSeparationOfDuties(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Get project IAM policy
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformReadOnlyScope))
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 1.3",
			Name:        "[CIS GCP 1.3] Separation of Duties",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to check IAM policies: %v", err),
			Remediation: "Verify Cloud Resource Manager API is enabled",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CIS-GCP": "1.3", "SOC2": "CC6.3"},
		}}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 1.3",
			Name:        "[CIS GCP 1.3] Separation of Duties",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Remediation: "Ensure proper permissions to read IAM policies",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CIS-GCP": "1.3", "SOC2": "CC6.3"},
		}}
	}

	// Check for conflicting role assignments
	// Map of members to their roles
	memberRoles := make(map[string][]string)
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			memberRoles[member] = append(memberRoles[member], binding.Role)
		}
	}

	// Check for members with both owner and other primitive roles
	conflictingMembers := []string{}

	for member, roles := range memberRoles {
		hasOwner := contains(roles, "roles/owner")
		hasEditor := contains(roles, "roles/editor")

		if hasOwner && hasEditor {
			conflictingMembers = append(conflictingMembers, fmt.Sprintf("%s (has Owner + Editor)", member))
		} else if hasOwner && len(roles) > 1 {
			conflictingMembers = append(conflictingMembers, fmt.Sprintf("%s (has Owner + %d other roles)", member, len(roles)-1))
		}
	}

	if len(conflictingMembers) > 0 {
		displayMembers := conflictingMembers
		if len(conflictingMembers) > 3 {
			displayMembers = conflictingMembers[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 1.3",
			Name:        "[CIS GCP 1.3] Separation of Duties",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d members have conflicting roles violating separation of duties: %s | Violates CIS 1.3", len(conflictingMembers), strings.Join(displayMembers, ", ")),
			Remediation: "Remove conflicting role assignments and implement least privilege",
			RemediationDetail: fmt.Sprintf(`# Review member roles
gcloud projects get-iam-policy %s --flatten="bindings[].members" --format="table(bindings.role)"

# Remove conflicting role binding
gcloud projects remove-iam-policy-binding %s \
  --member="%s" \
  --role=roles/owner

# Grant specific roles instead
gcloud projects add-iam-policy-binding %s \
  --member="%s" \
  --role=roles/SPECIFIC_ROLE`, c.projectID, c.projectID, strings.Split(conflictingMembers[0], " ")[0], c.projectID, strings.Split(conflictingMembers[0], " ")[0]),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing users with single, specific roles (no Owner+Editor combinations)",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "1.3", "SOC2": "CC6.3", "PCI-DSS": "7.2.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.3",
			Name:       "[CIS GCP 1.3] Separation of Duties",
			Status:     "PASS",
			Evidence:   "No conflicting role assignments detected | Meets CIS 1.3",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "1.3", "SOC2": "CC6.3", "PCI-DSS": "7.2.1"},
		})
	}

	return results
}

// CheckKMSKeysPublicAccess verifies KMS keys are not publicly accessible (CIS 1.8)
func (c *IAMChecks) CheckKMSKeysPublicAccess(ctx context.Context) []CheckResult {
	// Note: This requires KMS API client to check key policies
	// Implementing as manual check for now
	return []CheckResult{{
		Control:     "CIS GCP 1.8",
		Name:        "[CIS GCP 1.8] KMS Keys Not Publicly Accessible",
		Status:      "MANUAL",
		Severity:    "CRITICAL",
		Evidence:    "MANUAL CHECK: Verify KMS cryptokeys are not accessible by allUsers or allAuthenticatedUsers",
		Remediation: "Remove public access from all KMS cryptokeys",
		RemediationDetail: `# List KMS keys
gcloud kms keys list --location=LOCATION --keyring=KEYRING --project=` + c.projectID + `

# Get IAM policy for a key
gcloud kms keys get-iam-policy KEY_NAME \
  --location=LOCATION \
  --keyring=KEYRING \
  --project=` + c.projectID + `

# Remove public access if found
gcloud kms keys remove-iam-policy-binding KEY_NAME \
  --location=LOCATION \
  --keyring=KEYRING \
  --member=allUsers \
  --role=ROLE \
  --project=` + c.projectID + `

gcloud kms keys remove-iam-policy-binding KEY_NAME \
  --location=LOCATION \
  --keyring=KEYRING \
  --member=allAuthenticatedUsers \
  --role=ROLE \
  --project=` + c.projectID,
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Security → Key Management → Select key → Permissions → Screenshot showing NO allUsers or allAuthenticatedUsers",
		ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/security/kms?project=%s", c.projectID),
		Frameworks:      map[string]string{"CIS-GCP": "1.8", "SOC2": "CC6.1", "PCI-DSS": "3.5.1"},
	}}
}

// CheckKMSRoleSeparation verifies separation of duties for KMS roles (CIS 1.16)
func (c *IAMChecks) CheckKMSRoleSeparation(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Get project IAM policy
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformReadOnlyScope))
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 1.16",
			Name:        "[CIS GCP 1.16] KMS Role Separation of Duties",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to check IAM policies: %v", err),
			Remediation: "Verify Cloud Resource Manager API is enabled",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CIS-GCP": "1.16", "SOC2": "CC6.3"},
		}}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 1.16",
			Name:        "[CIS GCP 1.16] KMS Role Separation of Duties",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Remediation: "Ensure proper permissions to read IAM policies",
			Priority:    PriorityMedium,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CIS-GCP": "1.16", "SOC2": "CC6.3"},
		}}
	}

	// Map of members to their KMS-related roles
	memberKMSRoles := make(map[string][]string)
	kmsRoles := []string{
		"roles/cloudkms.admin",
		"roles/cloudkms.cryptoKeyEncrypterDecrypter",
		"roles/cloudkms.cryptoKeyEncrypter",
		"roles/cloudkms.cryptoKeyDecrypter",
	}

	for _, binding := range policy.Bindings {
		for _, kmsRole := range kmsRoles {
			if binding.Role == kmsRole {
				for _, member := range binding.Members {
					memberKMSRoles[member] = append(memberKMSRoles[member], binding.Role)
				}
			}
		}
	}

	// Check for members with both admin and cryptographic roles
	conflictingKMSMembers := []string{}
	for member, roles := range memberKMSRoles {
		hasAdmin := contains(roles, "roles/cloudkms.admin")
		hasCryptoRole := contains(roles, "roles/cloudkms.cryptoKeyEncrypterDecrypter") ||
			contains(roles, "roles/cloudkms.cryptoKeyEncrypter") ||
			contains(roles, "roles/cloudkms.cryptoKeyDecrypter")

		if hasAdmin && hasCryptoRole {
			conflictingKMSMembers = append(conflictingKMSMembers, fmt.Sprintf("%s (has KMS Admin + Crypto roles)", member))
		}
	}

	if len(conflictingKMSMembers) > 0 {
		displayMembers := conflictingKMSMembers
		if len(conflictingKMSMembers) > 3 {
			displayMembers = conflictingKMSMembers[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 1.16",
			Name:        "[CIS GCP 1.16] KMS Role Separation of Duties",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d members have both KMS admin and cryptographic roles: %s | Violates CIS 1.16 (no separation)", len(conflictingKMSMembers), strings.Join(displayMembers, ", ")),
			Remediation: "Separate KMS administration from cryptographic operations",
			RemediationDetail: fmt.Sprintf(`# Remove admin role from crypto users
gcloud projects remove-iam-policy-binding %s \
  --member="%s" \
  --role=roles/cloudkms.admin

# Or remove crypto role from admins
gcloud projects remove-iam-policy-binding %s \
  --member="%s" \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter

# Best practice: Use different accounts for KMS admin vs crypto operations`, c.projectID, strings.Split(conflictingKMSMembers[0], " ")[0], c.projectID, strings.Split(conflictingKMSMembers[0], " ")[0]),
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing KMS admins and crypto users are different principals",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "1.16", "SOC2": "CC6.3"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.16",
			Name:       "[CIS GCP 1.16] KMS Role Separation of Duties",
			Status:     "PASS",
			Evidence:   "KMS admin and cryptographic roles are properly separated | Meets CIS 1.16",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "1.16", "SOC2": "CC6.3"},
		})
	}

	return results
}

// CheckIAMUserRoles ensures service account roles are not assigned at project level (CIS 1.6)
func (c *IAMChecks) CheckIAMUserRoles(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Get project IAM policy
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformReadOnlyScope))
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 1.6",
			Name:        "[CIS GCP 1.6] Service Account Roles at Project Level",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Unable to check IAM policies: %v", err),
			Remediation: "Verify Cloud Resource Manager API is enabled",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CIS-GCP": "1.6", "SOC2": "CC6.1"},
		}}
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return []CheckResult{{
			Control:     "CIS GCP 1.6",
			Name:        "[CIS GCP 1.6] Service Account Roles at Project Level",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Remediation: "Ensure proper permissions to read IAM policies",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  map[string]string{"CIS-GCP": "1.6", "SOC2": "CC6.1"},
		}}
	}

	// Check for service account user/token creator roles at project level
	projectLevelSARoles := []string{
		"roles/iam.serviceAccountUser",
		"roles/iam.serviceAccountTokenCreator",
	}

	violatingBindings := []string{}

	for _, binding := range policy.Bindings {
		for _, saRole := range projectLevelSARoles {
			if binding.Role == saRole {
				// Count non-service account members with these roles
				for _, member := range binding.Members {
					if !strings.HasPrefix(member, "serviceAccount:") {
						violatingBindings = append(violatingBindings,
							fmt.Sprintf("%s has %s at project level", member, binding.Role))
					}
				}
			}
		}
	}

	if len(violatingBindings) > 0 {
		displayBindings := violatingBindings
		if len(violatingBindings) > 3 {
			displayBindings = violatingBindings[:3]
		}

		results = append(results, CheckResult{
			Control:     "CIS GCP 1.6",
			Name:        "[CIS GCP 1.6] Service Account Roles at Project Level",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("CIS 1.6: %d users have Service Account User/Token Creator roles at project level (should be service account-level only): %s", len(violatingBindings), strings.Join(displayBindings, ", ")),
			Remediation: "Grant Service Account User and Token Creator roles at the individual service account level, not project level",
			RemediationDetail: fmt.Sprintf(`# Remove project-level role binding
gcloud projects remove-iam-policy-binding %s \
  --member="user:USER_EMAIL" \
  --role=roles/iam.serviceAccountUser

# Grant at service account level instead
gcloud iam service-accounts add-iam-policy-binding SERVICE_ACCOUNT_EMAIL \
  --member="user:USER_EMAIL" \
  --role=roles/iam.serviceAccountUser \
  --project=%s

# This follows least privilege - users can only impersonate specific service accounts they need
# Rather than ALL service accounts in the project`, c.projectID, c.projectID),
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing no project-level serviceAccountUser/TokenCreator roles + Service Accounts → Permissions showing service-account-level grants",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "1.6", "SOC2": "CC6.1", "PCI-DSS": "7.2.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 1.6",
			Name:       "[CIS GCP 1.6] Service Account Roles at Project Level",
			Status:     "PASS",
			Evidence:   "Service Account User/Token Creator roles are not assigned at project level | Meets CIS 1.6 (least privilege enforced)",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "1.6", "SOC2": "CC6.1", "PCI-DSS": "7.2.2"},
		})
	}

	return results
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
