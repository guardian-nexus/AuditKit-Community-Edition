package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// AzureAvailabilityConfidentialityChecks covers the SOC 2 Availability and
// Confidentiality criteria for Azure. See the AWS module of the same name for
// why Processing Integrity and Privacy are out of scope.
//
// A1.3 is a documentation check here rather than automated. Azure SQL enables
// point-in-time restore by default with a week of retention, so "backups are
// missing" is not a meaningful failure signal the way it is on AWS and GCP. The
// question that matters is whether a restore has actually been exercised, and
// that is not visible from configuration on any provider.
type AzureAvailabilityConfidentialityChecks struct {
	storageClient *armstorage.AccountsClient
	policyClient  *armstorage.ManagementPoliciesClient
}

func NewAzureAvailabilityConfidentialityChecks(storageClient *armstorage.AccountsClient, policyClient *armstorage.ManagementPoliciesClient) *AzureAvailabilityConfidentialityChecks {
	return &AzureAvailabilityConfidentialityChecks{storageClient: storageClient, policyClient: policyClient}
}

func (c *AzureAvailabilityConfidentialityChecks) Name() string {
	return "Azure SOC2 Availability and Confidentiality"
}

func (c *AzureAvailabilityConfidentialityChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{
		{
			Control:           "A1.3",
			Name:              "Recovery Plan Testing",
			Status:            "INFO",
			Evidence:          "SOC2 A1.3: a backup that has never been restored is untested. Azure SQL retains point-in-time restore by default, so the evidence that matters is a dated restore test rather than the presence of backups",
			Remediation:       "Perform and record a restore test",
			RemediationDetail: "1. Restore a database to a point in time into an isolated resource group\n2. Record the date, what was restored and the elapsed time\n3. Repeat at the frequency your policy defines",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Dated restore test records, showing what was restored and how long it took",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Sql%2Fservers",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "A1.3"},
		},
	}
	results = append(results, c.checkStorageClassification(ctx)...)
	return results, nil
}

// resourceGroupFromID pulls the resource group out of an ARM resource ID, which
// is the only place the management policies API can get it from.
func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// C1.1 and C1.2 - identification and disposal of confidential information.
// Tags record what an account holds; management policies enforce disposal.
func (c *AzureAvailabilityConfidentialityChecks) checkStorageClassification(ctx context.Context) []CheckResult {
	untagged := []string{}
	noPolicy := []string{}
	total := 0

	pager := c.storageClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return []CheckResult{
				{
					Control:           "C1.1",
					Name:              "Confidential Data Identification",
					Status:            "INFO",
					Evidence:          fmt.Sprintf("SOC2 C1.1: unable to list storage accounts (%v). Identify and maintain a record of which resources hold confidential information", err),
					Remediation:       "Tag data-bearing resources with a classification",
					RemediationDetail: "Apply a classification tag to each storage account and keep an inventory of what each holds.",
					Priority:          PriorityMedium,
					Timestamp:         time.Now(),
					Frameworks:        map[string]string{"SOC2": "C1.1"},
				},
			}
		}

		for _, acct := range page.Value {
			if acct == nil || acct.Name == nil {
				continue
			}
			total++
			name := *acct.Name

			classified := false
			for k := range acct.Tags {
				lk := strings.ToLower(k)
				if strings.Contains(lk, "classification") || strings.Contains(lk, "sensitivity") || strings.Contains(lk, "dataclass") {
					classified = true
					break
				}
			}
			if !classified {
				untagged = append(untagged, name)
			}

			// Management policies are the blob lifecycle mechanism. A missing
			// policy means nothing expires data at end of retention.
			if c.policyClient == nil || acct.ID == nil {
				continue
			}
			rg := resourceGroupFromID(*acct.ID)
			if rg == "" {
				continue
			}
			if _, err := c.policyClient.Get(ctx, rg, name, armstorage.ManagementPolicyNameDefault, nil); err != nil {
				noPolicy = append(noPolicy, name)
			}
		}
	}

	trim := func(v []string) string {
		if len(v) > 3 {
			v = v[:3]
		}
		return strings.Join(v, ", ")
	}

	results := []CheckResult{}
	if len(untagged) > 0 {
		results = append(results, CheckResult{
			Control:           "C1.1",
			Name:              "Confidential Data Identification",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("SOC2 C1.1: %d of %d storage account(s) carry no data classification tag: %s", len(untagged), total, trim(untagged)),
			Remediation:       "Tag storage accounts with a data classification",
			RemediationDetail: "1. Agree a classification scheme, for example public, internal, confidential\n2. az storage account update --name NAME --resource-group RG --tags DataClassification=Confidential\n3. Keep the inventory current as accounts are created",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "Storage account tags showing a classification value, plus the classification scheme itself",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "C1.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "C1.1",
			Name:       "Confidential Data Identification",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("SOC2 C1.1: all %d storage account(s) carry a data classification tag", total),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "C1.1"},
		})
	}

	if c.policyClient == nil {
		results = append(results, CheckResult{
			Control:           "C1.2",
			Name:              "Confidential Data Disposal",
			Status:            "INFO",
			Evidence:          "SOC2 C1.2: dispose of confidential information once it is no longer needed. Management policies client unavailable, verify blob lifecycle rules by hand",
			Remediation:       "Apply lifecycle management policies",
			RemediationDetail: "Add a lifecycle rule that deletes blobs at the end of their retention period.",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "C1.2"},
		})
	} else if len(noPolicy) > 0 {
		results = append(results, CheckResult{
			Control:           "C1.2",
			Name:              "Confidential Data Disposal",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("SOC2 C1.2: %d of %d storage account(s) have no lifecycle management policy, so nothing enforces disposal at the end of retention: %s", len(noPolicy), total, trim(noPolicy)),
			Remediation:       "Apply lifecycle management policies",
			RemediationDetail: "1. Agree a retention period per classification\n2. az storage account management-policy create --account-name NAME --resource-group RG --policy @policy.json\n3. Include a rule for previous versions and snapshots",
			Priority:          PriorityMedium,
			ScreenshotGuide:   "Lifecycle management rules showing deletion matching your retention policy",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "C1.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "C1.2",
			Name:       "Confidential Data Disposal",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("SOC2 C1.2: all %d storage account(s) have a lifecycle management policy", total),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "C1.2"},
		})
	}
	return results
}
