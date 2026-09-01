package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
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
	storageClient     *armstorage.AccountsClient
	policyClient      *armstorage.ManagementPoliciesClient
	autoscaleClient   *armmonitor.AutoscaleSettingsClient
	blobServiceClient *armstorage.BlobServicesClient
}

func NewAzureAvailabilityConfidentialityChecks(
	storageClient *armstorage.AccountsClient,
	policyClient *armstorage.ManagementPoliciesClient,
	autoscaleClient *armmonitor.AutoscaleSettingsClient,
	blobServiceClient *armstorage.BlobServicesClient,
) *AzureAvailabilityConfidentialityChecks {
	return &AzureAvailabilityConfidentialityChecks{
		storageClient:     storageClient,
		policyClient:      policyClient,
		autoscaleClient:   autoscaleClient,
		blobServiceClient: blobServiceClient,
	}
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
	results = append(results, c.checkCapacity(ctx))
	results = append(results, c.checkStorageClassification(ctx)...)
	return results, nil
}

// A1.1 - processing capacity is monitored and managed. Autoscale settings are
// the mechanism Azure provides for responding to capacity demand.
func (c *AzureAvailabilityConfidentialityChecks) checkCapacity(ctx context.Context) CheckResult {
	base := CheckResult{
		Control:         "A1.1",
		Name:            "Processing Capacity Management",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Autoscale rules showing the metric, thresholds and instance bounds",
		ConsoleURL:      "https://portal.azure.com/#view/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade",
		Frameworks:      map[string]string{"SOC2": "A1.1"},
	}

	if c.autoscaleClient == nil {
		base.Status = "INFO"
		base.Evidence = "SOC2 A1.1: monitor and manage processing capacity. Autoscale client unavailable, verify by hand"
		base.Remediation = "Configure autoscale rules for capacity-sensitive workloads"
		base.RemediationDetail = "Define autoscale settings with metric thresholds, or document how capacity is monitored and provisioned instead."
		return base
	}

	names := []string{}
	pager := c.autoscaleClient.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			base.Status = "INFO"
			base.Evidence = fmt.Sprintf("SOC2 A1.1: unable to read autoscale settings (%v), verify capacity management by hand", err)
			base.Remediation = "Configure autoscale rules for capacity-sensitive workloads"
			base.RemediationDetail = "Define autoscale settings with metric thresholds, or document how capacity is monitored and provisioned instead."
			return base
		}
		for _, a := range page.Value {
			if a != nil && a.Name != nil {
				names = append(names, *a.Name)
			}
		}
	}

	if len(names) == 0 {
		// An absent autoscale setting is not a failure: a project running only
		// serverless workloads has nothing to autoscale. The remediation
		// itself accepts documented manual capacity management, which is
		// evidence a human has to supply.
		base.Status = StatusManual
		base.Evidence = "SOC2 A1.1: no autoscale settings are configured; confirm whether capacity is managed manually or the workload does not require scaling"
		base.Remediation = "Configure autoscale rules, or document manual capacity management"
		base.RemediationDetail = "1. Add autoscale settings to capacity-sensitive workloads\n2. Base rules on a metric that reflects real demand\n3. If capacity is managed manually, document the monitoring and provisioning process instead"
		return base
	}

	shown := names
	if len(shown) > 3 {
		shown = shown[:3]
	}
	base.Status = "PASS"
	base.Evidence = fmt.Sprintf("SOC2 A1.1: %d autoscale setting(s) configured: %s", len(names), strings.Join(shown, ", "))
	base.Remediation = "Confirm the thresholds reflect real demand"
	base.RemediationDetail = "Autoscale existing is not the same as capacity being managed. Check the metrics and bounds match observed load."
	return base
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
	noSoftDelete := []string{}
	unreadablePolicy := []string{}
	unreadableSoftDelete := []string{}
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
			rg := ""
			if acct.ID != nil {
				rg = resourceGroupFromID(*acct.ID)
			}
			if rg == "" {
				unreadablePolicy = append(unreadablePolicy, name)
				unreadableSoftDelete = append(unreadableSoftDelete, name)
				continue
			}
			if c.policyClient == nil {
				unreadablePolicy = append(unreadablePolicy, name)
			} else if _, err := c.policyClient.Get(ctx, rg, name, armstorage.ManagementPolicyNameDefault, nil); err != nil {
				// An absent policy is a real finding; an authorisation failure
				// or a throttle is not, and reporting one as the other blames
				// the customer for a permission the scanner was not granted.
				if strings.Contains(err.Error(), "ManagementPolicyNotFound") || strings.Contains(err.Error(), "ResourceNotFound") {
					noPolicy = append(noPolicy, name)
				} else {
					unreadablePolicy = append(unreadablePolicy, name)
				}
			}

			// A1.2 - blob soft delete is the recovery mechanism for accidental
			// or malicious deletion; without it a delete is unrecoverable.
			// This is assessed independently of the lifecycle policy above: a
			// failure to read one must not silently pass the other.
			if c.blobServiceClient == nil {
				unreadableSoftDelete = append(unreadableSoftDelete, name)
			} else {
				props, err := c.blobServiceClient.GetServiceProperties(ctx, rg, name, nil)
				if err != nil {
					unreadableSoftDelete = append(unreadableSoftDelete, name)
					continue
				}
				p := props.BlobServiceProperties.BlobServiceProperties
				enabled := p != nil &&
					p.DeleteRetentionPolicy != nil &&
					p.DeleteRetentionPolicy.Enabled != nil &&
					*p.DeleteRetentionPolicy.Enabled
				if !enabled {
					noSoftDelete = append(noSoftDelete, name)
				}
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
	if total == 0 {
		// "all 0 accounts are tagged" is not evidence of anything, and scoring
		// it as a pass inflates the compliance score for an empty subscription.
		return []CheckResult{
			{
				Control: "C1.1", Name: "Confidential Data Identification", Status: StatusInfo,
				Evidence:   "SOC2 C1.1: no storage accounts found in this subscription, so there was nothing to assess",
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"SOC2": "C1.1"},
			},
			{
				Control: "C1.2", Name: "Confidential Data Disposal", Status: StatusInfo,
				Evidence:   "SOC2 C1.2: no storage accounts found in this subscription, so there was nothing to assess",
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"SOC2": "C1.2"},
			},
			{
				Control: "A1.2", Name: "Data Backup and Recovery Infrastructure", Status: StatusInfo,
				Evidence:   "SOC2 A1.2: no storage accounts found in this subscription, so there was nothing to assess",
				Priority:   PriorityInfo,
				Timestamp:  time.Now(),
				Frameworks: map[string]string{"SOC2": "A1.2"},
			},
		}
	}
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
			Evidence:   fmt.Sprintf("SOC2 C1.2: all %d readable storage account(s) have a lifecycle management policy%s", total-len(unreadablePolicy), unreadableNote(len(unreadablePolicy))),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "C1.2"},
		})
	}
	if c.blobServiceClient == nil {
		results = append(results, CheckResult{
			Control:           "A1.2",
			Name:              "Data Backup and Recovery Infrastructure",
			Status:            "INFO",
			Evidence:          "SOC2 A1.2: blob services client unavailable, verify soft delete and backup configuration by hand",
			Remediation:       "Enable blob soft delete",
			RemediationDetail: "Enable delete retention so an accidental or malicious delete can be recovered.",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "A1.2"},
		})
	} else if len(unreadableSoftDelete) == total && total > 0 {
		results = append(results, CheckResult{
			Control:           "A1.2",
			Name:              "Data Backup and Recovery Infrastructure",
			Status:            StatusError,
			Evidence:          fmt.Sprintf("SOC2 A1.2: could not read the blob service properties of any of the %d storage account(s), so recoverability could not be assessed", total),
			Remediation:       "Grant Microsoft.Storage/storageAccounts/blobServices/read and re-run",
			RemediationDetail: "The scanner needs read access to blob service properties to determine whether soft delete is enabled.",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "A1.2"},
		})
	} else if len(noSoftDelete) > 0 {
		results = append(results, CheckResult{
			Control:           "A1.2",
			Name:              "Data Backup and Recovery Infrastructure",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("SOC2 A1.2: %d of %d storage account(s) have blob soft delete disabled, so a deletion cannot be recovered: %s", len(noSoftDelete), total, trim(noSoftDelete)),
			Remediation:       "Enable blob soft delete",
			RemediationDetail: "1. az storage account blob-service-properties update --account-name NAME --resource-group RG --enable-delete-retention true --delete-retention-days 7\n2. Set the retention window from your recovery objectives",
			Priority:          PriorityHigh,
			ScreenshotGuide:   "Blob service data protection settings showing soft delete enabled with a retention period",
			ConsoleURL:        "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
			Timestamp:         time.Now(),
			Frameworks:        map[string]string{"SOC2": "A1.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "A1.2",
			Name:       "Data Backup and Recovery Infrastructure",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("SOC2 A1.2: all %d readable storage account(s) have a blob soft delete setting%s", total-len(unreadableSoftDelete), unreadableNote(len(unreadableSoftDelete))),
			Priority:   PriorityHigh,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"SOC2": "A1.2"},
		})
	}

	return results
}

// unreadableNote appends a count of resources the scanner could not read, so a
// pass does not imply a completeness the scan never had.
func unreadableNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (a further %d could not be read)", n)
}
