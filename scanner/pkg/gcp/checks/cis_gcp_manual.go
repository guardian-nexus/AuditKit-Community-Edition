package checks

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CIS GCP Foundation v5.0.0 recommendations that no automated check answers,
// reported so the benchmark's own denominator - 93 - is what a report carries.
//
// Most are recommendations the benchmark itself marks Manual: organization
// structure, access approval, data classification. A few are marked Automated
// but sit outside what this scanner reaches, and each of those says so rather
// than being quietly omitted or, worse, passed.
//
// The wording is ours. CIS's terms require contacting their legal team before
// reproducing portions of recommendations in third-party documentation, so each
// requirement is described rather than quoted - the same reason cis-gcp.json
// carries identifiers and assessment types but no titles.
//
// Reported through the covered set rather than a fixed list: the identifiers
// the automated checks produce differ between the editions, and computing the
// remainder means neither edition reports a recommendation twice nor omits one.
type gcpManualRecommendation struct {
	// The full control identifier, "CIS-GCP-1.1.1". Held whole rather than as
	// a bare number so the guards and the coverage tooling, which look for
	// that literal, can see what this file claims.
	id       string
	name     string
	evidence string
	remedy   string
	console  string
}

var gcpManualRecommendations = []gcpManualRecommendation{
	{"CIS-GCP-1.1.1", "Super Admin Email Not Tied to One Person",
		"the super admin account's email, showing it is a role address rather than one person's mailbox",
		"Move the super admin to a monitored group address so the account survives that person leaving",
		"https://admin.google.com/"},
	{"CIS-GCP-1.1.2", "Super Admin Not Used for Daily Administration",
		"the sign-in log for the super admin, showing it is used only for the tasks that require it",
		"Administer Google Cloud with delegated roles and keep the super admin for break-glass",
		"https://admin.google.com/"},
	{"CIS-GCP-1.1.3", "Folders Structured by Environment and Sensitivity",
		"the resource hierarchy, showing production separated from non-production and sensitive workloads isolated",
		"Group projects into folders by environment and sensitivity so policy can be applied per folder",
		"https://console.cloud.google.com/cloud-resource-manager"},
	{"CIS-GCP-1.1.4", "Organization Policies Configured Centrally",
		"the organization policy constraints in force and the level they are set at",
		"Set the constraints you rely on at the organization or folder level rather than per project",
		"https://console.cloud.google.com/iam-admin/orgpolicies"},
	{"CIS-GCP-1.4", "Security Key Enforcement for Admin Accounts",
		"that administrative accounts require a hardware security key, not just any second factor",
		"Enforce security keys for the admin group; app-based factors remain phishable",
		"https://admin.google.com/"},
	{"CIS-GCP-1.17", "Essential Contacts Configured for the Organization",
		"the Essential Contacts entries for security, legal and technical notifications",
		"Configure Essential Contacts at the organization so Google's security notices reach a monitored address",
		"https://console.cloud.google.com/iam-admin/essential-contacts"},
	{"CIS-GCP-1.18", "Secrets Held in Secret Manager, Not Function Environment Variables",
		"the environment variables on each Cloud Function, showing no credential among them",
		"Move credentials into Secret Manager and reference them; environment variables are visible to anyone who can read the function",
		"https://console.cloud.google.com/functions"},
	{"CIS-GCP-2.2", "Workspace Data Sharing with Google Cloud Enabled",
		"the Workspace admin setting that shares admin log data with Google Cloud",
		"Enable data sharing so Workspace admin activity appears in Cloud Logging alongside everything else",
		"https://admin.google.com/"},
	{"CIS-GCP-2.14", "Cloud Asset Inventory Enabled",
		"that the Cloud Asset Inventory API is enabled, and the export or feed that makes its data usable",
		"Enable cloudasset.googleapis.com and set up an export, so there is a record of what existed when",
		"https://console.cloud.google.com/iam-admin/asset-inventory"},
	{"CIS-GCP-2.15", "Access Transparency Enabled",
		"that Access Transparency is on, and where its logs go",
		"Enable Access Transparency to get a log of Google staff access to your data",
		"https://console.cloud.google.com/iam-admin/settings"},
	{"CIS-GCP-2.16", "Access Approval Enabled",
		"that Access Approval is on and who the approvers are",
		"Enable Access Approval so Google staff access requires your explicit approval rather than only being logged",
		"https://console.cloud.google.com/security/access-approval"},
	{"CIS-GCP-3.8", "VPC Service Controls Enabled for Supported Services",
		"the service perimeter and the services inside it",
		"Define a VPC Service Controls perimeter around the services holding sensitive data",
		"https://console.cloud.google.com/security/service-perimeter"},
	{"CIS-GCP-3.12", "Identity Aware Proxy Restricts Traffic to Google Ranges",
		"the firewall rules showing only Google's IAP forwarding ranges may reach the backends",
		"Put the backends behind IAP and restrict ingress to 35.235.240.0/20",
		"https://console.cloud.google.com/security/iap"},
	{"CIS-GCP-4.10", "App Engine Applications Enforce HTTPS",
		"the App Engine configuration, showing HTTP requests are redirected or refused",
		"Set secure: always on each handler, so no request is served over plain HTTP",
		"https://console.cloud.google.com/appengine"},
	{"CIS-GCP-4.12", "Operating System Updates Installed on Instances",
		"the patch status of the instances, and the schedule that keeps them current",
		"Use VM Manager patch management, or your own tooling, and keep the record of what was applied",
		"https://console.cloud.google.com/compute/instances"},
	{"CIS-GCP-6.1.1", "MySQL Does Not Allow Anyone to Connect with Administrative Privileges",
		"the MySQL user list, showing the root account is restricted by host and has a password set",
		"Restrict the administrative account to known hosts and set a password on it",
		"https://console.cloud.google.com/sql/instances"},
	{"CIS-GCP-6.6", "Cloud SQL Instances Have IAM Database Authentication Enabled",
		"the instance flag enabling IAM database authentication",
		"Enable IAM database authentication so database access follows the same identities and revocation as everything else",
		"https://console.cloud.google.com/sql/instances"},
	{"CIS-GCP-6.9", "Cloud SQL Instances Have Deletion Protection Enabled",
		"the deletion protection setting on each instance",
		"Enable deletion protection; an accidental delete of a database instance is not recoverable from a backup alone",
		"https://console.cloud.google.com/sql/instances"},
	{"CIS-GCP-7.4", "Data in BigQuery Has Been Classified",
		"the classification applied to the datasets, whether by policy tags or a documented scheme",
		"Classify the data in BigQuery so the controls that depend on sensitivity can be applied",
		"https://console.cloud.google.com/bigquery"},
	{"CIS-GCP-8.1", "Dataproc Clusters Encrypted with Customer-Managed Keys",
		"the encryption configuration of each Dataproc cluster",
		"Create clusters with a customer-managed key; the setting cannot be changed after creation",
		"https://console.cloud.google.com/dataproc/clusters"},
}

// CISGCPManualReport reports the recommendations the automated checks did not.
type CISGCPManualReport struct {
	covered map[string]bool
}

func NewCISGCPManualReport(covered map[string]bool) *CISGCPManualReport {
	return &CISGCPManualReport{covered: covered}
}

func (c *CISGCPManualReport) Name() string { return "CIS GCP Manual Recommendations" }

func (c *CISGCPManualReport) Run(ctx context.Context) ([]CheckResult, error) {
	out := make([]CheckResult, 0, len(gcpManualRecommendations))
	for _, r := range gcpManualRecommendations {
		if c.covered[strings.TrimPrefix(r.id, "CIS-GCP-")] {
			continue
		}
		out = append(out, CheckResult{
			Control:         r.id,
			Name:            fmt.Sprintf("[%s] %s", r.id, r.name),
			Status:          "MANUAL",
			Severity:        "MEDIUM",
			Priority:        PriorityMedium,
			Evidence:        "MANUAL CHECK: An assessor will ask to see " + r.evidence,
			Remediation:     r.remedy,
			ScreenshotGuide: "Attach the configuration or record showing " + r.evidence,
			ConsoleURL:      r.console,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-GCP": strings.TrimPrefix(r.id, "CIS-GCP-")},
		})
	}
	return out, nil
}
