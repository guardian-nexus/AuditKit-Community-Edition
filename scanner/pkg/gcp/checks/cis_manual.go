package checks

import (
	"context"
	"fmt"
	"time"
)

// GCPCISManualChecks handles CIS controls that require manual verification
// Similar to AWS CloudWatch metric filters - these require Cloud Monitoring log-based metrics and alerts
type GCPCISManualChecks struct {
	projectID string
}

func NewGCPCISManualChecks(projectID string) *GCPCISManualChecks {
	return &GCPCISManualChecks{projectID: projectID}
}

func (c *GCPCISManualChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// CIS 2.x - Logging and Monitoring (Manual Alert Checks)
	results = append(results, c.CheckProjectOwnershipChanges()...)
	results = append(results, c.CheckAuditConfigChanges()...)
	results = append(results, c.CheckCustomRoleChanges()...)
	results = append(results, c.CheckVPCNetworkChanges()...)
	results = append(results, c.CheckVPCRouteChanges()...)
	results = append(results, c.CheckVPCFirewallChanges()...)
	results = append(results, c.CheckCloudStorageIAMChanges()...)
	results = append(results, c.CheckSQLInstanceConfigChanges()...)
	results = append(results, c.CheckProjectOwnerOrEditorAssignment()...)

	return results, nil
}

// CIS 2.4 - Ensure log metric filter and alerts exist for project ownership assignments/changes
func (c *GCPCISManualChecks) CheckProjectOwnershipChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.4",
		Name:        "[CIS GCP 2.4] Log Metric Filter - Project Ownership Changes",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for project ownership changes",
		Remediation: "Create log-based metric filter and alert for project ownership changes",
		RemediationDetail: `# Create log-based metric
gcloud logging metrics create project_ownership_changes \
  --description="Alert on project ownership changes" \
  --log-filter='protoPayload.serviceName="cloudresourcemanager.googleapis.com" 
AND (protoPayload.methodName="SetIamPolicy" OR protoPayload.methodName="setIamPolicy") 
AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"'

# Create alert policy
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="Project Ownership Changes Alert" \
  --condition-display-name="Project ownership modified" \
  --condition-threshold-value=0 \
  --condition-threshold-duration=0s`,
		Priority:  PriorityHigh,
		Timestamp: time.Now(),
		ScreenshotGuide: fmt.Sprintf(`Google Cloud Console steps for project %s:
1. Go to Logging → Logs-based Metrics
2. Screenshot showing metric "project_ownership_changes"
3. Go to Monitoring → Alerting
4. Screenshot showing alert policy for project ownership changes
5. Must show: Alert triggers on roles/owner changes
6. Must show: Notification channel configured`, c.projectID),
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.5 - Ensure log metric filter and alerts exist for audit configuration changes
func (c *GCPCISManualChecks) CheckAuditConfigChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.5",
		Name:        "[CIS GCP 2.5] Log Metric Filter - Audit Config Changes",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for audit configuration changes",
		Remediation: "Create log-based metric filter and alert for audit config changes",
		RemediationDetail: `gcloud logging metrics create audit_config_changes \
  --log-filter='protoPayload.methodName="SetIamPolicy" 
AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*'`,
		Priority:  PriorityHigh,
		Timestamp: time.Now(),
		ScreenshotGuide: `Logs-based Metrics → Screenshot "audit_config_changes" metric
Monitoring → Alerting → Screenshot alert for audit config changes`,
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.6 - Ensure log metric filter and alerts exist for custom role changes
func (c *GCPCISManualChecks) CheckCustomRoleChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.6",
		Name:        "[CIS GCP 2.6] Log Metric Filter - Custom Role Changes",
		Status:      "MANUAL",
		Severity:    "MEDIUM",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for custom role changes",
		Remediation: "Create log-based metric filter and alert for custom role modifications",
		RemediationDetail: `gcloud logging metrics create custom_role_changes \
  --log-filter='resource.type="iam_role" 
AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" 
OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" 
OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")'`,
		Priority:  PriorityMedium,
		Timestamp: time.Now(),
		ScreenshotGuide: `Screenshot showing:
1. Log-based metric for custom role changes
2. Alert policy configured
3. Notification channel active`,
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.7 - Ensure log metric filter and alerts exist for VPC network changes
func (c *GCPCISManualChecks) CheckVPCNetworkChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.7",
		Name:        "[CIS GCP 2.7] Log Metric Filter - VPC Network Changes",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for VPC network changes",
		Remediation: "Create log-based metric filter and alert for VPC network modifications",
		RemediationDetail: `gcloud logging metrics create vpc_network_changes \
  --log-filter='resource.type="gce_network" 
AND (protoPayload.methodName:"compute.networks.insert" 
OR protoPayload.methodName:"compute.networks.patch" 
OR protoPayload.methodName:"compute.networks.delete" 
OR protoPayload.methodName:"compute.networks.removePeering" 
OR protoPayload.methodName:"compute.networks.addPeering")'`,
		Priority:  PriorityHigh,
		Timestamp: time.Now(),
		ScreenshotGuide: `Screenshot requirements:
1. Metric "vpc_network_changes" exists
2. Alert policy active
3. Covers: insert, patch, delete, peering changes`,
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.8 - Ensure log metric filter and alerts exist for VPC route changes
func (c *GCPCISManualChecks) CheckVPCRouteChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.8",
		Name:        "[CIS GCP 2.8] Log Metric Filter - VPC Route Changes",
		Status:      "MANUAL",
		Severity:    "MEDIUM",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for VPC route changes",
		Remediation: "Create log-based metric filter and alert for route table modifications",
		RemediationDetail: `gcloud logging metrics create vpc_route_changes \
  --log-filter='resource.type="gce_route" 
AND (protoPayload.methodName:"compute.routes.delete" 
OR protoPayload.methodName:"compute.routes.insert")'`,
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		ScreenshotGuide: `Screenshot showing metric for route insert/delete operations with active alert`,
		ConsoleURL:      "https://console.cloud.google.com/logs/metrics",
		Frameworks:      GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.9 - Ensure log metric filter and alerts exist for VPC firewall rule changes
func (c *GCPCISManualChecks) CheckVPCFirewallChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.9",
		Name:        "[CIS GCP 2.9] Log Metric Filter - VPC Firewall Changes",
		Status:      "MANUAL",
		Severity:    "CRITICAL",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for firewall rule changes",
		Remediation: "Create log-based metric filter and alert for firewall modifications",
		RemediationDetail: `gcloud logging metrics create firewall_rule_changes \
  --log-filter='resource.type="gce_firewall_rule" 
AND (protoPayload.methodName:"compute.firewalls.patch" 
OR protoPayload.methodName:"compute.firewalls.insert" 
OR protoPayload.methodName:"compute.firewalls.delete")'`,
		Priority:  PriorityCritical,
		Timestamp: time.Now(),
		ScreenshotGuide: `CRITICAL - Screenshot must show:
1. Active metric for firewall changes
2. Alert policy with immediate notification
3. Covers: patch, insert, delete operations`,
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.10 - Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes
func (c *GCPCISManualChecks) CheckCloudStorageIAMChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.10",
		Name:        "[CIS GCP 2.10] Log Metric Filter - Cloud Storage IAM Changes",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for GCS bucket IAM changes",
		Remediation: "Create log-based metric filter and alert for Storage bucket permission changes",
		RemediationDetail: `gcloud logging metrics create storage_iam_changes \
  --log-filter='resource.type="gcs_bucket" 
AND protoPayload.methodName="storage.setIamPermissions"'`,
		Priority:  PriorityHigh,
		Timestamp: time.Now(),
		ScreenshotGuide: `Screenshot showing:
1. Metric for storage.setIamPermissions
2. Alert triggers on any bucket IAM change
3. Notification channel configured`,
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.11 - Ensure log metric filter and alerts exist for SQL instance configuration changes
func (c *GCPCISManualChecks) CheckSQLInstanceConfigChanges() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.11",
		Name:        "[CIS GCP 2.11] Log Metric Filter - SQL Instance Config Changes",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert exists for Cloud SQL configuration changes",
		Remediation: "Create log-based metric filter and alert for SQL instance modifications",
		RemediationDetail: `gcloud logging metrics create sql_instance_changes \
  --log-filter='protoPayload.serviceName="cloudsql.googleapis.com" 
AND (protoPayload.methodName="cloudsql.instances.update" 
OR protoPayload.methodName="cloudsql.instances.create" 
OR protoPayload.methodName="cloudsql.instances.delete")'`,
		Priority:  PriorityHigh,
		Timestamp: time.Now(),
		ScreenshotGuide: `Screenshot requirements:
1. Metric for SQL instance create/update/delete
2. Alert policy active
3. Covers all SQL configuration changes`,
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}

// CIS 2.12 - Ensure that Cloud DNS logging is enabled for all VPC networks
func (c *GCPCISManualChecks) CheckProjectOwnerOrEditorAssignment() []CheckResult {
	return []CheckResult{{
		Control:     "CIS GCP 2.12",
		Name:        "[CIS GCP 2.12] Log Metric Filter - Project Owner/Editor Assignment",
		Status:      "MANUAL",
		Severity:    "CRITICAL",
		Evidence:    "MANUAL CHECK REQUIRED: Verify log-based metric and alert for roles/owner or roles/editor assignments",
		Remediation: "Create log-based metric filter and alert for owner/editor role assignments",
		RemediationDetail: `gcloud logging metrics create owner_editor_assignment \
  --log-filter='protoPayload.serviceName="cloudresourcemanager.googleapis.com" 
AND protoPayload.methodName="SetIamPolicy" 
AND (protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" 
OR protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/editor")'`,
		Priority:  PriorityCritical,
		Timestamp: time.Now(),
		ScreenshotGuide: `CRITICAL - Must show:
1. Metric for roles/owner OR roles/editor assignments
2. Alert policy with IMMEDIATE notification
3. All project-level IAM changes monitored
4. SOC2/PCI requirement for privileged access monitoring`,
		ConsoleURL: "https://console.cloud.google.com/logs/metrics",
		Frameworks: GetFrameworkMappings("LOG_METRIC_FILTERS"),
	}}
}
