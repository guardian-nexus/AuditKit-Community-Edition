package checks

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Check result statuses. Only StatusPass and StatusFail are scoreable; every
// other value is excluded from the compliance score rather than counted as a
// failed automated check.
//
// Three separate defects came from this field being an unconstrained string:
// MANUAL, then WARN, then ERROR each sat in the scoring denominator and could
// never pass. .github/scripts/check-statuses.sh rejects any value outside this
// set, so a fourth cannot ship.
const (
	StatusPass   = "PASS"   // the control was checked and satisfied
	StatusFail   = "FAIL"   // the control was checked and not satisfied
	StatusInfo   = "INFO"   // guidance only; nothing was evaluated
	StatusManual = "MANUAL" // requires human verification or documentation
	StatusError  = "ERROR"  // the check could not run, usually a missing permission
)

// ValidStatus reports whether s is one of the recognised statuses.
func ValidStatus(s string) bool {
	switch s {
	case StatusPass, StatusFail, StatusInfo, StatusManual, StatusError:
		return true
	}
	return false
}

// Framework constants
const (
	FrameworkSOC2  = "SOC2"
	FrameworkPCI   = "PCI-DSS"
	FrameworkHIPAA = "HIPAA"
	FrameworkCIS   = "CIS-AWS"
)

type CheckResult struct {
	Control           string            `json:"control"`
	Name              string            `json:"name"`
	Status            string            `json:"status"` // PASS, FAIL, NOT_APPLICABLE
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Severity          string            `json:"severity,omitempty"`
	Priority          Priority          `json:"priority"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

type Priority struct {
	Level     string `json:"level"`
	Impact    string `json:"impact"`
	TimeToFix string `json:"time_to_fix"`
	WillFail  bool   `json:"will_fail_audit"`
}

type Check interface {
	Run(ctx context.Context) ([]CheckResult, error)
	Name() string
}

// Framework mappings for all controls
var FrameworkMappings = map[string]map[string]string{
	"S3_PUBLIC_ACCESS": {
		FrameworkSOC2:  "CC6.2",
		FrameworkPCI:   "1.4.2, 1.3.2",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "3.1.4",
	},
	"S3_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"S3_VERSIONING": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.3.4",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	"S3_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"S3_MFA_DELETE": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.4.2",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "3.1.2",
	},
	"ROOT_MFA": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.4.2",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "2.5, 2.6",
	},
	"ROOT_ACCESS_KEYS": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.4.2",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "2.4",
	},
	"PASSWORD_POLICY": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.3.6, 8.3.9, 8.3.7",
		FrameworkHIPAA: "164.308(a)(5)(ii)(D)",
		FrameworkCIS:   "2.8, 2.9, 2.10, 2.4",
	},
	"ACCESS_KEY_ROTATION": {
		FrameworkSOC2:  "CC6.8",
		FrameworkPCI:   "8.3.9",
		FrameworkHIPAA: "164.308(a)(4)(ii)(B)",
		FrameworkCIS:   "2.12",
	},
	"UNUSED_CREDENTIALS": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.6",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "2.11",
	},
	"IAM_USER_MFA": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.4.2",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "2.10",
	},
	"IAM_SUPPORT_ROLE": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "2.15",
	},
	"IAM_INSTANCE_ROLES": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "2.16",
	},
	"IAM_POLICIES_ATTACHED": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "2.13",
	},
	"IAM_USER_UNUSED": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.6",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "2.11",
	},
	"IAM_ACCESS_ANALYZER": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.2.2",
		FrameworkHIPAA: "164.308(a)(4)(ii)(A)",
		FrameworkCIS:   "2.8",
	},
	"ROUTE53_DNSSEC": {
		FrameworkSOC2: "CC6.1",
		FrameworkPCI:  "4.2.1",
	},
	"EBS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "6.1.1",
	},
	"EBS_PUBLIC_SNAPSHOTS": {
		FrameworkSOC2:  "CC6.2",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(a)(1)",
	},
	"RDS_PUBLIC_ACCESS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		// 3.2.3, not 3.2.1: the old table used 2.3.1 for both public access and
		// encryption at rest, and a number-level remap sent this one to
		// encryption.
		FrameworkCIS: "3.2.3",
	},
	"RDS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "3.2.1",
	},
	"RDS_BACKUP": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.3.4",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	"RDS_MINOR_UPGRADE": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.3.3",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
		FrameworkCIS:   "3.2.2",
	},
	"RDS_MULTI_AZ": {
		FrameworkSOC2:  "A1.1",
		FrameworkPCI:   "10.3.4",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "3.2.4",
	},
	"CLOUDTRAIL_ENABLED": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1, 10.2.1.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.1",
	},
	"CLOUDTRAIL_MULTIREGION": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.1",
	},
	"CLOUDTRAIL_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "4.5",
	},
	"CLOUDTRAIL_VALIDATION": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.3.2",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "4.2",
	},
	"CLOUDTRAIL_S3_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.4",
	},
	"CLOUDWATCH_LOG_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"CONFIG_ENABLED": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.3",
	},
	"VPC_FLOW_LOGS": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.7",
	},
	"KMS_KEY_ROTATION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.6.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		// 4.6 is answered by KMSChecks, which covers every customer-managed
		// symmetric key rather than only CloudTrail's.
	},
	"S3_CLOUDTRAIL_BUCKET": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.5.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"OPEN_SECURITY_GROUPS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2, 1.4.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.3",
	},
	"DEFAULT_VPC": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"PUBLIC_INSTANCES": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.5",
	},
	"IMDS_V2": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "2.2.4",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "6.7",
	},
	"UNUSED_CREDENTIALS_45": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.6",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "2.11",
	},
	"IAM_POLICIES_GROUPS_ONLY": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "2.13",
	},
	"VPC_PEERING_ROUTING": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.6",
	},
	"VPC_S3_ENDPOINTS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.8",
	},
	"VPC_PEERING": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.6",
	},
	"SECURITY_GROUP_UNRESTRICTED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "6.3",
	},
	"OLD_AMIS": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.3.3",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
	},
	"CLOUDTRAIL_INTEGRITY": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.3.2, 10.3.4",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	// Additional CIS AWS mappings for complete coverage
	"S3_LIFECYCLE": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.3.4",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	"IAM_HARDWARE_MFA_ROOT": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.4.2",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "2.6",
	},
	"IAM_CREDENTIALS_UNUSED_90_DAYS": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.6",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "2.11",
	},
	"S3_OBJECT_LOCK": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.3.4",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	"RDS_DELETION_PROTECTION": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.3.4",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	// Section 4 - Monitoring (CloudWatch Metric Filters) - These are MANUAL
	"METRIC_FILTER_UNAUTHORIZED_API": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.1",
	},
	"METRIC_FILTER_CONSOLE_NO_MFA": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.2",
	},
	"METRIC_FILTER_ROOT_USAGE": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.3",
	},
	"METRIC_FILTER_IAM_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.4",
	},
	"METRIC_FILTER_CLOUDTRAIL_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.5",
	},
	"METRIC_FILTER_CONSOLE_AUTH_FAIL": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.6",
	},
	"METRIC_FILTER_CMK_DISABLE": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.7",
	},
	"METRIC_FILTER_S3_POLICY_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.8",
	},
	"METRIC_FILTER_CONFIG_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.9",
	},
	"METRIC_FILTER_SECURITY_GROUP_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.10",
	},
	"METRIC_FILTER_NACL_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.11",
	},
	"METRIC_FILTER_GATEWAY_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.12",
	},
	"METRIC_FILTER_ROUTE_TABLE_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.13",
	},
	"METRIC_FILTER_VPC_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.14",
	},
	"METRIC_FILTER_ORGANIZATIONS_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "5.15",
	},
	"SECURITY_HUB": {
		FrameworkSOC2:  "CC7.1, CC7.2",
		FrameworkPCI:   "10.4.1, 11.5.1",
		FrameworkHIPAA: "164.308(a)(1)(ii)(A), 164.308(a)(8)",
		FrameworkCIS:   "5.16",
	},
	// Section 10 - Additional Services
	"SSM_PARAMETER_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"SSM_SESSION_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1.5",
		FrameworkHIPAA: "164.312(b)",
	},
	"SSM_PATCH_COMPLIANCE": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.3.3",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
	},
	"BEANSTALK_ENHANCED_HEALTH": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.4.1",
		FrameworkHIPAA: "164.308(a)(1)(ii)(D)",
	},
	"BEANSTALK_MANAGED_UPDATES": {
		FrameworkSOC2:  "CC8.1",
		FrameworkPCI:   "6.3.3",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
	},
	"BEANSTALK_LOGS": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"API_GATEWAY_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"API_GATEWAY_AUTH": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.312(a)(1)",
	},
	"API_GATEWAY_TLS": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "4.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"BACKUP_VAULT_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"BACKUP_PLAN_EXISTS": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.4.1",
		FrameworkHIPAA: "164.308(a)(7)(ii)(A)",
	},
	"BACKUP_VAULT_LOCK": {
		FrameworkSOC2:  "CC6.5",
		FrameworkPCI:   "10.5.1",
		FrameworkHIPAA: "164.312(c)(2)",
	},
	"SNS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"SQS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"MESSAGING_ACCESS_POLICY": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.312(a)(1)",
	},
	// Section 11 - AWS Organizations
	"ORGANIZATIONS_SCPS_ENABLED": {
		FrameworkSOC2: "CC5.2",
		FrameworkPCI:  "7.2.1",
		FrameworkCIS:  "2.1.2",
	},
	"ORGANIZATIONS_MULTI_ACCOUNT": {
		FrameworkSOC2: "CC5.2",
		FrameworkPCI:  "6.2.4",
		// No CIS entry: using Organizations at all is not v7.0.0 2.1.4, which
		// asks whether organizational units are structured by environment and
		// sensitivity.
	},
	"ORGANIZATIONS_TRAIL": {
		FrameworkSOC2: "CC7.2",
		FrameworkPCI:  "10.2.1",
		FrameworkCIS:  "4.1",
	},
	"ORGANIZATIONS_SCPS_CONFIGURED": {
		FrameworkSOC2: "CC5.2",
		FrameworkPCI:  "7.2.1",
		FrameworkCIS:  "2.1.2",
	},
	// Section 12 - Secrets Manager
	"SECRETS_ROTATION": {
		FrameworkSOC2: "CC6.7",
		FrameworkPCI:  "8.3.9",
	},
	"SECRETS_ENCRYPTION": {
		FrameworkSOC2: "CC6.3",
		FrameworkPCI:  "3.5.1",
	},
	"SECRETS_UNUSED": {
		FrameworkSOC2: "CC6.1",
		FrameworkPCI:  "7.2.1",
	},
	// Section 13 - ECR
	"ECR_IMAGE_SCANNING": {
		FrameworkSOC2: "CC7.2",
		FrameworkPCI:  "6.2.1",
	},
	"ECR_IMMUTABLE_TAGS": {
		FrameworkSOC2: "CC8.1",
		FrameworkPCI:  "6.2.1",
	},
	"ECR_ENCRYPTION": {
		FrameworkSOC2: "CC6.3",
		FrameworkPCI:  "3.5.1",
	},
	// Section 14 - DynamoDB
	"DYNAMODB_PITR": {
		FrameworkSOC2: "A1.2",
		FrameworkPCI:  "9.4.1",
	},
	"DYNAMODB_ENCRYPTION": {
		FrameworkSOC2: "CC6.3",
		FrameworkPCI:  "3.5.1",
	},
	"DYNAMODB_AUTOSCALING": {
		FrameworkSOC2: "A1.2",
		FrameworkPCI:  "10.3.2",
	},
	// Section 15 - CloudFormation
	"CFN_STACK_POLICY": {
		FrameworkSOC2: "CC5.2",
		FrameworkPCI:  "7.2.1",
	},
	"CFN_DRIFT_DETECTION": {
		FrameworkSOC2: "CC7.2",
		FrameworkPCI:  "11.5.2",
	},
	// Section 16 - ACM
	"ACM_RENEWAL": {
		FrameworkSOC2: "CC6.3",
		FrameworkPCI:  "4.2.1",
	},
	"ACM_IN_USE": {
		FrameworkSOC2: "CC6.1",
		FrameworkPCI:  "2.2.4",
	},
	// Section 17 - Advanced IAM
	"IAM_SERVICE_LINKED_ROLES": {
		FrameworkSOC2: "CC6.1",
		FrameworkPCI:  "7.2.1",
	},
	"IAM_PERMISSION_BOUNDARIES": {
		FrameworkSOC2: "CC6.1",
		FrameworkPCI:  "7.2.1",
	},
	// Section 18 - Aurora
	"AURORA_BACKTRACK": {
		FrameworkSOC2: "A1.2",
		FrameworkPCI:  "9.4.1",
	},
	// SageMaker Security
	"SAGEMAKER_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"SAGEMAKER_NETWORK": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"SAGEMAKER_ACCESS": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.312(a)(1)",
	},
	// Redshift Security
	"REDSHIFT_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"REDSHIFT_NETWORK": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"REDSHIFT_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"REDSHIFT_SSL": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"REDSHIFT_PATCHING": {
		FrameworkSOC2:  "CC7.5",
		FrameworkPCI:   "6.3.3",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
	},
	"REDSHIFT_BACKUP": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.4.1",
		FrameworkHIPAA: "164.308(a)(7)(ii)(A)",
	},
	// ElastiCache Security
	"ELASTICACHE_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"ELASTICACHE_TRANSIT": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"ELASTICACHE_AUTH": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.4.2",
		FrameworkHIPAA: "164.312(a)(2)(i)",
	},
	"ELASTICACHE_PATCHING": {
		FrameworkSOC2:  "CC7.5",
		FrameworkPCI:   "6.3.3",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
	},
	"ELASTICACHE_BACKUP": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.4.1",
		FrameworkHIPAA: "164.308(a)(7)(ii)(A)",
	},
	// OpenSearch Security
	"OPENSEARCH_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
	},
	"OPENSEARCH_TRANSIT": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"OPENSEARCH_HTTPS": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"OPENSEARCH_NETWORK": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.4.2",
		FrameworkHIPAA: "164.312(e)(1)",
	},
	"OPENSEARCH_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
	},
	"OPENSEARCH_ACCESS": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.2.1",
		FrameworkHIPAA: "164.312(a)(1)",
	},
}

// Helper function to get framework mappings for a control
func GetFrameworkMappings(controlType string) map[string]string {
	if mappings, exists := FrameworkMappings[controlType]; exists {
		return mappings
	}
	return make(map[string]string)
}

// Helper to format framework requirements in evidence
func FormatFrameworkRequirements(frameworks map[string]string) string {
	if len(frameworks) == 0 {
		return ""
	}

	result := " | Requirements: "
	for fw, requirement := range frameworks {
		result += fmt.Sprintf("%s %s, ", fw, requirement)
	}
	// Remove trailing comma and space
	return result[:len(result)-2]
}

// Priority definitions
var (
	PriorityCritical = Priority{
		Level:     "CRITICAL",
		Impact:    "AUDIT BLOCKER - Fix immediately or fail audit",
		TimeToFix: "Fix RIGHT NOW",
		WillFail:  true,
	}

	PriorityHigh = Priority{
		Level:     "HIGH",
		Impact:    "Major finding - Auditor will flag this",
		TimeToFix: "Fix this week",
		WillFail:  false,
	}

	PriorityMedium = Priority{
		Level:     "MEDIUM",
		Impact:    "Should fix - Makes audit smoother",
		TimeToFix: "Fix before audit",
		WillFail:  false,
	}

	PriorityLow = Priority{
		Level:     "LOW",
		Impact:    "Nice to have - Strengthens posture",
		TimeToFix: "When convenient",
		WillFail:  false,
	}

	PriorityInfo = Priority{
		Level:     "INFO",
		Impact:    "Good job, this passes",
		TimeToFix: "Already done",
		WillFail:  false,
	}
)

// runCheck runs one check and keeps whatever result it produced.
//
// Every Run used to append a result only when the check returned no error.
// That discarded the FAIL or ERROR a check deliberately built for a failed API
// call - a denied ListTrails produced a CRITICAL FAIL for CC7.1 that never
// reached the report - and the control then reappeared as MANUAL "No automated
// check covers this control". A result returned with an error is now kept, and
// one that claims PASS despite the error is reported as ERROR instead: a check
// that could not read the account has not shown that it complies.
func runCheck(ctx context.Context, results []CheckResult, check func(context.Context) (CheckResult, error)) []CheckResult {
	result, err := check(ctx)
	if err == nil {
		return append(results, result)
	}
	if result.Control == "" {
		return results
	}
	if result.Status == StatusPass {
		result.Status = StatusError
		result.Evidence = fmt.Sprintf("Could not run this check: %v", err)
	}
	return append(results, result)
}

// checkError is the result for a check whose API call failed before it could
// evaluate anything. These checks used to return an empty result, so the
// failure vanished; now the control is named in the report's errored list.
func checkError(control, name string, frameworks map[string]string, err error) CheckResult {
	return CheckResult{
		Control:     control,
		Name:        name,
		Status:      StatusError,
		Evidence:    fmt.Sprintf("Could not run this check: %v", err),
		Remediation: "Grant the scanning identity read access to this service (see SECURITY.md), then re-run the scan",
		Priority:    PriorityLow,
		Timestamp:   time.Now(),
		Frameworks:  frameworks,
	}
}

// unreadable collects the resources a check could not inspect. Per-resource
// lookups were written "if err == nil && <finding>", so a denied lookup read as
// "nothing wrong here" and a user whose policies could not be listed counted as
// clean. A check that found no problem among the resources it could read, but
// skipped some, has not shown that the control passes.
type unreadable struct {
	names []string
	first error
}

func (u *unreadable) add(name string, err error) {
	u.names = append(u.names, name)
	if u.first == nil {
		u.first = err
	}
}

// passOrError returns pass unchanged when every resource was read, and an ERROR
// naming the unread ones otherwise.
func (u *unreadable) passOrError(pass CheckResult) CheckResult {
	if len(u.names) == 0 {
		return pass
	}
	// Collapse repeats: a lookup denied for every user is one line, not fifty.
	counts := map[string]int{}
	var order []string
	for _, n := range u.names {
		if counts[n] == 0 {
			order = append(order, n)
		}
		counts[n]++
	}
	shown := make([]string, 0, len(order))
	for _, n := range order {
		if counts[n] > 1 {
			shown = append(shown, fmt.Sprintf("%s x%d", n, counts[n]))
		} else {
			shown = append(shown, n)
		}
	}
	pass.Status = StatusError
	pass.Evidence = fmt.Sprintf("Could not complete %d lookup(s), so the check is incomplete: %s (first error: %v)",
		len(u.names), strings.Join(shown, ", "), u.first)
	return pass
}

// failOrError is passOrError for checks that pass by finding something - an
// active trail, a support role. Finding one proves the pass whatever else
// could not be read, so there the unsafe verdict is the FAIL "none found",
// which becomes ERROR when some lookups failed.
func (u *unreadable) failOrError(fail CheckResult) CheckResult {
	return u.passOrError(fail)
}

// finish applies the same rule to a check that returns several results for
// one control: when any lookup failed, a PASS or INFO built from what could
// not be read becomes ERROR, and a check that produced nothing at all reports
// an ERROR row for its control instead of vanishing. A FAIL stands.
func (u *unreadable) finish(results []CheckResult, control, name string) []CheckResult {
	if len(u.names) == 0 {
		return results
	}
	if len(results) == 0 {
		return []CheckResult{u.passOrError(checkError(control, name, nil, u.first))}
	}
	for i := range results {
		if results[i].Status == StatusPass || results[i].Status == StatusInfo {
			results[i] = u.passOrError(results[i])
		}
	}
	return results
}
