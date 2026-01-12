package checks

import (
	"context"
	"time"
	"fmt"
)

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
		FrameworkPCI:   "1.2.1, 1.3.4",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "2.1.5",
	},
	"S3_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4, 3.4.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "2.1.1",
	},
	"S3_VERSIONING": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "2.1.3",
	},
	"S3_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "2.1.4",
	},
	"S3_MFA_DELETE": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "2.1.2",
	},
	"ROOT_MFA": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.5, 1.6",
	},
	"ROOT_ACCESS_KEYS": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.4",
	},
	"ROOT_USAGE": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.7",
	},
	"PASSWORD_POLICY": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.3, 8.2.4, 8.2.5",
		FrameworkHIPAA: "164.308(a)(5)(ii)(D)",
		FrameworkCIS:   "1.8, 1.9, 1.10, 1.11, 1.20, 1.21",
	},
	"PASSWORD_MIN_LENGTH": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.3",
		FrameworkHIPAA: "164.308(a)(5)(ii)(D)",
		FrameworkCIS:   "1.8",
	},
	"PASSWORD_REUSE": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.4",
		FrameworkHIPAA: "164.308(a)(5)(ii)(D)",
		FrameworkCIS:   "1.9",
	},
	"PASSWORD_EXPIRY": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.5",
		FrameworkHIPAA: "164.308(a)(5)(ii)(D)",
		FrameworkCIS:   "1.11",
	},
	"ACCESS_KEY_ROTATION": {
		FrameworkSOC2:  "CC6.8",
		FrameworkPCI:   "8.2.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(B)",
		FrameworkCIS:   "1.14",
	},
	"UNUSED_CREDENTIALS": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.1.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "1.12",
	},
	"IAM_USER_MFA": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.10",
	},
	"IAM_CREDENTIAL_REPORT": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.1.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "1.3",
	},
	"IAM_SUPPORT_ROLE": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.17",
	},
	"IAM_INSTANCE_ROLES": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.19",
	},
	"IAM_FULL_ADMIN_PRIVILEGES": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.16",
	},
	"PRIVILEGED_ROLES": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.16, 1.22",
	},
	"IAM_POLICIES_ATTACHED": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.308(a)(3)(i)",
		FrameworkCIS:   "1.15",
	},
	"IAM_USER_UNUSED": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.1.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "1.12, 1.13",
	},
	"IAM_ACCESS_ANALYZER": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1.2",
		FrameworkHIPAA: "164.308(a)(4)(ii)(A)",
		FrameworkCIS:   "1.8",
	},
	"ROUTE53_DNSSEC": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "4.1",
		FrameworkCIS:   "5.19",
	},
	"EBS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4, 3.4.1",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "2.2.1",
	},
	"EBS_PUBLIC_SNAPSHOTS": {
		FrameworkSOC2:  "CC6.2",
		FrameworkPCI:   "1.2.1",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "2.2.2",
	},
	"RDS_PUBLIC_ACCESS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.3.1, 1.3.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "2.3.1",
	},
	"RDS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "2.3.1",
	},
	"RDS_BACKUP": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "2.3.3",
	},
	"RDS_MINOR_UPGRADE": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
		FrameworkCIS:   "2.3.2",
	},
	"RDS_MULTI_AZ": {
		FrameworkSOC2:  "A1.1",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "2.3.4",
	},
	"CLOUDTRAIL_ENABLED": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.1, 10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.1",
	},
	"CLOUDTRAIL_MULTIREGION": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.1",
	},
	"CLOUDTRAIL_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "3.7",
	},
	"CLOUDTRAIL_VALIDATION": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.5.2",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "3.2",
	},
	"CLOUDTRAIL_S3_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.6",
	},
	"CLOUDWATCH_LOG_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "3.3",
	},
	"CONFIG_ENABLED": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.1",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.5",
	},
	"VPC_FLOW_LOGS": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.9",
	},
	"KMS_KEY_ROTATION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.5",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "3.8",
	},
	"S3_CLOUDTRAIL_BUCKET": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.5.3",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "3.4",
	},
	"OPEN_SECURITY_GROUPS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1, 1.3",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "5.2, 5.3",
	},
	"DEFAULT_VPC": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "5.1",
	},
	"PUBLIC_INSTANCES": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.3.1, 1.3.2",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "5.4",
	},
	"IMDS_V2": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "2.2.2",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "5.6",
	},
	"VPC_PEERING": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "5.5",
	},
	"SECURITY_GROUP_UNRESTRICTED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "5.2",
	},
	"OLD_AMIS": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
	},
	"CLOUDTRAIL_INTEGRITY": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.5.2, 10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
	},
	// Additional CIS AWS mappings for complete coverage
	"S3_LIFECYCLE": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "2.1.6",
	},
	"IAM_HARDWARE_MFA_ROOT": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.6",
	},
	"IAM_CREDENTIALS_UNUSED_90_DAYS": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.1.4",
		FrameworkHIPAA: "164.308(a)(4)(ii)(C)",
		FrameworkCIS:   "1.3",
	},
	"IAM_INITIAL_ACCESS_KEYS": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "1.4",
	},
	"S3_OBJECT_LOCK": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "2.1.6",
	},
	"RDS_DELETION_PROTECTION": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5.5",
		FrameworkHIPAA: "164.312(c)(1)",
		FrameworkCIS:   "2.3.5",
	},
	// Section 4 - Monitoring (CloudWatch Metric Filters) - These are MANUAL
	"METRIC_FILTER_UNAUTHORIZED_API": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.1",
	},
	"METRIC_FILTER_CONSOLE_NO_MFA": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.2",
	},
	"METRIC_FILTER_ROOT_USAGE": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.3",
	},
	"METRIC_FILTER_IAM_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.4",
	},
	"METRIC_FILTER_CLOUDTRAIL_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.5",
	},
	"METRIC_FILTER_CONSOLE_AUTH_FAIL": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.6",
	},
	"METRIC_FILTER_CMK_DISABLE": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.7",
	},
	"METRIC_FILTER_S3_POLICY_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.8",
	},
	"METRIC_FILTER_CONFIG_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.9",
	},
	"METRIC_FILTER_SECURITY_GROUP_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.10",
	},
	"METRIC_FILTER_NACL_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.11",
	},
	"METRIC_FILTER_GATEWAY_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.12",
	},
	"METRIC_FILTER_ROUTE_TABLE_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.13",
	},
	"METRIC_FILTER_VPC_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.14",
	},
	"METRIC_FILTER_ORGANIZATIONS_CHANGES": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "4.15",
	},
	"SECURITY_HUB": {
		FrameworkSOC2:  "CC7.1, CC7.2",
		FrameworkPCI:   "10.6, 11.4",
		FrameworkHIPAA: "164.308(a)(1)(ii)(A), 164.308(a)(8)",
		FrameworkCIS:   "4.16",
	},
	// Section 10 - Additional Services
	"SSM_PARAMETER_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "10.1",
	},
	"SSM_SESSION_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2.5",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "10.2",
	},
	"SSM_PATCH_COMPLIANCE": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
		FrameworkCIS:   "10.3",
	},
	"BEANSTALK_ENHANCED_HEALTH": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.6",
		FrameworkHIPAA: "164.308(a)(1)(ii)(D)",
		FrameworkCIS:   "10.4",
	},
	"BEANSTALK_MANAGED_UPDATES": {
		FrameworkSOC2:  "CC8.1",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
		FrameworkCIS:   "10.5",
	},
	"BEANSTALK_LOGS": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "10.6",
	},
	"API_GATEWAY_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "10.7",
	},
	"API_GATEWAY_AUTH": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "10.8",
	},
	"API_GATEWAY_TLS": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "4.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "10.9",
	},
	"BACKUP_VAULT_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "10.10",
	},
	"BACKUP_PLAN_EXISTS": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5",
		FrameworkHIPAA: "164.308(a)(7)(ii)(A)",
		FrameworkCIS:   "10.11",
	},
	"BACKUP_VAULT_LOCK": {
		FrameworkSOC2:  "CC6.5",
		FrameworkPCI:   "10.5.3",
		FrameworkHIPAA: "164.312(c)(2)",
		FrameworkCIS:   "10.12",
	},
	"SNS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "10.13",
	},
	"SQS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "10.14",
	},
	"MESSAGING_ACCESS_POLICY": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "10.15",
	},
	// Section 11 - AWS Organizations
	"ORGANIZATIONS_SCPS_ENABLED": {
		FrameworkSOC2:  "CC5.2",
		FrameworkPCI:   "7.1",
		FrameworkCIS:   "11.1",
	},
	"ORGANIZATIONS_MULTI_ACCOUNT": {
		FrameworkSOC2:  "CC5.2",
		FrameworkPCI:   "6.5.3",
		FrameworkCIS:   "11.2",
	},
	"ORGANIZATIONS_TRAIL": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.2",
		FrameworkCIS:   "11.3",
	},
	"ORGANIZATIONS_SCPS_CONFIGURED": {
		FrameworkSOC2:  "CC5.2",
		FrameworkPCI:   "7.1",
		FrameworkCIS:   "11.4",
	},
	// Section 12 - Secrets Manager
	"SECRETS_ROTATION": {
		FrameworkSOC2:  "CC6.7",
		FrameworkPCI:   "8.2.4",
		FrameworkCIS:   "12.1",
	},
	"SECRETS_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkCIS:   "12.2",
	},
	"SECRETS_UNUSED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.2",
		FrameworkCIS:   "12.3",
	},
	// Section 13 - ECR
	"ECR_IMAGE_SCANNING": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "6.3.2",
		FrameworkCIS:   "13.1",
	},
	"ECR_IMMUTABLE_TAGS": {
		FrameworkSOC2:  "CC8.1",
		FrameworkPCI:   "6.3.2",
		FrameworkCIS:   "13.2",
	},
	"ECR_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkCIS:   "13.3",
	},
	// Section 14 - DynamoDB
	"DYNAMODB_PITR": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5",
		FrameworkCIS:   "14.1",
	},
	"DYNAMODB_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkCIS:   "14.2",
	},
	"DYNAMODB_AUTOSCALING": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "10.5",
		FrameworkCIS:   "14.3",
	},
	// Section 15 - CloudFormation
	"CFN_STACK_POLICY": {
		FrameworkSOC2:  "CC5.2",
		FrameworkPCI:   "7.1",
		FrameworkCIS:   "15.1",
	},
	"CFN_DRIFT_DETECTION": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "11.5",
		FrameworkCIS:   "15.2",
	},
	// Section 16 - ACM
	"ACM_RENEWAL": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "4.1",
		FrameworkCIS:   "16.1",
	},
	"ACM_IN_USE": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "2.2.2",
		FrameworkCIS:   "16.2",
	},
	// Section 17 - Advanced IAM
	"IAM_SERVICE_LINKED_ROLES": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.1",
		FrameworkCIS:   "17.1",
	},
	"IAM_PERMISSION_BOUNDARIES": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "7.1",
		FrameworkCIS:   "17.2",
	},
	// Section 18 - Aurora
	"AURORA_BACKTRACK": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5",
		FrameworkCIS:   "18.1",
	},
	// SageMaker Security
	"SAGEMAKER_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "19.1",
	},
	"SAGEMAKER_NETWORK": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "19.2",
	},
	"SAGEMAKER_ACCESS": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "19.3",
	},
	// Redshift Security
	"REDSHIFT_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "20.1",
	},
	"REDSHIFT_NETWORK": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "20.2",
	},
	"REDSHIFT_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "20.3",
	},
	"REDSHIFT_SSL": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "20.4",
	},
	"REDSHIFT_PATCHING": {
		FrameworkSOC2:  "CC7.5",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
		FrameworkCIS:   "20.5",
	},
	"REDSHIFT_BACKUP": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5",
		FrameworkHIPAA: "164.308(a)(7)(ii)(A)",
		FrameworkCIS:   "20.6",
	},
	// ElastiCache Security
	"ELASTICACHE_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "21.1",
	},
	"ELASTICACHE_TRANSIT": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "21.2",
	},
	"ELASTICACHE_AUTH": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "8.3.1",
		FrameworkHIPAA: "164.312(a)(2)(i)",
		FrameworkCIS:   "21.3",
	},
	"ELASTICACHE_PATCHING": {
		FrameworkSOC2:  "CC7.5",
		FrameworkPCI:   "6.2",
		FrameworkHIPAA: "164.308(a)(5)(ii)(B)",
		FrameworkCIS:   "21.4",
	},
	"ELASTICACHE_BACKUP": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5",
		FrameworkHIPAA: "164.308(a)(7)(ii)(A)",
		FrameworkCIS:   "21.5",
	},
	// OpenSearch Security
	"OPENSEARCH_ENCRYPTION": {
		FrameworkSOC2:  "CC6.3",
		FrameworkPCI:   "3.4",
		FrameworkHIPAA: "164.312(a)(2)(iv)",
		FrameworkCIS:   "22.1",
	},
	"OPENSEARCH_TRANSIT": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "22.2",
	},
	"OPENSEARCH_HTTPS": {
		FrameworkSOC2:  "CC6.4",
		FrameworkPCI:   "4.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "22.3",
	},
	"OPENSEARCH_NETWORK": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "1.2.1",
		FrameworkHIPAA: "164.312(e)(1)",
		FrameworkCIS:   "22.4",
	},
	"OPENSEARCH_LOGGING": {
		FrameworkSOC2:  "CC7.1",
		FrameworkPCI:   "10.2",
		FrameworkHIPAA: "164.312(b)",
		FrameworkCIS:   "22.5",
	},
	"OPENSEARCH_ACCESS": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "7.1",
		FrameworkHIPAA: "164.312(a)(1)",
		FrameworkCIS:   "22.6",
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
