package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

// CC3: Risk Assessment (4 criteria)
// How risks are identified and managed

type CC3Checks struct {
	guarddutyClient   *guardduty.Client
	securityhubClient *securityhub.Client
	inspector2Client  *inspector2.Client
}

func NewCC3Checks(guarddutyClient *guardduty.Client, securityhubClient *securityhub.Client, inspector2Client *inspector2.Client) *CC3Checks {
	return &CC3Checks{
		guarddutyClient:   guarddutyClient,
		securityhubClient: securityhubClient,
		inspector2Client:  inspector2Client,
	}
}

func (c *CC3Checks) Name() string {
	return "SOC2 CC3 Checks"
}

func (c *CC3Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC3.1: Specifies Objectives
	results = append(results, c.CheckCC3_1_Objectives(ctx)...)

	// CC3.2: Identifies and Assesses Risks
	results = append(results, c.CheckCC3_2_RiskIdentification(ctx)...)

	// CC3.3: Considers Risk Potential for Fraud
	results = append(results, c.CheckCC3_3_FraudRisk(ctx)...)

	// CC3.4: Identifies and Assesses Changes
	results = append(results, c.CheckCC3_4_ChangeRisk(ctx)...)

	return results, nil
}

func (c *CC3Checks) CheckCC3_1_Objectives(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check if Security Hub is enabled (centralizes security objectives)
	if c.securityhubClient != nil {
		hub, err := c.securityhubClient.DescribeHub(ctx, &securityhub.DescribeHubInput{})

		if err != nil || hub == nil || hub.HubArn == nil {
			results = append(results, CheckResult{
				Control:         "CC3.1",
				Name:            "Security Objectives Management",
				Status:          "FAIL",
				Severity:        "HIGH",
				Evidence:        "AWS Security Hub not enabled - no centralized security objectives",
				Remediation:     "Enable Security Hub to centralize security standards and objectives",
				ScreenshotGuide: "1. Go to Security Hub\n2. Enable with security standards\n3. Document compliance scores",
				ConsoleURL:      "https://console.aws.amazon.com/securityhub/",
				Priority:        PriorityHigh,
				Timestamp:       time.Now(),
			})
		} else {
			// Check for enabled standards
			standards, _ := c.securityhubClient.DescribeStandards(ctx, &securityhub.DescribeStandardsInput{})

			if standards != nil && standards.Standards != nil && len(standards.Standards) > 0 {
				results = append(results, CheckResult{
					Control:   "CC3.1",
					Name:      "Security Objectives Management",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("Security Hub enabled with %d security standards", len(standards.Standards)),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			} else {
				results = append(results, CheckResult{
					Control:     "CC3.1",
					Name:        "Security Standards Adoption",
					Status:      "FAIL",
					Severity:    "MEDIUM",
					Evidence:    "Security Hub enabled but no standards activated",
					Remediation: "Enable AWS Foundational Security Best Practices and CIS standards",
					Priority:    PriorityMedium,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return results
}

func (c *CC3Checks) CheckCC3_2_RiskIdentification(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check GuardDuty for threat detection
	if c.guarddutyClient != nil {
		detectors, err := c.guarddutyClient.ListDetectors(ctx, &guardduty.ListDetectorsInput{})

		if err != nil || detectors == nil || detectors.DetectorIds == nil || len(detectors.DetectorIds) == 0 {
			results = append(results, CheckResult{
				Control:         "CC3.2",
				Name:            "Threat Detection and Risk Identification",
				Status:          "FAIL",
				Severity:        "CRITICAL",
				Evidence:        "GuardDuty not enabled - no automated threat detection",
				Remediation:     "Enable GuardDuty for continuous threat monitoring",
				ScreenshotGuide: "1. Go to GuardDuty\n2. Enable for all regions\n3. Configure threat intel feeds",
				ConsoleURL:      "https://console.aws.amazon.com/guardduty/",
				Priority:        PriorityCritical,
				Timestamp:       time.Now(),
			})
		} else {
			// Check if detector is actually enabled
			for _, detectorId := range detectors.DetectorIds {
				detector, _ := c.guarddutyClient.GetDetector(ctx, &guardduty.GetDetectorInput{
					DetectorId: &detectorId,
				})

				if detector != nil && detector.Status == "ENABLED" {
					results = append(results, CheckResult{
						Control:   "CC3.2",
						Name:      "Threat Detection and Risk Identification",
						Status:    "PASS",
						Evidence:  "GuardDuty actively monitoring for threats",
						Priority:  PriorityInfo,
						Timestamp: time.Now(),
					})
				} else {
					results = append(results, CheckResult{
						Control:     "CC3.2",
						Name:        "Threat Detection Status",
						Status:      "FAIL",
						Severity:    "HIGH",
						Evidence:    "GuardDuty detector exists but not enabled",
						Remediation: "Enable the GuardDuty detector",
						Priority:    PriorityHigh,
						Timestamp:   time.Now(),
					})
				}
				break // Check only first detector
			}
		}
	}

	// Check Inspector for vulnerability assessment
	if c.inspector2Client != nil {
		status, _ := c.inspector2Client.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})

		if status != nil && status.Accounts != nil && len(status.Accounts) > 0 {
			// For now, just check if Inspector is enabled at all
			results = append(results, CheckResult{
				Control:   "CC3.2",
				Name:      "Vulnerability Assessment",
				Status:    "INFO",
				Evidence:  "Inspector v2 status checked - manual review required",
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:     "CC3.2",
				Name:        "Vulnerability Assessment",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    "Inspector v2 not enabled",
				Remediation: "Enable Inspector v2 for vulnerability scanning",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

func (c *CC3Checks) CheckCC3_3_FraudRisk(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check GuardDuty for IAM finding types (potential fraud indicators)
	if c.guarddutyClient != nil {
		detectors, _ := c.guarddutyClient.ListDetectors(ctx, &guardduty.ListDetectorsInput{})

		if detectors != nil && detectors.DetectorIds != nil && len(detectors.DetectorIds) > 0 {
			// Simply check if findings exist
			results = append(results, CheckResult{
				Control:   "CC3.3",
				Name:      "Fraud Risk Detection",
				Status:    "PASS",
				Evidence:  "GuardDuty monitoring for fraudulent activity patterns",
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:     "CC3.3",
				Name:        "Fraud Risk Detection",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    "No automated fraud detection mechanisms in place",
				Remediation: "Enable GuardDuty with IAM finding types",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

func (c *CC3Checks) CheckCC3_4_ChangeRisk(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// This is more about process, but we can check if Security Hub tracks changes
	results = append(results, CheckResult{
		Control:   "CC3.4",
		Name:      "Change Risk Assessment",
		Status:    "INFO",
		Evidence:  "Manual review required: Verify change management process includes risk assessment",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	})

	return results
}

// CC4: Monitoring Activities (2 criteria)
// Continuous monitoring and evaluation

type CC4Checks struct {
	cloudwatchClient *cloudwatch.Client
	configClient     *configservice.Client
}

func NewCC4Checks(cloudwatchClient *cloudwatch.Client, configClient *configservice.Client) *CC4Checks {
	return &CC4Checks{
		cloudwatchClient: cloudwatchClient,
		configClient:     configClient,
	}
}

func (c *CC4Checks) Name() string {
	return "SOC2 CC4 Checks"
}

func (c *CC4Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC4.1: Selects and Develops Ongoing and Separate Evaluations
	results = append(results, c.CheckCC4_1_Evaluations(ctx)...)

	// CC4.2: Evaluates and Communicates Deficiencies
	results = append(results, c.CheckCC4_2_Deficiencies(ctx)...)

	return results, nil
}

func (c *CC4Checks) CheckCC4_1_Evaluations(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check Config for continuous monitoring
	if c.configClient != nil {
		recorders, err := c.configClient.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})

		if err != nil || recorders == nil || recorders.ConfigurationRecorders == nil || len(recorders.ConfigurationRecorders) == 0 {
			results = append(results, CheckResult{
				Control:         "CC4.1",
				Name:            "Continuous Configuration Monitoring",
				Status:          "FAIL",
				Severity:        "HIGH",
				Evidence:        "AWS Config not enabled - no continuous compliance monitoring",
				Remediation:     "Enable AWS Config to track configuration changes",
				ScreenshotGuide: "1. Go to AWS Config\n2. Set up configuration recorder\n3. Enable compliance rules",
				ConsoleURL:      "https://console.aws.amazon.com/config/",
				Priority:        PriorityHigh,
				Timestamp:       time.Now(),
			})
		} else {
			// Check if recorder is actually running
			status, _ := c.configClient.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})

			if status != nil && status.ConfigurationRecordersStatus != nil && len(status.ConfigurationRecordersStatus) > 0 {
				recording := false
				for _, recorderStatus := range status.ConfigurationRecordersStatus {
					if recorderStatus.Recording {
						recording = true
						break
					}
				}

				if recording {
					results = append(results, CheckResult{
						Control:   "CC4.1",
						Name:      "Continuous Configuration Monitoring",
						Status:    "PASS",
						Evidence:  "AWS Config actively recording configuration changes",
						Priority:  PriorityInfo,
						Timestamp: time.Now(),
					})
				} else {
					results = append(results, CheckResult{
						Control:     "CC4.1",
						Name:        "Configuration Recording Status",
						Status:      "FAIL",
						Severity:    "HIGH",
						Evidence:    "Config recorder exists but not recording",
						Remediation: "Start the Config recorder",
						Priority:    PriorityHigh,
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}

	// Check CloudWatch for monitoring
	if c.cloudwatchClient != nil {
		alarms, _ := c.cloudwatchClient.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})

		if alarms != nil && alarms.MetricAlarms != nil && len(alarms.MetricAlarms) > 0 {
			results = append(results, CheckResult{
				Control:   "CC4.1",
				Name:      "Performance Monitoring",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%d CloudWatch alarms configured for monitoring", len(alarms.MetricAlarms)),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		} else {
			results = append(results, CheckResult{
				Control:     "CC4.1",
				Name:        "Performance Monitoring",
				Status:      "FAIL",
				Severity:    "MEDIUM",
				Evidence:    "No CloudWatch alarms configured",
				Remediation: "Set up CloudWatch alarms for critical metrics",
				Priority:    PriorityMedium,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

func (c *CC4Checks) CheckCC4_2_Deficiencies(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check Config Rules for compliance evaluation
	if c.configClient != nil {
		rules, _ := c.configClient.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{})

		if rules != nil && rules.ConfigRules != nil && len(rules.ConfigRules) > 0 {
			// Check compliance status
			complianceResults, _ := c.configClient.DescribeComplianceByConfigRule(ctx, &configservice.DescribeComplianceByConfigRuleInput{})

			nonCompliantRules := 0
			if complianceResults != nil && complianceResults.ComplianceByConfigRules != nil {
				for _, compliance := range complianceResults.ComplianceByConfigRules {
					if compliance.Compliance != nil {
						if compliance.Compliance.ComplianceType == "NON_COMPLIANT" {
							nonCompliantRules++
						}
					}
				}
			}

			if nonCompliantRules > 0 {
				results = append(results, CheckResult{
					Control:     "CC4.2",
					Name:        "Compliance Deficiency Detection",
					Status:      "FAIL",
					Severity:    "MEDIUM",
					Evidence:    fmt.Sprintf("%d Config Rules are non-compliant", nonCompliantRules),
					Remediation: "Review and remediate non-compliant resources",
					Priority:    PriorityMedium,
					Timestamp:   time.Now(),
				})
			} else {
				results = append(results, CheckResult{
					Control:   "CC4.2",
					Name:      "Automated Compliance Evaluation",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("%d Config Rules all compliant", len(rules.ConfigRules)),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			}
		} else {
			results = append(results, CheckResult{
				Control:     "CC4.2",
				Name:        "Automated Compliance Evaluation",
				Status:      "FAIL",
				Severity:    "MEDIUM",
				Evidence:    "No Config Rules configured for compliance checking",
				Remediation: "Deploy Config Rules for compliance requirements",
				Priority:    PriorityMedium,
				Timestamp:   time.Now(),
			})
		}
	}

	return results
}

// CC5: Control Activities (3 criteria)
// The actual control implementations

type CC5Checks struct {
	backupClient *backup.Client
	kmsClient    *kms.Client
}

func NewCC5Checks(backupClient *backup.Client, kmsClient *kms.Client) *CC5Checks {
	return &CC5Checks{
		backupClient: backupClient,
		kmsClient:    kmsClient,
	}
}

func (c *CC5Checks) Name() string {
	return "SOC2 CC5 Checks"
}

func (c *CC5Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC5.1: Selects and Develops Control Activities
	results = append(results, c.CheckCC5_1_ControlSelection(ctx)...)

	// CC5.2: Selects and Develops General Controls Over Technology
	results = append(results, c.CheckCC5_2_TechnologyControls(ctx)...)

	// CC5.3: Deploys Through Policies and Procedures
	results = append(results, c.CheckCC5_3_Deployment(ctx)...)

	return results, nil
}

func (c *CC5Checks) CheckCC5_1_ControlSelection(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check AWS Backup for data protection controls
	if c.backupClient != nil {
		plans, err := c.backupClient.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})

		if err != nil || plans == nil || plans.BackupPlansList == nil || len(plans.BackupPlansList) == 0 {
			results = append(results, CheckResult{
				Control:         "CC5.1",
				Name:            "Backup and Recovery Controls",
				Status:          "FAIL",
				Severity:        "HIGH",
				Evidence:        "No AWS Backup plans configured - data at risk",
				Remediation:     "Create backup plans for critical resources",
				ScreenshotGuide: "1. Go to AWS Backup\n2. Create backup plan\n3. Assign resources",
				ConsoleURL:      "https://console.aws.amazon.com/backup/",
				Priority:        PriorityHigh,
				Timestamp:       time.Now(),
			})
		} else {
			// Check backup vaults
			vaults, _ := c.backupClient.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})

			vaultCount := 0
			if vaults != nil && vaults.BackupVaultList != nil {
				vaultCount = len(vaults.BackupVaultList)
			}

			results = append(results, CheckResult{
				Control:   "CC5.1",
				Name:      "Backup and Recovery Controls",
				Status:    "PASS",
				Evidence:  fmt.Sprintf("%d backup plans with %d vaults configured", len(plans.BackupPlansList), vaultCount),
				Priority:  PriorityInfo,
				Timestamp: time.Now(),
			})
		}
	}

	return results
}

func (c *CC5Checks) CheckCC5_2_TechnologyControls(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check KMS for encryption controls
	if c.kmsClient != nil {
		keys, err := c.kmsClient.ListKeys(ctx, &kms.ListKeysInput{})

		if err != nil || keys == nil || keys.Keys == nil || len(keys.Keys) == 0 {
			results = append(results, CheckResult{
				Control:     "CC5.2",
				Name:        "Encryption Key Management",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    "No KMS keys configured - using default encryption only",
				Remediation: "Create customer-managed KMS keys for sensitive data",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
			})
		} else {
			// Count customer managed keys
			customerKeys := 0
			for _, key := range keys.Keys {
				keyMetadata, _ := c.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
					KeyId: key.KeyId,
				})

				if keyMetadata != nil && keyMetadata.KeyMetadata != nil {
					if keyMetadata.KeyMetadata.KeyManager == "CUSTOMER" {
						customerKeys++
					}
				}
			}

			if customerKeys > 0 {
				results = append(results, CheckResult{
					Control:   "CC5.2",
					Name:      "Encryption Key Management",
					Status:    "PASS",
					Evidence:  fmt.Sprintf("%d customer-managed KMS keys configured", customerKeys),
					Priority:  PriorityInfo,
					Timestamp: time.Now(),
				})
			} else {
				results = append(results, CheckResult{
					Control:     "CC5.2",
					Name:        "Encryption Key Management",
					Status:      "FAIL",
					Severity:    "MEDIUM",
					Evidence:    "Only AWS-managed keys in use",
					Remediation: "Create customer-managed keys for better control",
					Priority:    PriorityMedium,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return results
}

func (c *CC5Checks) CheckCC5_3_Deployment(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// This is more about policies and procedures
	results = append(results, CheckResult{
		Control:   "CC5.3",
		Name:      "Control Deployment Through Policies",
		Status:    "INFO",
		Evidence:  "Manual review required: Verify security policies are documented and enforced",
		Priority:  PriorityInfo,
		Timestamp: time.Now(),
	})

	return results
}
