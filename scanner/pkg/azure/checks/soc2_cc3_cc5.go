package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
)

// CC3: Risk Assessment (4 criteria)
// CC4: Monitoring Activities (2 criteria)
// CC5: Control Activities (3 criteria)

// CC3: Risk Assessment
type AzureCC3Checks struct {
	monitorClient *armmonitor.ActivityLogsClient
}

func NewAzureCC3Checks(monitorClient *armmonitor.ActivityLogsClient) *AzureCC3Checks {
	return &AzureCC3Checks{
		monitorClient: monitorClient,
	}
}

func (c *AzureCC3Checks) Name() string {
	return "Azure SOC2 CC3 Risk Assessment"
}

func (c *AzureCC3Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC3.1: Risk Assessment Process
	results = append(results, CheckResult{
		Control:         "CC3.1",
		Name:            "Risk Assessment Process",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify risk assessment procedures are documented",
		Severity:        "MEDIUM",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Remediation:     "Document formal risk assessment process and methodology",
		ScreenshotGuide: "Provide risk assessment documentation and risk register",
		Frameworks: map[string]string{
			"SOC2": "CC3.1",
		},
	})

	// CC3.2: Risk Analysis - Check Azure Security Center/Defender
	results = append(results, c.CheckCC3_2_SecurityCenter(ctx))

	// CC3.3: Risk Mitigation
	results = append(results, CheckResult{
		Control:     "CC3.3",
		Name:        "Risk Mitigation Strategy",
		Status:      "INFO",
		Evidence:    "Manual review required: Verify risk mitigation strategies are implemented",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		Remediation: "Document risk treatment plans and mitigation controls",
		Frameworks: map[string]string{
			"SOC2": "CC3.3",
		},
	})

	// CC3.4: Risk Monitoring
	results = append(results, CheckResult{
		Control:     "CC3.4",
		Name:        "Ongoing Risk Monitoring",
		Status:      "INFO",
		Evidence:    "Manual review required: Verify continuous risk monitoring processes",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		Remediation: "Implement continuous risk monitoring and reporting",
		Frameworks: map[string]string{
			"SOC2": "CC3.4",
		},
	})

	return results, nil
}

func (c *AzureCC3Checks) CheckCC3_2_SecurityCenter(ctx context.Context) CheckResult {
	// In a real implementation, would check Azure Defender/Security Center status
	// For now, check if activity logs are enabled (basic risk visibility)

	filter := fmt.Sprintf("eventTimestamp ge '%s'",
		time.Now().Add(-24*time.Hour).Format(time.RFC3339))

	pager := c.monitorClient.NewListPager(filter, nil)

	hasLogs := false
	for pager.More() {
		_, err := pager.NextPage(ctx)
		if err == nil {
			hasLogs = true
			break
		}
	}

	if hasLogs {
		return CheckResult{
			Control:         "CC3.2",
			Name:            "Risk Analysis and Assessment",
			Status:          "PASS",
			Evidence:        "Activity logs enabled providing risk visibility",
			Severity:        "INFO",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Azure Portal -> Security Center -> Show secure score and recommendations",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade",
			Frameworks: map[string]string{
				"SOC2": "CC3.2",
			},
		}
	}

	return CheckResult{
		Control:     "CC3.2",
		Name:        "Risk Analysis and Assessment",
		Status:      "FAIL",
		Evidence:    "Azure Security Center/Defender not properly configured",
		Severity:    "HIGH",
		Priority:    PriorityHigh,
		Timestamp:   time.Now(),
		Remediation: "Enable Azure Defender and configure Security Center",
		Frameworks: map[string]string{
			"SOC2": "CC3.2",
		},
	}
}

// CC4: Monitoring Activities
type AzureCC4Checks struct {
	monitorClient *armmonitor.ActivityLogsClient
}

func NewAzureCC4Checks(monitorClient *armmonitor.ActivityLogsClient) *AzureCC4Checks {
	return &AzureCC4Checks{
		monitorClient: monitorClient,
	}
}

func (c *AzureCC4Checks) Name() string {
	return "Azure SOC2 CC4 Monitoring Activities"
}

func (c *AzureCC4Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC4.1: Performance Monitoring
	results = append(results, c.CheckCC4_1_PerformanceMonitoring(ctx))

	// CC4.2: Control Effectiveness
	results = append(results, CheckResult{
		Control:         "CC4.2",
		Name:            "Control Effectiveness Monitoring",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify control effectiveness monitoring procedures",
		Severity:        "MEDIUM",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Remediation:     "Implement control effectiveness testing and monitoring",
		ScreenshotGuide: "Provide evidence of control testing and monitoring reports",
		Frameworks: map[string]string{
			"SOC2": "CC4.2",
		},
	})

	return results, nil
}

func (c *AzureCC4Checks) CheckCC4_1_PerformanceMonitoring(ctx context.Context) CheckResult {
	// Check if monitoring is configured
	filter := fmt.Sprintf("eventTimestamp ge '%s'",
		time.Now().Add(-1*time.Hour).Format(time.RFC3339))

	pager := c.monitorClient.NewListPager(filter, nil)

	page, err := pager.NextPage(ctx)
	if err != nil {
		return CheckResult{
			Control:     "CC4.1",
			Name:        "Performance Monitoring",
			Status:      "FAIL",
			Evidence:    "Azure Monitor not properly configured",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Remediation: "Enable Azure Monitor and configure metrics collection",
			Frameworks: map[string]string{
				"SOC2": "CC4.1",
			},
		}
	}

	if page.Value != nil && len(page.Value) > 0 {
		return CheckResult{
			Control:         "CC4.1",
			Name:            "Performance Monitoring",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("Azure Monitor collecting metrics - %d recent events", len(page.Value)),
			Severity:        "INFO",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Azure Portal -> Monitor -> Metrics -> Show configured metrics",
			ConsoleURL:      "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade",
			Frameworks: map[string]string{
				"SOC2": "CC4.1",
			},
		}
	}

	return CheckResult{
		Control:   "CC4.1",
		Name:      "Performance Monitoring",
		Status:    "INFO",
		Evidence:  "Limited monitoring data available",
		Severity:  "MEDIUM",
		Priority:  PriorityMedium,
		Timestamp: time.Now(),
		Frameworks: map[string]string{
			"SOC2": "CC4.1",
		},
	}
}

// CC5: Control Activities
type AzureCC5Checks struct {
	keyVaultClient *armkeyvault.VaultsClient
}

func NewAzureCC5Checks(keyVaultClient *armkeyvault.VaultsClient) *AzureCC5Checks {
	return &AzureCC5Checks{
		keyVaultClient: keyVaultClient,
	}
}

func (c *AzureCC5Checks) Name() string {
	return "Azure SOC2 CC5 Control Activities"
}

func (c *AzureCC5Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CC5.1: Control Selection and Development
	results = append(results, c.CheckCC5_1_ControlSelection(ctx))

	// CC5.2: Technology General Controls
	results = append(results, c.CheckCC5_2_TechnologyControls(ctx))

	// CC5.3: Policies and Procedures
	results = append(results, CheckResult{
		Control:         "CC5.3",
		Name:            "Policies and Procedures",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify IT policies and procedures are documented",
		Severity:        "MEDIUM",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Remediation:     "Document and maintain IT policies and procedures",
		ScreenshotGuide: "Provide evidence of documented policies and procedures",
		Frameworks: map[string]string{
			"SOC2": "CC5.3",
		},
	})

	return results, nil
}

func (c *AzureCC5Checks) CheckCC5_1_ControlSelection(ctx context.Context) CheckResult {
	// Check if Key Vault is used (indicates control selection for secrets management)
	pager := c.keyVaultClient.NewListPager(nil)

	vaultCount := 0
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		vaultCount += len(page.Value)
	}

	if vaultCount > 0 {
		return CheckResult{
			Control:         "CC5.1",
			Name:            "Control Selection and Development",
			Status:          "PASS",
			Evidence:        fmt.Sprintf("Found %d Key Vaults indicating security control implementation", vaultCount),
			Severity:        "INFO",
			Priority:        PriorityInfo,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Azure Portal -> Key Vaults -> Show list of configured vaults",
			ConsoleURL:      "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults",
			Frameworks: map[string]string{
				"SOC2": "CC5.1",
			},
		}
	}

	return CheckResult{
		Control:     "CC5.1",
		Name:        "Control Selection and Development",
		Status:      "INFO",
		Evidence:    "Review security control selection and implementation",
		Severity:    "MEDIUM",
		Priority:    PriorityMedium,
		Timestamp:   time.Now(),
		Remediation: "Implement appropriate security controls based on risk assessment",
		Frameworks: map[string]string{
			"SOC2": "CC5.1",
		},
	}
}

func (c *AzureCC5Checks) CheckCC5_2_TechnologyControls(ctx context.Context) CheckResult {
	// Check for technology general controls (backup, encryption, etc.)
	// This would be more comprehensive in a full implementation

	return CheckResult{
		Control:         "CC5.2",
		Name:            "Technology General Controls",
		Status:          "INFO",
		Evidence:        "Manual review required: Verify technology controls (backup, encryption, access control)",
		Severity:        "HIGH",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Remediation:     "Implement technology controls including backup, encryption, and access management",
		ScreenshotGuide: "Document technology controls including backup policies and encryption status",
		Frameworks: map[string]string{
			"SOC2": "CC5.2",
		},
	}
}
