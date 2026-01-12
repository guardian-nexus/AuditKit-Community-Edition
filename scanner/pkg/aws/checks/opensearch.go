package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
)

type OpenSearchChecks struct {
	client *opensearch.Client
}

func NewOpenSearchChecks(client *opensearch.Client) *OpenSearchChecks {
	return &OpenSearchChecks{client: client}
}

func (c *OpenSearchChecks) Name() string {
	return "OpenSearch Security"
}

func (c *OpenSearchChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckEncryptionAtRest(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckNodeToNodeEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckHTTPS(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckVPCDeployment(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckAuditLogs(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckFineGrainedAccessControl(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *OpenSearchChecks) CheckEncryptionAtRest(ctx context.Context) (CheckResult, error) {
	domains, err := c.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unencrypted := []string{}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)

		detail, err := c.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err != nil {
			continue
		}

		if detail.DomainStatus.EncryptionAtRestOptions == nil ||
			!aws.ToBool(detail.DomainStatus.EncryptionAtRestOptions.Enabled) {
			unencrypted = append(unencrypted, domainName)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:           "CC6.3",
			Name:              "OpenSearch Encryption at Rest",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d OpenSearch domains without encryption at rest: %v", len(unencrypted), unencrypted),
			Remediation:       "Enable encryption at rest for OpenSearch domains",
			RemediationDetail: "Update domain configuration to enable encryption at rest with KMS key",
			ScreenshotGuide:   "OpenSearch Console → Domains → Select domain → Security → Screenshot showing 'Encryption at rest: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/aos/home#opensearch/domains",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPENSEARCH_ENCRYPTION"),
		}, nil
	}

	if len(domains.DomainNames) == 0 {
		return CheckResult{
			Control:    "CC6.3",
			Name:       "OpenSearch Encryption at Rest",
			Status:     "PASS",
			Evidence:   "No OpenSearch domains found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPENSEARCH_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "OpenSearch Encryption at Rest",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d OpenSearch domains have encryption at rest enabled", len(domains.DomainNames)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OPENSEARCH_ENCRYPTION"),
	}, nil
}

func (c *OpenSearchChecks) CheckNodeToNodeEncryption(ctx context.Context) (CheckResult, error) {
	domains, err := c.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noNodeEncryption := []string{}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)

		detail, err := c.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err != nil {
			continue
		}

		if detail.DomainStatus.NodeToNodeEncryptionOptions == nil ||
			!aws.ToBool(detail.DomainStatus.NodeToNodeEncryptionOptions.Enabled) {
			noNodeEncryption = append(noNodeEncryption, domainName)
		}
	}

	if len(noNodeEncryption) > 0 {
		return CheckResult{
			Control:           "CC6.4",
			Name:              "OpenSearch Node-to-Node Encryption",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d OpenSearch domains without node-to-node encryption: %v", len(noNodeEncryption), noNodeEncryption),
			Remediation:       "Enable node-to-node encryption for OpenSearch domains",
			RemediationDetail: "Update domain configuration to enable node-to-node encryption (may require blue/green deployment)",
			ScreenshotGuide:   "OpenSearch Console → Domains → Select domain → Security → Screenshot showing 'Node-to-node encryption: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/aos/home#opensearch/domains",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPENSEARCH_TRANSIT"),
		}, nil
	}

	if len(domains.DomainNames) == 0 {
		return CheckResult{
			Control:    "CC6.4",
			Name:       "OpenSearch Node-to-Node Encryption",
			Status:     "PASS",
			Evidence:   "No OpenSearch domains found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPENSEARCH_TRANSIT"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.4",
		Name:       "OpenSearch Node-to-Node Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d OpenSearch domains have node-to-node encryption enabled", len(domains.DomainNames)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OPENSEARCH_TRANSIT"),
	}, nil
}

func (c *OpenSearchChecks) CheckHTTPS(ctx context.Context) (CheckResult, error) {
	domains, err := c.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noHTTPS := []string{}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)

		detail, err := c.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err != nil {
			continue
		}

		if detail.DomainStatus.DomainEndpointOptions == nil ||
			!aws.ToBool(detail.DomainStatus.DomainEndpointOptions.EnforceHTTPS) {
			noHTTPS = append(noHTTPS, domainName)
		}
	}

	if len(noHTTPS) > 0 {
		return CheckResult{
			Control:           "CC6.4",
			Name:              "OpenSearch HTTPS Required",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d OpenSearch domains not enforcing HTTPS: %v", len(noHTTPS), noHTTPS),
			Remediation:       "Enable HTTPS enforcement for OpenSearch domains",
			RemediationDetail: "Update domain endpoint options to enforce HTTPS and use TLS 1.2 minimum",
			ScreenshotGuide:   "OpenSearch Console → Domains → Select domain → Security → Screenshot showing 'Require HTTPS: Yes'",
			ConsoleURL:        "https://console.aws.amazon.com/aos/home#opensearch/domains",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPENSEARCH_HTTPS"),
		}, nil
	}

	if len(domains.DomainNames) == 0 {
		return CheckResult{
			Control:    "CC6.4",
			Name:       "OpenSearch HTTPS Required",
			Status:     "PASS",
			Evidence:   "No OpenSearch domains found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPENSEARCH_HTTPS"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.4",
		Name:       "OpenSearch HTTPS Required",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d OpenSearch domains enforce HTTPS", len(domains.DomainNames)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OPENSEARCH_HTTPS"),
	}, nil
}

func (c *OpenSearchChecks) CheckVPCDeployment(ctx context.Context) (CheckResult, error) {
	domains, err := c.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	publicDomains := []string{}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)

		detail, err := c.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err != nil {
			continue
		}

		// If no VPC options, domain is public
		if detail.DomainStatus.VPCOptions == nil || len(detail.DomainStatus.VPCOptions.SubnetIds) == 0 {
			publicDomains = append(publicDomains, domainName)
		}
	}

	if len(publicDomains) > 0 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "OpenSearch VPC Deployment",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d OpenSearch domains are publicly accessible (not in VPC): %v", len(publicDomains), publicDomains),
			Remediation:       "Deploy OpenSearch domains within a VPC",
			RemediationDetail: "Create new domain in VPC. Note: Moving from public to VPC requires recreating the domain.",
			ScreenshotGuide:   "OpenSearch Console → Domains → Select domain → Network → Screenshot showing VPC configuration",
			ConsoleURL:        "https://console.aws.amazon.com/aos/home#opensearch/domains",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPENSEARCH_NETWORK"),
		}, nil
	}

	if len(domains.DomainNames) == 0 {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "OpenSearch VPC Deployment",
			Status:     "PASS",
			Evidence:   "No OpenSearch domains found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPENSEARCH_NETWORK"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "OpenSearch VPC Deployment",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d OpenSearch domains are deployed in VPC", len(domains.DomainNames)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OPENSEARCH_NETWORK"),
	}, nil
}

func (c *OpenSearchChecks) CheckAuditLogs(ctx context.Context) (CheckResult, error) {
	domains, err := c.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noAuditLogs := []string{}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)

		detail, err := c.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err != nil {
			continue
		}

		// Check if audit logs are enabled
		if detail.DomainStatus.LogPublishingOptions == nil {
			noAuditLogs = append(noAuditLogs, domainName)
			continue
		}

		auditLogEnabled := false
		for logType, logConfig := range detail.DomainStatus.LogPublishingOptions {
			if logType == "AUDIT_LOGS" && aws.ToBool(logConfig.Enabled) {
				auditLogEnabled = true
				break
			}
		}

		if !auditLogEnabled {
			noAuditLogs = append(noAuditLogs, domainName)
		}
	}

	if len(noAuditLogs) > 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "OpenSearch Audit Logs",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d OpenSearch domains without audit logging: %v", len(noAuditLogs), noAuditLogs),
			Remediation:       "Enable audit logging for OpenSearch domains",
			RemediationDetail: "Configure log publishing options to enable AUDIT_LOGS to CloudWatch Logs",
			ScreenshotGuide:   "OpenSearch Console → Domains → Select domain → Logs → Screenshot showing 'Audit logs: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/aos/home#opensearch/domains",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPENSEARCH_LOGGING"),
		}, nil
	}

	if len(domains.DomainNames) == 0 {
		return CheckResult{
			Control:    "CC7.1",
			Name:       "OpenSearch Audit Logs",
			Status:     "PASS",
			Evidence:   "No OpenSearch domains found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPENSEARCH_LOGGING"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.1",
		Name:       "OpenSearch Audit Logs",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d OpenSearch domains have audit logging enabled", len(domains.DomainNames)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OPENSEARCH_LOGGING"),
	}, nil
}

func (c *OpenSearchChecks) CheckFineGrainedAccessControl(ctx context.Context) (CheckResult, error) {
	domains, err := c.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noFGAC := []string{}

	for _, domain := range domains.DomainNames {
		domainName := aws.ToString(domain.DomainName)

		detail, err := c.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: domain.DomainName,
		})
		if err != nil {
			continue
		}

		if detail.DomainStatus.AdvancedSecurityOptions == nil ||
			!aws.ToBool(detail.DomainStatus.AdvancedSecurityOptions.Enabled) {
			noFGAC = append(noFGAC, domainName)
		}
	}

	if len(noFGAC) > 0 {
		return CheckResult{
			Control:           "CC6.6",
			Name:              "OpenSearch Fine-Grained Access Control",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d OpenSearch domains without fine-grained access control: %v", len(noFGAC), noFGAC),
			Remediation:       "Enable fine-grained access control for OpenSearch domains",
			RemediationDetail: "Enable Advanced Security Options with fine-grained access control. Requires encryption at rest and node-to-node encryption.",
			ScreenshotGuide:   "OpenSearch Console → Domains → Select domain → Security → Screenshot showing 'Fine-grained access control: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/aos/home#opensearch/domains",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("OPENSEARCH_ACCESS"),
		}, nil
	}

	if len(domains.DomainNames) == 0 {
		return CheckResult{
			Control:    "CC6.6",
			Name:       "OpenSearch Fine-Grained Access Control",
			Status:     "PASS",
			Evidence:   "No OpenSearch domains found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("OPENSEARCH_ACCESS"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.6",
		Name:       "OpenSearch Fine-Grained Access Control",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d OpenSearch domains have fine-grained access control enabled", len(domains.DomainNames)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("OPENSEARCH_ACCESS"),
	}, nil
}
