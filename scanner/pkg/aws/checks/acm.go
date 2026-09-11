package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acm"
)

type ACMChecks struct {
	client *acm.Client
}

func NewACMChecks(client *acm.Client) *ACMChecks {
	return &ACMChecks{client: client}
}

func (c *ACMChecks) Name() string {
	return "ACM (Certificate Manager) Security Configuration"
}

func (c *ACMChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckCertificateRenewal(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckCertificateInUse(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *ACMChecks) CheckCertificateRenewal(ctx context.Context) (CheckResult, error) {
	certs, err := c.client.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.3",
			Name:       "ACM Certificate Auto-Renewal",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Failed to list certificates: %v", err),
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ACM_RENEWAL"),
		}, err
	}

	if len(certs.CertificateSummaryList) == 0 {
		return CheckResult{
			Control:    "CC6.3",
			Name:       "ACM Certificate Auto-Renewal",
			Status:     "INFO",
			Evidence:   "No ACM certificates found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ACM_RENEWAL"),
		}, nil
	}

	expired := []string{}
	expiringSoon := []string{}
	valid := 0
	thirtyDaysFromNow := time.Now().AddDate(0, 0, 30)

	for _, cert := range certs.CertificateSummaryList {
		detail, err := c.client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
			CertificateArn: cert.CertificateArn,
		})
		if err != nil {
			continue
		}

		if detail.Certificate.NotAfter != nil {
			if detail.Certificate.NotAfter.Before(time.Now()) {
				expired = append(expired, *cert.DomainName)
			} else if detail.Certificate.NotAfter.Before(thirtyDaysFromNow) {
				expiringSoon = append(expiringSoon, *cert.DomainName)
			} else {
				valid++
			}
		}
	}

	if len(expired) > 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "ACM Certificate Auto-Renewal",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d certificates EXPIRED: %v", len(expired), expired),
			Remediation: "Renew or delete expired certificates immediately",
			Severity:    "CRITICAL",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/acm/home#/certificates/list",
			Frameworks:  GetFrameworkMappings("ACM_RENEWAL"),
		}, nil
	}

	if len(expiringSoon) > 0 {
		return CheckResult{
			Control:     "CC6.3",
			Name:        "ACM Certificate Auto-Renewal",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d certificates expiring within 30 days: %v", len(expiringSoon), expiringSoon),
			Remediation: "Renew certificates before expiration",
			Severity:    "HIGH",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/acm/home#/certificates/list",
			Frameworks:  GetFrameworkMappings("ACM_RENEWAL"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "ACM Certificate Auto-Renewal",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d certificates valid and not expiring soon", valid),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/acm/home#/certificates/list",
		Frameworks: GetFrameworkMappings("ACM_RENEWAL"),
	}, nil
}

func (c *ACMChecks) CheckCertificateInUse(ctx context.Context) (CheckResult, error) {
	certs, err := c.client.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "ACM Certificate In Use",
			Status:     "ERROR",
			Evidence:   "Failed to list certificates",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ACM_IN_USE"),
		}, err
	}

	if len(certs.CertificateSummaryList) == 0 {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "ACM Certificate In Use",
			Status:     "INFO",
			Evidence:   "No ACM certificates found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ACM_IN_USE"),
		}, nil
	}

	unused := []string{}
	inUse := 0

	for _, cert := range certs.CertificateSummaryList {
		detail, err := c.client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
			CertificateArn: cert.CertificateArn,
		})
		if err != nil {
			continue
		}

		if detail.Certificate.InUseBy == nil || len(detail.Certificate.InUseBy) == 0 {
			unused = append(unused, *cert.DomainName)
		} else {
			inUse++
		}
	}

	if len(unused) > 0 {
		return CheckResult{
			Control:     "CC6.1",
			Name:        "ACM Certificate In Use",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d certificates not in use: %v", len(unused), len(certs.CertificateSummaryList), unused),
			Remediation: "Delete unused certificates to reduce attack surface",
			Severity:    "LOW",
			Priority:    PriorityLow,
			Timestamp:   time.Now(),
			ConsoleURL:  "https://console.aws.amazon.com/acm/home#/certificates/list",
			Frameworks:  GetFrameworkMappings("ACM_IN_USE"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "ACM Certificate In Use",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d certificates are in use", inUse),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/acm/home#/certificates/list",
		Frameworks: GetFrameworkMappings("ACM_IN_USE"),
	}, nil
}
