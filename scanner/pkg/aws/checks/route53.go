package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/route53"
)

type Route53Checks struct {
	client *route53.Client
}

func NewRoute53Checks(client *route53.Client) *Route53Checks {
	return &Route53Checks{client: client}
}

func (c *Route53Checks) Name() string {
	return "Route53 DNS Security"
}

func (c *Route53Checks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckDNSSEC(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CheckDNSSEC verifies DNSSEC is enabled on Route53 hosted zones
// CIS AWS Foundations Benchmark 5.19
func (c *Route53Checks) CheckDNSSEC(ctx context.Context) (CheckResult, error) {
	// List all hosted zones
	resp, err := c.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return CheckResult{
			Control:    "CIS-5.19",
			Name:       "Route53 DNSSEC Enabled",
			Status:     "FAIL",
			Evidence:   fmt.Sprintf("Unable to check Route53 hosted zones: %v", err),
			Severity:   "MEDIUM",
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ROUTE53_DNSSEC"),
		}, err
	}

	if len(resp.HostedZones) == 0 {
		return CheckResult{
			Control:    "CIS-5.19",
			Name:       "Route53 DNSSEC Enabled",
			Status:     StatusInfo,
			Evidence:   "No Route53 hosted zones found",
			Severity:   "INFO",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ROUTE53_DNSSEC"),
		}, nil
	}

	nonDNSSECZones := []string{}
	checkedCount := 0

	for _, zone := range resp.HostedZones {
		// Only check public hosted zones
		if zone.Config != nil && zone.Config.PrivateZone {
			continue
		}

		checkedCount++

		// Get DNSSEC status for this hosted zone
		dnssecResp, err := c.client.GetDNSSEC(ctx, &route53.GetDNSSECInput{
			HostedZoneId: zone.Id,
		})

		if err != nil || dnssecResp == nil || dnssecResp.Status == nil || dnssecResp.Status.ServeSignature == nil {
			// DNSSEC not configured
			zoneName := *zone.Name
			nonDNSSECZones = append(nonDNSSECZones, zoneName)
		} else if *dnssecResp.Status.ServeSignature != "SIGNING" {
			// DNSSEC configured but not active
			zoneName := *zone.Name
			nonDNSSECZones = append(nonDNSSECZones, zoneName)
		}
	}

	if len(nonDNSSECZones) > 0 {
		zoneList := strings.Join(nonDNSSECZones, ", ")
		if len(nonDNSSECZones) > 3 {
			zoneList = strings.Join(nonDNSSECZones[:3], ", ") + fmt.Sprintf(" +%d more", len(nonDNSSECZones)-3)
		}

		return CheckResult{
			Control:     "CIS-5.19",
			Name:        "Route53 DNSSEC Enabled",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d/%d Route53 public hosted zones lack DNSSEC: %s | Violates CIS AWS 5.19 (DNS spoofing protection)", len(nonDNSSECZones), checkedCount, zoneList),
			Remediation: fmt.Sprintf("Enable DNSSEC on: %s", nonDNSSECZones[0]),
			RemediationDetail: fmt.Sprintf(`# Enable DNSSEC for hosted zone
aws route53 enable-hosted-zone-dnssec --hosted-zone-id $(aws route53 list-hosted-zones-by-name --dns-name %s --query 'HostedZones[0].Id' --output text)

# Alternative: Use Console
1. Open Route53 console
2. Click on hosted zone '%s'
3. Click 'DNSSEC signing' tab
4. Click 'Enable DNSSEC signing'
5. Follow the wizard to create KSK and enable signing`, nonDNSSECZones[0], nonDNSSECZones[0]),
			ScreenshotGuide: fmt.Sprintf(`Route53 DNSSEC Evidence:
1. Open Route53 Console: https://console.aws.amazon.com/route53/
2. Click 'Hosted zones' in left navigation
3. Click on zone '%s'
4. Click 'DNSSEC signing' tab
5. Screenshot showing:
   - DNSSEC signing status: Enabled
   - Key-signing key (KSK) status: Active
   - DNSSEC validation: Enabled`, nonDNSSECZones[0]),
			ConsoleURL: fmt.Sprintf("https://console.aws.amazon.com/route53/v2/hostedzones"),
			Priority:   PriorityMedium,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ROUTE53_DNSSEC"),
		}, nil
	}

	return CheckResult{
		Control:    "CIS-5.19",
		Name:       "Route53 DNSSEC Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Route53 public hosted zones have DNSSEC enabled | Meets CIS AWS 5.19 (DNS integrity protection)", checkedCount),
		Severity:   "INFO",
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ROUTE53_DNSSEC"),
	}, nil
}
