package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/rds"
)

type AuroraChecks struct {
	client *rds.Client
}

func NewAuroraChecks(client *rds.Client) *AuroraChecks {
	return &AuroraChecks{client: client}
}

func (c *AuroraChecks) Name() string {
	return "Aurora Database Security Configuration"
}

func (c *AuroraChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckBacktrackEnabled(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *AuroraChecks) CheckBacktrackEnabled(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return CheckResult{
			Control:    "AWS-AURORA-01",
			Name:       "Aurora Backtrack Enabled",
			Status:     "ERROR",
			Evidence:   fmt.Sprintf("Failed to list DB clusters: %v", err),
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("AURORA_BACKTRACK"),
		}, err
	}

	if len(clusters.DBClusters) == 0 {
		return CheckResult{
			Control:    "AWS-AURORA-01",
			Name:       "Aurora Backtrack Enabled",
			Status:     "INFO",
			Evidence:   "No Aurora DB clusters found",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("AURORA_BACKTRACK"),
		}, nil
	}

	// Filter to Aurora clusters only
	auroraClusters := []string{}
	without := []string{}
	with := 0

	for _, cluster := range clusters.DBClusters {
		if cluster.Engine != nil && (strings.Contains(*cluster.Engine, "aurora")) {
			auroraClusters = append(auroraClusters, *cluster.DBClusterIdentifier)

			if cluster.BacktrackWindow != nil && *cluster.BacktrackWindow > 0 {
				with++
			} else {
				without = append(without, *cluster.DBClusterIdentifier)
			}
		}
	}

	if len(auroraClusters) == 0 {
		return CheckResult{
			Control:    "AWS-AURORA-01",
			Name:       "Aurora Backtrack Enabled",
			Status:     "INFO",
			Evidence:   "No Aurora clusters found (only RDS/other databases)",
			Priority:   PriorityLow,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("AURORA_BACKTRACK"),
		}, nil
	}

	if len(without) > 0 {
		return CheckResult{
			Control:     "AWS-AURORA-01",
			Name:        "Aurora Backtrack Enabled",
			Status:      "FAIL",
			Evidence:    fmt.Sprintf("%d/%d Aurora clusters lack backtrack: %v", len(without), len(auroraClusters), without),
			Remediation: "Enable backtrack on Aurora clusters for point-in-time recovery",
			RemediationDetail: fmt.Sprintf(`Aurora Backtrack allows rewinding to specific point without restoring backup.

1. Modify Aurora cluster
2. Enable Backtrack
3. Set target backtrack window (hours)
4. Recommended: 24-72 hours
5. Clusters without backtrack: %v

Note: Backtrack only available for Aurora MySQL`, without),
			Severity:        "MEDIUM",
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "RDS → Databases → Cluster → Modify → Screenshot showing backtrack enabled",
			ConsoleURL:      "https://console.aws.amazon.com/rds/home#databases:",
			Frameworks:      GetFrameworkMappings("AURORA_BACKTRACK"),
		}, nil
	}

	return CheckResult{
		Control:    "AWS-AURORA-01",
		Name:       "Aurora Backtrack Enabled",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Aurora clusters have backtrack enabled", with),
		Priority:   PriorityLow,
		Timestamp:  time.Now(),
		ConsoleURL: "https://console.aws.amazon.com/rds/home#databases:",
		Frameworks: GetFrameworkMappings("AURORA_BACKTRACK"),
	}, nil
}
