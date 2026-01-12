package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

type ElastiCacheChecks struct {
	client *elasticache.Client
}

func NewElastiCacheChecks(client *elasticache.Client) *ElastiCacheChecks {
	return &ElastiCacheChecks{client: client}
}

func (c *ElastiCacheChecks) Name() string {
	return "ElastiCache Security"
}

func (c *ElastiCacheChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckEncryptionAtRest(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEncryptionInTransit(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckAutoMinorVersionUpgrade(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckAuthToken(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckBackupRetention(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *ElastiCacheChecks) CheckEncryptionAtRest(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unencrypted := []string{}

	for _, cluster := range clusters.CacheClusters {
		clusterID := aws.ToString(cluster.CacheClusterId)

		if !aws.ToBool(cluster.AtRestEncryptionEnabled) {
			unencrypted = append(unencrypted, clusterID)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:           "CC6.3",
			Name:              "ElastiCache Encryption at Rest",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d ElastiCache clusters without encryption at rest: %v", len(unencrypted), unencrypted),
			Remediation:       "Enable encryption at rest for ElastiCache clusters",
			RemediationDetail: "Encryption at rest must be enabled when creating the cluster. Create new cluster with AtRestEncryptionEnabled=true and migrate data.",
			ScreenshotGuide:   "ElastiCache Console → Redis/Memcached → Select cluster → Description → Screenshot showing 'Encryption at rest: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/elasticache/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ELASTICACHE_ENCRYPTION"),
		}, nil
	}

	if len(clusters.CacheClusters) == 0 {
		return CheckResult{
			Control:    "CC6.3",
			Name:       "ElastiCache Encryption at Rest",
			Status:     "PASS",
			Evidence:   "No ElastiCache clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ELASTICACHE_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "ElastiCache Encryption at Rest",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d ElastiCache clusters have encryption at rest enabled", len(clusters.CacheClusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ELASTICACHE_ENCRYPTION"),
	}, nil
}

func (c *ElastiCacheChecks) CheckEncryptionInTransit(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noTransitEncryption := []string{}

	for _, cluster := range clusters.CacheClusters {
		clusterID := aws.ToString(cluster.CacheClusterId)

		if !aws.ToBool(cluster.TransitEncryptionEnabled) {
			noTransitEncryption = append(noTransitEncryption, clusterID)
		}
	}

	if len(noTransitEncryption) > 0 {
		return CheckResult{
			Control:           "CC6.4",
			Name:              "ElastiCache Encryption in Transit",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d ElastiCache clusters without encryption in transit: %v", len(noTransitEncryption), noTransitEncryption),
			Remediation:       "Enable encryption in transit (TLS) for ElastiCache clusters",
			RemediationDetail: "Transit encryption must be enabled when creating the cluster. Create new cluster with TransitEncryptionEnabled=true.",
			ScreenshotGuide:   "ElastiCache Console → Select cluster → Description → Screenshot showing 'Encryption in transit: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/elasticache/",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ELASTICACHE_TRANSIT"),
		}, nil
	}

	if len(clusters.CacheClusters) == 0 {
		return CheckResult{
			Control:    "CC6.4",
			Name:       "ElastiCache Encryption in Transit",
			Status:     "PASS",
			Evidence:   "No ElastiCache clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ELASTICACHE_TRANSIT"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.4",
		Name:       "ElastiCache Encryption in Transit",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d ElastiCache clusters have encryption in transit enabled", len(clusters.CacheClusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ELASTICACHE_TRANSIT"),
	}, nil
}

func (c *ElastiCacheChecks) CheckAutoMinorVersionUpgrade(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noAutoUpgrade := []string{}

	for _, cluster := range clusters.CacheClusters {
		clusterID := aws.ToString(cluster.CacheClusterId)

		if !aws.ToBool(cluster.AutoMinorVersionUpgrade) {
			noAutoUpgrade = append(noAutoUpgrade, clusterID)
		}
	}

	if len(noAutoUpgrade) > 0 {
		return CheckResult{
			Control:           "CC7.5",
			Name:              "ElastiCache Auto Minor Version Upgrade",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d ElastiCache clusters without auto minor version upgrade: %v", len(noAutoUpgrade), noAutoUpgrade),
			Remediation:       "Enable auto minor version upgrade for ElastiCache clusters",
			RemediationDetail: "aws elasticache modify-cache-cluster --cache-cluster-id [CLUSTER_ID] --auto-minor-version-upgrade",
			ScreenshotGuide:   "ElastiCache Console → Select cluster → Maintenance → Screenshot showing 'Auto minor version upgrade: Yes'",
			ConsoleURL:        "https://console.aws.amazon.com/elasticache/",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ELASTICACHE_PATCHING"),
		}, nil
	}

	if len(clusters.CacheClusters) == 0 {
		return CheckResult{
			Control:    "CC7.5",
			Name:       "ElastiCache Auto Minor Version Upgrade",
			Status:     "PASS",
			Evidence:   "No ElastiCache clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ELASTICACHE_PATCHING"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.5",
		Name:       "ElastiCache Auto Minor Version Upgrade",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d ElastiCache clusters have auto minor version upgrade enabled", len(clusters.CacheClusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ELASTICACHE_PATCHING"),
	}, nil
}

func (c *ElastiCacheChecks) CheckAuthToken(ctx context.Context) (CheckResult, error) {
	// Check Redis replication groups for AUTH token
	repGroups, err := c.client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noAuth := []string{}

	for _, rg := range repGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)

		if !aws.ToBool(rg.AuthTokenEnabled) {
			noAuth = append(noAuth, rgID)
		}
	}

	if len(noAuth) > 0 {
		return CheckResult{
			Control:           "CC6.6",
			Name:              "ElastiCache Redis AUTH Token",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d Redis replication groups without AUTH token: %v", len(noAuth), noAuth),
			Remediation:       "Enable AUTH token for Redis replication groups",
			RemediationDetail: "AUTH token must be enabled when creating the replication group. Create new group with AuthToken parameter set.",
			ScreenshotGuide:   "ElastiCache Console → Redis → Select replication group → Description → Screenshot showing 'AUTH token: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/elasticache/home#redis:",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ELASTICACHE_AUTH"),
		}, nil
	}

	if len(repGroups.ReplicationGroups) == 0 {
		return CheckResult{
			Control:    "CC6.6",
			Name:       "ElastiCache Redis AUTH Token",
			Status:     "PASS",
			Evidence:   "No Redis replication groups found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ELASTICACHE_AUTH"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.6",
		Name:       "ElastiCache Redis AUTH Token",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redis replication groups have AUTH token enabled", len(repGroups.ReplicationGroups)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ELASTICACHE_AUTH"),
	}, nil
}

func (c *ElastiCacheChecks) CheckBackupRetention(ctx context.Context) (CheckResult, error) {
	repGroups, err := c.client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return CheckResult{}, err
	}

	lowRetention := []string{}

	for _, rg := range repGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)

		if rg.SnapshotRetentionLimit != nil && *rg.SnapshotRetentionLimit < 7 {
			lowRetention = append(lowRetention, fmt.Sprintf("%s (%d days)", rgID, *rg.SnapshotRetentionLimit))
		}
	}

	if len(lowRetention) > 0 {
		return CheckResult{
			Control:           "A1.2",
			Name:              "ElastiCache Backup Retention",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d Redis groups with backup retention < 7 days: %v", len(lowRetention), lowRetention),
			Remediation:       "Increase snapshot retention period to at least 7 days",
			RemediationDetail: "aws elasticache modify-replication-group --replication-group-id [GROUP_ID] --snapshot-retention-limit 7",
			ScreenshotGuide:   "ElastiCache Console → Redis → Select group → Backup → Screenshot showing retention >= 7 days",
			ConsoleURL:        "https://console.aws.amazon.com/elasticache/home#redis:",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("ELASTICACHE_BACKUP"),
		}, nil
	}

	if len(repGroups.ReplicationGroups) == 0 {
		return CheckResult{
			Control:    "A1.2",
			Name:       "ElastiCache Backup Retention",
			Status:     "PASS",
			Evidence:   "No Redis replication groups found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("ELASTICACHE_BACKUP"),
		}, nil
	}

	return CheckResult{
		Control:    "A1.2",
		Name:       "ElastiCache Backup Retention",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redis replication groups have adequate backup retention", len(repGroups.ReplicationGroups)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("ELASTICACHE_BACKUP"),
	}, nil
}
