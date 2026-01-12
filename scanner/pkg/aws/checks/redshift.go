package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

type RedshiftChecks struct {
	client *redshift.Client
}

func NewRedshiftChecks(client *redshift.Client) *RedshiftChecks {
	return &RedshiftChecks{client: client}
}

func (c *RedshiftChecks) Name() string {
	return "Redshift Data Warehouse Security"
}

func (c *RedshiftChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	if result, err := c.CheckClusterEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckClusterPublicAccess(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckClusterLogging(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckClusterSSL(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckClusterVersionUpgrade(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckClusterBackupRetention(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckClusterEnhancedVPCRouting(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

func (c *RedshiftChecks) CheckClusterEncryption(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	unencrypted := []string{}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)

		if !aws.ToBool(cluster.Encrypted) {
			unencrypted = append(unencrypted, clusterID)
		}
	}

	if len(unencrypted) > 0 {
		return CheckResult{
			Control:           "CC6.3",
			Name:              "Redshift Cluster Encryption",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d Redshift clusters NOT encrypted: %v", len(unencrypted), unencrypted),
			Remediation:       "Enable encryption for Redshift clusters",
			RemediationDetail: "1. Create snapshot of unencrypted cluster\n2. Restore snapshot with encryption enabled\n3. Update applications to use new endpoint\n4. Delete unencrypted cluster",
			ScreenshotGuide:   "Redshift Console → Clusters → Select cluster → Properties → Screenshot showing 'Encrypted: Yes'",
			ConsoleURL:        "https://console.aws.amazon.com/redshiftv2/home#clusters",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("REDSHIFT_ENCRYPTION"),
		}, nil
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "CC6.3",
			Name:       "Redshift Cluster Encryption",
			Status:     "PASS",
			Evidence:   "No Redshift clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("REDSHIFT_ENCRYPTION"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.3",
		Name:       "Redshift Cluster Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redshift clusters are encrypted", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("REDSHIFT_ENCRYPTION"),
	}, nil
}

func (c *RedshiftChecks) CheckClusterPublicAccess(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	publicClusters := []string{}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)

		if aws.ToBool(cluster.PubliclyAccessible) {
			publicClusters = append(publicClusters, clusterID)
		}
	}

	if len(publicClusters) > 0 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "Redshift Public Access",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("%d Redshift clusters are publicly accessible: %v", len(publicClusters), publicClusters),
			Remediation:       "Disable public accessibility for Redshift clusters",
			RemediationDetail: "aws redshift modify-cluster --cluster-identifier [CLUSTER_ID] --no-publicly-accessible",
			ScreenshotGuide:   "Redshift Console → Clusters → Select cluster → Properties → Screenshot showing 'Publicly accessible: No'",
			ConsoleURL:        "https://console.aws.amazon.com/redshiftv2/home#clusters",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("REDSHIFT_NETWORK"),
		}, nil
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "Redshift Public Access",
			Status:     "PASS",
			Evidence:   "No Redshift clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("REDSHIFT_NETWORK"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "Redshift Public Access",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redshift clusters are private (not publicly accessible)", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("REDSHIFT_NETWORK"),
	}, nil
}

func (c *RedshiftChecks) CheckClusterLogging(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noLogging := []string{}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)

		// Get logging status
		logging, err := c.client.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{
			ClusterIdentifier: cluster.ClusterIdentifier,
		})
		if err != nil || !aws.ToBool(logging.LoggingEnabled) {
			noLogging = append(noLogging, clusterID)
		}
	}

	if len(noLogging) > 0 {
		return CheckResult{
			Control:           "CC7.1",
			Name:              "Redshift Audit Logging",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d Redshift clusters without audit logging: %v", len(noLogging), noLogging),
			Remediation:       "Enable audit logging for Redshift clusters",
			RemediationDetail: "aws redshift enable-logging --cluster-identifier [CLUSTER_ID] --bucket-name [S3_BUCKET] --s3-key-prefix 'redshift-logs/'",
			ScreenshotGuide:   "Redshift Console → Clusters → Select cluster → Properties → Audit logging → Screenshot showing 'Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/redshiftv2/home#clusters",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("REDSHIFT_LOGGING"),
		}, nil
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "CC7.1",
			Name:       "Redshift Audit Logging",
			Status:     "PASS",
			Evidence:   "No Redshift clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("REDSHIFT_LOGGING"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.1",
		Name:       "Redshift Audit Logging",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redshift clusters have audit logging enabled", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("REDSHIFT_LOGGING"),
	}, nil
}

func (c *RedshiftChecks) CheckClusterSSL(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noSSL := []string{}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)

		// Check parameter group for require_ssl
		if cluster.ClusterParameterGroups != nil {
			for _, pg := range cluster.ClusterParameterGroups {
				pgName := aws.ToString(pg.ParameterGroupName)

				params, err := c.client.DescribeClusterParameters(ctx, &redshift.DescribeClusterParametersInput{
					ParameterGroupName: &pgName,
				})
				if err != nil {
					continue
				}

				sslRequired := false
				for _, param := range params.Parameters {
					if aws.ToString(param.ParameterName) == "require_ssl" && aws.ToString(param.ParameterValue) == "true" {
						sslRequired = true
						break
					}
				}

				if !sslRequired {
					noSSL = append(noSSL, clusterID)
				}
			}
		}
	}

	if len(noSSL) > 0 {
		return CheckResult{
			Control:           "CC6.4",
			Name:              "Redshift SSL Required",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d Redshift clusters do not require SSL: %v", len(noSSL), noSSL),
			Remediation:       "Enable require_ssl parameter for Redshift clusters",
			RemediationDetail: "1. Create/modify parameter group with require_ssl=true\n2. Associate parameter group with cluster\n3. Reboot cluster to apply changes",
			ScreenshotGuide:   "Redshift Console → Parameter groups → Select group → Parameters → Screenshot showing 'require_ssl: true'",
			ConsoleURL:        "https://console.aws.amazon.com/redshiftv2/home#parameter-groups",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("REDSHIFT_SSL"),
		}, nil
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "CC6.4",
			Name:       "Redshift SSL Required",
			Status:     "PASS",
			Evidence:   "No Redshift clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("REDSHIFT_SSL"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.4",
		Name:       "Redshift SSL Required",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redshift clusters require SSL connections", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("REDSHIFT_SSL"),
	}, nil
}

func (c *RedshiftChecks) CheckClusterVersionUpgrade(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noAutoUpgrade := []string{}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)

		if !aws.ToBool(cluster.AllowVersionUpgrade) {
			noAutoUpgrade = append(noAutoUpgrade, clusterID)
		}
	}

	if len(noAutoUpgrade) > 0 {
		return CheckResult{
			Control:           "CC7.5",
			Name:              "Redshift Auto Version Upgrade",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d Redshift clusters have auto version upgrade disabled: %v", len(noAutoUpgrade), noAutoUpgrade),
			Remediation:       "Enable automatic version upgrades for Redshift clusters",
			RemediationDetail: "aws redshift modify-cluster --cluster-identifier [CLUSTER_ID] --allow-version-upgrade",
			ScreenshotGuide:   "Redshift Console → Clusters → Select cluster → Maintenance → Screenshot showing 'Allow version upgrade: Yes'",
			ConsoleURL:        "https://console.aws.amazon.com/redshiftv2/home#clusters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("REDSHIFT_PATCHING"),
		}, nil
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "CC7.5",
			Name:       "Redshift Auto Version Upgrade",
			Status:     "PASS",
			Evidence:   "No Redshift clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("REDSHIFT_PATCHING"),
		}, nil
	}

	return CheckResult{
		Control:    "CC7.5",
		Name:       "Redshift Auto Version Upgrade",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redshift clusters have auto version upgrade enabled", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("REDSHIFT_PATCHING"),
	}, nil
}

func (c *RedshiftChecks) CheckClusterBackupRetention(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	lowRetention := []string{}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)

		// Check if backup retention is less than 7 days
		if cluster.AutomatedSnapshotRetentionPeriod != nil && *cluster.AutomatedSnapshotRetentionPeriod < 7 {
			lowRetention = append(lowRetention, fmt.Sprintf("%s (%d days)", clusterID, *cluster.AutomatedSnapshotRetentionPeriod))
		}
	}

	if len(lowRetention) > 0 {
		return CheckResult{
			Control:           "A1.2",
			Name:              "Redshift Backup Retention",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d Redshift clusters with backup retention < 7 days: %v", len(lowRetention), lowRetention),
			Remediation:       "Increase automated snapshot retention period to at least 7 days",
			RemediationDetail: "aws redshift modify-cluster --cluster-identifier [CLUSTER_ID] --automated-snapshot-retention-period 7",
			ScreenshotGuide:   "Redshift Console → Clusters → Select cluster → Backup → Screenshot showing retention period >= 7 days",
			ConsoleURL:        "https://console.aws.amazon.com/redshiftv2/home#clusters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("REDSHIFT_BACKUP"),
		}, nil
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "A1.2",
			Name:       "Redshift Backup Retention",
			Status:     "PASS",
			Evidence:   "No Redshift clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("REDSHIFT_BACKUP"),
		}, nil
	}

	return CheckResult{
		Control:    "A1.2",
		Name:       "Redshift Backup Retention",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redshift clusters have adequate backup retention (>= 7 days)", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("REDSHIFT_BACKUP"),
	}, nil
}

func (c *RedshiftChecks) CheckClusterEnhancedVPCRouting(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	noEnhancedRouting := []string{}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)

		if !aws.ToBool(cluster.EnhancedVpcRouting) {
			noEnhancedRouting = append(noEnhancedRouting, clusterID)
		}
	}

	if len(noEnhancedRouting) > 0 {
		return CheckResult{
			Control:           "CC6.1",
			Name:              "Redshift Enhanced VPC Routing",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d Redshift clusters without enhanced VPC routing: %v", len(noEnhancedRouting), noEnhancedRouting),
			Remediation:       "Enable enhanced VPC routing for better network security",
			RemediationDetail: "aws redshift modify-cluster --cluster-identifier [CLUSTER_ID] --enhanced-vpc-routing\nNote: This causes brief cluster unavailability",
			ScreenshotGuide:   "Redshift Console → Clusters → Select cluster → Properties → Network → Screenshot showing 'Enhanced VPC routing: Enabled'",
			ConsoleURL:        "https://console.aws.amazon.com/redshiftv2/home#clusters",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			Frameworks:        GetFrameworkMappings("REDSHIFT_NETWORK"),
		}, nil
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "CC6.1",
			Name:       "Redshift Enhanced VPC Routing",
			Status:     "PASS",
			Evidence:   "No Redshift clusters found",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: GetFrameworkMappings("REDSHIFT_NETWORK"),
		}, nil
	}

	return CheckResult{
		Control:    "CC6.1",
		Name:       "Redshift Enhanced VPC Routing",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d Redshift clusters have enhanced VPC routing enabled", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: GetFrameworkMappings("REDSHIFT_NETWORK"),
	}, nil
}
