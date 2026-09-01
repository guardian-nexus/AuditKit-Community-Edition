package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/eks"
)

type EKSChecks struct {
	client *eks.Client
}

func NewEKSChecks(client *eks.Client) *EKSChecks {
	return &EKSChecks{client: client}
}

func (c *EKSChecks) Name() string {
	return "EKS Security Configuration"
}

func (c *EKSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// CIS Section 8 - EKS controls
	if result, err := c.CheckEKSEndpointAccess(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEKSLogging(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEKSEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEKSNetworkPolicy(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEKSPodSecurityPolicy(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEKSRBAC(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEKSSecretsEncryption(ctx); err == nil {
		results = append(results, result)
	}

	if result, err := c.CheckEKSAuditLogging(ctx); err == nil {
		results = append(results, result)
	}

	return results, nil
}

// CIS 8.1 - Ensure EKS cluster endpoint access is properly configured
func (c *EKSChecks) CheckEKSEndpointAccess(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "[CIS-8.1]",
			Name:       "EKS Cluster Endpoint Access",
			Status:     "PASS",
			Evidence:   "No EKS clusters found | CIS 8.1 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "8.1"},
		}, nil
	}

	clustersWithPublicAccess := []string{}

	for _, clusterName := range clusters.Clusters {
		cluster, err := c.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: &clusterName,
		})
		if err != nil {
			continue
		}

		// Check if public endpoint is enabled
		if cluster.Cluster.ResourcesVpcConfig != nil {
			if cluster.Cluster.ResourcesVpcConfig.EndpointPublicAccess {
				// Public access is enabled - check if restricted
				if cluster.Cluster.ResourcesVpcConfig.PublicAccessCidrs == nil ||
					len(cluster.Cluster.ResourcesVpcConfig.PublicAccessCidrs) == 0 ||
					contains(cluster.Cluster.ResourcesVpcConfig.PublicAccessCidrs[0], "0.0.0.0/0") {
					clustersWithPublicAccess = append(clustersWithPublicAccess, clusterName)
				}
			}
		}
	}

	if len(clustersWithPublicAccess) > 0 {
		displayClusters := clustersWithPublicAccess
		if len(clustersWithPublicAccess) > 5 {
			displayClusters = clustersWithPublicAccess[:5]
		}

		return CheckResult{
			Control:     "[CIS-8.1]",
			Name:        "EKS Cluster Endpoint Access",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d EKS clusters with unrestricted public endpoint access: %v | CIS 8.1", len(clustersWithPublicAccess), displayClusters),
			Remediation: "Restrict EKS cluster endpoint access",
			RemediationDetail: `# Disable public access and enable private:
aws eks update-cluster-config \
  --name CLUSTER_NAME \
  --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true

# Or restrict public access CIDRs:
aws eks update-cluster-config \
  --name CLUSTER_NAME \
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs="10.0.0.0/8,192.168.0.0/16"`,
			ScreenshotGuide: "EKS Console → Clusters → Networking → Screenshot showing restricted endpoint access",
			ConsoleURL:      "https://console.aws.amazon.com/eks/home#/clusters",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "8.1", "SOC2": "CC6.6", "PCI-DSS": "1.2.1"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-8.1]",
		Name:       "EKS Cluster Endpoint Access",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d EKS clusters have restricted endpoint access | Meets CIS 8.1", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "8.1"},
	}, nil
}

// CIS 8.2 - Ensure EKS cluster logging is enabled
func (c *EKSChecks) CheckEKSLogging(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "[CIS-8.2]",
			Name:       "EKS Cluster Logging",
			Status:     "PASS",
			Evidence:   "No EKS clusters found | CIS 8.2 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "8.2"},
		}, nil
	}

	clustersWithoutLogging := []string{}
	requiredLogTypes := []string{"api", "audit", "authenticator", "controllerManager", "scheduler"}

	for _, clusterName := range clusters.Clusters {
		cluster, err := c.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: &clusterName,
		})
		if err != nil {
			continue
		}

		hasAllLogs := true
		if cluster.Cluster.Logging == nil || cluster.Cluster.Logging.ClusterLogging == nil {
			hasAllLogs = false
		} else {
			enabledTypes := make(map[string]bool)
			for _, logSetup := range cluster.Cluster.Logging.ClusterLogging {
				if logSetup.Enabled != nil && *logSetup.Enabled {
					for _, logType := range logSetup.Types {
						enabledTypes[string(logType)] = true
					}
				}
			}

			for _, required := range requiredLogTypes {
				if !enabledTypes[required] {
					hasAllLogs = false
					break
				}
			}
		}

		if !hasAllLogs {
			clustersWithoutLogging = append(clustersWithoutLogging, clusterName)
		}
	}

	if len(clustersWithoutLogging) > 0 {
		displayClusters := clustersWithoutLogging
		if len(clustersWithoutLogging) > 5 {
			displayClusters = clustersWithoutLogging[:5]
		}

		return CheckResult{
			Control:     "[CIS-8.2]",
			Name:        "EKS Cluster Logging",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d EKS clusters without complete logging: %v | CIS 8.2", len(clustersWithoutLogging), len(clusters.Clusters), displayClusters),
			Remediation: "Enable all EKS cluster logging types",
			RemediationDetail: `aws eks update-cluster-config \
  --name CLUSTER_NAME \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'`,
			ScreenshotGuide: "EKS Console → Clusters → Logging → Screenshot showing all 5 log types enabled",
			ConsoleURL:      "https://console.aws.amazon.com/eks/home#/clusters",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "8.2", "SOC2": "CC7.2", "PCI-DSS": "10.2.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-8.2]",
		Name:       "EKS Cluster Logging",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d EKS clusters have complete logging enabled | Meets CIS 8.2", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "8.2"},
	}, nil
}

// CIS 8.3 - Ensure EKS cluster encryption is enabled
func (c *EKSChecks) CheckEKSEncryption(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "[CIS-8.3]",
			Name:       "EKS Cluster Encryption",
			Status:     "PASS",
			Evidence:   "No EKS clusters found | CIS 8.3 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "8.3"},
		}, nil
	}

	clustersWithoutEncryption := []string{}

	for _, clusterName := range clusters.Clusters {
		cluster, err := c.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: &clusterName,
		})
		if err != nil {
			continue
		}

		hasEncryption := false
		if cluster.Cluster.EncryptionConfig != nil && len(cluster.Cluster.EncryptionConfig) > 0 {
			hasEncryption = true
		}

		if !hasEncryption {
			clustersWithoutEncryption = append(clustersWithoutEncryption, clusterName)
		}
	}

	if len(clustersWithoutEncryption) > 0 {
		displayClusters := clustersWithoutEncryption
		if len(clustersWithoutEncryption) > 5 {
			displayClusters = clustersWithoutEncryption[:5]
		}

		return CheckResult{
			Control:     "[CIS-8.3]",
			Name:        "EKS Cluster Encryption",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("%d/%d EKS clusters without encryption: %v | CIS 8.3", len(clustersWithoutEncryption), len(clusters.Clusters), displayClusters),
			Remediation: "Enable encryption for EKS clusters (must be set at creation time)",
			RemediationDetail: `# Encryption must be enabled at cluster creation:
aws eks create-cluster \
  --name CLUSTER_NAME \
  --encryption-config '[{"resources":["secrets"],"provider":{"keyArn":"arn:aws:kms:region:account:key/KEY_ID"}}]' \
  ...

# For existing clusters, you must create a new cluster with encryption enabled and migrate workloads`,
			ScreenshotGuide: "EKS Console → Clusters → Configuration → Secrets encryption → Screenshot showing KMS key",
			ConsoleURL:      "https://console.aws.amazon.com/eks/home#/clusters",
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "8.3", "SOC2": "CC6.7", "PCI-DSS": "3.4"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-8.3]",
		Name:       "EKS Cluster Encryption",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d EKS clusters have encryption enabled | Meets CIS 8.3", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "8.3"},
	}, nil
}

// CIS 8.4 - Ensure EKS network policy is enabled
func (c *EKSChecks) CheckEKSNetworkPolicy(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "[CIS-8.4]",
			Name:       "EKS Network Policy",
			Status:     "PASS",
			Evidence:   "No EKS clusters found | CIS 8.4 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "8.4"},
		}, nil
	}

	// Network policy enforcement requires manual verification or add-on checks
	// This is a manual check as network policy is typically implemented via Calico or other CNI plugins
	return CheckResult{
		Control:     "[CIS-8.4]",
		Name:        "EKS Network Policy",
		Status:      "MANUAL",
		Severity:    "MEDIUM",
		Evidence:    fmt.Sprintf("%d EKS clusters require manual verification of network policy | CIS 8.4", len(clusters.Clusters)),
		Remediation: "Implement network policies using Calico or AWS VPC CNI",
		RemediationDetail: `# Install Calico network policy engine:
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/master/calico-operator.yaml
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/master/calico-crs.yaml

# Then create NetworkPolicy resources for your namespaces`,
		ScreenshotGuide: "kubectl get networkpolicies --all-namespaces → Screenshot showing network policies",
		ConsoleURL:      "https://console.aws.amazon.com/eks/home#/clusters",
		Priority:        PriorityMedium,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-AWS": "8.4", "SOC2": "CC6.6"},
	}, nil
}

// CIS 8.5 - Ensure EKS pod security policy is enabled
func (c *EKSChecks) CheckEKSPodSecurityPolicy(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "[CIS-8.5]",
			Name:       "EKS Pod Security Policy",
			Status:     "PASS",
			Evidence:   "No EKS clusters found | CIS 8.5 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "8.5"},
		}, nil
	}

	// Pod Security Policy is deprecated in K8s 1.25+, replaced by Pod Security Standards
	// This requires manual verification of PSP or PSS implementation
	return CheckResult{
		Control:     "[CIS-8.5]",
		Name:        "EKS Pod Security Policy",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    fmt.Sprintf("%d EKS clusters require manual verification of Pod Security Standards | CIS 8.5 | Note: PSP deprecated in K8s 1.25+", len(clusters.Clusters)),
		Remediation: "Implement Pod Security Standards (PSS) or Pod Security Admission",
		RemediationDetail: `# For K8s 1.23+, use Pod Security Standards:
# Label namespaces with pod security levels:
kubectl label namespace default pod-security.kubernetes.io/enforce=restricted
kubectl label namespace default pod-security.kubernetes.io/audit=restricted
kubectl label namespace default pod-security.kubernetes.io/warn=restricted

# Verify:
kubectl get namespace default -o yaml | grep pod-security`,
		ScreenshotGuide: "kubectl get psp → Screenshot showing pod security policies OR namespace labels for PSS",
		ConsoleURL:      "https://console.aws.amazon.com/eks/home#/clusters",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-AWS": "8.5", "SOC2": "CC8.1", "PCI-DSS": "2.2"},
	}, nil
}

// CIS 8.6 - Ensure EKS RBAC is properly configured
func (c *EKSChecks) CheckEKSRBAC(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "[CIS-8.6]",
			Name:       "EKS RBAC Configuration",
			Status:     "PASS",
			Evidence:   "No EKS clusters found | CIS 8.6 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "8.6"},
		}, nil
	}

	// RBAC configuration requires kubectl access to verify
	// This is a manual check
	return CheckResult{
		Control:     "[CIS-8.6]",
		Name:        "EKS RBAC Configuration",
		Status:      "MANUAL",
		Severity:    "HIGH",
		Evidence:    fmt.Sprintf("%d EKS clusters require manual RBAC audit | CIS 8.6", len(clusters.Clusters)),
		Remediation: "Review and restrict RBAC permissions following least privilege",
		RemediationDetail: `# Audit cluster roles and role bindings:
kubectl get clusterrolebindings -o wide
kubectl get rolebindings --all-namespaces -o wide

# Review for overly permissive bindings:
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "cluster-admin")'

# Remove unnecessary admin permissions:
kubectl delete clusterrolebinding NAME`,
		ScreenshotGuide: "kubectl get clusterrolebindings → Screenshot showing no unnecessary admin bindings",
		ConsoleURL:      "https://console.aws.amazon.com/eks/home#/clusters",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks:      map[string]string{"CIS-AWS": "8.6", "SOC2": "CC6.3", "PCI-DSS": "7.1.2"},
	}, nil
}

// CIS 8.7 - Ensure EKS secrets encryption is enabled
func (c *EKSChecks) CheckEKSSecretsEncryption(ctx context.Context) (CheckResult, error) {
	// This is the same as CheckEKSEncryption (8.3) - EKS encryption specifically covers secrets
	// Keeping separate for CIS control mapping clarity
	return c.CheckEKSEncryption(ctx)
}

// CIS 8.8 - Ensure EKS audit logging is enabled
func (c *EKSChecks) CheckEKSAuditLogging(ctx context.Context) (CheckResult, error) {
	clusters, err := c.client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return CheckResult{}, err
	}

	if len(clusters.Clusters) == 0 {
		return CheckResult{
			Control:    "[CIS-8.8]",
			Name:       "EKS Audit Logging",
			Status:     "PASS",
			Evidence:   "No EKS clusters found | CIS 8.8 N/A",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-AWS": "8.8"},
		}, nil
	}

	clustersWithoutAuditLog := []string{}

	for _, clusterName := range clusters.Clusters {
		cluster, err := c.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: &clusterName,
		})
		if err != nil {
			continue
		}

		hasAuditLog := false
		if cluster.Cluster.Logging != nil && cluster.Cluster.Logging.ClusterLogging != nil {
			for _, logSetup := range cluster.Cluster.Logging.ClusterLogging {
				if logSetup.Enabled != nil && *logSetup.Enabled {
					for _, logType := range logSetup.Types {
						if string(logType) == "audit" {
							hasAuditLog = true
							break
						}
					}
				}
				if hasAuditLog {
					break
				}
			}
		}

		if !hasAuditLog {
			clustersWithoutAuditLog = append(clustersWithoutAuditLog, clusterName)
		}
	}

	if len(clustersWithoutAuditLog) > 0 {
		displayClusters := clustersWithoutAuditLog
		if len(clustersWithoutAuditLog) > 5 {
			displayClusters = clustersWithoutAuditLog[:5]
		}

		return CheckResult{
			Control:     "[CIS-8.8]",
			Name:        "EKS Audit Logging",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d/%d EKS clusters without audit logging: %v | CIS 8.8", len(clustersWithoutAuditLog), len(clusters.Clusters), displayClusters),
			Remediation: "Enable audit logging for EKS clusters",
			RemediationDetail: `aws eks update-cluster-config \
  --name CLUSTER_NAME \
  --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'`,
			ScreenshotGuide: "EKS Console → Clusters → Logging → Screenshot showing audit log type enabled",
			ConsoleURL:      "https://console.aws.amazon.com/eks/home#/clusters",
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			Frameworks:      map[string]string{"CIS-AWS": "8.8", "SOC2": "CC7.2", "PCI-DSS": "10.2"},
		}, nil
	}

	return CheckResult{
		Control:    "[CIS-8.8]",
		Name:       "EKS Audit Logging",
		Status:     "PASS",
		Evidence:   fmt.Sprintf("All %d EKS clusters have audit logging enabled | Meets CIS 8.8", len(clusters.Clusters)),
		Priority:   PriorityInfo,
		Timestamp:  time.Now(),
		Frameworks: map[string]string{"CIS-AWS": "8.8"},
	}, nil
}
