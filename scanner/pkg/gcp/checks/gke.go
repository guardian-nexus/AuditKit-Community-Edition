package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	container "google.golang.org/api/container/v1"
)

// GKEChecks handles GCP GKE (Kubernetes) security checks
type GKEChecks struct {
	service   *container.Service
	projectID string
}

// NewGKEChecks creates a new GKE checker
func NewGKEChecks(service *container.Service, projectID string) *GKEChecks {
	return &GKEChecks{
		service:   service,
		projectID: projectID,
	}
}

// Run executes all GKE security checks
func (c *GKEChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	// CIS Section 8 - GKE checks
	results = append(results, c.CheckBinaryAuthorization(ctx)...)
	results = append(results, c.CheckNetworkPolicies(ctx)...)
	results = append(results, c.CheckKubernetesDashboard(ctx)...)
	results = append(results, c.CheckPodSecurityPolicy(ctx)...)
	results = append(results, c.CheckWorkloadIdentity(ctx)...)

	return results, nil
}

// CheckBinaryAuthorization verifies Binary Authorization is enabled (CIS 8.1)
func (c *GKEChecks) CheckBinaryAuthorization(ctx context.Context) []CheckResult {
	var results []CheckResult

	// List all locations to find clusters
	locations := []string{"-"} // "-" means all locations

	var allClusters []*container.Cluster
	totalClusters := 0

	for _, location := range locations {
		parent := fmt.Sprintf("projects/%s/locations/%s", c.projectID, location)
		resp, err := c.service.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
		if err != nil {
			// Try legacy zones API if locations API fails
			zones, zErr := c.listAllZones(ctx)
			if zErr != nil {
				return []CheckResult{{
					Control:     "CIS GCP 8.1",
					Name:        "[CIS GCP 8.1] GKE Binary Authorization",
					Status:      "FAIL",
					Severity:    "HIGH",
					Evidence:    fmt.Sprintf("Unable to list GKE clusters: %v", err),
					Remediation: "Verify Kubernetes Engine API is enabled",
					Priority:    PriorityHigh,
					Timestamp:   time.Now(),
					Frameworks:  map[string]string{"CIS-GCP": "8.1", "SOC2": "CC8.1"},
				}}
			}

			// Use zones-based listing
			for _, zone := range zones {
				zoneParent := fmt.Sprintf("projects/%s/locations/%s", c.projectID, zone)
				zoneResp, zErr := c.service.Projects.Locations.Clusters.List(zoneParent).Context(ctx).Do()
				if zErr == nil && zoneResp.Clusters != nil {
					allClusters = append(allClusters, zoneResp.Clusters...)
				}
			}
			break
		}

		if resp.Clusters != nil {
			allClusters = append(allClusters, resp.Clusters...)
		}
	}

	totalClusters = len(allClusters)

	if totalClusters == 0 {
		return []CheckResult{{
			Control:    "CIS GCP 8.1",
			Name:       "[CIS GCP 8.1] GKE Binary Authorization",
			Status:     "INFO",
			Evidence:   "No GKE clusters found in project | CIS 8.1 not applicable",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.1", "SOC2": "CC8.1"},
		}}
	}

	// Check each cluster for Binary Authorization
	clustersWithoutBinAuthz := []string{}

	for _, cluster := range allClusters {
		if cluster.BinaryAuthorization == nil || !cluster.BinaryAuthorization.Enabled {
			clustersWithoutBinAuthz = append(clustersWithoutBinAuthz, cluster.Name)
		}
	}

	if len(clustersWithoutBinAuthz) > 0 {
		displayClusters := clustersWithoutBinAuthz
		if len(clustersWithoutBinAuthz) > 3 {
			displayClusters = clustersWithoutBinAuthz[:3]
		}

		results = append(results, CheckResult{
			Control:  "CIS GCP 8.1",
			Name:     "[CIS GCP 8.1] GKE Binary Authorization",
			Status:   "FAIL",
			Severity: "HIGH",
			Evidence: fmt.Sprintf("CIS 8.1: %d/%d GKE clusters do not have Binary Authorization enabled: %s | Binary Authorization ensures only trusted container images run",
				len(clustersWithoutBinAuthz), totalClusters, strings.Join(displayClusters, ", ")),
			Remediation: "Enable Binary Authorization on all GKE clusters to ensure only verified images are deployed",
			RemediationDetail: `# Enable Binary Authorization on existing cluster
gcloud container clusters update CLUSTER_NAME \
  --enable-binauthz \
  --zone=ZONE \
  --project=` + c.projectID + `

# For new clusters, enable at creation
gcloud container clusters create CLUSTER_NAME \
  --enable-binauthz \
  --zone=ZONE \
  --project=` + c.projectID + `

# Configure Binary Authorization policy
gcloud container binauthz policy import policy.yaml`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Kubernetes Engine → Clusters → Security → Screenshot showing Binary Authorization: Enabled",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/kubernetes/list?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "8.1", "SOC2": "CC8.1", "PCI-DSS": "2.2.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 8.1",
			Name:       "[CIS GCP 8.1] GKE Binary Authorization",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d GKE clusters have Binary Authorization enabled | Meets CIS 8.1", totalClusters),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.1", "SOC2": "CC8.1", "PCI-DSS": "2.2.1"},
		})
	}

	return results
}

// CheckNetworkPolicies verifies Network Policy is enabled (CIS 8.2)
func (c *GKEChecks) CheckNetworkPolicies(ctx context.Context) []CheckResult {
	var results []CheckResult

	clusters := c.getAllClusters(ctx)

	if len(clusters) == 0 {
		return []CheckResult{{
			Control:    "CIS GCP 8.2",
			Name:       "[CIS GCP 8.2] GKE Network Policies",
			Status:     "INFO",
			Evidence:   "No GKE clusters found in project | CIS 8.2 not applicable",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.2", "SOC2": "CC6.6"},
		}}
	}

	// Check each cluster for Network Policy
	clustersWithoutNetworkPolicy := []string{}

	for _, cluster := range clusters {
		// Check if network policy is enabled
		if cluster.NetworkPolicy == nil || !cluster.NetworkPolicy.Enabled {
			clustersWithoutNetworkPolicy = append(clustersWithoutNetworkPolicy, cluster.Name)
		} else if cluster.AddonsConfig != nil && cluster.AddonsConfig.NetworkPolicyConfig != nil && cluster.AddonsConfig.NetworkPolicyConfig.Disabled {
			clustersWithoutNetworkPolicy = append(clustersWithoutNetworkPolicy, cluster.Name)
		}
	}

	if len(clustersWithoutNetworkPolicy) > 0 {
		displayClusters := clustersWithoutNetworkPolicy
		if len(clustersWithoutNetworkPolicy) > 3 {
			displayClusters = clustersWithoutNetworkPolicy[:3]
		}

		results = append(results, CheckResult{
			Control:  "CIS GCP 8.2",
			Name:     "[CIS GCP 8.2] GKE Network Policies",
			Status:   "FAIL",
			Severity: "HIGH",
			Evidence: fmt.Sprintf("CIS 8.2: %d/%d GKE clusters do not have Network Policy enabled: %s | Network policies provide pod-level firewall rules",
				len(clustersWithoutNetworkPolicy), len(clusters), strings.Join(displayClusters, ", ")),
			Remediation: "Enable Network Policy on all GKE clusters to control pod-to-pod communication",
			RemediationDetail: `# Enable Network Policy on existing cluster
gcloud container clusters update CLUSTER_NAME \
  --enable-network-policy \
  --zone=ZONE \
  --project=` + c.projectID + `

# For new clusters, enable at creation
gcloud container clusters create CLUSTER_NAME \
  --enable-network-policy \
  --zone=ZONE \
  --project=` + c.projectID + `

# Create a NetworkPolicy resource to define rules
kubectl apply -f network-policy.yaml`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Kubernetes Engine → Clusters → Networking → Screenshot showing Network policy: Enabled",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/kubernetes/list?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "8.2", "SOC2": "CC6.6", "PCI-DSS": "1.4.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 8.2",
			Name:       "[CIS GCP 8.2] GKE Network Policies",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d GKE clusters have Network Policy enabled | Meets CIS 8.2", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.2", "SOC2": "CC6.6", "PCI-DSS": "1.4.2"},
		})
	}

	return results
}

// CheckKubernetesDashboard verifies Kubernetes Dashboard is disabled (CIS 8.3)
func (c *GKEChecks) CheckKubernetesDashboard(ctx context.Context) []CheckResult {
	var results []CheckResult

	clusters := c.getAllClusters(ctx)

	if len(clusters) == 0 {
		return []CheckResult{{
			Control:    "CIS GCP 8.3",
			Name:       "[CIS GCP 8.3] Kubernetes Dashboard Disabled",
			Status:     "INFO",
			Evidence:   "No GKE clusters found in project | CIS 8.3 not applicable",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.3", "SOC2": "CC6.1"},
		}}
	}

	// Check each cluster for Kubernetes Dashboard
	clustersWithDashboard := []string{}

	for _, cluster := range clusters {
		// Check if Kubernetes Dashboard addon is enabled
		if cluster.AddonsConfig != nil && cluster.AddonsConfig.KubernetesDashboard != nil {
			if !cluster.AddonsConfig.KubernetesDashboard.Disabled {
				clustersWithDashboard = append(clustersWithDashboard, cluster.Name)
			}
		}
	}

	if len(clustersWithDashboard) > 0 {
		displayClusters := clustersWithDashboard
		if len(clustersWithDashboard) > 3 {
			displayClusters = clustersWithDashboard[:3]
		}

		results = append(results, CheckResult{
			Control:  "CIS GCP 8.3",
			Name:     "[CIS GCP 8.3] Kubernetes Dashboard Disabled",
			Status:   "FAIL",
			Severity: "MEDIUM",
			Evidence: fmt.Sprintf("CIS 8.3: %d/%d GKE clusters have Kubernetes Dashboard enabled: %s | Dashboard has known security vulnerabilities",
				len(clustersWithDashboard), len(clusters), strings.Join(displayClusters, ", ")),
			Remediation: "Disable Kubernetes Dashboard and use Cloud Console or kubectl for cluster management",
			RemediationDetail: `# Disable Kubernetes Dashboard on existing cluster
gcloud container clusters update CLUSTER_NAME \
  --update-addons=KubernetesDashboard=DISABLED \
  --zone=ZONE \
  --project=` + c.projectID + `

# For new clusters, dashboard is disabled by default in GKE
# Use Google Cloud Console or kubectl instead`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Kubernetes Engine → Clusters → Add-ons → Screenshot showing Kubernetes Dashboard: Disabled",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/kubernetes/list?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "8.3", "SOC2": "CC6.1", "PCI-DSS": "2.2.4"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 8.3",
			Name:       "[CIS GCP 8.3] Kubernetes Dashboard Disabled",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d GKE clusters have Kubernetes Dashboard disabled | Meets CIS 8.3", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.3", "SOC2": "CC6.1", "PCI-DSS": "2.2.4"},
		})
	}

	return results
}

// CheckPodSecurityPolicy verifies Pod Security Policy is enabled (CIS 8.4)
func (c *GKEChecks) CheckPodSecurityPolicy(ctx context.Context) []CheckResult {
	var results []CheckResult

	clusters := c.getAllClusters(ctx)

	if len(clusters) == 0 {
		return []CheckResult{{
			Control:    "CIS GCP 8.4",
			Name:       "[CIS GCP 8.4] Pod Security Policy",
			Status:     "INFO",
			Evidence:   "No GKE clusters found in project | CIS 8.4 not applicable",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.4", "SOC2": "CC6.1"},
		}}
	}

	// Check each cluster for Pod Security Policy
	clustersWithoutPSP := []string{}

	for _, cluster := range clusters {
		// Check if PodSecurityPolicy is enabled (legacy) or if using Workload Identity with GKE Autopilot
		hasPSP := false

		// Check legacy Pod Security Policy (deprecated in K8s 1.25+)
		if cluster.LegacyAbac != nil && cluster.LegacyAbac.Enabled {
			// ABAC is legacy, we want this disabled, not enabled
			hasPSP = false
		}

		// Note: PSP is deprecated in K8s 1.25+, replaced by Pod Security Standards
		// For newer clusters, check if it's an Autopilot cluster (which has security policies built-in)
		if cluster.Autopilot != nil && cluster.Autopilot.Enabled {
			hasPSP = true // Autopilot clusters have built-in pod security
		}

		// Check if the cluster has Workload Identity (proxy for modern security)
		if cluster.WorkloadIdentityConfig != nil && cluster.WorkloadIdentityConfig.WorkloadPool != "" {
			hasPSP = true // Modern cluster with security features
		}

		if !hasPSP {
			clustersWithoutPSP = append(clustersWithoutPSP, cluster.Name)
		}
	}

	if len(clustersWithoutPSP) > 0 {
		displayClusters := clustersWithoutPSP
		if len(clustersWithoutPSP) > 3 {
			displayClusters = clustersWithoutPSP[:3]
		}

		results = append(results, CheckResult{
			Control:  "CIS GCP 8.4",
			Name:     "[CIS GCP 8.4] Pod Security Policy",
			Status:   "FAIL",
			Severity: "HIGH",
			Evidence: fmt.Sprintf("CIS 8.4: %d/%d GKE clusters do not have Pod Security Policy enabled: %s | PSP prevents insecure pod configurations",
				len(clustersWithoutPSP), len(clusters), strings.Join(displayClusters, ", ")),
			Remediation: "Enable Pod Security Policy (legacy K8s <1.25) or use GKE Autopilot / Pod Security Standards (K8s 1.25+)",
			RemediationDetail: `# For clusters < K8s 1.25: Enable Pod Security Policy
gcloud container clusters update CLUSTER_NAME \
  --enable-pod-security-policy \
  --zone=ZONE \
  --project=` + c.projectID + `

# For K8s 1.25+: Use Pod Security Standards (PSS)
# Create namespace with security standards
kubectl label namespace NAMESPACE \
  pod-security.kubernetes.io/enforce=restricted

# Or use GKE Autopilot which has built-in pod security
gcloud container clusters create-auto CLUSTER_NAME \
  --region=REGION \
  --project=` + c.projectID,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Kubernetes Engine → Clusters → Security → Screenshot showing Pod Security Policy: Enabled or Autopilot mode",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/kubernetes/list?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "8.4", "SOC2": "CC6.1", "PCI-DSS": "2.2.1"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 8.4",
			Name:       "[CIS GCP 8.4] Pod Security Policy",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d GKE clusters have Pod Security Policy or Autopilot enabled | Meets CIS 8.4", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.4", "SOC2": "CC6.1", "PCI-DSS": "2.2.1"},
		})
	}

	return results
}

// CheckWorkloadIdentity verifies Workload Identity is enabled (CIS 8.5)
func (c *GKEChecks) CheckWorkloadIdentity(ctx context.Context) []CheckResult {
	var results []CheckResult

	clusters := c.getAllClusters(ctx)

	if len(clusters) == 0 {
		return []CheckResult{{
			Control:    "CIS GCP 8.5",
			Name:       "[CIS GCP 8.5] GKE Workload Identity",
			Status:     "INFO",
			Evidence:   "No GKE clusters found in project | CIS 8.5 not applicable",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.5", "SOC2": "CC6.1"},
		}}
	}

	// Check each cluster for Workload Identity
	clustersWithoutWI := []string{}

	for _, cluster := range clusters {
		// Check if Workload Identity is enabled
		hasWI := false

		if cluster.WorkloadIdentityConfig != nil && cluster.WorkloadIdentityConfig.WorkloadPool != "" {
			hasWI = true
		}

		// Autopilot clusters have Workload Identity enabled by default
		if cluster.Autopilot != nil && cluster.Autopilot.Enabled {
			hasWI = true
		}

		if !hasWI {
			clustersWithoutWI = append(clustersWithoutWI, cluster.Name)
		}
	}

	if len(clustersWithoutWI) > 0 {
		displayClusters := clustersWithoutWI
		if len(clustersWithoutWI) > 3 {
			displayClusters = clustersWithoutWI[:3]
		}

		results = append(results, CheckResult{
			Control:  "CIS GCP 8.5",
			Name:     "[CIS GCP 8.5] GKE Workload Identity",
			Status:   "FAIL",
			Severity: "HIGH",
			Evidence: fmt.Sprintf("CIS 8.5: %d/%d GKE clusters do not have Workload Identity enabled: %s | Workload Identity prevents node SA credential exposure",
				len(clustersWithoutWI), len(clusters), strings.Join(displayClusters, ", ")),
			Remediation: "Enable Workload Identity on all GKE clusters to securely access Google Cloud services from pods",
			RemediationDetail: `# Enable Workload Identity on existing cluster
gcloud container clusters update CLUSTER_NAME \
  --workload-pool=` + c.projectID + `.svc.id.goog \
  --zone=ZONE \
  --project=` + c.projectID + `

# Enable on node pool
gcloud container node-pools update NODE_POOL \
  --cluster=CLUSTER_NAME \
  --workload-metadata=GKE_METADATA \
  --zone=ZONE \
  --project=` + c.projectID + `

# For new clusters, enable at creation
gcloud container clusters create CLUSTER_NAME \
  --workload-pool=` + c.projectID + `.svc.id.goog \
  --zone=ZONE \
  --project=` + c.projectID,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Kubernetes Engine → Clusters → Security → Screenshot showing Workload Identity: Enabled",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/kubernetes/list?project=%s", c.projectID),
			Frameworks:      map[string]string{"CIS-GCP": "8.5", "SOC2": "CC6.1", "PCI-DSS": "8.2.2"},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "CIS GCP 8.5",
			Name:       "[CIS GCP 8.5] GKE Workload Identity",
			Status:     "PASS",
			Evidence:   fmt.Sprintf("All %d GKE clusters have Workload Identity enabled | Meets CIS 8.5", len(clusters)),
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{"CIS-GCP": "8.5", "SOC2": "CC6.1", "PCI-DSS": "8.2.2"},
		})
	}

	return results
}

// Helper function to get all clusters across all zones/regions
func (c *GKEChecks) getAllClusters(ctx context.Context) []*container.Cluster {
	parent := fmt.Sprintf("projects/%s/locations/-", c.projectID)
	resp, err := c.service.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		// Try legacy zones API
		zones, zErr := c.listAllZones(ctx)
		if zErr != nil {
			return []*container.Cluster{}
		}

		var allClusters []*container.Cluster
		for _, zone := range zones {
			zoneParent := fmt.Sprintf("projects/%s/locations/%s", c.projectID, zone)
			zoneResp, zErr := c.service.Projects.Locations.Clusters.List(zoneParent).Context(ctx).Do()
			if zErr == nil && zoneResp.Clusters != nil {
				allClusters = append(allClusters, zoneResp.Clusters...)
			}
		}
		return allClusters
	}

	if resp.Clusters == nil {
		return []*container.Cluster{}
	}

	return resp.Clusters
}

// Helper function to list all available zones
func (c *GKEChecks) listAllZones(ctx context.Context) ([]string, error) {
	// Common GCP zones - in production, you'd query the Compute API
	return []string{
		"us-central1-a", "us-central1-b", "us-central1-c", "us-central1-f",
		"us-east1-b", "us-east1-c", "us-east1-d",
		"us-west1-a", "us-west1-b", "us-west1-c",
		"europe-west1-b", "europe-west1-c", "europe-west1-d",
		"asia-east1-a", "asia-east1-b", "asia-east1-c",
	}, nil
}
