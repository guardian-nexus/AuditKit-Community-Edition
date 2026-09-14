package checks

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4"
)

// Helper to create string pointer
func strPtr(s string) *string {
	return &s
}

// Helper to create bool pointer
func boolPtr(b bool) *bool {
	return &b
}

func TestAKSChecks_CheckAPIServerAccess(t *testing.T) {
	tests := []struct {
		name           string
		clusters       []*armcontainerservice.ManagedCluster
		expectedStatus string
		expectedCount  int
	}{
		{
			name:           "No clusters",
			clusters:       []*armcontainerservice.ManagedCluster{},
			expectedStatus: "PASS",
			expectedCount:  1,
		},
		{
			name: "Cluster with restricted API access",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
							AuthorizedIPRanges: []*string{strPtr("10.0.0.0/8")},
						},
					},
				},
			},
			expectedStatus: "PASS",
			expectedCount:  1,
		},
		{
			name: "Cluster without API restrictions",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						APIServerAccessProfile: nil,
					},
				},
			},
			expectedStatus: "FAIL",
			expectedCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AKSChecks{subscriptionID: "test-sub"}
			results := checker.CheckAPIServerAccess(context.Background(), tt.clusters)

			if len(results) != tt.expectedCount {
				t.Errorf("Expected %d results, got %d", tt.expectedCount, len(results))
			}

			if len(results) > 0 && results[0].Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, results[0].Status)
			}
		})
	}
}

func TestAKSChecks_CheckNetworkPolicy(t *testing.T) {
	azurePolicy := armcontainerservice.NetworkPolicyAzure

	tests := []struct {
		name           string
		clusters       []*armcontainerservice.ManagedCluster
		expectedStatus string
	}{
		{
			name: "Cluster with Azure network policy",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						NetworkProfile: &armcontainerservice.NetworkProfile{
							NetworkPolicy: &azurePolicy,
						},
					},
				},
			},
			expectedStatus: "PASS",
		},
		{
			name: "Cluster without network policy",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						NetworkProfile: &armcontainerservice.NetworkProfile{
							NetworkPolicy: nil,
						},
					},
				},
			},
			expectedStatus: "FAIL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AKSChecks{subscriptionID: "test-sub"}
			results := checker.CheckNetworkPolicy(context.Background(), tt.clusters)

			if len(results) == 0 {
				t.Fatal("Expected at least one result")
			}

			if results[0].Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, results[0].Status)
			}
		})
	}
}

func TestAKSChecks_CheckRBACEnabled(t *testing.T) {
	tests := []struct {
		name           string
		clusters       []*armcontainerservice.ManagedCluster
		expectedStatus string
	}{
		{
			name: "Cluster with RBAC enabled",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						EnableRBAC: boolPtr(true),
					},
				},
			},
			expectedStatus: "PASS",
		},
		{
			name: "Cluster with RBAC disabled",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						EnableRBAC: boolPtr(false),
					},
				},
			},
			expectedStatus: "FAIL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AKSChecks{subscriptionID: "test-sub"}
			results := checker.CheckRBACEnabled(context.Background(), tt.clusters)

			if len(results) == 0 {
				t.Fatal("Expected at least one result")
			}

			if results[0].Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, results[0].Status)
			}
		})
	}
}

func TestAKSChecks_CheckPrivateCluster(t *testing.T) {
	tests := []struct {
		name           string
		clusters       []*armcontainerservice.ManagedCluster
		expectedStatus string
	}{
		{
			name: "Private cluster",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
							EnablePrivateCluster: boolPtr(true),
						},
					},
				},
			},
			expectedStatus: "PASS",
		},
		{
			name: "Public cluster",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
							EnablePrivateCluster: boolPtr(false),
						},
					},
				},
			},
			expectedStatus: "FAIL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AKSChecks{subscriptionID: "test-sub"}
			results := checker.CheckPrivateCluster(context.Background(), tt.clusters)

			if len(results) == 0 {
				t.Fatal("Expected at least one result")
			}

			if results[0].Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, results[0].Status)
			}
		})
	}
}

func TestAKSChecks_CheckManagedIdentity(t *testing.T) {
	systemAssigned := armcontainerservice.ResourceIdentityTypeSystemAssigned

	tests := []struct {
		name           string
		clusters       []*armcontainerservice.ManagedCluster
		expectedStatus string
	}{
		{
			name: "Cluster with managed identity",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Identity: &armcontainerservice.ManagedClusterIdentity{
						Type: &systemAssigned,
					},
					Properties: &armcontainerservice.ManagedClusterProperties{},
				},
			},
			expectedStatus: "PASS",
		},
		{
			name: "Cluster without managed identity",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name:       strPtr("test-cluster"),
					Identity:   nil,
					Properties: &armcontainerservice.ManagedClusterProperties{},
				},
			},
			expectedStatus: "FAIL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AKSChecks{subscriptionID: "test-sub"}
			results := checker.CheckManagedIdentity(context.Background(), tt.clusters)

			if len(results) == 0 {
				t.Fatal("Expected at least one result")
			}

			if results[0].Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, results[0].Status)
			}
		})
	}
}

func TestAKSChecks_CheckDefenderEnabled(t *testing.T) {
	tests := []struct {
		name           string
		clusters       []*armcontainerservice.ManagedCluster
		expectedStatus string
	}{
		{
			name: "Cluster with Defender enabled",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{
							Defender: &armcontainerservice.ManagedClusterSecurityProfileDefender{
								SecurityMonitoring: &armcontainerservice.ManagedClusterSecurityProfileDefenderSecurityMonitoring{
									Enabled: boolPtr(true),
								},
							},
						},
					},
				},
			},
			expectedStatus: "PASS",
		},
		{
			name: "Cluster without Defender",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						SecurityProfile: nil,
					},
				},
			},
			expectedStatus: "FAIL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AKSChecks{subscriptionID: "test-sub"}
			results := checker.CheckDefenderEnabled(context.Background(), tt.clusters)

			if len(results) == 0 {
				t.Fatal("Expected at least one result")
			}

			if results[0].Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, results[0].Status)
			}
		})
	}
}

func TestAKSChecks_CheckAutoUpgrade(t *testing.T) {
	stableChannel := armcontainerservice.UpgradeChannelStable
	noneChannel := armcontainerservice.UpgradeChannelNone

	tests := []struct {
		name           string
		clusters       []*armcontainerservice.ManagedCluster
		expectedStatus string
	}{
		{
			name: "Cluster with auto-upgrade",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						AutoUpgradeProfile: &armcontainerservice.ManagedClusterAutoUpgradeProfile{
							UpgradeChannel: &stableChannel,
						},
					},
				},
			},
			expectedStatus: "PASS",
		},
		{
			name: "Cluster without auto-upgrade",
			clusters: []*armcontainerservice.ManagedCluster{
				{
					Name: strPtr("test-cluster"),
					Properties: &armcontainerservice.ManagedClusterProperties{
						AutoUpgradeProfile: &armcontainerservice.ManagedClusterAutoUpgradeProfile{
							UpgradeChannel: &noneChannel,
						},
					},
				},
			},
			expectedStatus: "FAIL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AKSChecks{subscriptionID: "test-sub"}
			results := checker.CheckAutoUpgrade(context.Background(), tt.clusters)

			if len(results) == 0 {
				t.Fatal("Expected at least one result")
			}

			if results[0].Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, results[0].Status)
			}
		})
	}
}

func TestAKSChecks_ResultsHaveFrameworkMappings(t *testing.T) {
	checker := &AKSChecks{subscriptionID: "test-sub"}
	clusters := []*armcontainerservice.ManagedCluster{
		{
			Name: strPtr("test-cluster"),
			Properties: &armcontainerservice.ManagedClusterProperties{
				EnableRBAC: boolPtr(false),
			},
		},
	}

	results := checker.CheckRBACEnabled(context.Background(), clusters)

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	if results[0].Frameworks == nil {
		t.Error("Expected framework mappings to be present")
	}

	// AKS recommendations come from the CIS Azure Kubernetes Service benchmark,
	// not Azure Foundations, so they carry CIS-AKS. Tagging them CIS-Azure would
	// claim a Foundations number they do not have. The framework filter still
	// reaches them on a `-framework cis` scan, which matches on the prefix.
	if results[0].Frameworks["CIS-AKS"] == "" {
		t.Error("Expected CIS-AKS framework mapping")
	}
	if results[0].Frameworks["CIS-Azure"] != "" {
		t.Error("AKS results must not claim an Azure Foundations number")
	}

	if results[0].Frameworks["SOC2"] == "" {
		t.Error("Expected SOC2 framework mapping")
	}
}

func TestAKSChecks_ResultsHaveTimestamp(t *testing.T) {
	checker := &AKSChecks{subscriptionID: "test-sub"}
	clusters := []*armcontainerservice.ManagedCluster{
		{
			Name: strPtr("test-cluster"),
			Properties: &armcontainerservice.ManagedClusterProperties{
				EnableRBAC: boolPtr(true),
			},
		},
	}

	before := time.Now()
	results := checker.CheckRBACEnabled(context.Background(), clusters)
	after := time.Now()

	if len(results) == 0 {
		t.Fatal("Expected at least one result")
	}

	if results[0].Timestamp.Before(before) || results[0].Timestamp.After(after) {
		t.Error("Result timestamp should be within test execution time")
	}
}
