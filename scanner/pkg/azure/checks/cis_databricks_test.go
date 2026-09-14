package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
)

// A private endpoint left Pending exists as a resource and carries no traffic.
// Counting the list length would pass a workspace nothing can reach privately.
func TestOnlyApprovedPrivateEndpointsCount(t *testing.T) {
	conn := func(s armdatabricks.PrivateLinkServiceConnectionStatus) *armdatabricks.PrivateEndpointConnection {
		return &armdatabricks.PrivateEndpointConnection{
			Properties: &armdatabricks.PrivateEndpointConnectionProperties{
				PrivateLinkServiceConnectionState: &armdatabricks.PrivateLinkServiceConnectionState{Status: &s},
			},
		}
	}
	cases := []struct {
		name  string
		props *armdatabricks.WorkspaceProperties
		want  bool
	}{
		{"no properties", nil, false},
		{"no endpoints", &armdatabricks.WorkspaceProperties{}, false},
		{
			name:  "approved",
			props: &armdatabricks.WorkspaceProperties{PrivateEndpointConnections: []*armdatabricks.PrivateEndpointConnection{conn(armdatabricks.PrivateLinkServiceConnectionStatusApproved)}},
			want:  true,
		},
		{
			name:  "pending only",
			props: &armdatabricks.WorkspaceProperties{PrivateEndpointConnections: []*armdatabricks.PrivateEndpointConnection{conn(armdatabricks.PrivateLinkServiceConnectionStatusPending)}},
			want:  false,
		},
		{
			name:  "rejected only",
			props: &armdatabricks.WorkspaceProperties{PrivateEndpointConnections: []*armdatabricks.PrivateEndpointConnection{conn(armdatabricks.PrivateLinkServiceConnectionStatusRejected)}},
			want:  false,
		},
		{
			name: "pending alongside approved",
			props: &armdatabricks.WorkspaceProperties{PrivateEndpointConnections: []*armdatabricks.PrivateEndpointConnection{
				conn(armdatabricks.PrivateLinkServiceConnectionStatusPending),
				conn(armdatabricks.PrivateLinkServiceConnectionStatusApproved),
			}},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasApprovedPrivateEndpoint(tc.props); got != tc.want {
				t.Errorf("hasApprovedPrivateEndpoint = %v, want %v", got, tc.want)
			}
		})
	}
}

// The custom virtual network id is the single fact 2.1.1 turns on, and its
// absence is what marks a Databricks-managed network.
func TestCustomNetworkAndSubnetExtraction(t *testing.T) {
	sp := func(s string) *armdatabricks.WorkspaceCustomStringParameter {
		return &armdatabricks.WorkspaceCustomStringParameter{Value: &s}
	}
	managed := workspace{name: "managed", props: &armdatabricks.WorkspaceProperties{}}
	if managed.customVNetID() != "" {
		t.Error("a workspace with no parameters is on the Databricks-managed network")
	}
	if len(managed.customSubnets()) != 0 {
		t.Error("a managed workspace has no custom subnet names")
	}

	injected := workspace{name: "injected", props: &armdatabricks.WorkspaceProperties{
		Parameters: &armdatabricks.WorkspaceCustomParameters{
			CustomVirtualNetworkID:  sp("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-1"),
			CustomPrivateSubnetName: sp("db-private"),
			CustomPublicSubnetName:  sp("db-public"),
		},
	}}
	if !strings.HasSuffix(injected.customVNetID(), "/vnet-1") {
		t.Errorf("customVNetID = %q", injected.customVNetID())
	}
	subnets := injected.customSubnets()
	if len(subnets) != 2 || subnets[0] != "db-private" || subnets[1] != "db-public" {
		t.Errorf("customSubnets = %v, want both the private and public subnet", subnets)
	}

	// A parameter present but empty is the same as absent, and must not be
	// reported as a subnet named "".
	blank := workspace{name: "blank", props: &armdatabricks.WorkspaceProperties{
		Parameters: &armdatabricks.WorkspaceCustomParameters{CustomPrivateSubnetName: sp("")},
	}}
	if len(blank.customSubnets()) != 0 {
		t.Errorf("an empty subnet name must not be counted, got %v", blank.customSubnets())
	}
}

// An estate with no Databricks at all is not a finding, but the evidence has
// to say that is why - a bare PASS with no reason is the shape this codebase
// keeps having to correct.
func TestNoWorkspacesPassesWithItsReason(t *testing.T) {
	r := dbVerdict(CheckResult{Control: "CIS-2.1.9"}, nil, 0)
	if r.Status != StatusPass {
		t.Errorf("status = %s, want PASS", r.Status)
	}
	if !strings.Contains(strings.ToLower(r.Evidence), "no azure databricks") {
		t.Errorf("evidence must name why it passed, got %q", r.Evidence)
	}
}

func TestDatabricksChecksReportErrorWithoutClients(t *testing.T) {
	results, err := NewCISDatabricksChecks(nil, nil, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	want := []string{"CIS-2.1.1", "CIS-2.1.2", "CIS-2.1.7", "CIS-2.1.9", "CIS-2.1.10", "CIS-2.1.11"}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	seen := map[string]bool{}
	for _, r := range results {
		if r.Status != StatusError {
			t.Errorf("%s reported %s with no client; want ERROR", r.Control, r.Status)
		}
		if r.Frameworks["CIS-Azure"] == "" {
			t.Errorf("%s carries no CIS-Azure tag, so the framework filter would drop it", r.Control)
		}
		seen[r.Control] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("%s was not reported at all", w)
		}
	}
}
