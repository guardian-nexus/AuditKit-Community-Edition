package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
)

// A custom role is a subscription administrator only when both halves hold: it
// reaches the whole subscription and it permits every action. Testing one half
// alone is what makes this check either useless or noisy.
func TestSubscriptionAdminNeedsBothScopeAndWildcard(t *testing.T) {
	sp := func(s string) *string { return &s }
	sub := "/subscriptions/0000-1111"
	cases := []struct {
		name   string
		props  armauthorization.RoleDefinitionProperties
		expect bool
	}{
		{
			name: "subscription scope with wildcard action",
			props: armauthorization.RoleDefinitionProperties{
				AssignableScopes: []*string{sp(sub)},
				Permissions:      []*armauthorization.Permission{{Actions: []*string{sp("*")}}},
			},
			expect: true,
		},
		{
			name: "tenant root scope with wildcard action",
			props: armauthorization.RoleDefinitionProperties{
				AssignableScopes: []*string{sp("/")},
				Permissions:      []*armauthorization.Permission{{Actions: []*string{sp("*")}}},
			},
			expect: true,
		},
		{
			name: "wildcard confined to a resource group is not a subscription admin",
			props: armauthorization.RoleDefinitionProperties{
				AssignableScopes: []*string{sp(sub + "/resourceGroups/rg-1")},
				Permissions:      []*armauthorization.Permission{{Actions: []*string{sp("*")}}},
			},
			expect: false,
		},
		{
			name: "subscription-scoped reader is not a subscription admin",
			props: armauthorization.RoleDefinitionProperties{
				AssignableScopes: []*string{sp(sub)},
				Permissions:      []*armauthorization.Permission{{Actions: []*string{sp("Microsoft.Storage/*/read")}}},
			},
			expect: false,
		},
		{
			name: "trailing slash on the scope still counts",
			props: armauthorization.RoleDefinitionProperties{
				AssignableScopes: []*string{sp(sub + "/")},
				Permissions:      []*armauthorization.Permission{{Actions: []*string{sp("*")}}},
			},
			expect: true,
		},
		{
			name: "one of several scopes reaching the subscription is enough",
			props: armauthorization.RoleDefinitionProperties{
				AssignableScopes: []*string{sp(sub + "/resourceGroups/rg-1"), sp(sub)},
				Permissions:      []*armauthorization.Permission{{Actions: []*string{sp("*")}}},
			},
			expect: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grantsSubscriptionAdmin(&tc.props); got != tc.expect {
				t.Errorf("grantsSubscriptionAdmin = %v, want %v", got, tc.expect)
			}
		})
	}
}

// Machines Defender skipped must stay visible: a pass over three machines when
// forty were skipped is a different finding from a pass over forty-three.
func TestNotAssessedMachinesAreNamedInEvidence(t *testing.T) {
	if s := notAssessedSuffix(0); s != "" {
		t.Errorf("with nothing skipped the suffix should be empty, got %q", s)
	}
	if s := notAssessedSuffix(7); !strings.Contains(s, "7") {
		t.Errorf("the skipped count is missing from %q", s)
	}
}

// Every check must report ERROR when its client is absent. A PASS would be a
// verdict from data nobody read, and an unreachable API is not compliance.
func TestAbsentClientsReportErrorNotPass(t *testing.T) {
	results, err := NewCISIdentityDefenderChecks(nil, nil, nil, nil, nil, "sub-1").Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	want := []string{"CIS-5.3.3", "CIS-5.4", "CIS-8.1.1.1", "CIS-8.1.10", "CIS-8.1.12", "CIS-8.1.15"}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	seen := map[string]string{}
	for _, r := range results {
		if r.Status != StatusError {
			t.Errorf("%s reported %s with no client; want ERROR", r.Control, r.Status)
		}
		if r.Frameworks["CIS-Azure"] == "" {
			t.Errorf("%s carries no CIS-Azure tag, so the framework filter would drop it", r.Control)
		}
		if _, dup := seen[r.Control]; dup {
			t.Errorf("%s reported more than once", r.Control)
		}
		seen[r.Control] = r.Status
	}
	for _, w := range want {
		if _, ok := seen[w]; !ok {
			t.Errorf("%s was not reported at all", w)
		}
	}
}
