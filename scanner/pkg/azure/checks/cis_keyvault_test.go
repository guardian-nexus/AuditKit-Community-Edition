package checks

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
)

// A rotation policy whose only action is "notify" warns somebody the key is
// old and rotates nothing. It is the configuration most likely to be mistaken
// for compliance, so it must not pass.
func TestNotifyOnlyPolicyDoesNotRotate(t *testing.T) {
	act := func(t armkeyvault.KeyRotationPolicyActionType) *armkeyvault.LifetimeAction {
		return &armkeyvault.LifetimeAction{Action: &armkeyvault.Action{Type: &t}}
	}
	cases := []struct {
		name   string
		policy *armkeyvault.RotationPolicy
		want   bool
	}{
		{"no policy", nil, false},
		{"policy with no actions", &armkeyvault.RotationPolicy{}, false},
		{
			name:   "notify only",
			policy: &armkeyvault.RotationPolicy{LifetimeActions: []*armkeyvault.LifetimeAction{act(armkeyvault.KeyRotationPolicyActionTypeNotify)}},
			want:   false,
		},
		{
			name:   "rotate",
			policy: &armkeyvault.RotationPolicy{LifetimeActions: []*armkeyvault.LifetimeAction{act(armkeyvault.KeyRotationPolicyActionTypeRotate)}},
			want:   true,
		},
		{
			name: "notify and rotate together",
			policy: &armkeyvault.RotationPolicy{LifetimeActions: []*armkeyvault.LifetimeAction{
				act(armkeyvault.KeyRotationPolicyActionTypeNotify),
				act(armkeyvault.KeyRotationPolicyActionTypeRotate),
			}},
			want: true,
		},
		{
			name:   "an action with no type",
			policy: &armkeyvault.RotationPolicy{LifetimeActions: []*armkeyvault.LifetimeAction{{Action: &armkeyvault.Action{}}}},
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rotatesAutomatically(tc.policy); got != tc.want {
				t.Errorf("rotatesAutomatically = %v, want %v", got, tc.want)
			}
		})
	}
}

// 8.3.2 and 8.3.4 are the access-policy recommendations; 8.3.1 and 8.3.3 are
// the RBAC ones. Judging a vault by both would report one estate twice under
// two identifiers, and each would disagree with the other.
func TestOnlyAccessPolicyVaultsAreInScope(t *testing.T) {
	all := []vault{
		{name: "legacy-a", group: "rg-1", rbac: false},
		{name: "rbac-a", group: "rg-1", rbac: true},
		{name: "legacy-b", group: "rg-2", rbac: false},
		// A vault whose id carried no resource group cannot be queried for
		// its keys, so it is not silently treated as clean.
		{name: "no-group", group: "", rbac: false},
	}
	got := legacyVaults(all)
	if len(got) != 2 {
		t.Fatalf("got %d access-policy vault(s), want 2: %+v", len(got), got)
	}
	for _, v := range got {
		if v.rbac {
			t.Errorf("%s is on RBAC and should not be in scope for 8.3.2/8.3.4", v.name)
		}
		if v.group == "" {
			t.Errorf("%s has no resource group, so its keys cannot be listed", v.name)
		}
	}
}

// The certificate issuance policy is only on the Key Vault data plane, which
// this scanner does not reach. That must be reported as a manual check with
// the reason, never as a pass.
func TestCertificateValidityIsReportedManualWithItsReason(t *testing.T) {
	r := (&CISKeyVaultChecks{}).certificateValidityPeriod()
	if r.Status != StatusManual {
		t.Errorf("status is %s; a setting the API does not expose must not be scored", r.Status)
	}
	if r.Evidence == "" || r.Frameworks["CIS-Azure"] != "8.3.11" {
		t.Errorf("the result must say why and carry its identifier: %+v", r)
	}
}

func TestKeyVaultChecksReportErrorWithoutClients(t *testing.T) {
	results, err := NewCISKeyVaultChecks(nil, nil, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	want := map[string]string{
		"CIS-8.3.2":  StatusError,
		"CIS-8.3.4":  StatusError,
		"CIS-8.3.9":  StatusError,
		"CIS-8.3.11": StatusManual, // never readable from this API, so not an error
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for _, r := range results {
		expect, ok := want[r.Control]
		if !ok {
			t.Errorf("unexpected control %s", r.Control)
			continue
		}
		if r.Status != expect {
			t.Errorf("%s reported %s, want %s", r.Control, r.Status, expect)
		}
		if r.Frameworks["CIS-Azure"] == "" {
			t.Errorf("%s carries no CIS-Azure tag, so the framework filter would drop it", r.Control)
		}
	}
}
