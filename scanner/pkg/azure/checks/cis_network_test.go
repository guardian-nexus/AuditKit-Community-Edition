package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

// The benchmark's own wording: 0, 90 or more days satisfies 7.8, because 0
// means no retention policy is applied and the records are kept indefinitely.
// Reading 0 as "nothing retained" fails the strongest configuration there is.
func TestFlowLogRetentionTreatsZeroAsIndefinite(t *testing.T) {
	i32 := func(v int32) *int32 { return &v }
	cases := []struct {
		name   string
		policy *armnetwork.RetentionPolicyParameters
		want   bool
	}{
		{"no policy at all", nil, false},
		{"no days field", &armnetwork.RetentionPolicyParameters{}, false},
		{"zero means indefinite", &armnetwork.RetentionPolicyParameters{Days: i32(0)}, true},
		{"exactly ninety", &armnetwork.RetentionPolicyParameters{Days: i32(90)}, true},
		{"more than ninety", &armnetwork.RetentionPolicyParameters{Days: i32(365)}, true},
		{"eighty-nine is short", &armnetwork.RetentionPolicyParameters{Days: i32(89)}, false},
		{"one day", &armnetwork.RetentionPolicyParameters{Days: i32(1)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retentionSatisfies90(tc.policy); got != tc.want {
				t.Errorf("retentionSatisfies90 = %v, want %v", got, tc.want)
			}
		})
	}
}

// "Entra ID only" means exactly that: a gateway that also accepts certificates
// is not Entra-only, however many of its types are AAD.
func TestVPNAuthMustBeEntraAlone(t *testing.T) {
	aad := armnetwork.VPNAuthenticationTypeAAD
	cert := armnetwork.VPNAuthenticationTypeCertificate
	radius := armnetwork.VPNAuthenticationTypeRadius
	cases := []struct {
		name  string
		types []*armnetwork.VPNAuthenticationType
		want  bool
	}{
		{"entra alone", []*armnetwork.VPNAuthenticationType{&aad}, true},
		{"entra and certificate", []*armnetwork.VPNAuthenticationType{&aad, &cert}, false},
		{"entra and radius", []*armnetwork.VPNAuthenticationType{&aad, &radius}, false},
		{"certificate alone", []*armnetwork.VPNAuthenticationType{&cert}, false},
		{"nothing configured", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := entraOnly(tc.types); got != tc.want {
				t.Errorf("entraOnly = %v, want %v", got, tc.want)
			}
		})
	}
}

// A predefined SSL policy reports its name and no minimum version, so reading
// only MinProtocolVersion would fail a gateway pinned to a 2022 policy - which
// is TLS 1.2 - while passing one with no policy at all.
func TestTLSPolicyReadsBothTheMinimumAndThePredefinedName(t *testing.T) {
	proto := func(p armnetwork.ApplicationGatewaySSLProtocol) *armnetwork.ApplicationGatewaySSLProtocol { return &p }
	name := func(n armnetwork.ApplicationGatewaySSLPolicyName) *armnetwork.ApplicationGatewaySSLPolicyName {
		return &n
	}
	cases := []struct {
		label  string
		policy *armnetwork.ApplicationGatewaySSLPolicy
		want   bool
	}{
		{"no policy uses the platform default, which permitted TLS 1.0", nil, false},
		{"explicit TLS 1.2", &armnetwork.ApplicationGatewaySSLPolicy{MinProtocolVersion: proto(armnetwork.ApplicationGatewaySSLProtocolTLSv12)}, true},
		{"explicit TLS 1.3", &armnetwork.ApplicationGatewaySSLPolicy{MinProtocolVersion: proto(armnetwork.ApplicationGatewaySSLProtocolTLSv13)}, true},
		{"explicit TLS 1.0", &armnetwork.ApplicationGatewaySSLPolicy{MinProtocolVersion: proto(armnetwork.ApplicationGatewaySSLProtocolTLSv10)}, false},
		{"explicit TLS 1.1", &armnetwork.ApplicationGatewaySSLPolicy{MinProtocolVersion: proto(armnetwork.ApplicationGatewaySSLProtocolTLSv11)}, false},
		{"2022 predefined policy", &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: name(armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20220101)}, true},
		{"2015 predefined policy", &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: name(armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20150501)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			if got := tlsPolicyAtLeast12(tc.policy); got != tc.want {
				t.Errorf("tlsPolicyAtLeast12 = %v, want %v", got, tc.want)
			}
		})
	}
}

// The Azure-managed subnets cannot take a network security group at all.
// Counting them would fail every estate running a gateway or Bastion on a
// recommendation it has no way to satisfy.
func TestReservedSubnetsAreNotCounted(t *testing.T) {
	for _, n := range []string{"GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet",
		"AzureFirewallManagementSubnet", "RouteServerSubnet", "azurebastionsubnet"} {
		if !isReservedSubnet(n) {
			t.Errorf("%s should be treated as reserved", n)
		}
	}
	for _, n := range []string{"default", "app-tier", "GatewaySubnet2", "data"} {
		if isReservedSubnet(n) {
			t.Errorf("%s is an ordinary subnet and must be counted", n)
		}
	}
}

// The rule set name has shipped both bare and with a version suffix, so the
// match is a case-insensitive substring rather than an equality.
func TestBotRuleSetMatchesTheNameVariants(t *testing.T) {
	sp := func(s string) *string { return &s }
	set := func(t string) *armnetwork.WebApplicationFirewallPolicyPropertiesFormat {
		return &armnetwork.WebApplicationFirewallPolicyPropertiesFormat{
			ManagedRules: &armnetwork.ManagedRulesDefinition{
				ManagedRuleSets: []*armnetwork.ManagedRuleSet{{RuleSetType: sp(t)}},
			},
		}
	}
	for _, n := range []string{"Microsoft_BotManagerRuleSet", "microsoft_botmanagerruleset", "Microsoft_BotManagerRuleSet_1.0"} {
		if !hasBotManagerRuleSet(set(n)) {
			t.Errorf("%q should match the bot manager rule set", n)
		}
	}
	if hasBotManagerRuleSet(set("OWASP")) {
		t.Error("the OWASP rule set is not bot protection")
	}
	if hasBotManagerRuleSet(nil) {
		t.Error("a policy with no properties cannot have bot protection")
	}
	if hasBotManagerRuleSet(&armnetwork.WebApplicationFirewallPolicyPropertiesFormat{}) {
		t.Error("a policy with no managed rules cannot have bot protection")
	}
}

// Every check must report ERROR when its client is absent. An unreachable API
// is not compliance, and a PASS here would be a verdict from no data.
func TestNetworkChecksReportErrorWithoutClients(t *testing.T) {
	results, err := NewCISNetworkChecks(nil, nil, nil, nil, nil, nil, nil).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	want := []string{"CIS-7.8", "CIS-7.9", "CIS-7.10", "CIS-7.11", "CIS-7.12", "CIS-7.13", "CIS-7.14", "CIS-7.15", "CIS-8.4.1", "CIS-8.5"}
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
		if seen[r.Control] {
			t.Errorf("%s reported more than once", r.Control)
		}
		seen[r.Control] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("%s was not reported at all", w)
		}
	}
}

// netVerdict must never report a pass without saying what it compared. An
// empty estate is a pass with its reason named; a non-empty one carries the
// denominator.
func TestNetVerdictAlwaysCarriesADenominator(t *testing.T) {
	base := CheckResult{Control: "CIS-7.13"}
	empty := netVerdict(base, "application gateway(s)", nil, 0)
	if empty.Status != StatusPass || empty.Evidence == "" {
		t.Errorf("an empty estate should pass with a reason, got %s %q", empty.Status, empty.Evidence)
	}
	clean := netVerdict(base, "application gateway(s)", nil, 4)
	if clean.Status != StatusPass || !strings.Contains(clean.Evidence, "4") {
		t.Errorf("a clean estate must name how many were examined, got %q", clean.Evidence)
	}
	bad := netVerdict(base, "application gateway(s)", []string{"gw-1"}, 4)
	if bad.Status != StatusFail || !strings.Contains(bad.Evidence, "1 of 4") {
		t.Errorf("a failure must carry both halves of the fraction, got %q", bad.Evidence)
	}
}
