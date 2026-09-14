package checks

import (
	"net/url"
	"testing"
)

func i32(v int32) *int32 { return &v }

func TestRuleCoversHandlesRangesNotJustExactPorts(t *testing.T) {
	// The older security-group checks compared FromPort for equality, so a rule
	// opening 0-65535 did not "match" port 22 and the group passed while being
	// wide open. That is the case this function exists for.
	for _, tc := range []struct {
		name     string
		from, to *int32
		port     int32
		want     bool
	}{
		{"exact port", i32(22), i32(22), 22, true},
		{"range covering the port", i32(0), i32(65535), 22, true},
		{"range starting at the port", i32(22), i32(80), 22, true},
		{"range ending at the port", i32(1), i32(22), 22, true},
		{"range below", i32(80), i32(443), 22, false},
		{"range above", i32(3390), i32(4000), 3389, false},
		{"all protocols, no ports named", nil, nil, 22, true},
		{"only from set", i32(445), nil, 445, true},
		{"only from set, different port", i32(445), nil, 22, false},
		{"rdp in a wide range", i32(3000), i32(4000), 3389, true},
	} {
		if got := ruleCovers(tc.from, tc.to, tc.port); got != tc.want {
			t.Errorf("%s: ruleCovers(%v,%v,%d) = %v, want %v",
				tc.name, tc.from, tc.to, tc.port, got, tc.want)
		}
	}
}

func TestGrantsFullAdminDistinguishesAllowFromDeny(t *testing.T) {
	// A substring search for "*" would call every one of these a full-admin
	// grant. Only the first two are.
	for _, tc := range []struct {
		name string
		doc  string
		want bool
	}{
		{"allow star on star", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, true},
		{"single statement object, not a list", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, true},
		{"action list containing star", `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","*"],"Resource":"*"}]}`, true},
		{"resource list containing star", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":["arn:aws:s3:::x","*"]}]}`, true},

		{"deny star on star is a guardrail", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, false},
		{"allow star bounded by a condition", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`, false},
		{"wildcard action, specific resource", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket"}]}`, false},
		{"specific action, wildcard resource", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, false},
		{"prefix wildcard is not a full grant", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, false},
		{"deny alongside a narrow allow", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`, false},

		{"not json", `this is not a policy`, false},
		{"empty", ``, false},
		{"no statement", `{"Version":"2012-10-17"}`, false},
	} {
		if got := grantsFullAdmin(tc.doc); got != tc.want {
			t.Errorf("%s: grantsFullAdmin = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGrantsFullAdminDecodesTheUrlEncodedDocument(t *testing.T) {
	// GetPolicyVersion returns the document URL-encoded. Without decoding it,
	// every policy would parse as "not JSON" and the check would pass on an
	// account that is wide open.
	raw := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	encoded := url.QueryEscape(raw)
	if encoded == raw {
		t.Fatal("setup: the fixture must actually be encoded")
	}
	if !grantsFullAdmin(encoded) {
		t.Error("a URL-encoded full-admin policy must still be detected")
	}
}

func TestHasWildcard(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field any
		want  bool
	}{
		{"bare star", "*", true},
		{"list with star", []any{"s3:Get*", "*"}, true},
		{"list without star", []any{"s3:Get*", "ec2:Describe*"}, false},
		{"prefix wildcard only", "s3:*", false},
		{"nil", nil, false},
		{"unexpected type", 42, false},
	} {
		if got := hasWildcard(tc.field); got != tc.want {
			t.Errorf("%s: hasWildcard(%v) = %v, want %v", tc.name, tc.field, got, tc.want)
		}
	}
}
