package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// fakeIAM answers ListUsers with the given users, GetLoginProfile with
// NoSuchEntity for users in noProfile, and AccessDenied for everything else -
// the shape of a role that may list users but not read their policies, keys or
// MFA devices.
func fakeIAM(t *testing.T, users []string, noProfile map[string]bool) *iam.Client {
	return iam.NewFromConfig(fakeIAMConfig(t, users, noProfile))
}

func fakeIAMConfig(t *testing.T, users []string, noProfile map[string]bool) aws.Config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/xml")
		switch action := r.Form.Get("Action"); {
		case action == "ListUsers":
			// Two users per page, so a caller that reads one page misses the rest.
			start := 0
			if m := r.Form.Get("Marker"); m != "" {
				_, _ = fmt.Sscanf(m, "page-%d", &start)
			}
			end := start + 2
			if end > len(users) {
				end = len(users)
			}
			truncated, marker := "false", ""
			if end < len(users) {
				truncated, marker = "true", fmt.Sprintf("<Marker>page-%d</Marker>", end)
			}
			var b strings.Builder
			for _, u := range users[start:end] {
				fmt.Fprintf(&b, `<member><UserName>%s</UserName><UserId>AID%s</UserId><Arn>arn:aws:iam::123456789012:user/%s</Arn><Path>/</Path><CreateDate>2020-01-01T00:00:00Z</CreateDate></member>`, u, u, u)
			}
			fmt.Fprintf(w, `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult><IsTruncated>%s</IsTruncated>%s<Users>%s</Users></ListUsersResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListUsersResponse>`, truncated, marker, b.String())
		case action == "GetLoginProfile" && noProfile[r.Form.Get("UserName")]:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>no profile</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
		default:
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>denied by test</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
		}
	}))
	t.Cleanup(srv.Close)
	return aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secret", ""),
		BaseEndpoint: aws.String(srv.URL),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	}
}

// Per-user lookups were written "if err == nil && len(policies) > 0", so a
// denied lookup read as "this user has no policies" and the control passed.
// Three PCI checks also dereferenced the nil output of a denied lookup.
func TestDeniedPerUserLookupsAreNotAPass(t *testing.T) {
	client := fakeIAM(t, []string{"alice", "bob"}, nil)
	ctx := context.Background()

	single := map[string]func(context.Context) (CheckResult, error){
		"IAM.CheckIAMPoliciesAttached":          NewIAMChecks(client).CheckIAMPoliciesAttached,
		"IAM.CheckIAMPoliciesAttachedToUsers":   NewIAMChecks(client).CheckIAMPoliciesAttachedToUsers,
		"IAM.CheckIAMPoliciesOnGroupsOnly":      NewIAMChecks(client).CheckIAMPoliciesOnGroupsOnly,
		"IAM.CheckCredentialsUnused45Days":      NewIAMChecks(client).CheckCredentialsUnused45Days,
		"IAMAdvanced.CheckExcessivePermissions": NewIAMAdvancedChecks(client).CheckExcessivePermissions,
		"IAMAdvanced.CheckServiceAccountMFA":    NewIAMAdvancedChecks(client).CheckServiceAccountMFA,
	}
	for name, check := range single {
		r, _ := check(ctx)
		if r.Status == StatusPass {
			t.Errorf("%s: PASS with every per-user lookup denied: %s", name, r.Evidence)
		}
	}

	// Every other service shares the fake and is denied outright.
	cfg := fakeIAMConfig(t, []string{"alice", "bob"}, nil)
	pci := NewPCIDSSChecks(client, ec2.NewFromConfig(cfg), s3.NewFromConfig(cfg), cloudtrail.NewFromConfig(cfg), configservice.NewFromConfig(cfg))
	var rows []CheckResult
	rows = append(rows, pci.CheckReq7_AccessControl(ctx)...)
	rows = append(rows, pci.CheckReq8_Authentication(ctx)...)
	rows = append(rows, pci.CheckFutureDated(ctx)...)
	for _, r := range rows {
		if !strings.HasPrefix(r.Control, "PCI-7.2.1") && !strings.HasPrefix(r.Control, "PCI-8.4.2") && !strings.HasPrefix(r.Control, "PCI-8.6.1") {
			continue
		}
		if r.Status == StatusPass {
			t.Errorf("%s %s: PASS with every per-user lookup denied: %s", r.Control, r.Name, r.Evidence)
		}
	}
}

// GetLoginProfile says "no console password" with NoSuchEntity. Only that
// error means no; anything else leaves the question open.
func TestHasLoginProfile(t *testing.T) {
	client := fakeIAM(t, nil, map[string]bool{"svc": true})
	ctx := context.Background()

	if has, err := hasLoginProfile(ctx, client, "svc"); err != nil || has {
		t.Fatalf("NoSuchEntity: got (%v, %v), want (false, nil)", has, err)
	}
	if _, err := hasLoginProfile(ctx, client, "alice"); err == nil {
		t.Fatal("AccessDenied must come back as an error, not as 'no console password'")
	}
}

func TestRunCheckKeepsResultsReturnedWithAnError(t *testing.T) {
	ctx := context.Background()
	denied := fmt.Errorf("AccessDenied")

	fail := func(context.Context) (CheckResult, error) {
		return CheckResult{Control: "CC7.1", Status: StatusFail}, denied
	}
	pass := func(context.Context) (CheckResult, error) {
		return CheckResult{Control: "CC7.1", Status: StatusPass}, denied
	}
	bare := func(context.Context) (CheckResult, error) { return CheckResult{}, denied }

	got := runCheck(ctx, nil, fail)
	if len(got) != 1 || got[0].Status != StatusFail {
		t.Fatalf("a FAIL returned with its error was dropped: %+v", got)
	}
	got = runCheck(ctx, nil, pass)
	if len(got) != 1 || got[0].Status != StatusError {
		t.Fatalf("a PASS returned with an error must become ERROR: %+v", got)
	}
	if got := runCheck(ctx, nil, bare); len(got) != 0 {
		t.Fatalf("a result with no control cannot be reported: %+v", got)
	}
}
