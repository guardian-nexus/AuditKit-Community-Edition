package azure

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/azure/checks"
)

type staticToken struct{}

func (staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// denyAll answers every request 403, for both Resource Manager and Graph.
type denyAll struct{}

func (denyAll) Do(r *http.Request) (*http.Response, error) { return denyAll{}.RoundTrip(r) }

func (denyAll) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"error":{"code":"AuthorizationFailed","message":"denied by test"}}`
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    r,
	}, nil
}

// deniedScanner returns a scanner whose every Azure Resource Manager and
// Microsoft Graph call is refused - a principal with no role assignments.
func deniedScanner(t *testing.T) *AzureScanner {
	t.Helper()
	t.Setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")
	checks.TestCredential = staticToken{}
	checks.TestARMOptions = &arm.ClientOptions{ClientOptions: policy.ClientOptions{
		Transport: denyAll{},
		Retry:     policy.RetryOptions{MaxRetries: -1},
	}}
	checks.TestGraphHTTPClient = &http.Client{Transport: denyAll{}}
	t.Cleanup(func() { checks.TestCredential, checks.TestARMOptions, checks.TestGraphHTTPClient = nil, nil, nil })

	s, err := NewScanner("00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A check that cannot read the subscription has not established anything about it.
func TestDeniedAPICallsNeverProducePass(t *testing.T) {
	results := deniedScanner(t).runSuites(context.Background(), false)

	byStatus := map[string]int{}
	var passes []string
	for _, r := range results {
		byStatus[r.Status]++
		if r.Status == "PASS" {
			passes = append(passes, r.Control+" "+r.Name+": "+r.Evidence)
		}
	}
	sort.Strings(passes)
	t.Logf("results with every call denied: %d %v", len(results), byStatus)
	for _, p := range passes {
		t.Errorf("PASS with every API call denied: %s", p)
	}
}
