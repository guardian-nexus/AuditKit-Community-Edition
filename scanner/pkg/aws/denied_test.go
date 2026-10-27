package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// deniedScanner returns a scanner whose every AWS API call is answered 403
// AccessDenied, the shape of a scan run with a policy that grants nothing.
func deniedScanner(t *testing.T) *AWSScanner {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amzn-ErrorType", "AccessDeniedException")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"denied by test"}`))
	}))
	t.Cleanup(srv.Close)

	cfg := sdkaws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secret", ""),
		BaseEndpoint: sdkaws.String(srv.URL),
		Retryer:      func() sdkaws.Retryer { return sdkaws.NopRetryer{} },
	}
	s, err := NewScannerWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A check that cannot read the account has not established anything about it.
// The Inspector collector has always had a test pinning this; the regular
// checks had none, which is how a denied ListFirewalls came back PASS "No
// Network Firewalls deployed" and a denied per-user policy lookup made the
// user look clean.
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
