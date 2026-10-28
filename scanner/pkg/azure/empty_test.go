package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/azure/checks"
)

// emptyAll answers every request 200 with an empty list: a subscription the
// scanner may read that holds nothing.
type emptyAll struct{}

func (emptyAll) Do(r *http.Request) (*http.Response, error) { return emptyAll{}.RoundTrip(r) }

func (emptyAll) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"value":[]}`)),
		Request:    r,
	}, nil
}

func emptyScanner(t *testing.T) *AzureScanner {
	t.Helper()
	s := deniedScanner(t)
	checks.TestARMOptions = &arm.ClientOptions{ClientOptions: policy.ClientOptions{Transport: emptyAll{}, Retry: policy.RetryOptions{MaxRetries: -1}}}
	checks.TestGraphHTTPClient = &http.Client{Transport: emptyAll{}}
	s2, err := NewScanner(s.subscriptionID)
	if err != nil {
		t.Fatal(err)
	}
	return s2
}

// absenceClaim matches evidence that asserts something about the account - that
// nothing was found, configured or enabled. Under a denied call the scanner did
// not look, so it cannot say that.
var absenceClaim = regexp.MustCompile(`(?i)\b(no|none|zero|0)\b[^.|]{0,60}\b(found|configured|exists?|detected|enabled|deployed|defined|assigned)\b|not found|unable to`)

// TestDeniedDiffersFromEmpty runs every check twice: against an account where
// every call is refused, and against one the scanner may read that holds
// nothing. A check that gives the same answer in both cannot tell "I could not
// look" from "there is nothing here". Under denial every result must be ERROR
// or MANUAL, or an INFO that is fixed guidance - identical in the empty run
// and making no claim about the account. PASS and FAIL both need data.
func TestDeniedDiffersFromEmpty(t *testing.T) {
	denied := deniedScanner(t).runSuites(context.Background(), false)
	empty := emptyScanner(t).runSuites(context.Background(), false)
	inEmpty := map[string]bool{}
	for _, r := range empty {
		inEmpty[r.Control+"\x00"+r.Status+"\x00"+r.Evidence] = true
	}
	var bad []string
	for _, r := range denied {
		switch r.Status {
		case "ERROR", "MANUAL":
			continue
		case "INFO":
			if inEmpty[r.Control+"\x00"+r.Status+"\x00"+r.Evidence] && !absenceClaim.MatchString(r.Evidence) {
				continue
			}
		}
		bad = append(bad, fmt.Sprintf("%s %s: %.140s", r.Status, r.Control, r.Evidence))
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("with every call denied: %s", b)
	}
}
