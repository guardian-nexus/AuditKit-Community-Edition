package aws

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// emptyAccount answers every AWS call with a well-formed empty result: an
// account the scanner may read that holds nothing. AWS services speak several
// wire protocols, so the shape depends on the request.
func emptyAccount(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ct := r.Header.Get("Content-Type")
	ua := r.Header.Get("User-Agent") // carries "api/<service>#<version>"
	restXML := strings.Contains(ua, "api/s3#") || strings.Contains(ua, "api/s3control#") ||
		strings.Contains(ua, "api/route53#") || strings.Contains(ua, "api/cloudfront#")
	switch {
	case strings.Contains(r.URL.Path, "/publicAccessBlock"):
		// S3 Control: no account-level block is an error, not an empty one.
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchPublicAccessBlockConfiguration</Code><Message>none</Message><RequestId>r</RequestId></Error>`)
	case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeOrganization"):
		// An account outside any organization gets this, not an empty organization.
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"__type":"AWSOrganizationsNotInUseException","Message":"not in use"}`)
	case strings.Contains(ct, "x-www-form-urlencoded"):
		// Query protocol (IAM, STS, CloudWatch, SNS, RDS, Auto Scaling, ...):
		// <ActionResponse><ActionResult/></ActionResponse>.
		action := ""
		for _, kv := range strings.Split(string(body), "&") {
			if strings.HasPrefix(kv, "Action=") {
				action = strings.TrimPrefix(kv, "Action=")
			}
		}
		w.Header().Set("Content-Type", "text/xml")
		if action == "GetCallerIdentity" {
			fmt.Fprint(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>AIDATEST</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
			return
		}
		if action == "GetAccountPasswordPolicy" {
			// The real answer when no policy exists is an error, not an empty policy.
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>no policy</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
			return
		}
		fmt.Fprintf(w, `<%sResponse><%sResult></%sResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></%sResponse>`, action, action, action, action)
	case !restXML:
		// JSON protocols (most services) and REST-JSON, whose GETs carry no
		// Content-Type or X-Amz-Target at all.
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		fmt.Fprint(w, `{}`)
	default:
		// REST-XML (S3, Route 53, CloudFront): an empty document.
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<Empty xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></Empty>`)
	}
}

func emptyScanner(t *testing.T) *AWSScanner {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(emptyAccount))
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

// TestEmptyAccountIsReadable checks the fake itself: an empty account must not
// look like a denied one, or the comparison below proves nothing.
func TestEmptyAccountIsReadable(t *testing.T) {
	results := emptyScanner(t).runSuites(context.Background(), false)
	errored := 0
	for _, r := range results {
		if r.Status == "ERROR" {
			errored++
		}
	}
	if errored > len(results)/4 {
		t.Fatalf("%d of %d results are ERROR against the empty account; the fake is answering with something the SDK rejects", errored, len(results))
	}
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
