package gcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/gcp/checks"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// emptyAll answers every REST request 200 with an empty object: a project the
// scanner may read that holds nothing.
type emptyAll struct{}

func (emptyAll) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString("{}")),
		Request:    r,
	}, nil
}

// emptyScanner routes every Google call to a server that answers with an empty
// message. A zero-length protobuf body decodes as the zero value of any
// response type, so every list comes back empty.
func emptyScanner(t *testing.T) *GCPScanner {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		return stream.SendMsg(&emptypb.Empty{})
	}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	checks.RESTTestOptions = []option.ClientOption{option.WithHTTPClient(&http.Client{Transport: emptyAll{}})}
	checks.GRPCTestOptions = []option.ClientOption{option.WithGRPCConn(conn)}
	t.Cleanup(func() { checks.RESTTestOptions, checks.GRPCTestOptions = nil, nil })

	s, err := NewScanner("test-project")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
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
	denied := deniedScanner(t).runSuites(context.Background(), false, "test")
	empty := emptyScanner(t).runSuites(context.Background(), false, "test")
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
