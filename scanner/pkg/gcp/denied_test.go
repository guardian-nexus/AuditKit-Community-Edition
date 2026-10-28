package gcp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sort"
	"testing"

	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/gcp/checks"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type denyAll struct{}

func (denyAll) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"error":{"code":403,"message":"denied by test","status":"PERMISSION_DENIED"}}`
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    r,
	}, nil
}

// deniedScanner returns a scanner whose every Google API call, REST or gRPC,
// is refused with PERMISSION_DENIED - a service account that may read nothing.
func deniedScanner(t *testing.T) *GCPScanner {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
		return status.Error(codes.PermissionDenied, "denied by test")
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

	checks.RESTTestOptions = []option.ClientOption{option.WithHTTPClient(&http.Client{Transport: denyAll{}})}
	checks.GRPCTestOptions = []option.ClientOption{option.WithGRPCConn(conn)}
	t.Cleanup(func() { checks.RESTTestOptions, checks.GRPCTestOptions = nil, nil })

	s, err := NewScanner("test-project")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// A check that cannot read the project has not established anything about it.
func TestDeniedAPICallsNeverProducePass(t *testing.T) {
	results := deniedScanner(t).runSuites(context.Background(), false, "test")

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
