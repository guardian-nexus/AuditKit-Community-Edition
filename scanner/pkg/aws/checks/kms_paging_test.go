package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// fakeKMS answers ListKeys two keys per page, so a caller that reads one page
// sees two of them and a caller that stops early sees fewer than all.
func fakeKMS(t *testing.T, keyIDs []string) *kms.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if r.Header.Get("X-Amz-Target") != "TrentService.ListKeys" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"__type":"AccessDeniedException","message":"denied by test"}`)
			return
		}
		var in struct{ Marker string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		start := 0
		if in.Marker != "" {
			_, _ = fmt.Sscanf(in.Marker, "page-%d", &start)
		}
		end := start + 2
		if end > len(keyIDs) {
			end = len(keyIDs)
		}
		var keys []map[string]string
		for _, id := range keyIDs[start:end] {
			keys = append(keys, map[string]string{"KeyId": id, "KeyArn": "arn:aws:kms:us-east-1:123456789012:key/" + id})
		}
		out := map[string]any{"Keys": keys, "Truncated": end < len(keyIDs)}
		if end < len(keyIDs) {
			out["NextMarker"] = fmt.Sprintf("page-%d", end)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return kms.NewFromConfig(aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secret", ""),
		BaseEndpoint: aws.String(srv.URL),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	})
}

// The key-rotation check used to stop after maxKeyPages pages and judge the
// account on what it had seen. listAllKeys has no ceiling; every key comes
// back, however many pages that takes.
func TestListAllKeysReadsEveryPage(t *testing.T) {
	var want []string
	for i := 0; i < 7; i++ {
		want = append(want, fmt.Sprintf("key-%d", i))
	}
	client := fakeKMS(t, want)

	single, err := client.ListKeys(context.Background(), &kms.ListKeysInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(single.Keys) >= len(want) {
		t.Fatalf("the fake must page: one call returned %d of %d keys", len(single.Keys), len(want))
	}

	all, err := listAllKeys(context.Background(), client, &kms.ListKeysInput{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, k := range all.Keys {
		got = append(got, aws.ToString(k.KeyId))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("listAllKeys returned %v, want %v", got, want)
	}
}
