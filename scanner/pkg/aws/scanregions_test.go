package aws

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// regionOf reads the signing region out of the SigV4 credential scope, which
// is how a fake behind one endpoint can tell which region a request is for.
var credScope = regexp.MustCompile(`Credential=[^/]+/\d{8}/([a-z0-9-]+)/`)

func regionOf(r *http.Request) string {
	if m := credScope.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		return m[1]
	}
	return "?"
}

// twoRegionAccount is an empty account enabled in two regions, with GuardDuty
// on in the first and off in the second. It also counts IAM ListUsers calls.
type twoRegionAccount struct {
	mu        sync.Mutex
	listUsers int
}

func (a *twoRegionAccount) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	region := regionOf(r)
	form := string(body)
	switch {
	case strings.Contains(form, "Action=DescribeRegions"):
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<DescribeRegionsResponse><regionInfo><item><regionName>eu-west-1</regionName></item><item><regionName>us-east-1</regionName></item></regionInfo></DescribeRegionsResponse>`)
	case strings.Contains(form, "Action=ListUsers"):
		a.mu.Lock()
		a.listUsers++
		a.mu.Unlock()
		r2 := r.Clone(r.Context())
		r2.Body = io.NopCloser(strings.NewReader(form))
		emptyAccount(w, r2)
	case strings.HasSuffix(r.URL.Path, "/detector") && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		if region == "us-east-1" {
			fmt.Fprint(w, `{"detectorIds":["d-1"]}`)
		} else {
			fmt.Fprint(w, `{"detectorIds":[]}`)
		}
	case strings.HasSuffix(r.URL.Path, "/detector/d-1") && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ENABLED","serviceRole":"r","findingPublishingFrequency":"SIX_HOURS"}`)
	default:
		r2 := r.Clone(r.Context())
		r2.Body = io.NopCloser(strings.NewReader(form))
		emptyAccount(w, r2)
	}
}

func TestScanRegionsRunsGlobalSuitesOnceAndMergesRegionalResults(t *testing.T) {
	fake := &twoRegionAccount{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	cfg := sdkaws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secret", ""),
		BaseEndpoint: sdkaws.String(srv.URL),
		Retryer:      func() sdkaws.Retryer { return sdkaws.NopRetryer{} },
	}
	ctx := context.Background()

	regions, err := ResolveRegions(ctx, cfg, "all")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(regions, ",") != "us-east-1,eu-west-1" {
		t.Fatalf("configured region must come first: %v", regions)
	}

	// Baseline: how many ListUsers calls one region makes.
	single, err := NewScannerWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := single.ScanServices(ctx, nil, false, "soc2"); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	perRegionCalls := fake.listUsers
	fake.listUsers = 0
	fake.mu.Unlock()

	rows, scanned, err := ScanRegions(ctx, cfg, regions, nil, false, "soc2")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(scanned, ",") != "us-east-1,eu-west-1" {
		t.Fatalf("scanned = %v", scanned)
	}
	fake.mu.Lock()
	multiCalls := fake.listUsers
	fake.mu.Unlock()
	// The IAM suites run once; the mixed SOC2/PCI/CMMC suites that also read
	// IAM run per region, so the count rises but must stay well under double.
	if multiCalls >= 2*perRegionCalls {
		t.Errorf("IAM was listed %d times across two regions against %d for one: the global suites ran in every region", multiCalls, perRegionCalls)
	}

	var gd []ScanResult
	for _, r := range rows {
		if strings.Contains(r.Evidence, "GuardDuty NOT enabled") {
			gd = append(gd, r)
		}
	}
	if len(gd) == 0 {
		t.Fatal("no GuardDuty row reports it off in eu-west-1")
	}
	for _, r := range gd {
		if r.Status != "FAIL" || !strings.Contains(r.Evidence, "FAIL in eu-west-1") || !strings.Contains(r.Evidence, "us-east-1") {
			t.Errorf("GuardDuty off in one region must be a FAIL naming both regions: %s %q", r.Status, r.Evidence)
		}
	}
}
