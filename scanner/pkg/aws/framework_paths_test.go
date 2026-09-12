package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/guardian-nexus/AuditKit-Community-Edition/scanner/pkg/mappings"
)

// deadEndpointScanner is a scanner whose every API call fails immediately.
// Enough to drive the framework paths end to end: each suite still runs and
// still emits its rows, which is what these tests count.
func deadEndpointScanner(t *testing.T) *AWSScanner {
	t.Helper()
	cfg := aws.Config{
		Region: "us-east-1",
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIAFAKE", SecretAccessKey: "fake"}, nil
		}),
		BaseEndpoint: aws.String("http://127.0.0.1:1"),
		Retryer:      func() aws.Retryer { return aws.NopRetryer{} },
	}
	s, err := NewScannerWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rowKey(r ScanResult) string { return r.Control + "\x00" + r.Status + "\x00" + r.Evidence }

func countRows(rows []ScanResult) map[string]int {
	n := map[string]int{}
	for _, r := range rows {
		n[rowKey(r)]++
	}
	return n
}

// Each framework path used to construct some of the suites itself, run them,
// and then call runSuites, whose allSuites contains the same suites - so a
// -framework cmmc, pci or cis-aws scan ran every check twice, reported every
// row twice and counted every FAIL twice. A path may add rows of its own (the
// vulnerability coverage check, the CMMC practice fill-in) but must emit each
// suite row exactly as often as runSuites does.
func TestFrameworkPathsRunEachSuiteOnce(t *testing.T) {
	s := deadEndpointScanner(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	suite := countRows(s.runSuites(ctx, false))
	if len(suite) == 0 {
		t.Fatal("runSuites produced no rows; the paths cannot be checked against it")
	}

	paths := map[string]func(context.Context, bool) []ScanResult{
		"soc2":    s.runSOC2Checks,
		"pci":     s.runPCIChecks,
		"cmmc":    s.runCMMCChecks,
		"cis-aws": s.runCISChecks,
	}
	for name, run := range paths {
		t.Run(name, func(t *testing.T) {
			got := countRows(run(ctx, false))
			for key, want := range suite {
				if got[key] != want {
					t.Errorf("suite row %q emitted %d times, want %d", key, got[key], want)
				}
			}
		})
	}
}

// A cmmc scan reports all 110 practices, each exactly once. The fill-in has to
// run after the suites: run before them it reported a practice a suite answers
// only through a tag both as unanswered and as answered.
func TestCMMCPathReportsEveryPracticeOnce(t *testing.T) {
	s := deadEndpointScanner(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	seen := map[string]int{}
	for _, r := range s.runCMMCChecks(ctx, false) {
		if isCMMCPractice(r.Control) {
			seen[r.Control]++
		}
		for _, id := range splitCMMCTag(r.Frameworks["CMMC"]) {
			if id != r.Control {
				seen[id]++
			}
		}
	}
	for _, p := range mappings.CMMCPractices() {
		if n := seen[p.ID]; n != 1 {
			t.Errorf("%s reported %d times, want exactly once", p.ID, n)
		}
	}
	if len(seen) != mappings.CMMCPracticeCount {
		t.Errorf("%d distinct practices reported, want %d", len(seen), mappings.CMMCPracticeCount)
	}
}
