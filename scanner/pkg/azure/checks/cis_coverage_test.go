package checks

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The CIS Azure suites written for Foundations v6.0.0. Each owns a disjoint set
// of recommendations; the older suites predate the migration and legitimately
// emit several results for one recommendation, which is why they are not here.
func cisV6Suites() []Check {
	return []Check{
		NewCISFoundationsManualChecks(),
		NewCISStorageChecks(nil, nil, nil),
		NewCISActivityAlertChecks(nil, nil, "sub-1"),
		NewCISIdentityDefenderChecks(nil, nil, nil, nil, nil, "sub-1"),
		NewCISNetworkChecks(nil, nil, nil, nil, nil, nil, nil),
		NewCISKeyVaultChecks(nil, nil, nil),
		NewCISDatabricksChecks(nil, nil, nil),
	}
}

// No two of these suites may claim the same recommendation. Two results for one
// identifier is the report disagreeing with itself, and it is how a superseded
// manual stand-in survived alongside the automated check that replaced it.
func TestCISV6SuitesClaimDisjointRecommendations(t *testing.T) {
	owner := map[string]string{}
	for _, suite := range cisV6Suites() {
		results, err := suite.Run(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", suite.Name(), err)
		}
		seen := map[string]bool{}
		for _, r := range results {
			id := strings.TrimPrefix(r.Control, "CIS-")
			if id == r.Control {
				continue // not a CIS identifier
			}
			if seen[id] {
				t.Errorf("%s emits %s more than once", suite.Name(), r.Control)
			}
			seen[id] = true
			if prev, ok := owner[id]; ok {
				t.Errorf("%s is claimed by both %s and %s", r.Control, prev, suite.Name())
			}
			owner[id] = suite.Name()
		}
	}
}

// Nothing these suites report may be scored from data they never read. With no
// clients every result must be ERROR - the API was unreachable - or MANUAL,
// for the settings this API does not expose at all.
func TestCISV6SuitesScoreNothingWithoutClients(t *testing.T) {
	for _, suite := range cisV6Suites() {
		results, err := suite.Run(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", suite.Name(), err)
		}
		for _, r := range results {
			switch r.Status {
			case StatusError, StatusManual:
			default:
				t.Errorf("%s: %s reported %s with no client; only ERROR or MANUAL is honest here",
					suite.Name(), r.Control, r.Status)
			}
		}
	}
}

// Every recommendation in the benchmark catalog must be claimed by something in
// this package. cis-gaps.py asserts the same thing over the source; this
// asserts it over what the suites actually emit plus the identifiers the older
// files carry, so a suite that stops being registered is caught here too.
func TestEveryV6RecommendationIsClaimed(t *testing.T) {
	raw, err := os.ReadFile("../../mappings/catalogs/cis-azure.json")
	if err != nil {
		t.Skipf("no catalog to compare against: %v", err)
	}
	var doc struct {
		Recommendations map[string]string `json:"recommendations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("catalog is not readable: %v", err)
	}

	claimed := map[string]bool{}
	for _, suite := range cisV6Suites() {
		results, err := suite.Run(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", suite.Name(), err)
		}
		for _, r := range results {
			if id := strings.TrimPrefix(r.Control, "CIS-"); id != r.Control {
				claimed[id] = true
			}
			for _, part := range strings.Split(r.Frameworks["CIS-Azure"], ",") {
				if p := strings.TrimSpace(part); p != "" {
					claimed[p] = true
				}
			}
		}
	}
	// The recommendations answered by checks written before the migration are
	// claimed in files these suites do not cover, so read those identifiers
	// from the source the same way the guard does.
	claimed = addSourceClaims(t, claimed)

	var missing []string
	for id := range doc.Recommendations {
		if !claimed[id] {
			missing = append(missing, id)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return versionLess(missing[i], missing[j]) })
	if len(missing) > 0 {
		t.Errorf("%d of %d recommendation(s) in %s are claimed by nothing: %v",
			len(missing), len(doc.Recommendations), "cis-azure.json", missing)
	}
}

var cisIDPattern = regexp.MustCompile(`"CIS-([0-9][0-9.]*)"`)
var cisTagPattern = regexp.MustCompile(`"CIS-Azure":\s*"([^"]+)"`)
var cisTablePattern = regexp.MustCompile(`FrameworkCIS\w*:\s*"([^"]+)"`)

// addSourceClaims reads the three routes a claim reaches a report by, which is
// the same set cis-gaps.py counts. Counting only the Control: position
// under-reported Azure by four and hid a whole table of superseded numbers.
func addSourceClaims(t *testing.T, claimed map[string]bool) map[string]bool {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("cannot read the checks directory: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		for _, m := range cisIDPattern.FindAllStringSubmatch(string(src), -1) {
			claimed[m[1]] = true
		}
		for _, pattern := range []*regexp.Regexp{cisTagPattern, cisTablePattern} {
			for _, m := range pattern.FindAllStringSubmatch(string(src), -1) {
				for _, part := range strings.Split(m[1], ",") {
					if p := strings.TrimSpace(part); p != "" {
						claimed[p] = true
					}
				}
			}
		}
	}
	return claimed
}

func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, _ := strconv.Atoi(as[i])
		bi, _ := strconv.Atoi(bs[i])
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}
