package checks

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func TestListAllUsersReadsEveryPage(t *testing.T) {
	want := []string{"alice", "bob", "carol", "dave", "erin"}
	client := fakeIAM(t, want, nil)

	single, err := client.ListUsers(context.Background(), &iam.ListUsersInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(single.Users) >= len(want) {
		t.Fatalf("the fake must page: one call returned %d of %d users", len(single.Users), len(want))
	}

	all, err := listAllUsers(context.Background(), client, &iam.ListUsersInput{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, u := range all.Users {
		got = append(got, *u.UserName)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("listAllUsers returned %v, want %v", got, want)
	}
}

// Each of these returns one page per call. A check that calls one directly
// evaluates the first page and can pass on it, which is how a 101st IAM user
// or an 11th SSM managed instance went unexamined. Use the listAll /
// describeAll helpers in paginate.go, or page explicitly with Marker or
// NextToken as the two IAM ListPolicies loops do.
func TestPagedListCallsReadEveryPage(t *testing.T) {
	direct := regexp.MustCompile(`\.(ListUsers|ListRoles|ListFunctions|DescribeInstanceInformation|DescribeParameters|DescribeDBInstances|DescribeAlarms)\(\w+, |\.ListPolicies\(\w+, &iam\.ListPoliciesInput\{`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "paginate.go" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if direct.MatchString(line) && !strings.Contains(line, "Marker") {
				// The explicit loops set Marker on the next line.
				lines := strings.Split(string(data), "\n")
				if i+3 < len(lines) && strings.Contains(strings.Join(lines[i:i+4], " "), "Marker") {
					continue
				}
				t.Errorf("%s:%d reads one page only: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
