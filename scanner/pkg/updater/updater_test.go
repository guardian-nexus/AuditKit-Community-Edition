package updater

import "testing"

// A plain string compare said v0.9.0 > v0.10.0, so the update check would have
// gone quiet for good at the first double-digit minor.
func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.10.0", "v0.9.0", true},
		{"v0.9.0", "v0.10.0", false},
		{"v0.8.7", "v0.8.6", true},
		{"v0.8.6", "v0.8.6", false},
		{"v1.0.0", "v0.99.99", true},
		{"v0.8.7", "dev", true},
	}
	for _, c := range cases {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
