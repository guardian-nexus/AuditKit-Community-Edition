package offline

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sample() CachedScan {
	return CachedScan{
		Timestamp: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), Provider: "aws", Framework: "soc2", AccountID: "111122223333",
		Score: 50, TotalControls: 2, PassedControls: 1, FailedControls: 1,
		Controls: []CachedControl{{ID: "CC6.1", Status: "FAIL", Evidence: "3 buckets public"}, {ID: "CC6.2", Status: "PASS"}},
	}
}

func newTestCache(t *testing.T) *Cache {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	c, err := NewCache()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A cache file is plain JSON the offline report trusts as a past scan. An
// edited one used to be indistinguishable from the original.
func TestEditedCacheIsNotVerified(t *testing.T) {
	c := newTestCache(t)
	if err := c.Save(sample()); err != nil {
		t.Fatal(err)
	}
	got, err := c.LoadLatest("aws", "111122223333", "soc2")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified() || got.IntegrityNote() != "" {
		t.Fatalf("a record this machine just wrote must verify: %q", got.Integrity)
	}

	path := filepath.Join(c.basePath, c.getLatestFilename("aws", "111122223333", "soc2"))
	data, _ := os.ReadFile(path)
	edited := strings.Replace(string(data), `"status": "FAIL"`, `"status": "PASS"`, 1)
	if edited == string(data) {
		t.Fatal("test did not edit anything")
	}
	if err := os.WriteFile(path, []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = c.LoadLatest("aws", "111122223333", "soc2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Integrity != IntegrityNotVerified || !strings.Contains(got.IntegrityNote(), "FAILED") {
		t.Fatalf("a FAIL rewritten to PASS must not verify: %q", got.Integrity)
	}
}

func TestCacheFromAnotherMachineIsNotVerified(t *testing.T) {
	c := newTestCache(t)
	if err := c.Save(sample()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.basePath, c.getLatestFilename("aws", "111122223333", "soc2"))

	other := newTestCache(t) // a different HOME, so a different key
	got, err := other.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Integrity != IntegrityNotVerified {
		t.Fatalf("a file signed with another machine's key must not verify: %q", got.Integrity)
	}
}

func TestUnsignedCacheIsLoadedAndMarked(t *testing.T) {
	c := newTestCache(t)
	path := filepath.Join(c.basePath, "old.json")
	if err := os.WriteFile(path, []byte(`{"timestamp":"2026-01-01T00:00:00Z","provider":"aws","framework":"soc2","account_id":"1","controls":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := c.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Integrity != IntegrityUnsigned || !strings.Contains(got.IntegrityNote(), "unsigned") {
		t.Fatalf("a pre-signing file must load and be marked unsigned: %q", got.Integrity)
	}
}

func TestCacheFilesAndKeyArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	c := newTestCache(t)
	if err := c.Save(sample()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(c.basePath, c.getLatestFilename("aws", "111122223333", "soc2")),
		filepath.Join(filepath.Dir(c.basePath), "cache.key"),
	} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %04o, want 0600", filepath.Base(p), info.Mode().Perm())
		}
	}
}
