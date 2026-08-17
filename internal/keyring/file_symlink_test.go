package keyring_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/keyring"
)

// Regression: FileBackend.save wrote secrets to the predictable path
// <keyring>.tmp with os.WriteFile (no O_EXCL, follows symlinks). In a
// shared/writable directory (CI pattern JENKINS_MCP_KEYRING_FILE=/tmp/...),
// a pre-planted symlink redirected the full keyring write into an
// attacker-chosen file. The temp file is now created with os.CreateTemp
// (unpredictable name, O_EXCL) in the same directory before rename.
func TestFileBackend_SaveDoesNotFollowPlantedTmpSymlink(t *testing.T) {
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.json")
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plant the predictable temp path as a symlink to the victim.
	if err := os.Symlink(victim, krPath+".tmp"); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	be, err := keyring.NewFileBackend(krPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := be.Set("svc", "user", "s3cr3t"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "untouched" {
		t.Fatalf("planted symlink target overwritten with keyring data: %q", got)
	}
	// And the real keyring file holds the secret.
	val, err := be.Get("svc", "user")
	if err != nil || val != "s3cr3t" {
		t.Fatalf("Get = %q, %v", val, err)
	}
	// No leftover predictable tmp file.
	if _, err := os.Lstat(krPath + ".tmp"); err == nil {
		if data, _ := os.ReadFile(krPath + ".tmp"); strings.Contains(string(data), "s3cr3t") {
			t.Fatal("secret material left at predictable tmp path")
		}
	}
}
