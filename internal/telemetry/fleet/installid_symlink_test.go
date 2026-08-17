package fleet_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry/fleet"
)

// Regression: LoadOrCreateInstallationID wrote path+".tmp" then renamed — a
// predictable shared temp path. Two processes first-running at once could
// interleave writes (split identity), and a pre-planted symlink at the
// predictable path would be followed. The temp file is now created with
// os.CreateTemp (unpredictable, O_EXCL) in the same directory.
func TestLoadOrCreateInstallationID_IgnoresPlantedTmpSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	paths := config.Paths{DataDir: dir}
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plant the predictable temp path as a symlink to the victim.
	tmpGuess := fleet.InstallIDPath(paths) + ".tmp"
	if err := os.MkdirAll(filepath.Dir(tmpGuess), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, tmpGuess); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	id, err := fleet.LoadOrCreateInstallationID(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 {
		t.Fatalf("id %q not UUID-shaped", id)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "untouched" {
		t.Fatalf("planted symlink target overwritten: %q", got)
	}
	// Stable on second call.
	id2, err := fleet.LoadOrCreateInstallationID(paths)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id {
		t.Fatalf("id not stable: %q vs %q", id, id2)
	}
}
