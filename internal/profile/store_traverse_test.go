package profile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

// Regression: Store.Load/Delete/Exists joined the caller-supplied id into a
// filesystem path without validating it against the profile id pattern —
// `jenkins-mcp profile remove ../../otherapp/config` deleted
// $XDG_CONFIG_HOME/otherapp/config.json, and Load read the file before
// validation (existence/JSON oracle). All three now reject ids that are not
// single safe file-name segments.
func TestStore_TraversalIDRejected(t *testing.T) {
	tmp := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(tmp, "cfg"),
		DataDir:   filepath.Join(tmp, "data"),
		CacheDir:  filepath.Join(tmp, "cache"),
	}
	s := profile.NewStore(paths)

	// Plant a victim file outside the profiles dir.
	victim := filepath.Join(tmp, "cfg", "victim.json")
	if err := os.MkdirAll(filepath.Dir(victim), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte(`{"id":"victim"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"../victim", "../../victim", "a/b", "..", ".", "a b", "a;b"} {
		if _, err := s.Load(id); err == nil {
			t.Errorf("Load(%q) must fail closed", id)
		}
		if err := s.Delete(id); err == nil {
			t.Errorf("Delete(%q) must fail closed", id)
		}
		// Exists must not report files outside the profiles dir.
		if s.Exists(id) {
			t.Errorf("Exists(%q) must not see files outside the profiles dir", id)
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("victim file removed: %v", err)
	}

	// A normal id still works.
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if !s.Exists("corp") {
		t.Fatal("Exists(corp) after save")
	}
	if _, err := s.Load("corp"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("corp"); err != nil {
		t.Fatal(err)
	}
	if s.Exists("corp") {
		t.Fatal("Exists(corp) after delete")
	}
}
