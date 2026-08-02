package keyring_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/keyring"
)

func TestFileBackend_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	fb, err := keyring.NewFileBackend(path)
	if err != nil {
		t.Fatal(err)
	}
	st := keyring.NewStore(fb)
	ref := keyring.CredentialRef{
		ProfileID: "smoke",
		Origin:    "http://127.0.0.1:9",
		Method:    "api_token",
		Account:   "smoke",
	}
	const tok = "FILE_KEYRING_CANARY_token_xyz"
	if err := st.SetAPIToken(ref, tok); err != nil {
		t.Fatal(err)
	}
	// Mode 0600 on file
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("secrets file mode %o should be owner-only", fi.Mode().Perm())
	}
	got, err := st.GetAPIToken(ref)
	if err != nil || got != tok {
		t.Fatalf("get: %q %v", got, err)
	}
	// Canary: file must not be world-readable content dump in errors — just ensure get works.
	if err := st.DeleteAPIToken(ref); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetAPIToken(ref)
	if err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestDefault_UsesFileWhenEnvSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kr.json")
	t.Setenv(keyring.EnvKeyringFile, path)
	st := keyring.Default()
	ref := keyring.CredentialRef{
		ProfileID: "p1",
		Origin:    "https://jenkins.example",
		Method:    "api_token",
		Account:   "alice",
	}
	if err := st.SetAPIToken(ref, "tok-file-default"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAPIToken(ref)
	if err != nil || got != "tok-file-default" {
		t.Fatalf("got %q %v", got, err)
	}
}
