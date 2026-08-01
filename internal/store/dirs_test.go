package store_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func TestEnsureDir_Creates0700(t *testing.T) {
	root := t.TempDir()
	// Ensure parent is usable; create nested under temp.
	dir := filepath.Join(root, "jenkins-mcp", "profiles", "corp")
	if err := store.EnsureDir(dir); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatal("expected directory")
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("mode: got %04o want 0700", perm)
	}
	if err := store.ValidateDir(dir); err != nil {
		t.Fatalf("ValidateDir after EnsureDir: %v", err)
	}
}

func TestValidateDir_RejectsWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows out of scope")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "open")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	// Force world-writable (umask may have cleared bits).
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	err := store.ValidateDir(dir)
	if err == nil {
		t.Fatal("expected error for world-writable dir")
	}
	if !apperr.IsCode(err, apperr.CodeCorruptCache) {
		t.Fatalf("code: got %s want %s (%v)", apperr.CodeOf(err), apperr.CodeCorruptCache, err)
	}
}

func TestValidateDir_RejectsGroupWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows out of scope")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "groupw")
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateDir(dir); err == nil {
		t.Fatal("expected error for group-writable dir")
	}
}

func TestValidateDir_RejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows out of scope")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := store.ValidateDir(link); err == nil {
		t.Fatal("expected error for symlink data path")
	}
}

func TestValidateDir_RejectsFile(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "notadir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateDir(f); err == nil {
		t.Fatal("expected error for file path")
	}
}

func TestEnsureDir_RejectsRelative(t *testing.T) {
	if err := store.EnsureDir("relative/path"); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestEnsureDir_RejectsEmpty(t *testing.T) {
	if err := store.EnsureDir(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestEnsureProfileDataDir_UsesXDGLayout(t *testing.T) {
	root := t.TempDir()
	// Simulate config.Paths.ProfileDataDir("corp").
	paths := config.Paths{
		DataDir: filepath.Join(root, "share", "jenkins-mcp"),
	}
	// Ensure parents so ProfileDataDir is absolute under temp.
	dataRoot := paths.ProfileDataDir("corp")
	got, err := store.EnsureProfileDataDir(dataRoot, "corp")
	if err != nil {
		t.Fatalf("EnsureProfileDataDir: %v", err)
	}
	if got != dataRoot {
		t.Fatalf("path: got %q want %q", got, dataRoot)
	}
	fi, err := os.Lstat(got)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %04o", fi.Mode().Perm())
	}
}

func TestEnsureProfileDataDir_JoinsUnderAppData(t *testing.T) {
	root := t.TempDir()
	appData := filepath.Join(root, "jenkins-mcp")
	got, err := store.EnsureProfileDataDir(appData, "corp")
	if err != nil {
		t.Fatalf("EnsureProfileDataDir: %v", err)
	}
	want := filepath.Join(appData, "corp")
	if got != want {
		t.Fatalf("path: got %q want %q", got, want)
	}
}

func TestEnsureProfileDataDir_RejectsTraversal(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"../escape", "a/b", "..", "."} {
		if _, err := store.EnsureProfileDataDir(root, id); err == nil {
			t.Fatalf("expected error for profile id %q", id)
		}
	}
}

func TestEnsureDir_TightensLooseMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows out of scope")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "loose")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureDir(dir); err != nil {
		t.Fatalf("EnsureDir should tighten mode: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode after EnsureDir: %04o", fi.Mode().Perm())
	}
}
