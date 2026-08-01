package config_test

import (
	"path/filepath"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/config"
)

func TestResolveXDG(t *testing.T) {
	t.Setenv("HOME", "/tmp/jenkins-mcp-home")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-config")
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg-data")
	t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-cache")

	p, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigDir != filepath.Join("/tmp/xdg-config", "jenkins-mcp") {
		t.Fatalf("ConfigDir: got %q", p.ConfigDir)
	}
	if p.DataDir != filepath.Join("/tmp/xdg-data", "jenkins-mcp") {
		t.Fatalf("DataDir: got %q", p.DataDir)
	}
	if p.CacheDir != filepath.Join("/tmp/xdg-cache", "jenkins-mcp") {
		t.Fatalf("CacheDir: got %q", p.CacheDir)
	}
	if p.ProfilesDir() != filepath.Join(p.ConfigDir, "profiles") {
		t.Fatalf("ProfilesDir: got %q", p.ProfilesDir())
	}
	if p.ProfileFile("corp") != filepath.Join(p.ProfilesDir(), "corp.json") {
		t.Fatalf("ProfileFile: got %q", p.ProfileFile("corp"))
	}
	if p.ProfileDataDir("corp") != filepath.Join(p.DataDir, "profiles", "corp") {
		t.Fatalf("ProfileDataDir: got %q", p.ProfileDataDir("corp"))
	}
	if p.PolicyDir() != filepath.Join(p.ConfigDir, "policy") {
		t.Fatalf("PolicyDir: got %q", p.PolicyDir())
	}
	if p.DefaultPolicyFile() != filepath.Join(p.PolicyDir(), "overlay.json") {
		t.Fatalf("DefaultPolicyFile: got %q", p.DefaultPolicyFile())
	}
	if p.DefaultPolicyBundleFile() != filepath.Join(p.PolicyDir(), "overlay.bundle.json") {
		t.Fatalf("DefaultPolicyBundleFile: got %q", p.DefaultPolicyBundleFile())
	}
	if p.TrustedKeysDir() != filepath.Join(p.PolicyDir(), "trusted_keys") {
		t.Fatalf("TrustedKeysDir: got %q", p.TrustedKeysDir())
	}
	if p.PolicyLastGoodFile() != filepath.Join(p.CacheDir, "policy", "last_good.json") {
		t.Fatalf("PolicyLastGoodFile: got %q", p.PolicyLastGoodFile())
	}
	if p.UpdateDir() != filepath.Join(p.ConfigDir, "update") {
		t.Fatalf("UpdateDir: got %q", p.UpdateDir())
	}
	if p.UpdateTrustedKeysDir() != filepath.Join(p.UpdateDir(), "trusted_keys") {
		t.Fatalf("UpdateTrustedKeysDir: got %q", p.UpdateTrustedKeysDir())
	}
	if p.UpdateDataDir() != filepath.Join(p.DataDir, "update") {
		t.Fatalf("UpdateDataDir: got %q", p.UpdateDataDir())
	}
	if p.UpdateLKGFile() != filepath.Join(p.UpdateDataDir(), "last_known_good.json") {
		t.Fatalf("UpdateLKGFile: got %q", p.UpdateLKGFile())
	}
}

func TestResolveDefaultsUnderHome(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	// Clear may not unset; force empty via Setenv to empty is fine for os.Getenv.

	p, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigDir != "/home/alice/.config/jenkins-mcp" {
		t.Fatalf("default ConfigDir: %q", p.ConfigDir)
	}
	if p.DataDir != "/home/alice/.local/share/jenkins-mcp" {
		t.Fatalf("default DataDir: %q", p.DataDir)
	}
	if p.CacheDir != "/home/alice/.cache/jenkins-mcp" {
		t.Fatalf("default CacheDir: %q", p.CacheDir)
	}
}
