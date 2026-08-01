package profile_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

func testStore(t *testing.T) *profile.Store {
	t.Helper()
	root := t.TempDir()
	return profile.NewStore(config.Paths{
		ConfigDir: filepath.Join(root, "config"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	})
}

func TestStoreSaveLoadListDelete(t *testing.T) {
	s := testStore(t)
	p := &profile.Profile{
		ID:          "corp",
		DisplayName: "Corporate",
		JenkinsURL:  "https://jenkins.example.com",
		AuthMethod:  profile.AuthMethodAPIToken,
		Username:    "alice",
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	// File mode should be restrictive.
	path := s.Paths.ProfileFile("corp")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("profile file should not be group/world accessible: %v", st.Mode())
	}

	loaded, err := s.Load("corp")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DisplayName != "Corporate" || loaded.Username != "alice" {
		t.Fatalf("%+v", loaded)
	}
	if loaded.ConfigVersion != profile.CurrentConfigVersion {
		t.Fatalf("version %d", loaded.ConfigVersion)
	}

	ids, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "corp" {
		t.Fatalf("list: %v", ids)
	}

	if err := s.Delete("corp"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("corp"); err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		t.Fatalf("expected not_found, got %v", err)
	}
}

func TestStoreMigratesLegacyFile(t *testing.T) {
	s := testStore(t)
	// Write a pre-versioned document (no configVersion, no authMethod).
	dir := s.Paths.ProfilesDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"id":"legacy","jenkinsURL":"https://jenkins.example.com"}` + "\n")
	if err := os.WriteFile(s.Paths.ProfileFile("legacy"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := s.Load("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigVersion != profile.CurrentConfigVersion {
		t.Fatalf("migrated version: %d", p.ConfigVersion)
	}
	if p.AuthMethod != profile.AuthMethodAPIToken {
		t.Fatalf("migrated method: %q", p.AuthMethod)
	}
}

func TestStoreRejectsSecretFields(t *testing.T) {
	s := testStore(t)
	dir := s.Paths.ProfilesDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Document with forbidden secret key.
	bad := map[string]any{
		"configVersion": 1,
		"id":            "bad",
		"jenkinsURL":    "https://jenkins.example.com",
		"authMethod":    "api_token",
		"token":         "super-secret-token-value",
	}
	data, _ := json.Marshal(bad)
	if err := os.WriteFile(s.Paths.ProfileFile("bad"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Load("bad")
	if err == nil {
		t.Fatal("expected reject secret field")
	}
	if strings.Contains(err.Error(), "super-secret-token-value") {
		t.Fatalf("error must not include secret: %v", err)
	}
}

// Regression: nested client_secret under oidc must be rejected (OAUTH-001).
func TestStoreRejectsNestedClientSecret(t *testing.T) {
	s := testStore(t)
	dir := s.Paths.ProfilesDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{
		"configVersion": 1,
		"id":            "bad-oidc",
		"jenkinsURL":    "https://jenkins.example.com",
		"authMethod":    "oidc_bearer",
		"oidc": map[string]any{
			"issuer":          "https://idp.example.com",
			"clientId":        "public",
			"jenkinsAudience": "api://j",
			"clientSecret":    "NESTED_CLIENT_SECRET_MUST_NOT_PERSIST",
		},
	}
	data, _ := json.Marshal(bad)
	if err := os.WriteFile(s.Paths.ProfileFile("bad-oidc"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Load("bad-oidc")
	if err == nil {
		t.Fatal("expected reject nested client_secret")
	}
	if strings.Contains(err.Error(), "NESTED_CLIENT_SECRET") {
		t.Fatalf("error must not include secret: %v", err)
	}
}

func TestStoreOIDCRoundTrip(t *testing.T) {
	s := testStore(t)
	p := &profile.Profile{
		ID:         "oidc1",
		JenkinsURL: "https://jenkins.example.com",
		AuthMethod: profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://login.example.com/tenant/v2.0",
			ClientID:        "public-client",
			JenkinsAudience: "api://jenkins-api",
			Scopes:          []string{"openid"},
			RedirectURIs:    []string{"http://127.0.0.1:8765/callback"},
			TenantID:        "tenant-guid",
		},
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load("oidc1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.OIDC == nil || loaded.OIDC.ClientID != "public-client" {
		t.Fatalf("%+v", loaded.OIDC)
	}
	if loaded.OIDC.JenkinsAudience != "api://jenkins-api" {
		t.Fatalf("audience: %q", loaded.OIDC.JenkinsAudience)
	}
	// Ensure on-disk JSON has no clientSecret key.
	raw, err := os.ReadFile(s.Paths.ProfileFile("oidc1"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "secret") {
		t.Fatalf("profile file must not mention secret: %s", raw)
	}
}

func TestStoreRejectsInvalidURL(t *testing.T) {
	s := testStore(t)
	err := s.Save(&profile.Profile{
		ID:         "x",
		JenkinsURL: "not-a-url",
		AuthMethod: profile.AuthMethodAPIToken,
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDuplicateSaveOverwrites(t *testing.T) {
	s := testStore(t)
	p := &profile.Profile{
		ID:         "corp",
		JenkinsURL: "https://jenkins.example.com",
		AuthMethod: profile.AuthMethodAPIToken,
	}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	p.DisplayName = "Updated"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load("corp")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DisplayName != "Updated" {
		t.Fatalf("%q", loaded.DisplayName)
	}
}
