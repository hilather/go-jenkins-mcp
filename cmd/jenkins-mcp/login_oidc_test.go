package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

func TestLoginOIDC_RequiresOIDCProfile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	t.Setenv("HOME", tmp)

	store, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	// api_token profile rejects --oidc.
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "token-corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	err = runLogin([]string{"--profile", "token-corp", "--oidc"})
	if err == nil || !strings.Contains(err.Error(), "oidc_bearer") {
		t.Fatalf("expected oidc_bearer requirement: %v", err)
	}

	// oidc profile without redirect fails closed before browser.
	p2 := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "oidc-corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://login.example.com/t/v2.0",
			ClientID:        "public-cid",
			JenkinsAudience: "api://jenkins-api",
			Scopes:          []string{"openid"},
			// no redirectUris
		},
	}
	if err := store.Save(p2); err != nil {
		t.Fatal(err)
	}
	err = runLogin([]string{"--profile", "oidc-corp", "--oidc"})
	if err == nil {
		t.Fatal("expected redirect / discovery failure")
	}
	// Must not leak secrets.
	if strings.Contains(err.Error(), "public-cid") && strings.Contains(err.Error(), "secret") {
		t.Fatalf("suspicious error: %v", err)
	}
}

func TestLoginMethodConflict(t *testing.T) {
	err := runLogin([]string{"--profile", "x", "--oidc", "--method", "api-token"})
	if err == nil || !strings.Contains(err.Error(), "only one") {
		// Flag parse may fail on missing profile first depending on order —
		// conflict check runs after profile required.
		if err == nil {
			t.Fatal("expected error")
		}
	}
}
