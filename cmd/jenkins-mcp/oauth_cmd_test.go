package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

func TestOAuthValidateProfile_FlagsAndOffline(t *testing.T) {
	// Needs writable XDG dirs for profile store.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	t.Setenv("HOME", tmp)

	err := runOAuthValidateProfile([]string{"--offline"})
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("expected --profile required: %v", err)
	}

	// Missing profile id on disk.
	err = runOAuthValidateProfile([]string{"--profile", "missing", "--offline"})
	if err == nil {
		t.Fatal("expected not found")
	}

	// Save oidc profile and validate offline.
	store, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "oidc-corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://login.example.com/t/v2.0",
			ClientID:        "public-cid",
			JenkinsAudience: "api://jenkins-api",
			Scopes:          []string{"openid"},
		},
	}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}

	err = runOAuthValidateProfile([]string{"--profile", "oidc-corp", "--offline"})
	if err != nil {
		t.Fatal(err)
	}

	// api_token profile must fail oauth validate-profile.
	p2 := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "token-corp",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := store.Save(p2); err != nil {
		t.Fatal(err)
	}
	err = runOAuthValidateProfile([]string{"--profile", "token-corp", "--offline"})
	if err == nil {
		t.Fatal("api_token profile should fail oauth validate")
	}

	err = runOAuth([]string{"nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown subcommand: %v", err)
	}
}

func TestOAuthProbeRS_Offline(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	t.Setenv("HOME", tmp)

	if err := runOAuthProbeRS([]string{"--offline"}); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("profile required: %v", err)
	}

	store, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "oidc-rs",
		JenkinsURL:    "https://jenkins.example.com",
		AuthMethod:    profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://login.example.com/t/v2.0",
			ClientID:        "public-cid",
			JenkinsAudience: "api://jenkins-api",
			Scopes:          []string{"openid"},
		},
	}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}

	// Capture stdout for secret-free matrix.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = runOAuthProbeRS([]string{"--profile", "oidc-rs", "--offline"})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, s := range []string{
		"fallthrough_must_deny", "progressive_text", "outside", "residual", "oic-auth",
		// Wave 33 offline matrix expansions (secret-free).
		"classifier", "Done*", "401_empty_bearer_www", "html_error", "live jwt-auth-filter",
		"classifier_fixtures",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("probe-rs output missing %q\n%s", s, out)
		}
	}
	// Canary: never leak probe bearer material.
	if strings.Contains(out, "oauth-009-invalid-bearer") || strings.Contains(out, "password=") {
		t.Fatal("probe-rs offline output looks secret-bearing")
	}
}

func TestOAuthSubcommandRequired(t *testing.T) {
	t.Parallel()
	err := runOAuth(nil)
	if err == nil {
		t.Fatal("expected error")
	}
}
