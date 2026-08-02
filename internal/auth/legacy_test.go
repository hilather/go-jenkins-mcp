package auth_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

func TestRejectLegacyBootstrap_Flag(t *testing.T) {
	t.Setenv(auth.LegacyEnvVar, "")
	err := auth.RejectLegacyBootstrap("user:token")
	if err == nil {
		t.Fatal("expected reject for -auth flag")
	}
	msg := err.Error()
	if !strings.Contains(msg, "removed") && !strings.Contains(msg, "login --profile") {
		t.Fatalf("migration message missing: %q", msg)
	}
	// Canary: secret material from flag must not be echoed.
	if strings.Contains(msg, "user:token") || strings.Contains(msg, "token") {
		// "token" may appear in "api token" guidance — ensure raw user:token pair absent
		if strings.Contains(msg, "user:token") {
			t.Fatalf("must not echo flag value: %q", msg)
		}
	}
}

func TestRejectLegacyBootstrap_Env(t *testing.T) {
	t.Setenv(auth.LegacyEnvVar, "alice:CANARY_legacy_env_secret_xyz")
	err := auth.RejectLegacyBootstrap("")
	if err == nil {
		t.Fatal("expected reject for JENKINS_MCP_AUTH")
	}
	if strings.Contains(err.Error(), "CANARY_legacy_env_secret_xyz") {
		t.Fatalf("must not echo env secret: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "login --profile") {
		t.Fatalf("want migration hint: %q", err.Error())
	}
}

func TestRejectLegacyBootstrap_Clean(t *testing.T) {
	t.Setenv(auth.LegacyEnvVar, "")
	if err := auth.RejectLegacyBootstrap(""); err != nil {
		t.Fatal(err)
	}
	if err := auth.RejectLegacyBootstrap("   "); err != nil {
		t.Fatal(err)
	}
}

func TestParseUserToken(t *testing.T) {
	t.Parallel()
	u, tok, err := auth.ParseUserToken("alice:mytoken")
	if err != nil || u != "alice" || tok != "mytoken" {
		t.Fatalf("%q %q %v", u, tok, err)
	}
	u, tok, err = auth.ParseUserToken("alice:a:b:c")
	if err != nil || tok != "a:b:c" {
		t.Fatalf("%q %v", tok, err)
	}
	_, _, err = auth.ParseUserToken("nocolon")
	if err == nil {
		t.Fatal("expected error")
	}
}
