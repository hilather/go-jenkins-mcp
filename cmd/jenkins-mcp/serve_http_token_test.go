package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: loadHTTPServeToken never embeds the secret in errors when the
// env var name or file path is wrong — only names/paths. Canary is the value
// that must never appear when loading fails for empty/unset cases.
const canaryHTTPServeToken = "test-token-xyz"

func TestLoadHTTPServeToken_EmptyBoth(t *testing.T) {
	t.Parallel()
	tok, err := loadHTTPServeToken("", "")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		t.Fatalf("want empty token, got %q", tok)
	}
}

func TestLoadHTTPServeToken_EnvOK(t *testing.T) {
	// Not parallel: mutates process env.
	const envName = "JENKINS_MCP_TEST_HTTP_TOKEN_OK"
	t.Setenv(envName, canaryHTTPServeToken)
	tok, err := loadHTTPServeToken(envName, "")
	if err != nil {
		t.Fatal(err)
	}
	if tok != canaryHTTPServeToken {
		t.Fatalf("got %q", tok)
	}
}

func TestLoadHTTPServeToken_EnvEmptyOrUnset(t *testing.T) {
	const envName = "JENKINS_MCP_TEST_HTTP_TOKEN_EMPTY"
	t.Setenv(envName, "")
	_, err := loadHTTPServeToken(envName, "")
	if err == nil {
		t.Fatal("expected empty env fail-closed")
	}
	if strings.Contains(err.Error(), canaryHTTPServeToken) {
		t.Fatalf("canary in error: %v", err)
	}
	// Unset entirely.
	_ = os.Unsetenv(envName)
	_, err = loadHTTPServeToken(envName, "")
	if err == nil {
		t.Fatal("expected unset env fail-closed")
	}
}

func TestLoadHTTPServeToken_BothFlagsReject(t *testing.T) {
	t.Parallel()
	_, err := loadHTTPServeToken("SOME_ENV", "/tmp/token")
	if err == nil {
		t.Fatal("expected mutual exclusion error")
	}
	if !strings.Contains(err.Error(), "only one") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestLoadHTTPServeToken_FileOK(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "http.token")
	if err := os.WriteFile(path, []byte(canaryHTTPServeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := loadHTTPServeToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if tok != canaryHTTPServeToken {
		t.Fatalf("got %q want stripped newline secret", tok)
	}
}

func TestLoadHTTPServeToken_FileInsecureMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "http.token")
	if err := os.WriteFile(path, []byte(canaryHTTPServeToken), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadHTTPServeToken("", path)
	if err == nil {
		t.Fatal("expected mode 0644 rejection")
	}
	if !strings.Contains(err.Error(), "0600") {
		t.Fatalf("unexpected: %v", err)
	}
	if strings.Contains(err.Error(), canaryHTTPServeToken) {
		t.Fatalf("canary leaked in error: %v", err)
	}
}

func TestLoadHTTPServeToken_FileEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "http.token")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadHTTPServeToken("", path)
	if err == nil {
		t.Fatal("expected empty file rejection")
	}
}

func TestResolveHTTPRequireToken_FlagAndEnv(t *testing.T) {
	// Not parallel: mutates process env.
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "")
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "")
	if resolveHTTPRequireToken(false) {
		t.Fatal("empty env + flag false should be off (compat)")
	}
	if !resolveHTTPRequireToken(true) {
		t.Fatal("flag true should require token")
	}
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", v)
		t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "")
		if !resolveHTTPRequireToken(false) {
			t.Fatalf("REQUIRE_TOKEN env %q should require token", v)
		}
	}
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "0")
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "")
	if resolveHTTPRequireToken(false) {
		t.Fatal("env 0 should not require token")
	}
	// Flag wins even if env is off.
	if !resolveHTTPRequireToken(true) {
		t.Fatal("flag true with env 0 should still require")
	}
}

// Wave 41: JENKINS_MCP_HTTP_DENY_ANONYMOUS is an OR alias of require-token.
func TestResolveHTTPRequireToken_DenyAnonymousEnv(t *testing.T) {
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "")
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "")
	if resolveHTTPRequireToken(false) {
		t.Fatal("both envs empty should be off (default residual open)")
	}
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "")
		t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", v)
		if !resolveHTTPRequireToken(false) {
			t.Fatalf("DENY_ANONYMOUS env %q should require token", v)
		}
	}
	// Non-truthy deny-anonymous alone stays off.
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "0")
	if resolveHTTPRequireToken(false) {
		t.Fatal("DENY_ANONYMOUS=0 should not require token")
	}
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "nope")
	if resolveHTTPRequireToken(false) {
		t.Fatal("DENY_ANONYMOUS=nope should not require token")
	}
	// Either env alone is enough; both together still true.
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "1")
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "0")
	if !resolveHTTPRequireToken(false) {
		t.Fatal("REQUIRE_TOKEN=1 with DENY_ANONYMOUS=0 should still require")
	}
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "0")
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "1")
	if !resolveHTTPRequireToken(false) {
		t.Fatal("DENY_ANONYMOUS=1 with REQUIRE_TOKEN=0 should require")
	}
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "1")
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "1")
	if !resolveHTTPRequireToken(false) {
		t.Fatal("both truthy should require")
	}
	// Flag OR with deny-anonymous off.
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "")
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "0")
	if !resolveHTTPRequireToken(true) {
		t.Fatal("flag true should require even when both envs off")
	}
}

func TestEnvHTTPRequireTokenTruthy(t *testing.T) {
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "")
	if envHTTPRequireTokenTruthy() {
		t.Fatal("empty should be false")
	}
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "1")
	if !envHTTPRequireTokenTruthy() {
		t.Fatal("1 should be true")
	}
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_TOKEN", "nope")
	if envHTTPRequireTokenTruthy() {
		t.Fatal("nope should be false")
	}
}

func TestEnvHTTPDenyAnonymousTruthy(t *testing.T) {
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "")
	if envHTTPDenyAnonymousTruthy() {
		t.Fatal("empty should be false")
	}
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "1")
	if !envHTTPDenyAnonymousTruthy() {
		t.Fatal("1 should be true")
	}
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "true")
	if !envHTTPDenyAnonymousTruthy() {
		t.Fatal("true should be true")
	}
	t.Setenv("JENKINS_MCP_HTTP_DENY_ANONYMOUS", "nope")
	if envHTTPDenyAnonymousTruthy() {
		t.Fatal("nope should be false")
	}
}
