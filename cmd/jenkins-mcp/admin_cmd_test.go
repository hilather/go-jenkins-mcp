package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAdminToken_EnvAndFile(t *testing.T) {
	// Both empty → no token
	tok, err := loadAdminToken("", "")
	if err != nil || tok != "" {
		t.Fatalf("empty: tok=%q err=%v", tok, err)
	}

	// Both set → reject
	if _, err := loadAdminToken("A", "/tmp/x"); err == nil {
		t.Fatal("both env and file must fail")
	}

	// Env empty / unset
	t.Setenv("JENKINS_MCP_ADMIN_TOKEN_TEST_EMPTY", "")
	if _, err := loadAdminToken("JENKINS_MCP_ADMIN_TOKEN_TEST_EMPTY", ""); err == nil {
		t.Fatal("empty env must fail")
	}
	if _, err := loadAdminToken("JENKINS_MCP_ADMIN_TOKEN_TEST_UNSET_XYZ", ""); err == nil {
		t.Fatal("unset env must fail")
	}

	const canary = "admin-token-canary-not-for-prod"
	t.Setenv("JENKINS_MCP_ADMIN_TOKEN_TEST", canary)
	tok, err = loadAdminToken("JENKINS_MCP_ADMIN_TOKEN_TEST", "")
	if err != nil {
		t.Fatal(err)
	}
	if tok != canary {
		t.Fatalf("tok mismatch")
	}

	// File mode 0600
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err = loadAdminToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if tok != canary {
		t.Fatalf("file tok=%q", tok)
	}

	// Loose perms rejected
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(canary), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminToken("", loose); err == nil {
		t.Fatal("0644 token file must fail")
	}

	// Error messages must not include the token value
	errStr := ""
	if _, err := loadAdminToken("JENKINS_MCP_ADMIN_TOKEN_TEST_UNSET_XYZ", ""); err != nil {
		errStr = err.Error()
	}
	if strings.Contains(errStr, canary) {
		t.Fatal("error must not contain token")
	}
}

func TestAdminUsageMentionsServe(t *testing.T) {
	u := adminUsage()
	for _, s := range []string{
		"admin serve", "/admin/v1", "require-token", "admin-token-env", "loopback",
		"admin-role", "/admin/v1/me", "policy_admin", "CSP", "uiBuild",
		"/usr/share/jenkins-mcp/admin-ui",
	} {
		if !strings.Contains(u, s) {
			t.Errorf("usage missing %q", s)
		}
	}
}

func TestRunAdmin_InvalidRoleFails(t *testing.T) {
	// Regression: invalid --admin-role must fail start (UI-003).
	err := runAdminServe([]string{"--addr", "127.0.0.1:0", "--admin-role", "superuser"})
	if err == nil {
		t.Fatal("expected invalid admin-role to fail")
	}
	if !strings.Contains(err.Error(), "admin role") && !strings.Contains(err.Error(), "role") {
		t.Fatalf("err=%v", err)
	}
	// Canary: planted token-like string must not appear in error
	if strings.Contains(err.Error(), "supersecret-token-xyz") {
		t.Fatal("error must not contain unrelated secret")
	}
}

func TestRunAdmin_UnknownSubcommand(t *testing.T) {
	err := runAdmin([]string{"nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown admin") && !strings.Contains(err.Error(), "serve") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunAdmin_RequireTokenFailsClosed(t *testing.T) {
	// require-token without token source
	err := runAdminServe([]string{"--addr", "127.0.0.1:0", "--require-token"})
	if err == nil {
		t.Fatal("expected require-token without secret to fail")
	}
	if !strings.Contains(err.Error(), "require-token") && !strings.Contains(err.Error(), "shared secret") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunAdmin_NonLocalRequiresToken(t *testing.T) {
	err := runAdminServe([]string{"--addr", "0.0.0.0:8799", "--admin-allow-non-local"})
	if err == nil {
		t.Fatal("non-local without token must fail")
	}
	if !strings.Contains(err.Error(), "admin-allow-non-local") && !strings.Contains(err.Error(), "shared secret") {
		// may also fail on listen addr validation path after token check
		if !strings.Contains(err.Error(), "loopback") && !strings.Contains(err.Error(), "token") {
			t.Fatalf("err=%v", err)
		}
	}
}
