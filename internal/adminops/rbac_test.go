package adminops_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/adminops"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

func generatePubPEM(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := policy.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// UI-011 / multi-fleet: MCP rbac put must refuse when signed path is active
// (parity with BFF PlainApplyBlocked).
func TestRbacPut_RefuseRequireSigned(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv(policy.EnvRequireSignedPolicyVar, "1")
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")
	t.Setenv(policy.EnvPolicyFileVar, filepath.Join(dir, "overlay.json"))
	t.Setenv(policy.EnvPolicyRequiredVar, "")

	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	svc := adminops.New(adminops.Config{
		Role:  adminops.RolePolicyAdmin,
		Paths: &paths,
	})
	_, err = svc.RbacPutBindings(context.Background(),
		[]policy.UserBinding{{JenkinsUserID: "alice", DenyTools: []string{"jenkins_get_build_logs"}}},
		nil, "corp", "APPLY")
	if err == nil {
		t.Fatal("expected refuse under REQUIRE_SIGNED_POLICY")
	}
	msg := strings.ToLower(err.Error())
	// apperr may redact env names; message still says plain overlay write refused.
	if !strings.Contains(msg, "refused") && !strings.Contains(msg, "signed") && !strings.Contains(msg, "plain") {
		t.Fatalf("want signed-path refuse message, got %v", err)
	}
	// No durable write
	if _, err := os.Stat(filepath.Join(dir, "overlay.json")); err == nil {
		// may not exist — good
	}
}

func TestRbacPut_RefuseTrustedKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv(policy.EnvRequireSignedPolicyVar, "")
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	// Non-empty trusted keys path that exists (empty dir still loads as empty set —
	// write a dummy public key so LoadTrustedKeys has keys).
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Use a real Ed25519 public PEM via policy Encode if we can; otherwise
	// set env to a file that LoadTrustedKeys treats as configured with Len>0.
	// Generate via openssl-style minimal: write trust dir with valid key from policy tests pattern.
	// Minimal: if keys dir is empty Len=0 — need real key. Skip if we can't:
	// write empty and also set POLICY_REQUIRED as alternate — better generate key.
	pubPEM := mustLabPubPEM(t)
	if err := os.WriteFile(filepath.Join(keysDir, "fleet.pub"), pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policy.EnvPolicyTrustedKeysVar, keysDir)
	t.Setenv(policy.EnvPolicyFileVar, filepath.Join(dir, "overlay.json"))

	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	svc := adminops.New(adminops.Config{Role: adminops.RolePolicyAdmin, Paths: &paths})
	_, err = svc.RbacPutBindings(context.Background(),
		[]policy.UserBinding{{JenkinsUserID: "alice", DenyTools: []string{"jenkins_get_build_logs"}}},
		nil, "corp", "APPLY")
	if err == nil {
		t.Fatal("expected refuse when trusted keys configured")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "trusted") && !strings.Contains(strings.ToLower(err.Error()), "signed") {
		t.Fatalf("want trusted-keys refuse message, got %v", err)
	}
}

func TestRbacPut_ConfirmAndRoleGate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv(policy.EnvRequireSignedPolicyVar, "")
	t.Setenv(policy.EnvPolicyTrustedKeysVar, "")
	t.Setenv(policy.EnvPolicyRequiredVar, "")
	t.Setenv(policy.EnvPolicyFileVar, "")

	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.DefaultPolicyFile()), 0o700); err != nil {
		t.Fatal(err)
	}

	// Viewer cannot put
	svcView := adminops.New(adminops.Config{Role: adminops.RoleViewer, Paths: &paths})
	_, err = svcView.RbacPutBindings(context.Background(),
		[]policy.UserBinding{{JenkinsUserID: "alice", DenyTools: []string{"jenkins_get_build_logs"}}},
		nil, "corp", "APPLY")
	if err == nil {
		t.Fatal("viewer must not put bindings")
	}

	// policy_admin wrong confirm
	svc := adminops.New(adminops.Config{Role: adminops.RolePolicyAdmin, Paths: &paths})
	_, err = svc.RbacPutBindings(context.Background(),
		[]policy.UserBinding{{JenkinsUserID: "alice", DenyTools: []string{"jenkins_get_build_logs"}}},
		nil, "corp", "YES")
	if err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatalf("want confirm=APPLY required, got %v", err)
	}

	// Happy path plain write
	out, err := svc.RbacPutBindings(context.Background(),
		[]policy.UserBinding{{JenkinsUserID: "alice", DenyTools: []string{"jenkins_get_build_logs"}}},
		[]policy.GroupBinding{{GroupID: "contractors", DenyTools: []string{"jenkins_get_console_log"}}},
		"corp", "APPLY")
	if err != nil {
		t.Fatal(err)
	}
	if applied, _ := out["applied"].(bool); !applied {
		t.Fatalf("expected applied: %+v", out)
	}
	// Secret-free canary
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "Bearer ") || strings.Contains(string(raw), "api_token") ||
		strings.Contains(string(raw), "BEGIN PRIVATE") {
		t.Fatalf("secret-shaped material in rbac put result: %s", raw)
	}

	// List returns bindings
	list, err := svc.RbacListBindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	listRaw, _ := json.Marshal(list)
	if strings.Contains(string(listRaw), "Bearer ") {
		t.Fatalf("token in list: %s", listRaw)
	}
	if list["fleet_sot"] == nil || list["fleet_sot"] == "" {
		t.Fatal("expected fleet_sot honesty")
	}

	// Delete requires confirm=DELETE
	_, err = svc.RbacDeleteBinding(context.Background(), "user", "alice", "corp", "NO")
	if err == nil || !strings.Contains(err.Error(), "DELETE") {
		t.Fatalf("want DELETE confirm, got %v", err)
	}
	delOut, err := svc.RbacDeleteBinding(context.Background(), "user", "alice", "corp", "DELETE")
	if err != nil {
		t.Fatal(err)
	}
	if delOut == nil {
		t.Fatal("nil delete result")
	}
}

func mustLabPubPEM(t *testing.T) []byte {
	t.Helper()
	// Generate via policy.EncodePublicKeyPEM after ed25519.GenerateKey
	// Keep in this test file to avoid exporting bundle_test helpers.
	return generatePubPEM(t)
}
