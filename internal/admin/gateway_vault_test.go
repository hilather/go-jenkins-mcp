package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

const vaultCanaryToken = "admin-vault-canary-token-NEVER-IN-JSON"

// HOST-007: health lists enabledModes secret-free (mode ids only; no vault tokens).
func TestHealth_EnabledModesSecretFree(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	t.Setenv(gateway.EnvGatewayEnabledModes, "api_token_vault,jwt_rs_bearer")
	t.Setenv(gateway.EnvGatewayVaultPath, filepath.Join(t.TempDir(), "unused.json"))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, vaultCanaryToken) {
		t.Fatalf("canary leaked in health: %s", body)
	}
	if !strings.Contains(body, "api_token_vault") || !strings.Contains(body, "jwt_rs_bearer") {
		t.Fatalf("health missing enabledModes: %s", body)
	}
	if !strings.Contains(body, `"enabledModes"`) {
		t.Fatalf("health missing enabledModes field: %s", body)
	}
}

func TestGatewayVault_ViewerRead_NoTokenLeak(t *testing.T) {
	// Not parallel: uses process env for vault path + credential mode.
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "apitoken_vault.json")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	t.Setenv(gateway.EnvGatewayVaultPath, vaultPath)
	t.Setenv(gateway.EnvGatewayEnabledModes, "")

	// Plant a secret entry via vault API.
	v, err := gateway.NewFileAPITokenVault(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	subjectKey := gateway.SubjectKeyParts("t1", "user-sub", "corp")
	if err := v.Put(context.Background(), subjectKey, "alice", vaultCanaryToken); err != nil {
		t.Fatal(err)
	}
	wantHash := gateway.SubjectKeyHash(subjectKey)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/vault", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if strings.Contains(raw, vaultCanaryToken) {
		t.Fatal("Regression: vault token leaked in admin JSON")
	}
	if strings.Contains(raw, "alice") {
		// Prefer hash-only inventory; username must not appear.
		t.Fatal("username must not appear in vault status JSON")
	}
	if strings.Contains(raw, subjectKey) {
		t.Fatal("raw subject key must not appear; use SubjectKeyHash only")
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["mode"] != string(gateway.CredentialModeAPITokenVault) {
		t.Fatalf("mode %v", body["mode"])
	}
	if body["vaultConfigured"] != true {
		t.Fatalf("vaultConfigured %v", body["vaultConfigured"])
	}
	if body["entryCount"] != float64(1) {
		t.Fatalf("entryCount %v", body["entryCount"])
	}
	subjects, _ := body["subjects"].([]any)
	if len(subjects) != 1 || subjects[0] != wantHash {
		t.Fatalf("subjects %v want hash %s", subjects, wantHash)
	}
	// Residual should mention CLI vault write (no SPA write).
	residual, _ := body["residual"].(string)
	if !strings.Contains(residual, "CLI") && !strings.Contains(residual, "vault put") {
		t.Fatalf("want CLI residual: %q", residual)
	}
}

func TestGatewayVault_EmptyVault(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "missing-vault.json")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAgentCore))
	t.Setenv(gateway.EnvGatewayVaultPath, vaultPath)
	t.Setenv(gateway.EnvGatewayEnabledModes, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/vault", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["mode"] != string(gateway.CredentialModeAgentCore) {
		t.Fatalf("mode %v", body["mode"])
	}
	if body["vaultConfigured"] != false {
		t.Fatalf("vaultConfigured %v", body["vaultConfigured"])
	}
	if body["entryCount"] != float64(0) {
		t.Fatalf("entryCount %v", body["entryCount"])
	}
	if strings.Contains(rr.Body.String(), vaultCanaryToken) {
		t.Fatal("canary")
	}
}

func TestGatewayVault_ModeBResidualInStatus(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeJWTRSBearer))
	t.Setenv(gateway.EnvGatewayEnabledModes, "")
	t.Setenv(gateway.EnvGatewayVaultPath, filepath.Join(t.TempDir(), "v.json"))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/vault", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if !strings.Contains(raw, "jwt_rs_bearer") {
		t.Fatalf("want mode B in body: %s", raw)
	}
	if !strings.Contains(raw, "HOST-010") && !strings.Contains(raw, "residual") {
		t.Fatalf("want residual note: %s", raw)
	}
}

func TestGatewayVault_MethodNotAllowed(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/vault", strings.NewReader(`{}`)))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rr.Code)
	}
}
