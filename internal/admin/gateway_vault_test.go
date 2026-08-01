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

// HOST-007 / HOST-008: health lists enabledModes + gateway residual posture (secret-free).
func TestHealth_EnabledModesSecretFree(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	t.Setenv(gateway.EnvGatewayEnabledModes, "api_token_vault,jwt_rs_bearer")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
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
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["credentialMode"] != string(gateway.CredentialModeAPITokenVault) {
		t.Fatalf("credentialMode=%v", m["credentialMode"])
	}
	if m["multiUserEnabled"] != false {
		t.Fatalf("multiUserEnabled=%v", m["multiUserEnabled"])
	}
	if m["gatewayReady"] != false {
		t.Fatalf("admin gatewayReady residual must be false: %v", m["gatewayReady"])
	}
	if m["haMultiReplica"] != false {
		t.Fatalf("HOST-008 haMultiReplica must be false: %v", m["haMultiReplica"])
	}
	if m["sessionAffinityRecommended"] != false {
		t.Fatalf("sessionAffinityRecommended want false when multi_user off: %v", m["sessionAffinityRecommended"])
	}
	// Default rate env empty → rateEnabled true + package defaults (HOST-006 residual).
	if m["rateEnabled"] != true {
		t.Fatalf("rateEnabled default want true got %v", m["rateEnabled"])
	}
	if m["ratePerMinute"] != float64(gateway.DefaultSubjectRatePerMinute) {
		t.Fatalf("ratePerMinute default want %d got %v", gateway.DefaultSubjectRatePerMinute, m["ratePerMinute"])
	}
	if m["rateBurst"] != float64(gateway.DefaultSubjectRateBurst) {
		t.Fatalf("rateBurst default want %d got %v", gateway.DefaultSubjectRateBurst, m["rateBurst"])
	}
	res, _ := m["residual"].(string)
	if !strings.Contains(res, "process-local") {
		t.Fatalf("want process-local rate residual note: %q", res)
	}
	if strings.Contains(res, vaultCanaryToken) {
		t.Fatal("canary in residual")
	}
}

// HOST-006 / HOST-008 residual: rate knobs from ResolveSubjectRateCaps (secret-free).
func TestHealth_RateEnabledFromEnv(t *testing.T) {
	t.Setenv(gateway.EnvSubjectRatePerMinute, "0")
	t.Setenv(gateway.EnvSubjectRateBurst, "99")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
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
	if strings.Contains(rr.Body.String(), vaultCanaryToken) {
		t.Fatal("canary in rate health")
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["rateEnabled"] != false {
		t.Fatalf("rateEnabled with env 0 want false got %v", m["rateEnabled"])
	}
	if m["ratePerMinute"] != float64(0) {
		t.Fatalf("ratePerMinute disabled want 0 got %v", m["ratePerMinute"])
	}
	// Burst ignored when rate off → report 0 (not env 99).
	if m["rateBurst"] != float64(0) {
		t.Fatalf("rateBurst disabled want 0 got %v", m["rateBurst"])
	}
}

// HOST-006 residual knobs: custom rate env surfaces numeric fields (secret-free canary).
func TestHealth_RateKnobsFromEnv(t *testing.T) {
	t.Setenv(gateway.EnvSubjectRatePerMinute, "45")
	t.Setenv(gateway.EnvSubjectRateBurst, "7")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
	t.Setenv(gateway.EnvGatewayVaultPath, filepath.Join(t.TempDir(), "unused.json"))
	// Plant a fake secret env that must never appear in health JSON.
	t.Setenv("JENKINS_MCP_FAKE_TOKEN", vaultCanaryToken)

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
	raw := rr.Body.String()
	if strings.Contains(raw, vaultCanaryToken) {
		t.Fatal("Regression: canary token leaked in health rate knobs")
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["rateEnabled"] != true {
		t.Fatalf("rateEnabled=%v", m["rateEnabled"])
	}
	if m["ratePerMinute"] != float64(45) {
		t.Fatalf("ratePerMinute=%v want 45", m["ratePerMinute"])
	}
	if m["rateBurst"] != float64(7) {
		t.Fatalf("rateBurst=%v want 7", m["rateBurst"])
	}
}

// OAUTH-010 / GWY-001: progressive consent residual on health (static, secret-free).
// Bools always present; residual note when Mode C enabled. Never authorization_url
// with secrets or tokens in admin JSON.
func TestHealth_ProgressiveConsentResidual_ModeC(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAgentCore))
	t.Setenv(gateway.EnvGatewayEnabledModes, "")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
	t.Setenv(gateway.EnvGatewayVaultPath, filepath.Join(t.TempDir(), "unused.json"))
	// Plant canaries that must never appear in health JSON (static residual only).
	const canaryToken = "pc-health-canary-access-token-NEVER"
	const canaryAuthURL = "https://login.example/oauth2/v2.0/authorize?client_secret=s3cret&code=xyz"
	t.Setenv("JENKINS_MCP_FAKE_TOKEN", canaryToken)
	t.Setenv("JENKINS_MCP_FAKE_AUTHORIZATION_URL", canaryAuthURL)

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
	raw := rr.Body.String()
	for _, bad := range []string{canaryToken, canaryAuthURL, "client_secret=", "access_token=", vaultCanaryToken} {
		if strings.Contains(raw, bad) {
			t.Fatalf("Regression: canary/marker %q leaked in health progressive consent: %s", bad, raw)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["progressiveConsentMetadataDoneStar"] != true {
		t.Fatalf("progressiveConsentMetadataDoneStar want true got %v", m["progressiveConsentMetadataDoneStar"])
	}
	if m["progressiveConsentBrowser3loAutomated"] != false {
		t.Fatalf("progressiveConsentBrowser3loAutomated want false got %v", m["progressiveConsentBrowser3loAutomated"])
	}
	note, _ := m["progressiveConsentResidual"].(string)
	if note == "" {
		t.Fatal("Mode C health must include progressiveConsentResidual note")
	}
	want := gateway.NewProgressiveConsentResidual()
	if note != want.ResidualNote {
		t.Fatalf("residual note mismatch:\n got %q\nwant %q", note, want.ResidualNote)
	}
	if !strings.Contains(note, "OAUTH-010") || !strings.Contains(note, "not automated") {
		t.Fatalf("note honesty: %q", note)
	}
	// Must not embed a live authorize URL (field names in prose are ok; query secrets are not).
	if strings.Contains(note, "https://") || strings.Contains(note, "?") {
		t.Fatalf("residual note must not embed URL/query: %q", note)
	}
}

// When Mode C is not enabled, progressive consent bools remain static; residual note omitted.
func TestHealth_ProgressiveConsentResidual_ModeA_NoNote(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	t.Setenv(gateway.EnvGatewayEnabledModes, "api_token_vault")
	t.Setenv(gateway.EnvGatewayMultiUser, "")
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
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["progressiveConsentMetadataDoneStar"] != true {
		t.Fatalf("metadata Done* always true: %v", m["progressiveConsentMetadataDoneStar"])
	}
	if m["progressiveConsentBrowser3loAutomated"] != false {
		t.Fatalf("browser 3lo always false: %v", m["progressiveConsentBrowser3loAutomated"])
	}
	if _, ok := m["progressiveConsentResidual"]; ok {
		t.Fatalf("Mode A must omit progressiveConsentResidual, got %v", m["progressiveConsentResidual"])
	}
	if strings.Contains(rr.Body.String(), vaultCanaryToken) {
		t.Fatal("canary in Mode A progressive health")
	}
}

// HOST-008 residual: multi_user env surfaces residual note without tokens.
func TestHealth_MultiUserResidualNote(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAgentCore))
	t.Setenv(gateway.EnvGatewayMultiUser, "true")
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
	raw := rr.Body.String()
	if strings.Contains(raw, vaultCanaryToken) {
		t.Fatal("canary in multi-user health")
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["multiUserEnabled"] != true {
		t.Fatalf("multiUserEnabled=%v", m["multiUserEnabled"])
	}
	res, _ := m["residual"].(string)
	if !strings.Contains(res, "MULTI_USER") && !strings.Contains(res, "multi-user") {
		t.Fatalf("want multi-user residual note: %q", res)
	}
	if m["haMultiReplica"] != false {
		t.Fatalf("haMultiReplica=%v", m["haMultiReplica"])
	}
	// HOST-008: multi-user env → recommend sticky Service affinity (scaffold only).
	if m["sessionAffinityRecommended"] != true {
		t.Fatalf("sessionAffinityRecommended want true when multi_user: %v", m["sessionAffinityRecommended"])
	}
	if !strings.Contains(res, "sessionAffinityRecommended") && !strings.Contains(strings.ToLower(res), "session affinity") {
		t.Fatalf("want sessionAffinity residual honesty in note: %q", res)
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
	if body["rateEnabled"] != true && body["rateEnabled"] != false {
		t.Fatalf("rateEnabled must be bool, got %v", body["rateEnabled"])
	}
	// HOST-006 residual knobs present and numeric (default or env; never tokens).
	rpm, ok := body["ratePerMinute"].(float64)
	if !ok {
		t.Fatalf("ratePerMinute must be number, got %T %v", body["ratePerMinute"], body["ratePerMinute"])
	}
	burst, ok := body["rateBurst"].(float64)
	if !ok {
		t.Fatalf("rateBurst must be number, got %T %v", body["rateBurst"], body["rateBurst"])
	}
	if body["rateEnabled"] == true {
		if rpm <= 0 {
			t.Fatalf("rateEnabled true implies ratePerMinute>0, got %v", rpm)
		}
		if burst <= 0 {
			t.Fatalf("rateEnabled true implies rateBurst>0, got %v", burst)
		}
	} else if rpm != 0 || burst != 0 {
		t.Fatalf("disabled rate knobs must be 0, got rpm=%v burst=%v", rpm, burst)
	}
	if !strings.Contains(residual, "process-local") {
		t.Fatalf("want process-local rate residual in vault: %q", residual)
	}
	// Secret-free: never tokens when rate residual is present.
	if strings.Contains(rr.Body.String(), vaultCanaryToken) {
		t.Fatal("canary after rateEnabled field")
	}
}

// HOST-006 residual: vault JSON rate knobs follow env; secret-free canary.
func TestGatewayVault_RateKnobsFromEnv(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "apitoken_vault.json")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	t.Setenv(gateway.EnvGatewayVaultPath, vaultPath)
	t.Setenv(gateway.EnvGatewayEnabledModes, "")
	t.Setenv(gateway.EnvSubjectRatePerMinute, "12")
	t.Setenv(gateway.EnvSubjectRateBurst, "3")
	t.Setenv("JENKINS_MCP_FAKE_TOKEN", vaultCanaryToken)

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
	if strings.Contains(raw, vaultCanaryToken) {
		t.Fatal("Regression: canary token leaked in gateway/vault rate knobs")
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["rateEnabled"] != true {
		t.Fatalf("rateEnabled=%v", body["rateEnabled"])
	}
	if body["ratePerMinute"] != float64(12) {
		t.Fatalf("ratePerMinute=%v", body["ratePerMinute"])
	}
	if body["rateBurst"] != float64(3) {
		t.Fatalf("rateBurst=%v", body["rateBurst"])
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
