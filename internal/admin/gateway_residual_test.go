package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

const residualStatusCanary = "admin-residual-status-canary-NEVER-IN-JSON"

// HOST-007: GET /admin/v1/gateway/residual-status mirrors CLI secret-free snapshot.
func TestGatewayResidualStatus_SecretFreeAndCoreFields(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeJWTRSBearer))
	t.Setenv(gateway.EnvGatewayEnabledModes, "")
	t.Setenv("JENKINS_MCP_GATEWAY_MULTI_USER", "1")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("HOST007_FAKE_TOKEN", residualStatusCanary)
	t.Setenv("Authorization", "Bearer "+residualStatusCanary)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/residual-status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if strings.Contains(raw, residualStatusCanary) {
		t.Fatal("Regression: canary token leaked in residual-status JSON")
	}
	for _, bad := range []string{"access_token=", "refresh_token=", "client_secret=", "Bearer " + residualStatusCanary} {
		if strings.Contains(raw, bad) {
			t.Fatalf("forbidden %q in residual-status", bad)
		}
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json: %v body=%s", err, raw)
	}

	// Mode B residual id always present (parity with CLI).
	if body["residual_id"] != "oauth009_offline" {
		t.Fatalf("residual_id=%v", body["residual_id"])
	}
	if body["oauth009_offline"] != true {
		t.Fatalf("oauth009_offline=%v", body["oauth009_offline"])
	}
	if body["mode_b_enabled"] != true {
		t.Fatalf("mode_b_enabled=%v", body["mode_b_enabled"])
	}
	if body["mode_b_live_rs_qualified"] != false {
		t.Fatalf("mode_b_live_rs_qualified must be false: %v", body["mode_b_live_rs_qualified"])
	}

	// Multi-user / HA / multi-pod honesty.
	if body["multi_user_enabled"] != true {
		t.Fatalf("multi_user_enabled=%v", body["multi_user_enabled"])
	}
	if body["ha_multi_replica"] != false {
		t.Fatalf("ha_multi_replica must be false: %v", body["ha_multi_replica"])
	}
	if body["session_affinity_recommended"] != true {
		t.Fatalf("session_affinity_recommended=%v", body["session_affinity_recommended"])
	}
	if body["multi_pod_vault_residual"] != true {
		t.Fatalf("multi_pod_vault_residual must be true: %v", body["multi_pod_vault_residual"])
	}
	if body["gateway_ready"] != false {
		t.Fatalf("gateway_ready residual must be false on admin: %v", body["gateway_ready"])
	}

	// residual_ids includes oauth009_offline.
	ids, ok := body["residual_ids"].([]any)
	if !ok || len(ids) == 0 {
		t.Fatalf("residual_ids: %+v", body["residual_ids"])
	}
	found := false
	for _, id := range ids {
		if s, _ := id.(string); s == "oauth009_offline" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("residual_ids missing oauth009_offline: %+v", ids)
	}

	// Rate knobs (admin health field names).
	if _, ok := body["rateEnabled"].(bool); !ok {
		t.Fatalf("rateEnabled: %v", body["rateEnabled"])
	}
	if _, ok := body["ratePerMinute"].(float64); !ok {
		t.Fatalf("ratePerMinute: %v", body["ratePerMinute"])
	}
	if _, ok := body["rateBurst"].(float64); !ok {
		t.Fatalf("rateBurst: %v", body["rateBurst"])
	}

	// principal_cache_entries count only; process note states CLI/admin ≠ serve.
	if _, ok := body["principal_cache_entries"].(float64); !ok {
		t.Fatalf("principal_cache_entries: %T %v", body["principal_cache_entries"], body["principal_cache_entries"])
	}
	pcNote, _ := body["principal_cache_process_note"].(string)
	if pcNote == "" || !strings.Contains(strings.ToLower(pcNote), "this process") {
		t.Fatalf("principal_cache_process_note: %q", pcNote)
	}
	// shared_subject_rate_file / shared_jwks_file / shared_token_cache_file default false when paths unset.
	if body["shared_subject_rate_file"] != false {
		t.Fatalf("shared_subject_rate_file default false: %+v", body["shared_subject_rate_file"])
	}
	if body["shared_jwks_file"] != false {
		t.Fatalf("shared_jwks_file default false: %+v", body["shared_jwks_file"])
	}
	if body["shared_token_cache_file"] != false {
		t.Fatalf("shared_token_cache_file default false: %+v", body["shared_token_cache_file"])
	}

	// Progressive consent object.
	pc, ok := body["progressive_consent"].(map[string]any)
	if !ok {
		t.Fatalf("progressive_consent: %+v", body["progressive_consent"])
	}
	if pc["browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated: %+v", pc)
	}

	// Honesty pointer to live-pin-blockers.
	note, _ := body["residual_note"].(string)
	doc, _ := body["doc"].(string)
	if !strings.Contains(note, "live-pin-blockers") && !strings.Contains(doc, "live-pin-blockers") {
		t.Fatalf("want live-pin-blockers pointer: note=%q doc=%q", note, doc)
	}
	if strings.Contains(strings.ToLower(raw), "production go complete") {
		t.Fatal("must not claim production GO complete")
	}
}

func TestGatewayResidualStatus_MultiPodK8s(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/residual-status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if strings.Contains(raw, "10.0.0.1") {
		t.Fatal("must not embed KUBERNETES_SERVICE_HOST value")
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["kubernetes_env_detected"] != true {
		t.Fatalf("kubernetes_env_detected=%v", body["kubernetes_env_detected"])
	}
	cl, _ := body["multi_pod_residual_checklist"].(string)
	if cl == "" || !strings.Contains(strings.ToLower(cl), "multi-pod") {
		t.Fatalf("want multi_pod_residual_checklist: %q", cl)
	}
}

func TestGatewayResidualStatus_ModeCConsentNote(t *testing.T) {
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAgentCore))
	t.Setenv(gateway.EnvGatewayEnabledModes, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/residual-status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["mode_c_enabled"] != true {
		t.Fatalf("mode_c_enabled=%v", body["mode_c_enabled"])
	}
	if _, ok := body["progressive_consent_residual"].(string); !ok {
		t.Fatalf("want progressive_consent_residual when Mode C: %+v", body["progressive_consent_residual"])
	}
	if strings.Contains(rr.Body.String(), residualStatusCanary) {
		t.Fatal("canary")
	}
}

func TestGatewayResidualStatus_ViewerOK(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	cfg.BearerToken = "admin-secret-for-test"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Missing token → 401
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/residual-status", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without token, got %d", rr.Code)
	}
	// With token → 200
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/residual-status", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-for-test")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("viewer with token want 200, got %d body %s", rr2.Code, rr2.Body.String())
	}
	if strings.Contains(rr2.Body.String(), "admin-secret-for-test") {
		t.Fatal("admin token must never appear in residual-status body")
	}
}

func TestGatewayResidualStatus_MethodNotAllowed(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/residual-status", strings.NewReader(`{}`)))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rr.Code)
	}
}
