package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
)

func TestMe_WithAndWithoutToken(t *testing.T) {
	const canary = "planted-admin-secret-token-NEVER-ECHO"
	// No token: residual pilot mode, authenticated true, role applies.
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["authenticated"] != true {
		t.Fatalf("authenticated=%v want true (loopback residual)", body["authenticated"])
	}
	if body["role"] != "operator" {
		t.Fatalf("role=%v", body["role"])
	}
	if body["tokenConfigured"] != false {
		t.Fatalf("tokenConfigured=%v", body["tokenConfigured"])
	}
	residual, _ := body["residual"].(string)
	if residual == "" {
		t.Fatal("expected residual note when no token")
	}
	perms, ok := body["permissions"].([]any)
	if !ok || len(perms) < 1 {
		t.Fatalf("permissions=%v", body["permissions"])
	}
	// Canary: planted secret must never appear
	if strings.Contains(rr.Body.String(), canary) {
		t.Fatal("response must not contain planted secret")
	}

	// With token: 401 without, 200 with Bearer; never echo token.
	cfg2 := admin.DefaultConfig()
	cfg2.Addr = "127.0.0.1:0"
	cfg2.BearerToken = canary
	cfg2.Role = admin.RolePolicyAdmin
	h2, err := admin.NewHandler(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	rr401 := httptest.NewRecorder()
	h2.ServeHTTP(rr401, httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil))
	if rr401.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without token, got %d", rr401.Code)
	}
	if strings.Contains(rr401.Body.String(), canary) {
		t.Fatal("401 body must not echo token")
	}

	rrOK := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+canary)
	h2.ServeHTTP(rrOK, req)
	if rrOK.Code != http.StatusOK {
		t.Fatalf("want 200 with token, got %d body=%s", rrOK.Code, rrOK.Body.String())
	}
	if strings.Contains(rrOK.Body.String(), canary) {
		t.Fatal("me body must never contain token value")
	}
	var me map[string]any
	if err := json.Unmarshal(rrOK.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me["authenticated"] != true {
		t.Fatalf("authenticated=%v", me["authenticated"])
	}
	if me["role"] != "policy_admin" {
		t.Fatalf("role=%v", me["role"])
	}
	if me["tokenConfigured"] != true {
		t.Fatalf("tokenConfigured=%v", me["tokenConfigured"])
	}
	// Residual omit when token configured
	if r, ok := me["residual"].(string); ok && r != "" {
		t.Fatalf("unexpected residual with token: %q", r)
	}
	// policy_admin permissions include policy_write
	foundPolicy := false
	for _, p := range me["permissions"].([]any) {
		if p == "policy_write" {
			foundPolicy = true
		}
	}
	if !foundPolicy {
		t.Fatalf("policy_admin permissions=%v", me["permissions"])
	}
}

func TestRequirePermission_403(t *testing.T) {
	const canary = "rbac-canary-token-not-for-prod"
	// Build production handler (viewer), then wrap a test-only write path
	// with RequirePermission to exercise 403 without shipping write APIs.
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.BearerToken = canary
	cfg.Role = admin.RoleViewer
	base, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Test mux: outer auth is already on base; we need a path that goes through
	// authMiddleware + RequirePermission. Compose: auth attaches role, then
	// RequirePermission(PermPolicyWrite) on a stub handler.
	// Use NewHandler's middleware by registering via a custom stack:
	//   authMiddleware(token, role, RequirePermission(... stub))
	// since base already has full mux, test RequirePermission in isolation with
	// WithRole context (and a second stack with full auth).

	// Isolation: CheckPermission / middleware with context role.
	denied := admin.RequirePermission(admin.PermPolicyWrite)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	// Viewer role on context → 403
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/test-policy", nil)
	req = req.WithContext(admin.WithRole(req.Context(), admin.RoleViewer))
	denied.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer policy_write want 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody["code"] != "permission_denied" {
		t.Fatalf("code=%q", errBody["code"])
	}
	if strings.Contains(rr.Body.String(), canary) {
		t.Fatal("403 body must not contain token")
	}

	// policy_admin → allowed
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/admin/v1/test-policy", nil)
	req2 = req2.WithContext(admin.WithRole(req2.Context(), admin.RolePolicyAdmin))
	denied.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("policy_admin want 204, got %d", rr2.Code)
	}

	// operator cannot policy_write
	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/admin/v1/test-policy", nil)
	req3 = req3.WithContext(admin.WithRole(req3.Context(), admin.RoleOperator))
	denied.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusForbidden {
		t.Fatalf("operator policy_write want 403, got %d", rr3.Code)
	}

	// Cache destructive: operator ok, viewer denied
	cacheMW := admin.RequirePermission(admin.PermCacheDestructive)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rr4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodPost, "/admin/v1/test-cache", nil)
	req4 = req4.WithContext(admin.WithRole(req4.Context(), admin.RoleOperator))
	cacheMW.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusNoContent {
		t.Fatalf("operator cache want 204, got %d", rr4.Code)
	}
	rr5 := httptest.NewRecorder()
	req5 := httptest.NewRequest(http.MethodPost, "/admin/v1/test-cache", nil)
	req5 = req5.WithContext(admin.WithRole(req5.Context(), admin.RoleViewer))
	cacheMW.ServeHTTP(rr5, req5)
	if rr5.Code != http.StatusForbidden {
		t.Fatalf("viewer cache want 403, got %d", rr5.Code)
	}

	// Full stack canary: GET /me with token still never echoes secret
	_ = base
	rrMe := httptest.NewRecorder()
	reqMe := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
	reqMe.Header.Set(admin.HeaderAdminToken, canary)
	base.ServeHTTP(rrMe, reqMe)
	if rrMe.Code != http.StatusOK {
		t.Fatalf("me status %d", rrMe.Code)
	}
	if strings.Contains(rrMe.Body.String(), canary) {
		t.Fatal("canary: me must not echo admin token")
	}
	var me map[string]any
	if err := json.Unmarshal(rrMe.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me["role"] != "viewer" {
		t.Fatalf("role=%v", me["role"])
	}
}

func TestValidateConfig_InvalidRole(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:8787"
	cfg.Role = admin.Role("superuser")
	if err := admin.ValidateConfig(cfg); err == nil {
		t.Fatal("invalid role must fail ValidateConfig")
	}
	cfg.Role = admin.RoleViewer
	if err := admin.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	// Empty role is ok (defaults to viewer)
	cfg.Role = ""
	if err := admin.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPermission_Helper(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(admin.WithRole(req.Context(), admin.RoleViewer))
	if admin.CheckPermission(rr, req, admin.PermPolicyWrite) {
		t.Fatal("viewer must fail CheckPermission for policy write")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2 = req2.WithContext(admin.WithRole(req2.Context(), admin.RolePolicyAdmin))
	if !admin.CheckPermission(rr2, req2, admin.PermPolicyWrite) {
		t.Fatal("policy_admin must pass CheckPermission for policy write")
	}
	// Still cannot widen force RO
	if admin.CanWidenForceReadOnly(admin.RolePolicyAdmin) {
		t.Fatal("policy_admin must not widen force_read_only")
	}
}
