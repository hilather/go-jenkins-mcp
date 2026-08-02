package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

const subjectInvalidateCanary = "admin-subject-invalidate-canary-NEVER-IN-JSON"

// HOST-007: POST /admin/v1/gateway/subject-invalidate clears process principal.
func TestGatewaySubjectInvalidate_ProcessPrincipal(t *testing.T) {
	sk := gateway.SubjectKeyParts("tid-admin", "alice-admin", "corp")
	gateway.ProcessPrincipalCache().Set(sk, "alice-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })

	t.Setenv(gateway.EnvGatewayPrincipalCachePath, "")
	t.Setenv(gateway.EnvGatewayTokenCachePath, "")
	t.Setenv("HOST007_FAKE_TOKEN", subjectInvalidateCanary)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"subject_key":"` + sk + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if strings.Contains(raw, subjectInvalidateCanary) {
		t.Fatal("Regression: canary token leaked in subject-invalidate JSON")
	}
	for _, bad := range []string{"access_token=", "refresh_token=", "client_secret=", "Authorization: Bearer"} {
		if strings.Contains(raw, bad) {
			t.Fatalf("forbidden %q in response", bad)
		}
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, raw)
	}
	if payload["subject_key"] != sk {
		t.Fatalf("subject_key: %+v", payload["subject_key"])
	}
	if payload["principal_cleared"] != true {
		t.Fatalf("principal_cleared: %+v", payload)
	}
	if payload["token_cache_cleared"] != false {
		t.Fatalf("token_cache_cleared without path: %+v", payload)
	}
	if payload["token_cache_path_configured"] != false {
		t.Fatalf("token_cache_path_configured: %+v", payload)
	}
	if payload["principal_cache_path_configured"] != false {
		t.Fatalf("principal_cache_path_configured: %+v", payload)
	}
	note, _ := payload["residual_note"].(string)
	if !strings.Contains(note, "multi-pod") || !strings.Contains(strings.ToLower(note), "not live") {
		t.Fatalf("residual honesty: %q", note)
	}
	if _, ok := gateway.ProcessPrincipalCache().Get(sk); ok {
		t.Fatal("principal must be cleared in process cache")
	}
	// Hash present (secret-free correlation).
	if hash, _ := payload["subject_key_hash"].(string); hash == "" {
		t.Fatal("want subject_key_hash")
	}
}

// HOST-007: FilePrincipalCache when PRINCIPAL_CACHE_PATH set.
func TestGatewaySubjectInvalidate_FilePrincipalCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "principal_cache.json")
	fpc, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	alice := gateway.SubjectKeyParts("tid-fpc-admin", "alice-fpc", "corp")
	bob := gateway.SubjectKeyParts("tid-fpc-admin", "bob-fpc", "corp")
	fpc.Set(alice, "alice-j")
	fpc.Set(bob, "bob-j")

	t.Setenv(gateway.EnvGatewayPrincipalCachePath, path)
	t.Setenv(gateway.EnvGatewayTokenCachePath, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RolePolicyAdmin
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate",
		strings.NewReader(`{"subject_key":`+jsonString(alice)+`}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if strings.Contains(raw, path) {
		t.Fatal("principal cache path value must not appear in admin JSON")
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["principal_cleared"] != true {
		t.Fatalf("principal_cleared: %+v", payload)
	}
	if payload["principal_cache_path_configured"] != true {
		t.Fatalf("principal_cache_path_configured: %+v", payload)
	}

	fpc2, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fpc2.Get(alice); ok {
		t.Fatal("alice principal must be deleted from file cache")
	}
	if p, ok := fpc2.Get(bob); !ok || p != "bob-j" {
		t.Fatalf("bob must remain: ok=%v p=%q", ok, p)
	}
}

// HOST-007: FileTokenCache subject-namespace purge when TOKEN_CACHE_PATH set.
func TestGatewaySubjectInvalidate_FileTokenCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tok-cache.json")
	ftc, err := gateway.NewFileTokenCache(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	alice := gateway.CacheKey{Tenant: "tid-tok", User: "alice-tok", Workload: "wl", Profile: "corp"}
	bob := gateway.CacheKey{Tenant: "tid-tok", User: "bob-tok", Workload: "wl", Profile: "corp"}
	exp := time.Now().Add(time.Hour)
	ftc.Set(alice, gateway.CachedToken{AccessToken: subjectInvalidateCanary + "-a", ExpiresAt: exp})
	ftc.Set(bob, gateway.CachedToken{AccessToken: subjectInvalidateCanary + "-b", ExpiresAt: exp})

	sk := alice.NamespaceSubjectKey()
	gateway.ProcessPrincipalCache().Set(sk, "alice-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })
	t.Setenv(gateway.EnvGatewayTokenCachePath, path)
	t.Setenv(gateway.EnvGatewayPrincipalCachePath, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate",
		bytes.NewReader([]byte(`{"subject_key":`+jsonString(sk)+`}`)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if strings.Contains(raw, subjectInvalidateCanary) {
		t.Fatal("canary token leaked in admin JSON")
	}
	if strings.Contains(raw, path) {
		t.Fatal("token cache path must not appear in admin JSON")
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["token_cache_cleared"] != true {
		t.Fatalf("want token_cache cleared: %+v", payload)
	}
	if payload["token_cache_path_configured"] != true {
		t.Fatalf("path configured: %+v", payload)
	}

	ftc2, err := gateway.NewFileTokenCache(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ftc2.Get(alice); ok {
		t.Fatal("alice token must be deleted from file cache")
	}
	if _, ok := ftc2.Get(bob); !ok {
		t.Fatal("bob token must remain")
	}
}

func TestGatewaySubjectInvalidate_ComposeParts(t *testing.T) {
	sk := gateway.SubjectKeyParts("t-compose", "sub-compose", "corp")
	gateway.ProcessPrincipalCache().Set(sk, "u-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })
	t.Setenv(gateway.EnvGatewayPrincipalCachePath, "")
	t.Setenv(gateway.EnvGatewayTokenCachePath, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"tenant":"t-compose","subject_id":"sub-compose","profile":"corp"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["subject_key"] != sk {
		t.Fatalf("subject_key: %+v", payload["subject_key"])
	}
	if _, ok := gateway.ProcessPrincipalCache().Get(sk); ok {
		t.Fatal("principal must be cleared")
	}
}

func TestGatewaySubjectInvalidate_RequiresSubject(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 empty body, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestGatewaySubjectInvalidate_MalformedKey(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate",
		strings.NewReader(`{"subject_key":"only-two|parts"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 malformed key, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestGatewaySubjectInvalidate_ViewerForbidden(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sk := gateway.SubjectKeyParts("tid", "viewer-deny", "corp")
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate",
		strings.NewReader(`{"subject_key":`+jsonString(sk)+`}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer want 403, got %d body %s", rr.Code, rr.Body.String())
	}
	var errBody map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody["code"] != "permission_denied" {
		t.Fatalf("code=%v", errBody["code"])
	}
}

func TestGatewaySubjectInvalidate_PolicyAdminOK(t *testing.T) {
	sk := gateway.SubjectKeyParts("tid-pa", "pa-ok", "corp")
	gateway.ProcessPrincipalCache().Set(sk, "pa-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })
	t.Setenv(gateway.EnvGatewayPrincipalCachePath, "")
	t.Setenv(gateway.EnvGatewayTokenCachePath, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RolePolicyAdmin
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate",
		strings.NewReader(`{"subject_key":`+jsonString(sk)+`}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("policy_admin want 200, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestGatewaySubjectInvalidate_IgnoresTokenFields(t *testing.T) {
	// Regression: body fields named token / access_token must never be treated
	// as credentials and must never echo into the response.
	sk := gateway.SubjectKeyParts("tid-tok-field", "tok-field", "corp")
	gateway.ProcessPrincipalCache().Set(sk, "u-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })
	t.Setenv(gateway.EnvGatewayPrincipalCachePath, "")
	t.Setenv(gateway.EnvGatewayTokenCachePath, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"subject_key":  sk,
		"token":        subjectInvalidateCanary,
		"access_token": subjectInvalidateCanary,
		"password":     subjectInvalidateCanary,
	}
	rawBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), subjectInvalidateCanary) {
		t.Fatal("Regression: planted body token must never appear in response")
	}
}

func TestGatewaySubjectInvalidate_MethodNotAllowed(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Route is registered as POST only — Go ServeMux returns 404 for GET when no
	// GET pattern exists (405 only when the same path has another method).
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/subject-invalidate", nil))
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET want 404 or 405, got %d", rr.Code)
	}
	// PUT must not invalidate either.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodPut, "/admin/v1/gateway/subject-invalidate",
		strings.NewReader(`{"subject_key":"t|s|p"}`)))
	if rr2.Code != http.StatusNotFound && rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT want 404 or 405, got %d", rr2.Code)
	}
}

func TestGatewaySubjectInvalidate_BearerNeverEchoed(t *testing.T) {
	const adminTok = "admin-bearer-secret-NEVER-ECHO"
	sk := gateway.SubjectKeyParts("tid-bear", "bear-sub", "corp")
	gateway.ProcessPrincipalCache().Set(sk, "u-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })
	t.Setenv(gateway.EnvGatewayPrincipalCachePath, "")
	t.Setenv(gateway.EnvGatewayTokenCachePath, "")

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	cfg.BearerToken = adminTok
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Missing token → 401
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate",
		strings.NewReader(`{"subject_key":`+jsonString(sk)+`}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), adminTok) {
		t.Fatal("401 must not echo admin token")
	}
	// With token → 200, never echo
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/subject-invalidate",
		strings.NewReader(`{"subject_key":`+jsonString(sk)+`}`))
	req.Header.Set("Authorization", "Bearer "+adminTok)
	req.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rr2.Code, rr2.Body.String())
	}
	if strings.Contains(rr2.Body.String(), adminTok) {
		t.Fatal("response must never contain admin bearer")
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
