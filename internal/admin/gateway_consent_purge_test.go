package admin_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

const consentPurgeCanary = "admin-consent-purge-canary-NEVER-IN-JSON"

// HOST-007: POST /admin/v1/gateway/consent-purge default purge_expired.
func TestGatewayConsentPurge_PurgeExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "consent_sessions.json")
	now := time.Now().UTC()
	seed := fmt.Sprintf(`{
  "version": 1,
  "entries": {
    "sess-live": {
      "authorization_url": "https://login.example/authorize?state=live&code=not-a-token",
      "session_id": "sess-live",
      "provider": "agentcore",
      "stored_at": %q,
      "expires_at": %q
    },
    "sess-exp": {
      "authorization_url": "https://login.example/authorize?state=exp",
      "session_id": "sess-exp",
      "provider": "agentcore",
      "stored_at": %q,
      "expires_at": %q
    }
  }
}
`, now.Add(-time.Hour).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano),
		now.Add(-2*time.Hour).Format(time.RFC3339Nano), now.Add(-time.Minute).Format(time.RFC3339Nano))
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvConsentSessionStorePath, path)
	t.Setenv("HOST007_CONSENT_FAKE_TOKEN", consentPurgeCanary)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	assertConsentPurgeAdminSecretFree(t, raw, path)
	if strings.Contains(raw, "sess-live") || strings.Contains(raw, "sess-exp") {
		t.Fatal("Regression: session_id must not be echoed in consent-purge JSON")
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, raw)
	}
	if payload["action"] != "purge_expired" {
		t.Fatalf("action: %+v", payload["action"])
	}
	if payload["deleted_count"] != float64(1) {
		t.Fatalf("deleted_count: %+v", payload["deleted_count"])
	}
	if payload["remaining_count"] != float64(1) {
		t.Fatalf("remaining_count: %+v", payload["remaining_count"])
	}
	if payload["metadata_only"] != true || payload["stores_tokens"] != false {
		t.Fatalf("honesty flags: %+v", payload)
	}
	if payload["file_basename"] != "consent_sessions.json" {
		t.Fatalf("file_basename: %+v", payload["file_basename"])
	}
	if payload["file_backed"] != true {
		t.Fatalf("file_backed: %+v", payload)
	}
	note, _ := payload["residual_note"].(string)
	if !strings.Contains(note, "multi-replica") || !strings.Contains(note, "never tokens") {
		t.Fatalf("residual honesty: %q", note)
	}
	if !strings.Contains(strings.ToLower(note), "browser") {
		t.Fatalf("want browser 3LO residual: %q", note)
	}

	// Live session still on disk; expired gone.
	reloaded, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Get("sess-live"); !ok {
		t.Fatal("live session must remain after purge_expired")
	}
	if _, ok := reloaded.Get("sess-exp"); ok {
		t.Fatal("expired session must be purged")
	}
}

// HOST-007: delete_session by session_id.
func TestGatewayConsentPurge_DeleteSession(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	store, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize?state=del",
			SessionID:        "sess-del-1",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize?state=keep",
			SessionID:        "sess-keep-1",
		},
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RolePolicyAdmin
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"action":"delete_session","session_id":"sess-del-1"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	assertConsentPurgeAdminSecretFree(t, raw, path)
	// session_id used for delete must not appear in response.
	if strings.Contains(raw, "sess-del-1") {
		t.Fatal("Regression: session_id must not be echoed")
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != "delete_session" || payload["deleted_count"] != float64(1) {
		t.Fatalf("delete_session: %+v", payload)
	}
	if payload["remaining_count"] != float64(1) {
		t.Fatalf("remaining: %+v", payload["remaining_count"])
	}

	reloaded, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Get("sess-del-1"); ok {
		t.Fatal("deleted session must be gone")
	}
	if _, ok := reloaded.Get("sess-keep-1"); !ok {
		t.Fatal("other session must remain")
	}
}

// HOST-007: clear_all requires explicit flag / action.
func TestGatewayConsentPurge_ClearAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clear.json")
	store, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"sess-a", "sess-b"} {
		if err := store.Put(gateway.ConsentSessionRecord{
			Info: gateway.ConsentInfo{
				AuthorizationURL: "https://login.example/authorize?state=" + sid,
				SessionID:        sid,
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Explicit clear_all:true
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{"clear_all":true}`))
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
	if payload["action"] != "clear_all" || payload["deleted_count"] != float64(2) {
		t.Fatalf("clear_all: %+v", payload)
	}
	if payload["remaining_count"] != float64(0) {
		t.Fatalf("remaining: %+v", payload["remaining_count"])
	}
	assertConsentPurgeAdminSecretFree(t, rr.Body.String(), path)

	reloaded, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.List()) != 0 {
		t.Fatal("clear_all must empty store")
	}
}

func TestGatewayConsentPurge_ClearAllViaAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clear2.json")
	store, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize?state=x",
			SessionID:        "sess-x",
		},
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{"action":"clear_all"}`))
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
	if payload["action"] != "clear_all" || payload["deleted_count"] != float64(1) {
		t.Fatalf("action clear_all: %+v", payload)
	}
}

func TestGatewayConsentPurge_ClearAllAndSessionExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{"clear_all":true,"session_id":"sess-x"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 mutual exclusion, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestGatewayConsentPurge_DeleteSessionRequiresID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{"action":"delete_session"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 missing session_id, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestGatewayConsentPurge_PathOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "explicit.json")
	store, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize?state=p",
			SessionID:        "sess-path-1",
		},
	}); err != nil {
		t.Fatal(err)
	}
	// Env points at another basename in the same store dir — body path may select
	// a sibling file under that directory (admin path jail).
	t.Setenv(gateway.EnvConsentSessionStorePath, filepath.Join(dir, "other.json"))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"clear_all": true, "path": path}
	rawBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	if strings.Contains(raw, path) {
		t.Fatal("full consent store path must not appear in admin JSON")
	}
	if strings.Contains(raw, "sess-path-1") {
		t.Fatal("session_id must not be echoed")
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["deleted_count"] != float64(1) {
		t.Fatalf("deleted: %+v", payload["deleted_count"])
	}
	if payload["file_basename"] != "explicit.json" {
		t.Fatalf("basename: %+v", payload["file_basename"])
	}

	reloaded, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.List()) != 0 {
		t.Fatal("path clear_all must clear explicit file")
	}
}

// Regression: body path outside the configured consent store directory must fail
// closed (no arbitrary file overwrite via gateway_ops admin BFF).
func TestGatewayConsentPurge_PathJailRejectsOutsideStoreDir(t *testing.T) {
	storeDir := t.TempDir()
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "not-consent.json")
	// Plant a canary file that must not be rewritten by clear_all.
	canary := []byte(`{"do_not_overwrite":true,"marker":"admin-consent-path-jail-CANARY"}`)
	if err := os.WriteFile(outside, canary, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvConsentSessionStorePath, filepath.Join(storeDir, "consent_sessions.json"))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"clear_all": true, "path": outside}
	rawBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 path jail, got %d body %s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	// Never echo the full outside path or canary contents.
	if strings.Contains(raw, outside) {
		t.Fatal("Regression: outside path leaked in error body")
	}
	if strings.Contains(raw, "admin-consent-path-jail-CANARY") {
		t.Fatal("Regression: canary leaked in error body")
	}
	// File must be unchanged (no clear/overwrite).
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(canary) {
		t.Fatalf("Regression: outside file was modified: %s", got)
	}
}

func TestGatewayConsentPurge_PathJailRejectsRelativeAndTraversal(t *testing.T) {
	storeDir := t.TempDir()
	t.Setenv(gateway.EnvConsentSessionStorePath, filepath.Join(storeDir, "consent_sessions.json"))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
	}{
		{name: "relative", path: "consent_sessions.json"},
		{name: "dotdot_escape", path: filepath.Join(storeDir, "..", filepath.Base(t.TempDir()), "escape.json")},
		{name: "nested_subdir", path: filepath.Join(storeDir, "nested", "deep.json")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"action": "purge_expired", "path": tc.path}
			rawBody, _ := json.Marshal(body)
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge", bytes.NewReader(rawBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d body %s", rr.Code, rr.Body.String())
			}
			// Fail closed: never echo absolute path override in error JSON.
			if filepath.IsAbs(tc.path) && strings.Contains(rr.Body.String(), tc.path) {
				t.Fatal("Regression: absolute path override leaked in error body")
			}
		})
	}
}

func TestGatewayConsentPurge_ViewerForbidden(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(gateway.EnvConsentSessionStorePath, filepath.Join(dir, "c.json"))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleViewer
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{}`))
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

func TestGatewayConsentPurge_IgnoresTokenFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tok.json")
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"action":       "purge_expired",
		"token":        consentPurgeCanary,
		"access_token": consentPurgeCanary,
		"password":     consentPurgeCanary,
	}
	rawBody, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), consentPurgeCanary) {
		t.Fatal("Regression: planted body token must never appear in response")
	}
}

func TestGatewayConsentPurge_BearerNeverEchoed(t *testing.T) {
	const adminTok = "admin-consent-bearer-secret-NEVER-ECHO"
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

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
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), adminTok) {
		t.Fatal("401 must not echo admin token")
	}
	// With token → 200, never echo
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge", strings.NewReader(`{}`))
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

func TestGatewayConsentPurge_MethodNotAllowed(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/gateway/consent-purge", nil))
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET want 404 or 405, got %d", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodPut, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{}`)))
	if rr2.Code != http.StatusNotFound && rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT want 404 or 405, got %d", rr2.Code)
	}
}

func TestGatewayConsentPurge_UnknownAction(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(gateway.EnvConsentSessionStorePath, filepath.Join(dir, "u.json"))

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Role = admin.RoleOperator
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/gateway/consent-purge",
		strings.NewReader(`{"action":"explode"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 unknown action, got %d %s", rr.Code, rr.Body.String())
	}
}

func assertConsentPurgeAdminSecretFree(t *testing.T, out, fullPath string) {
	t.Helper()
	for _, bad := range []string{
		consentPurgeCanary,
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"Authorization: Bearer",
	} {
		if strings.Contains(out, bad) {
			t.Fatalf("forbidden %q in consent-purge admin JSON", bad)
		}
	}
	if fullPath != "" && strings.Contains(out, fullPath) {
		t.Fatal("full consent store path must not appear in admin JSON")
	}
}
