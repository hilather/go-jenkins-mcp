package admin_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
)

func TestTokenMatches_BearerAndHeader(t *testing.T) {
	const want = "test-admin-secret-xyz"
	// Success: Bearer
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	r.Header.Set("Authorization", "Bearer "+want)
	if !admin.TokenMatches(r, want) {
		t.Fatal("Bearer token should match")
	}
	// Success: alternate header
	r2 := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	r2.Header.Set(admin.HeaderAdminToken, want)
	if !admin.TokenMatches(r2, want) {
		t.Fatal("X-Jenkins-MCP-Admin-Token should match")
	}
	// Fail: wrong token
	r3 := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	r3.Header.Set("Authorization", "Bearer wrong-token")
	if admin.TokenMatches(r3, want) {
		t.Fatal("wrong Bearer must not match")
	}
	// Fail: missing
	r4 := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	if admin.TokenMatches(r4, want) {
		t.Fatal("missing token must not match")
	}
	// Empty want: open
	if !admin.TokenMatches(r4, "") {
		t.Fatal("empty want should always match")
	}
	// Case-insensitive Bearer scheme
	r5 := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	r5.Header.Set("Authorization", "bearer "+want)
	if !admin.TokenMatches(r5, want) {
		t.Fatal("bearer scheme should be case-insensitive")
	}
}

func TestAuthMiddleware_FailAndSuccess(t *testing.T) {
	const token = "admin-gate-token-canary"
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.BearerToken = token
	cfg.Version = "test"
	cfg.Commit = "abc"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Fail without token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without token, got %d body=%s", rr.Code, rr.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody["code"] != "authentication" {
		t.Fatalf("code=%q want authentication", errBody["code"])
	}
	// Canary: token must never appear in body
	if strings.Contains(rr.Body.String(), token) {
		t.Fatal("response must not echo admin token")
	}

	// Success with Bearer
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("want 200 with token, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	body, _ := io.ReadAll(rr2.Body)
	if strings.Contains(string(body), token) {
		t.Fatal("success body must not contain token")
	}

	// Success with header
	rr3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	req3.Header.Set(admin.HeaderAdminToken, token)
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("want 200 with header token, got %d", rr3.Code)
	}

	// SPA root remains open when token configured (assets residual)
	rr4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rr4, req4)
	if rr4.Code != http.StatusOK {
		t.Fatalf("GET / without token should still work, got %d", rr4.Code)
	}
}

func TestHealthWithoutTokenWhenNotConfigured(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Version = "v0.1.0-test"
	cfg.Commit = "deadbeef"
	// BearerToken empty — open on loopback residual
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 without token when not configured, got %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status=%v", body["status"])
	}
	if body["version"] != "v0.1.0-test" {
		t.Fatalf("version=%v", body["version"])
	}
	if body["commit"] != "deadbeef" {
		t.Fatalf("commit=%v", body["commit"])
	}
}
