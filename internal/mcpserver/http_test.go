package mcpserver_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

func TestValidateListenAddr_LoopbackOnly(t *testing.T) {
	t.Parallel()
	// Accepted without AllowNonLocal.
	for _, addr := range []string{
		"127.0.0.1:8765",
		"localhost:0",
		"[::1]:9090",
		"127.0.0.1:0",
	} {
		if err := mcpserver.ValidateListenAddr(addr, false); err != nil {
			t.Errorf("expected allow %q: %v", addr, err)
		}
	}
	// Rejected by default (non-local / all-interfaces).
	for _, addr := range []string{
		"0.0.0.0:8765",
		"[::]:8765",
		":8765",
		"192.168.1.10:8765",
		"example.com:8765",
	} {
		err := mcpserver.ValidateListenAddr(addr, false)
		if err == nil {
			t.Errorf("expected reject %q", addr)
			continue
		}
		if !strings.Contains(err.Error(), "loopback") && !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%q: unexpected error: %v", addr, err)
		}
	}
	// Empty.
	if err := mcpserver.ValidateListenAddr("", false); err == nil {
		t.Fatal("expected empty addr error")
	}
	// AllowNonLocal opts out of bind enforcement (origin allow-list checked separately).
	if err := mcpserver.ValidateListenAddr("0.0.0.0:8765", true); err != nil {
		t.Fatalf("AllowNonLocal should permit 0.0.0.0: %v", err)
	}
}

func TestValidateHTTPConfig_NonLocalRequiresOrigins(t *testing.T) {
	t.Parallel()
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "0.0.0.0:8765"
	cfg.AllowNonLocal = true
	err := mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("expected AllowNonLocal without origins to fail closed")
	}
	if !strings.Contains(err.Error(), "allowed-origin") && !strings.Contains(err.Error(), "origin") {
		t.Fatalf("unexpected: %v", err)
	}
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	// Wave 35: non-local also requires AllowedHosts before token check.
	err = mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("expected AllowNonLocal without AllowedHosts to fail closed")
	}
	if !strings.Contains(err.Error(), "allowed-host") && !strings.Contains(err.Error(), "host") {
		t.Fatalf("unexpected: %v", err)
	}
	cfg.AllowedHosts = []string{"mcp.example.corp"}
	// Non-local still fails without shared secret (Wave 32 fail-closed).
	err = mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("expected AllowNonLocal without token to fail closed")
	}
	if !strings.Contains(err.Error(), "shared secret") && !strings.Contains(err.Error(), "token") {
		t.Fatalf("unexpected: %v", err)
	}
	cfg.BearerToken = "test-token-xyz"
	if err := mcpserver.ValidateHTTPConfig(cfg); err != nil {
		t.Fatalf("with origins+hosts+token: %v", err)
	}
	// Loopback default still fine without origins, hosts, or token.
	cfg2 := mcpserver.DefaultHTTPConfig()
	cfg2.Addr = "127.0.0.1:8765"
	if err := mcpserver.ValidateHTTPConfig(cfg2); err != nil {
		t.Fatalf("loopback: %v", err)
	}
}

// Wave 35: non-local bind requires AllowedHosts (DNS rebinding defense).
func TestValidateHTTPConfig_NonLocalRequiresAllowedHosts(t *testing.T) {
	t.Parallel()
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "0.0.0.0:8765"
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	cfg.BearerToken = "test-token-xyz"
	// Missing AllowedHosts → fail closed.
	err := mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("expected missing AllowedHosts to fail closed")
	}
	if !strings.Contains(err.Error(), "allowed-host") {
		t.Fatalf("unexpected: %v", err)
	}
	// Empty entry → fail closed.
	cfg.AllowedHosts = []string{"  "}
	err = mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("expected empty AllowedHosts entry to fail")
	}
	// URL-like entry → fail closed.
	cfg.AllowedHosts = []string{"https://mcp.example.corp"}
	err = mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("expected URL-like AllowedHosts entry to fail")
	}
	// Hostname and hostname:port accepted.
	cfg.AllowedHosts = []string{"mcp.example.corp", "192.168.1.10:8765"}
	if err := mcpserver.ValidateHTTPConfig(cfg); err != nil {
		t.Fatalf("valid hosts: %v", err)
	}
	// Loopback unchanged: no AllowedHosts required.
	cfgLoop := mcpserver.DefaultHTTPConfig()
	cfgLoop.Addr = "127.0.0.1:8765"
	if err := mcpserver.ValidateHTTPConfig(cfgLoop); err != nil {
		t.Fatalf("loopback without AllowedHosts: %v", err)
	}
}

// Wave 32 / KD-008: require-token and non-local always need a non-empty secret.
func TestValidateHTTPConfig_RequireToken(t *testing.T) {
	t.Parallel()

	// require without token → error
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "127.0.0.1:8765"
	cfg.RequireToken = true
	err := mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("expected RequireToken without BearerToken to fail")
	}
	if !strings.Contains(err.Error(), "http-require-token") {
		t.Fatalf("unexpected: %v", err)
	}
	if strings.Contains(err.Error(), "test-token") {
		t.Fatalf("must not embed secrets: %v", err)
	}

	// require with token → ok
	cfg.BearerToken = "test-token-xyz"
	if err := mcpserver.ValidateHTTPConfig(cfg); err != nil {
		t.Fatalf("require+token: %v", err)
	}
	if !mcpserver.HTTPTokenRequired(cfg) {
		t.Fatal("HTTPTokenRequired should be true when RequireToken set")
	}

	// non-local without token → error (even with origins + hosts)
	cfgNL := mcpserver.DefaultHTTPConfig()
	cfgNL.Addr = "0.0.0.0:8765"
	cfgNL.AllowNonLocal = true
	cfgNL.AllowedOrigins = []string{"https://portal.example.corp"}
	cfgNL.AllowedHosts = []string{"mcp.example.corp"}
	err = mcpserver.ValidateHTTPConfig(cfgNL)
	if err == nil {
		t.Fatal("expected non-local without token to fail")
	}
	if !strings.Contains(err.Error(), "http-allow-non-local") {
		t.Fatalf("unexpected: %v", err)
	}
	if !mcpserver.HTTPTokenRequired(cfgNL) {
		t.Fatal("HTTPTokenRequired should be true for AllowNonLocal")
	}

	// non-local with token + origin + host → ok
	cfgNL.BearerToken = "test-token-xyz"
	if err := mcpserver.ValidateHTTPConfig(cfgNL); err != nil {
		t.Fatalf("non-local+token+origin+host: %v", err)
	}

	// require off, loopback, empty token → current compat behavior
	cfgCompat := mcpserver.DefaultHTTPConfig()
	cfgCompat.Addr = "127.0.0.1:8765"
	if err := mcpserver.ValidateHTTPConfig(cfgCompat); err != nil {
		t.Fatalf("compat loopback empty token: %v", err)
	}
	if mcpserver.HTTPTokenRequired(cfgCompat) {
		t.Fatal("HTTPTokenRequired should be false for default loopback")
	}
	if cfgCompat.BearerToken != "" {
		t.Fatal("BearerToken should remain empty")
	}
}

func TestNewHTTPHandler_NonLocalStillRejectsArbitraryOrigin(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	cfg.AllowedHosts = []string{"192.168.1.10"}
	// Wave 32: non-local always requires a shared secret (fail closed at handler build).
	cfg.BearerToken = "test-shared-secret"
	// HOST-001: non-local implies RequireSubject — lab identity for offline tests.
	cfg.LabIdentity = true
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://0.0.0.0:8765/mcp", strings.NewReader(`{}`))
	req.Host = "192.168.1.10:8765"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer test-shared-secret")
	req.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	// Allowed origin + host passes protect layer (SDK may still 4xx on body).
	req2 := httptest.NewRequest(http.MethodPost, "http://0.0.0.0:8765/mcp", strings.NewReader(`{}`))
	req2.Host = "192.168.1.10:8765"
	req2.Header.Set("Origin", "https://portal.example.corp")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")
	req2.Header.Set("Authorization", "Bearer test-shared-secret")
	req2.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusForbidden && strings.Contains(rr2.Body.String(), "Origin") {
		t.Fatalf("allowed origin should not fail Origin check: %s", rr2.Body.String())
	}
	if rr2.Code == http.StatusForbidden && strings.Contains(rr2.Body.String(), "Host") {
		t.Fatalf("allowed host should not fail Host check: %s", rr2.Body.String())
	}
	if rr2.Code == http.StatusUnauthorized {
		t.Fatalf("lab subject + token should not 401: %s", rr2.Body.String())
	}
}

// Wave 35: non-local Host allow-list (DNS rebinding defense).
func TestNewHTTPHandler_NonLocalHostAllowList(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	cfg.AllowedHosts = []string{"mcp.example.corp", "192.168.1.10:8765"}
	cfg.BearerToken = "test-shared-secret"
	// HOST-001: non-local implies RequireSubject.
	cfg.LabIdentity = true
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Allowed host (case-insensitive, port-normalized) passes Host check.
	reqOK := httptest.NewRequest(http.MethodPost, "http://mcp.example.corp/mcp", strings.NewReader(`{}`))
	reqOK.Host = "MCP.Example.Corp:9443"
	reqOK.Header.Set("Content-Type", "application/json")
	reqOK.Header.Set("Accept", "application/json, text/event-stream")
	reqOK.Header.Set("Authorization", "Bearer test-shared-secret")
	reqOK.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rrOK := httptest.NewRecorder()
	h.ServeHTTP(rrOK, reqOK)
	if rrOK.Code == http.StatusForbidden {
		t.Fatalf("allowed host should not 403: %s", rrOK.Body.String())
	}

	// Allowed host entry with port matches request without port difference.
	reqIP := httptest.NewRequest(http.MethodPost, "http://192.168.1.10/mcp", strings.NewReader(`{}`))
	reqIP.Host = "192.168.1.10:9999"
	reqIP.Header.Set("Content-Type", "application/json")
	reqIP.Header.Set("Accept", "application/json, text/event-stream")
	reqIP.Header.Set("Authorization", "Bearer test-shared-secret")
	reqIP.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rrIP := httptest.NewRecorder()
	h.ServeHTTP(rrIP, reqIP)
	if rrIP.Code == http.StatusForbidden {
		t.Fatalf("allowed IP host should not 403: %s", rrIP.Body.String())
	}

	// Wrong Host → 403.
	reqBad := httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", strings.NewReader(`{}`))
	reqBad.Host = "evil.example"
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.Header.Set("Accept", "application/json, text/event-stream")
	reqBad.Header.Set("Authorization", "Bearer test-shared-secret")
	reqBad.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rrBad := httptest.NewRecorder()
	h.ServeHTTP(rrBad, reqBad)
	if rrBad.Code != http.StatusForbidden {
		t.Fatalf("wrong Host want 403, got %d body=%s", rrBad.Code, rrBad.Body.String())
	}
	if !strings.Contains(rrBad.Body.String(), "not allowed") && !strings.Contains(rrBad.Body.String(), "Host") {
		t.Fatalf("body should mention Host allow-list: %s", rrBad.Body.String())
	}
}

// Loopback mode still rejects non-loopback Host (unchanged; AllowedHosts unused).
func TestNewHTTPHandler_LoopbackHostUnchangedWithoutAllowedHosts(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	// No AllowedHosts; loopback-only.
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	reqLoop := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	reqLoop.Host = "127.0.0.1:8765"
	reqLoop.Header.Set("Content-Type", "application/json")
	reqLoop.Header.Set("Accept", "application/json, text/event-stream")
	rrLoop := httptest.NewRecorder()
	h.ServeHTTP(rrLoop, reqLoop)
	if rrLoop.Code == http.StatusForbidden {
		t.Fatalf("loopback Host should pass: %s", rrLoop.Body.String())
	}
	reqEvil := httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", strings.NewReader(`{}`))
	reqEvil.Host = "evil.example"
	reqEvil.Header.Set("Content-Type", "application/json")
	reqEvil.Header.Set("Accept", "application/json, text/event-stream")
	rrEvil := httptest.NewRecorder()
	h.ServeHTTP(rrEvil, reqEvil)
	if rrEvil.Code != http.StatusForbidden {
		t.Fatalf("non-loopback Host want 403, got %d", rrEvil.Code)
	}
	if !strings.Contains(rrEvil.Body.String(), "loopback") {
		t.Fatalf("body: %s", rrEvil.Body.String())
	}
}

func TestNewHTTPHandler_RejectsNonLoopbackHost(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	h, err := mcpserver.NewHTTPHandler(srv, mcpserver.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", strings.NewReader(`{}`))
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "loopback") {
		t.Fatalf("body: %s", rr.Body.String())
	}
}

func TestNewHTTPHandler_RejectsNonLoopbackOrigin(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	h, err := mcpserver.NewHTTPHandler(srv, mcpserver.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestNewHTTPHandler_AllowsLoopbackOriginAndMissingOrigin(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	h, err := mcpserver.NewHTTPHandler(srv, mcpserver.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Missing Origin: protection layer must not 403 (SDK may still 400 on body).
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req.Host = "127.0.0.1:8765"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("missing Origin should not be Forbidden: %s", rr.Body.String())
	}

	// Loopback Origin allowed past protectHandler.
	req2 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req2.Host = "127.0.0.1"
	req2.Header.Set("Origin", "http://127.0.0.1:3000")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusForbidden {
		t.Fatalf("loopback Origin Forbidden: %s", rr2.Body.String())
	}
}

func TestNewHTTPHandler_BodyLimit(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.MaxBodyBytes = 64
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Oversized Content-Length: early 413 before SDK body parse.
	body := bytes.Repeat([]byte("x"), 256)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", bytes.NewReader(body))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.ContentLength = int64(len(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "too large") {
		t.Fatalf("body: %s", rr.Body.String())
	}
}

func TestRunHTTP_RejectsNonLocalBind(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "0.0.0.0:0"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := mcpserver.RunHTTP(ctx, srv, cfg)
	if err == nil {
		t.Fatal("expected non-local bind rejection")
	}
	if !strings.Contains(err.Error(), "loopback") && !strings.Contains(err.Error(), "http-allow-non-local") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestRunHTTP_LoopbackListenAndShutdown(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	// Pick a free loopback port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = addr
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- mcpserver.RunHTTP(ctx, srv, cfg)
	}()

	// Wait until the port accepts connections.
	deadline := time.Now().Add(3 * time.Second)
	var dialErr error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			dialErr = nil
			break
		}
		dialErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if dialErr != nil {
		cancel()
		t.Fatalf("server never became ready: %v", dialErr)
	}

	// Host protection: non-loopback Host → 403.
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/mcp", strings.NewReader(`{}`))
	req.Host = "evil.example"
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunHTTP shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunHTTP did not exit after cancel")
	}
}

func TestNewServer(t *testing.T) {
	t.Parallel()
	s := mcpserver.NewServer("n", "v1")
	if s == nil {
		t.Fatal("nil server")
	}
	// Defaults for empty name/version.
	s2 := mcpserver.NewServer("", "")
	if s2 == nil {
		t.Fatal("nil server with defaults")
	}
}

// canaryHTTPToken is a fixture shared secret for KD-008 lite tests.
// Regression: this string must never appear in 401 error bodies.
const canaryHTTPToken = "test-token-xyz"

func newTokenHandler(t *testing.T, token string) http.Handler {
	t.Helper()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.BearerToken = token
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func postLoopback(t *testing.T, h http.Handler, setAuth func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req.Host = "127.0.0.1:8765"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if setAuth != nil {
		setAuth(req)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestNewHTTPHandler_TokenMissing401(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, canaryHTTPToken)
	rr := postLoopback(t, h, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, canaryHTTPToken) {
		t.Fatalf("canary token leaked in 401 body: %s", body)
	}
	if !strings.Contains(strings.ToLower(body), "unauthorized") {
		t.Fatalf("body: %s", body)
	}
}

func TestNewHTTPHandler_TokenWrong401(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, canaryHTTPToken)
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer wrong-token-not-the-canary")
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, canaryHTTPToken) {
		t.Fatalf("canary token leaked in 401 body: %s", body)
	}
	// Wrong header token must not be reflected either in a way that echoes expected.
	if strings.Contains(body, "test-token") {
		t.Fatalf("token-like material in body: %s", body)
	}
}

func TestNewHTTPHandler_TokenCorrectBearerPassesProtect(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, canaryHTTPToken)
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	})
	// Protection layer must not 401/403; SDK may still 4xx on empty JSON-RPC.
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("valid Bearer should not 401: %s", rr.Body.String())
	}
	if rr.Code == http.StatusForbidden {
		t.Fatalf("valid Bearer should not 403: %s", rr.Body.String())
	}
}

func TestNewHTTPHandler_TokenCorrectHeaderPassesProtect(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, canaryHTTPToken)
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderJenkinsMCPToken, canaryHTTPToken)
	})
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("valid X-Jenkins-MCP-Token should not 401: %s", rr.Body.String())
	}
	if rr.Code == http.StatusForbidden {
		t.Fatalf("valid header token should not 403: %s", rr.Body.String())
	}
}

func TestNewHTTPHandler_EmptyTokenConfigSkipsCheck(t *testing.T) {
	t.Parallel()
	// Empty BearerToken: behavior unchanged — no 401 from auth gate.
	h := newTokenHandler(t, "")
	rr := postLoopback(t, h, nil)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("empty token config must skip auth gate: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestNewHTTPHandler_TokenWrongHeader401(t *testing.T) {
	t.Parallel()
	h := newTokenHandler(t, canaryHTTPToken)
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderJenkinsMCPToken, "not-"+canaryHTTPToken)
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canaryHTTPToken) {
		t.Fatalf("canary leaked: %s", rr.Body.String())
	}
}

func TestNewHTTPHandler_TokenAppliesToGET(t *testing.T) {
	t.Parallel()
	// Shared secret gates SSE GET as well (Streamable HTTP).
	h := newTokenHandler(t, canaryHTTPToken)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp", nil)
	req.Host = "127.0.0.1:8765"
	req.Header.Set("Accept", "text/event-stream")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("GET without token want 401, got %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canaryHTTPToken) {
		t.Fatalf("canary leaked on GET 401: %s", rr.Body.String())
	}
}

// --- HOST-002 path-prefix reverse-proxy ------------------------------------

func TestValidateHTTPPathPrefix(t *testing.T) {
	t.Parallel()
	// Accepted / normalized.
	for _, tc := range []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"/", ""},
		{"/mcp", "/mcp"},
		{"/mcp/", "/mcp"},
		{"/api/mcp", "/api/mcp"},
		{"/api/mcp/", "/api/mcp"},
		{"  /gateway  ", "/gateway"},
	} {
		got, err := mcpserver.ValidateHTTPPathPrefix(tc.in)
		if err != nil {
			t.Errorf("ValidateHTTPPathPrefix(%q) err=%v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ValidateHTTPPathPrefix(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
	// Fail closed.
	for _, bad := range []string{
		"mcp",         // missing leading /
		"//mcp",       // double slash
		"/mcp//v1",    // internal //
		"/../mcp",     // parent segment
		"/mcp/..",     // parent segment
		"/mcp/../x",   // parent segment
		"/mcp/./x",    // dot segment
		"/mcp\\x",     // backslash
		"http://x/mcp", // not a path
	} {
		_, err := mcpserver.ValidateHTTPPathPrefix(bad)
		if err == nil {
			t.Errorf("ValidateHTTPPathPrefix(%q) expected error", bad)
		}
	}
}

func TestResolveHTTPPathPrefix(t *testing.T) {
	t.Parallel()
	// Empty → none.
	got, err := mcpserver.ResolveHTTPPathPrefix("", "")
	if err != nil || got != "" {
		t.Fatalf("empty: got=%q err=%v", got, err)
	}
	// Env only.
	got, err = mcpserver.ResolveHTTPPathPrefix("", "/from-env")
	if err != nil || got != "/from-env" {
		t.Fatalf("env: got=%q err=%v", got, err)
	}
	// Flag wins over env.
	got, err = mcpserver.ResolveHTTPPathPrefix("/from-flag", "/from-env")
	if err != nil || got != "/from-flag" {
		t.Fatalf("flag wins: got=%q err=%v", got, err)
	}
	// Flag empty keeps env.
	got, err = mcpserver.ResolveHTTPPathPrefix("  ", "/mcp/")
	if err != nil || got != "/mcp" {
		t.Fatalf("whitespace flag + env: got=%q err=%v", got, err)
	}
	// Invalid env fails closed and names source.
	_, err = mcpserver.ResolveHTTPPathPrefix("", "no-slash")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), mcpserver.EnvHTTPPathPrefix) && !strings.Contains(err.Error(), "env") {
		t.Fatalf("error should name env source: %v", err)
	}
	// Invalid flag fails closed and names flag.
	_, err = mcpserver.ResolveHTTPPathPrefix("//bad", "/ok")
	if err == nil {
		t.Fatal("invalid flag must fail closed")
	}
	if !strings.Contains(err.Error(), "flag") && !strings.Contains(err.Error(), "http-path-prefix") {
		t.Fatalf("error should name flag source: %v", err)
	}
	if mcpserver.EnvHTTPPathPrefix != "JENKINS_MCP_HTTP_PATH_PREFIX" {
		t.Fatalf("env name drift: %q", mcpserver.EnvHTTPPathPrefix)
	}
}

func TestValidateHTTPConfig_PathPrefix(t *testing.T) {
	t.Parallel()
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "127.0.0.1:8765"
	cfg.PathPrefix = "/mcp"
	if err := mcpserver.ValidateHTTPConfig(cfg); err != nil {
		t.Fatalf("valid prefix: %v", err)
	}
	cfg.PathPrefix = "../evil"
	err := mcpserver.ValidateHTTPConfig(cfg)
	if err == nil {
		t.Fatal("invalid path prefix must fail closed")
	}
	if !strings.Contains(err.Error(), "path prefix") && !strings.Contains(err.Error(), "..") {
		t.Fatalf("unexpected: %v", err)
	}
}

// HOST-002: with PathPrefix=/mcp, MCP POSTs under /mcp pass protect; root MCP 404s.
func TestNewHTTPHandler_PathPrefix_MCPRoutes(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.PathPrefix = "/mcp"
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Under prefix: protect layer must not 403/404 (SDK may still 4xx on body).
	reqOK := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	reqOK.Host = "127.0.0.1:8765"
	reqOK.Header.Set("Content-Type", "application/json")
	reqOK.Header.Set("Accept", "application/json, text/event-stream")
	rrOK := httptest.NewRecorder()
	h.ServeHTTP(rrOK, reqOK)
	if rrOK.Code == http.StatusNotFound {
		t.Fatalf("prefixed MCP path should not 404: %s", rrOK.Body.String())
	}
	if rrOK.Code == http.StatusForbidden {
		t.Fatalf("prefixed MCP path should not 403: %s", rrOK.Body.String())
	}

	// Nested under prefix also accepted (strip leaves residual path).
	reqNest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp/v1", strings.NewReader(`{}`))
	reqNest.Host = "127.0.0.1:8765"
	reqNest.Header.Set("Content-Type", "application/json")
	reqNest.Header.Set("Accept", "application/json, text/event-stream")
	rrNest := httptest.NewRecorder()
	h.ServeHTTP(rrNest, reqNest)
	if rrNest.Code == http.StatusNotFound {
		t.Fatalf("nested prefixed MCP path should not 404: %s", rrNest.Body.String())
	}

	// Root MCP when prefix configured → 404.
	reqRoot := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", strings.NewReader(`{}`))
	reqRoot.Host = "127.0.0.1:8765"
	reqRoot.Header.Set("Content-Type", "application/json")
	reqRoot.Header.Set("Accept", "application/json, text/event-stream")
	rrRoot := httptest.NewRecorder()
	h.ServeHTTP(rrRoot, reqRoot)
	if rrRoot.Code != http.StatusNotFound {
		t.Fatalf("root MCP with prefix want 404, got %d body=%s", rrRoot.Code, rrRoot.Body.String())
	}

	// Non-boundary match /mcpfoo must not strip as /mcp → 404.
	reqBoundary := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcpfoo", strings.NewReader(`{}`))
	reqBoundary.Host = "127.0.0.1:8765"
	reqBoundary.Header.Set("Content-Type", "application/json")
	reqBoundary.Header.Set("Accept", "application/json, text/event-stream")
	rrBoundary := httptest.NewRecorder()
	h.ServeHTTP(rrBoundary, reqBoundary)
	if rrBoundary.Code != http.StatusNotFound {
		t.Fatalf("/mcpfoo with prefix /mcp want 404, got %d", rrBoundary.Code)
	}
}

// HOST-002: without PathPrefix, root and /mcp MCP paths still reach protect (unchanged).
func TestNewHTTPHandler_PathPrefix_EmptyUnchanged(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	h, err := mcpserver.NewHTTPHandler(srv, mcpserver.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/mcp", "/anything"} {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, strings.NewReader(`{}`))
		req.Host = "127.0.0.1:8765"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusNotFound {
			t.Fatalf("path %q without prefix must not 404: %s", path, rr.Body.String())
		}
		if rr.Code == http.StatusForbidden {
			t.Fatalf("path %q without prefix must not 403: %s", path, rr.Body.String())
		}
	}
}

// HOST-002: health at root always; with prefix also at {prefix}/healthz and {prefix}/readyz.
func TestNewHTTPHandler_PathPrefix_Health(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.PathPrefix = "/mcp"
	cfg.BearerToken = canaryHTTPToken // health must skip token
	ready := false
	cfg.ReadyCheck = func() bool { return ready }
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = "127.0.0.1:8765"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	for _, path := range []string{
		mcpserver.HealthzPath,
		"/mcp" + mcpserver.HealthzPath,
	} {
		rr := get(path)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s want 200, got %d body=%s", path, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
			t.Fatalf("%s body: %s", path, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), canaryHTTPToken) {
			t.Fatalf("%s leaked token: %s", path, rr.Body.String())
		}
	}

	// Root + prefixed readyz when not ready → 503, secret-free.
	for _, path := range []string{
		mcpserver.ReadyzPath,
		"/mcp" + mcpserver.ReadyzPath,
	} {
		rr := get(path)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s not ready want 503, got %d body=%s", path, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "gateway_ready") {
			t.Fatalf("%s body missing gateway_ready: %s", path, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), canaryHTTPToken) {
			t.Fatalf("%s leaked token: %s", path, rr.Body.String())
		}
	}
	ready = true
	for _, path := range []string{
		mcpserver.ReadyzPath,
		"/mcp" + mcpserver.ReadyzPath,
	} {
		rr := get(path)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s ready want 200, got %d body=%s", path, rr.Code, rr.Body.String())
		}
	}

	// Without prefix: only root health; /mcp/healthz is not our unauthenticated health path.
	h2, err := mcpserver.NewHTTPHandler(srv, mcpserver.DefaultHTTPConfig())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/mcp"+mcpserver.HealthzPath, nil)
	req.Host = "127.0.0.1:8765"
	rr := httptest.NewRecorder()
	h2.ServeHTTP(rr, req)
	// SDK GET without session is typically 4xx/405 — must not look like secret-free health.
	if rr.Code == http.StatusOK && strings.TrimSpace(rr.Body.String()) == `{"status":"ok"}` {
		t.Fatalf("without PathPrefix, /mcp/healthz must not be treated as health endpoint")
	}
	// Root health still works without prefix.
	reqRoot := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+mcpserver.HealthzPath, nil)
	reqRoot.Host = "127.0.0.1:8765"
	rrRoot := httptest.NewRecorder()
	h2.ServeHTTP(rrRoot, reqRoot)
	if rrRoot.Code != http.StatusOK || !strings.Contains(rrRoot.Body.String(), `"status":"ok"`) {
		t.Fatalf("root health without prefix: status=%d body=%s", rrRoot.Code, rrRoot.Body.String())
	}
}

// HOST-002: Origin/Host checks still apply after path-prefix strip.
func TestNewHTTPHandler_PathPrefix_OriginHostUnchanged(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.PathPrefix = "/mcp"
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	cfg.AllowedHosts = []string{"mcp.example.corp"}
	cfg.BearerToken = canaryHTTPToken
	cfg.LabIdentity = true
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Bad Origin under prefix → 403.
	reqBadOrigin := httptest.NewRequest(http.MethodPost, "http://mcp.example.corp/mcp", strings.NewReader(`{}`))
	reqBadOrigin.Host = "mcp.example.corp"
	reqBadOrigin.Header.Set("Origin", "https://evil.example")
	reqBadOrigin.Header.Set("Content-Type", "application/json")
	reqBadOrigin.Header.Set("Accept", "application/json, text/event-stream")
	reqBadOrigin.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	reqBadOrigin.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rrBadOrigin := httptest.NewRecorder()
	h.ServeHTTP(rrBadOrigin, reqBadOrigin)
	if rrBadOrigin.Code != http.StatusForbidden {
		t.Fatalf("bad Origin want 403, got %d body=%s", rrBadOrigin.Code, rrBadOrigin.Body.String())
	}

	// Bad Host under prefix → 403.
	reqBadHost := httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", strings.NewReader(`{}`))
	reqBadHost.Host = "evil.example"
	reqBadHost.Header.Set("Origin", "https://portal.example.corp")
	reqBadHost.Header.Set("Content-Type", "application/json")
	reqBadHost.Header.Set("Accept", "application/json, text/event-stream")
	reqBadHost.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	reqBadHost.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rrBadHost := httptest.NewRecorder()
	h.ServeHTTP(rrBadHost, reqBadHost)
	if rrBadHost.Code != http.StatusForbidden {
		t.Fatalf("bad Host want 403, got %d body=%s", rrBadHost.Code, rrBadHost.Body.String())
	}

	// Allowed origin+host under prefix passes protect (not 403/401).
	reqOK := httptest.NewRequest(http.MethodPost, "http://mcp.example.corp/mcp", strings.NewReader(`{}`))
	reqOK.Host = "mcp.example.corp"
	reqOK.Header.Set("Origin", "https://portal.example.corp")
	reqOK.Header.Set("Content-Type", "application/json")
	reqOK.Header.Set("Accept", "application/json, text/event-stream")
	reqOK.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	reqOK.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rrOK := httptest.NewRecorder()
	h.ServeHTTP(rrOK, reqOK)
	if rrOK.Code == http.StatusForbidden || rrOK.Code == http.StatusUnauthorized || rrOK.Code == http.StatusNotFound {
		t.Fatalf("allowed prefixed request should pass protect: status=%d body=%s", rrOK.Code, rrOK.Body.String())
	}
}

// TestHOST002_PathPrefixOriginPinFixtureMatrix is the offline HOST-002 fixture
// matrix for reverse-proxy path-prefix + Origin/Host pin + unauthenticated
// health + fail-closed X-Forwarded-* (TrustedProxy residual default false).
//
// Live edge rewrite of Host/Origin/X-Forwarded-* remains NET-001 residual.
func TestHOST002_PathPrefixOriginPinFixtureMatrix(t *testing.T) {
	t.Parallel()
	const (
		prefix      = "/mcp"
		allowedOrig = "https://portal.example.corp"
		allowedHost = "mcp.example.corp"
	)
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.PathPrefix = prefix
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{allowedOrig}
	cfg.AllowedHosts = []string{allowedHost}
	cfg.BearerToken = canaryHTTPToken
	cfg.LabIdentity = true
	// TrustedProxy default false — explicit for matrix documentation.
	cfg.TrustedProxy = false
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}

	type want struct {
		status int
		// when status is 0: assert not protect-layer 401/403/404 (SDK may 4xx)
		passProtect bool
		bodySubstr  string
	}
	type row struct {
		name   string
		method string
		path   string
		host   string
		origin string
		// extraHeaders applied after base auth headers when withAuth
		extraHeaders map[string]string
		withAuth     bool // shared secret + lab subject
		want         want
	}

	rows := []row{
		{
			name:     "origin_exact_match_under_prefix",
			method:   http.MethodPost,
			path:     prefix,
			host:     allowedHost,
			origin:   allowedOrig,
			withAuth: true,
			want:     want{passProtect: true},
		},
		{
			name:     "wrong_origin_403_under_prefix",
			method:   http.MethodPost,
			path:     prefix,
			host:     allowedHost,
			origin:   "https://evil.example",
			withAuth: true,
			want:     want{status: http.StatusForbidden, bodySubstr: "Origin"},
		},
		{
			name:     "host_allow_list_ok_non_local_prefix",
			method:   http.MethodPost,
			path:     prefix + "/rpc",
			host:     allowedHost,
			origin:   allowedOrig,
			withAuth: true,
			want:     want{passProtect: true},
		},
		{
			name:     "host_allow_list_reject_non_local_prefix",
			method:   http.MethodPost,
			path:     prefix,
			host:     "evil.example",
			origin:   allowedOrig,
			withAuth: true,
			want:     want{status: http.StatusForbidden, bodySubstr: "Host"},
		},
		{
			name:     "health_root_unauthenticated",
			method:   http.MethodGet,
			path:     mcpserver.HealthzPath,
			host:     allowedHost,
			withAuth: false,
			want:     want{status: http.StatusOK, bodySubstr: `"status":"ok"`},
		},
		{
			name:     "health_prefixed_unauthenticated",
			method:   http.MethodGet,
			path:     prefix + mcpserver.HealthzPath,
			host:     allowedHost,
			withAuth: false,
			want:     want{status: http.StatusOK, bodySubstr: `"status":"ok"`},
		},
		{
			// Spoofed X-Forwarded-Host must not satisfy AllowedHosts when Host is wrong.
			name:   "x_forwarded_host_not_trusted_default",
			method: http.MethodPost,
			path:   prefix,
			host:   "evil.example",
			origin: allowedOrig,
			extraHeaders: map[string]string{
				"X-Forwarded-Host": allowedHost,
			},
			withAuth: true,
			want:     want{status: http.StatusForbidden, bodySubstr: "Host"},
		},
		{
			// X-Forwarded-Prefix must not mount MCP outside configured PathPrefix.
			name:   "x_forwarded_prefix_not_trusted_for_path",
			method: http.MethodPost,
			path:   "/", // outside /mcp
			host:   allowedHost,
			origin: allowedOrig,
			extraHeaders: map[string]string{
				"X-Forwarded-Prefix": prefix,
			},
			withAuth: true,
			want:     want{status: http.StatusNotFound},
		},
	}

	for _, tc := range rows {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, "http://"+tc.host+tc.path, strings.NewReader(`{}`))
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
			}
			if tc.withAuth {
				req.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
				req.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
			}
			for k, v := range tc.extraHeaders {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			body := rr.Body.String()
			if strings.Contains(body, canaryHTTPToken) {
				t.Fatalf("response leaked token canary: %s", body)
			}
			if tc.want.passProtect {
				if rr.Code == http.StatusForbidden || rr.Code == http.StatusUnauthorized || rr.Code == http.StatusNotFound {
					t.Fatalf("want pass protect, got status=%d body=%s", rr.Code, body)
				}
				return
			}
			if rr.Code != tc.want.status {
				t.Fatalf("status=%d want %d body=%s", rr.Code, tc.want.status, body)
			}
			if tc.want.bodySubstr != "" && !strings.Contains(body, tc.want.bodySubstr) {
				t.Fatalf("body missing %q: %s", tc.want.bodySubstr, body)
			}
		})
	}
}

// HOST-002: TrustedProxy=true remains fail-closed residual (still ignores X-Forwarded-*).
func TestHOST002_TrustedProxyTrueStillIgnoresXForwarded(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.PathPrefix = "/mcp"
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	cfg.AllowedHosts = []string{"mcp.example.corp"}
	cfg.BearerToken = canaryHTTPToken
	cfg.LabIdentity = true
	cfg.TrustedProxy = true // residual: must not auto-trust
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", strings.NewReader(`{}`))
	req.Host = "evil.example"
	req.Header.Set("Origin", "https://portal.example.corp")
	req.Header.Set("X-Forwarded-Host", "mcp.example.corp")
	req.Header.Set("X-Forwarded-Prefix", "/mcp")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	req.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("TrustedProxy residual must not trust X-Forwarded-Host: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canaryHTTPToken) {
		t.Fatalf("403 body leaked token canary: %s", rr.Body.String())
	}
	// DefaultHTTPConfig leaves TrustedProxy false.
	if mcpserver.DefaultHTTPConfig().TrustedProxy {
		t.Fatal("DefaultHTTPConfig.TrustedProxy must be false (fail closed)")
	}
}

// HOST-002: trailing-slash prefix config normalizes; invalid rejected at handler build.
func TestNewHTTPHandler_PathPrefix_NormalizeAndReject(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.PathPrefix = "/mcp/"
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatalf("trailing slash prefix should normalize: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusNotFound {
		t.Fatalf("normalized /mcp/ config should serve /mcp: %s", rr.Body.String())
	}

	cfgBad := mcpserver.DefaultHTTPConfig()
	cfgBad.PathPrefix = "/../x"
	if _, err := mcpserver.NewHTTPHandler(srv, cfgBad); err == nil {
		t.Fatal("NewHTTPHandler must reject .. path prefix")
	}
}
