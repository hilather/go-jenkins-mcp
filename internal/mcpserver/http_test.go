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
