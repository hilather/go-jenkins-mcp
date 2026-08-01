package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/authlab"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

func TestResolveHTTPRequireSubject(t *testing.T) {
	// Not parallel: mutates process env.
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_SUBJECT", "")
	if resolveHTTPRequireSubject(false, false) {
		t.Fatal("default off")
	}
	if !resolveHTTPRequireSubject(true, false) {
		t.Fatal("flag true")
	}
	if !resolveHTTPRequireSubject(false, true) {
		t.Fatal("gateway true")
	}
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		t.Setenv("JENKINS_MCP_HTTP_REQUIRE_SUBJECT", v)
		if !resolveHTTPRequireSubject(false, false) {
			t.Fatalf("env %q should require subject", v)
		}
	}
	t.Setenv("JENKINS_MCP_HTTP_REQUIRE_SUBJECT", "0")
	if resolveHTTPRequireSubject(false, false) {
		t.Fatal("env 0 off")
	}
	// Flag or gateway still wins with env off.
	if !resolveHTTPRequireSubject(true, false) {
		t.Fatal("flag with env 0")
	}
	if !resolveHTTPRequireSubject(false, true) {
		t.Fatal("gateway with env 0")
	}
}

func TestLabIdentityEnabledEnv(t *testing.T) {
	t.Setenv("JENKINS_MCP_LAB_IDENTITY", "")
	if labIdentityEnabled() {
		t.Fatal("empty off")
	}
	t.Setenv("JENKINS_MCP_LAB_IDENTITY", "1")
	if !labIdentityEnabled() {
		t.Fatal("1 on")
	}
	t.Setenv("JENKINS_MCP_LAB_IDENTITY", "nope")
	if labIdentityEnabled() {
		t.Fatal("nope off")
	}
}

func TestParseHTTPJWTEnv(t *testing.T) {
	t.Parallel()
	// Empty → not configured.
	cfg, err := parseHTTPJWTEnv(func(string) string { return "" })
	if err != nil || cfg.Configured() || cfg.Required {
		t.Fatalf("empty: %+v err=%v", cfg, err)
	}
	// Partial fails closed.
	_, err = parseHTTPJWTEnv(func(k string) string {
		if k == EnvHTTPJWKSURL {
			return "http://127.0.0.1:18081/jwks"
		}
		return ""
	})
	if err == nil {
		t.Fatal("partial JWKS URL only should fail")
	}
	// JWT_REQUIRED without config fails closed.
	_, err = parseHTTPJWTEnv(func(k string) string {
		if k == EnvHTTPJWTRequired {
			return "1"
		}
		return ""
	})
	if err == nil {
		t.Fatal("JWT_REQUIRED without JWKS should fail")
	}
	// Credentials in URL fail closed.
	_, err = parseHTTPJWTEnv(func(k string) string {
		switch k {
		case EnvHTTPJWKSURL:
			return "http://user:pass@127.0.0.1:18081/jwks"
		case EnvHTTPJWTIssuer:
			return "http://127.0.0.1:18081"
		case EnvHTTPJWTAudience:
			return "jenkins-api"
		}
		return ""
	})
	if err == nil {
		t.Fatal("credentials in JWKS URL should fail")
	}
	// Full config ok.
	cfg, err = parseHTTPJWTEnv(func(k string) string {
		switch k {
		case EnvHTTPJWKSURL:
			return "http://127.0.0.1:18081/jwks"
		case EnvHTTPJWTIssuer:
			return "http://127.0.0.1:18081"
		case EnvHTTPJWTAudience:
			return "jenkins-api"
		case EnvHTTPJWTRequired:
			return "1"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Configured() || !cfg.Required || cfg.Audience != "jenkins-api" {
		t.Fatalf("%+v", cfg)
	}
}

func TestFetchHTTPJWKS_HTTPTest(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	labDoc, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(labDoc)
	}))
	t.Cleanup(srv.Close)

	cfg := httpJWTEnv{
		JWKSURL:  srv.URL + "/jwks",
		Issuer:   "http://issuer.test",
		Audience: "jenkins-api",
	}
	jwks, err := fetchHTTPJWKS(context.Background(), srv.Client(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if jwks == nil || len(jwks.Keys) == 0 {
		t.Fatal("expected JWKS keys")
	}
	// Unconfigured → nil.
	jwks, err = fetchHTTPJWKS(context.Background(), srv.Client(), httpJWTEnv{})
	if err != nil || jwks != nil {
		t.Fatalf("unconfigured: jwks=%v err=%v", jwks, err)
	}
}

func TestParseHTTPJWKSRefreshTTL(t *testing.T) {
	t.Parallel()
	d, err := parseHTTPJWKSRefreshTTL(func(string) string { return "" })
	if err != nil || d != auth.DefaultJWKSRefreshTTL {
		t.Fatalf("default: %v err=%v", d, err)
	}
	d, err = parseHTTPJWKSRefreshTTL(func(k string) string {
		if k == EnvHTTPJWKSRefreshTTL {
			return "45s"
		}
		return ""
	})
	if err != nil || d != 45*time.Second {
		t.Fatalf("45s: %v err=%v", d, err)
	}
	_, err = parseHTTPJWKSRefreshTTL(func(k string) string {
		if k == EnvHTTPJWKSRefreshTTL {
			return "1s"
		}
		return ""
	})
	if err == nil {
		t.Fatal("below min must fail closed")
	}
}

func TestNewHTTPJWKSSource_RefreshRotateKid(t *testing.T) {
	t.Parallel()
	key1, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	key1.Kid = "wire-kid-1"
	key2, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	key2.Kid = "wire-kid-2"
	doc1, err := key1.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	doc2, err := key2.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	cur := doc1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		d := cur
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(d)
	}))
	t.Cleanup(srv.Close)

	cfg := httpJWTEnv{
		JWKSURL:  srv.URL,
		Issuer:   "https://issuer.example",
		Audience: "jenkins-api",
	}
	// Short TTL; use ForceRefresh path via Get after advancing is internal —
	// newHTTPJWKSSource starts background; we ForceRefresh after swapping doc.
	src, err := newHTTPJWKSSource(context.Background(), srv.Client(), cfg, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.StopBackground)

	const secret = "transport"
	now := time.Now()
	params := auth.AccessTokenParams{
		Issuer:   cfg.Issuer,
		Audience: cfg.Audience,
		Now:      func() time.Time { return now },
	}
	res := newHTTPIdentityResolver(false, secret, src, params)

	// Token signed by key1 accepted.
	tok1, err := key1.MintAccessToken(authlab.MintParams{
		Issuer:   cfg.Issuer,
		Subject:  "alice",
		Audience: cfg.Audience,
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok1)
	id, err := res(req)
	if err != nil || id.ExternalSubject != "alice" {
		t.Fatalf("kid1: id=%+v err=%v", id, err)
	}

	// Rotate JWKS to key2 only; refresh source.
	mu.Lock()
	cur = doc2
	mu.Unlock()
	if err := src.ForceRefresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	tok2, err := key2.MintAccessToken(authlab.MintParams{
		Issuer:   cfg.Issuer,
		Subject:  "bob",
		Audience: cfg.Audience,
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+tok2)
	id, err = res(req2)
	if err != nil || id.ExternalSubject != "bob" {
		t.Fatalf("after rotate kid2: id=%+v err=%v", id, err)
	}

	// Old kid1 token must fail closed after key removed from JWKS.
	reqOld := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	reqOld.Header.Set("Authorization", "Bearer "+tok1)
	_, err = res(reqOld)
	if err == nil {
		t.Fatal("stale kid after rotation must fail closed")
	}
	if strings.Contains(err.Error(), tok1) {
		t.Fatalf("Regression: token in error after rotation: %v", err)
	}

	// Unconfigured → nil source.
	nilSrc, err := newHTTPJWKSSource(context.Background(), srv.Client(), httpJWTEnv{}, 30*time.Second)
	if err != nil || nilSrc != nil {
		t.Fatalf("unconfigured: %v err=%v", nilSrc, err)
	}
}

func TestNewHTTPJWKSSource_FailedRefreshKeepsOldViaResolver(t *testing.T) {
	t.Parallel()
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	key.Kid = "stable-kid"
	doc, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		shouldFail := fail
		mu.Unlock()
		if shouldFail {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)

	cfg := httpJWTEnv{
		JWKSURL:  srv.URL,
		Issuer:   "https://issuer.example",
		Audience: "jenkins-api",
	}
	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client: srv.Client(),
		URI:    cfg.JWKSURL,
		TTL:    30 * time.Second,
		Logf:   func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	res := newHTTPIdentityResolver(false, "sec", src, auth.AccessTokenParams{
		Issuer:   cfg.Issuer,
		Audience: cfg.Audience,
		Now:      func() time.Time { return now },
	})
	tok, err := key.MintAccessToken(authlab.MintParams{
		Issuer:   cfg.Issuer,
		Subject:  "carol",
		Audience: cfg.Audience,
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	if err := src.ForceRefresh(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	id, err := res(req)
	if err != nil || id.ExternalSubject != "carol" {
		t.Fatalf("stale-if-error must still validate with last good: id=%+v err=%v", id, err)
	}
}

func TestNewLabHTTPIdentityResolver(t *testing.T) {
	t.Parallel()
	if newLabHTTPIdentityResolver(false, "secret") != nil {
		t.Fatal("lab off → nil resolver")
	}
	res := newLabHTTPIdentityResolver(true, "secret")
	if res == nil {
		t.Fatal("lab on → resolver")
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	id, err := res(req)
	if err != nil || id.Present() {
		t.Fatalf("no header: id=%+v err=%v", id, err)
	}
	req.Header.Set("X-Jenkins-MCP-Lab-Subject", "lab-user")
	req.Header.Set("X-Jenkins-MCP-Lab-Tenant", "tid")
	id, err = res(req)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Present() || id.ExternalSubject != "lab-user" || id.Tenant != "tid" {
		t.Fatalf("%+v", id)
	}
	if id.Source != mcpserver.IdentitySourceLabHeader || !id.Verified {
		t.Fatalf("source/verified: %+v", id)
	}
}

func TestNewHTTPIdentityResolver_JWTAcceptReject(t *testing.T) {
	t.Parallel()
	const (
		iss    = "https://issuer.example"
		aud    = "jenkins-api"
		secret = "transport-shared-secret"
	)
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks := authJWKSFromLab(t, key)
	now := time.Now()
	params := auth.AccessTokenParams{
		Issuer:   iss,
		Audience: aud,
		Now:      func() time.Time { return now },
	}
	res := newHTTPIdentityResolver(false, secret, auth.NewStaticJWKS(jwks), params)
	if res == nil {
		t.Fatal("JWKS configured → non-nil resolver")
	}

	// Good JWT → subject.
	tok, err := key.MintAccessToken(authlab.MintParams{
		Issuer:   iss,
		Subject:  "jwt-user-1",
		Audience: aud,
		TTL:      time.Hour,
		Extra:    map[string]any{"tid": "tenant-a"},
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Jenkins-MCP-Token", secret) // transport gate separate
	id, err := res(req)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Present() || id.ExternalSubject != "jwt-user-1" {
		t.Fatalf("%+v", id)
	}
	if id.Source != mcpserver.IdentitySourceJWT || !id.Verified {
		t.Fatalf("want SourceJWT verified: %+v", id)
	}
	if id.Tenant != "tenant-a" {
		t.Fatalf("tenant: %q", id.Tenant)
	}

	// Invalid JWT → error, canary: raw token not in error.
	reqBad := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	reqBad.Header.Set("Authorization", "Bearer "+tok+"x")
	_, err = res(reqBad)
	if err == nil {
		t.Fatal("expected invalid JWT fail")
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatalf("Regression: raw JWT in error body: %v", err)
	}
	// Also canary: full token substring segments should not appear when long enough.
	if len(tok) > 32 && strings.Contains(err.Error(), tok[:32]) {
		t.Fatalf("Regression: JWT prefix in error: %v", err)
	}

	// Wrong audience → reject.
	wrongAud, err := key.MintAccessToken(authlab.MintParams{
		Issuer:   iss,
		Subject:  "jwt-user-2",
		Audience: "https://graph.microsoft.com",
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	reqWA := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	reqWA.Header.Set("Authorization", "Bearer "+wrongAud)
	_, err = res(reqWA)
	if err == nil {
		t.Fatal("wrong audience should fail")
	}
	if strings.Contains(err.Error(), wrongAud) {
		t.Fatalf("Regression: wrong-aud JWT in error: %v", err)
	}

	// No JWT / no lab → empty identity (not error).
	reqEmpty := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	id, err = res(reqEmpty)
	if err != nil || id.Present() {
		t.Fatalf("empty: id=%+v err=%v", id, err)
	}
}

// HOST-001: transport shared secret alone is never RequestIdentity under RequireSubject.
func TestNewHTTPIdentityResolver_TransportSecretNotIdentity(t *testing.T) {
	t.Parallel()
	const secret = "shared-transport-secret"
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks := authJWKSFromLab(t, key)
	params := auth.AccessTokenParams{
		Issuer:   "https://issuer.example",
		Audience: "jenkins-api",
	}
	res := newHTTPIdentityResolver(false, secret, auth.NewStaticJWKS(jwks), params)
	if res == nil {
		t.Fatal("resolver")
	}
	// Bearer equals transport secret → BearerAccessToken treats as gate only.
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	id, err := res(req)
	if err != nil {
		t.Fatal(err)
	}
	if id.Present() {
		t.Fatalf("Regression: shared secret treated as subject: %+v", id)
	}

	// End-to-end: RequireSubject + only transport secret → 401.
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.BearerToken = secret
	cfg.RequireSubject = true
	cfg.IdentityResolver = res
	h, err := mcpserver.NewHTTPHandler(mcpserver.NewServer("test", "0.0.1"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req2.Header.Set("Authorization", "Bearer "+secret)
	req2.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req2)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for secret-only under RequireSubject, got %d body=%q", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("Regression: transport secret echoed in response: %q", body)
	}
}

func TestNewHTTPIdentityResolver_JWTThenLabFallback(t *testing.T) {
	t.Parallel()
	const secret = "transport"
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks := authJWKSFromLab(t, key)
	params := auth.AccessTokenParams{
		Issuer:   "https://issuer.example",
		Audience: "jenkins-api",
	}
	// Lab on + JWKS: no Bearer → lab header works.
	res := newHTTPIdentityResolver(true, secret, auth.NewStaticJWKS(jwks), params)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	req.Header.Set("X-Jenkins-MCP-Lab-Subject", "lab-only")
	id, err := res(req)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Present() || id.ExternalSubject != "lab-only" || id.Source != mcpserver.IdentitySourceLabHeader {
		t.Fatalf("%+v", id)
	}
	// Lab off: same header ignored.
	resOff := newHTTPIdentityResolver(false, secret, auth.NewStaticJWKS(jwks), params)
	id, err = resOff(req)
	if err != nil || id.Present() {
		t.Fatalf("lab off must ignore headers: %+v err=%v", id, err)
	}
	// Neither JWKS nor lab → nil resolver.
	if newHTTPIdentityResolver(false, secret, nil, params) != nil {
		t.Fatal("nil jwks + lab off → nil")
	}
	if newHTTPIdentityResolver(false, secret, auth.NewStaticJWKS(&auth.JWKS{}), params) != nil {
		t.Fatal("empty jwks + lab off → nil")
	}
}

// HOST-001 canary: invalid JWT through HTTP handler never echoes token.
func TestHTTPHandler_InvalidJWT_NoTokenEcho(t *testing.T) {
	t.Parallel()
	const (
		iss    = "https://issuer.example"
		aud    = "jenkins-api"
		secret = "gate-secret"
	)
	key, err := authlab.GenerateLabKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks := authJWKSFromLab(t, key)
	now := time.Now()
	tok, err := key.MintAccessToken(authlab.MintParams{
		Issuer:   iss,
		Subject:  "user",
		Audience: aud,
		TTL:      time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt signature.
	bad := tok + "x"
	res := newHTTPIdentityResolver(false, secret, auth.NewStaticJWKS(jwks), auth.AccessTokenParams{
		Issuer:   iss,
		Audience: aud,
		Now:      func() time.Time { return now },
	})
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.BearerToken = secret
	cfg.RequireSubject = true
	cfg.IdentityResolver = res
	h, err := mcpserver.NewHTTPHandler(mcpserver.NewServer("test", "0.0.1"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+bad)
	req.Header.Set("X-Jenkins-MCP-Token", secret)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	bodyStr := string(body)
	if strings.Contains(bodyStr, bad) || strings.Contains(bodyStr, tok) {
		t.Fatalf("Regression: JWT in HTTP error body: %q", bodyStr)
	}
	// Good JWT passes identity gate (handler may still fail later on protocol).
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{}`))
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("X-Jenkins-MCP-Token", secret)
	req2.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr2, req2)
	if rr2.Code == http.StatusUnauthorized {
		t.Fatalf("valid JWT should not 401 on identity gate; body=%q", rr2.Body.String())
	}
}

func authJWKSFromLab(t *testing.T, key *authlab.LabKey) *auth.JWKS {
	t.Helper()
	doc, err := key.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	out := &auth.JWKS{Keys: make([]auth.JWK, 0, len(doc.Keys))}
	for _, k := range doc.Keys {
		out.Keys = append(out.Keys, auth.JWK{
			Kty: k.Kty,
			Kid: k.Kid,
			Use: k.Use,
			Alg: k.Alg,
			N:   k.N,
			E:   k.E,
		})
	}
	return out
}
