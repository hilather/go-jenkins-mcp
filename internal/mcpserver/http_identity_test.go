package mcpserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

// HOST-001: require-subject without identity → 401; shared secret alone insufficient.
func TestNewHTTPHandler_RequireSubjectMissing401(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Valid transport secret but no subject → 401.
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without subject, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, canaryHTTPToken) {
		t.Fatalf("Regression: canary token leaked in 401 body: %s", body)
	}
	if strings.Contains(body, "Bearer ") {
		t.Fatalf("Regression: Bearer material in body: %s", body)
	}
}

// HOST-001: lab identity mode with header → subject present; protect layer passes.
func TestNewHTTPHandler_LabIdentitySubjectSet(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	var got mcpserver.RequestIdentity
	// Resolver records identity (same trusted lab path as builtin extract).
	cfg.IdentityResolver = func(r *http.Request) (mcpserver.RequestIdentity, error) {
		sub := strings.TrimSpace(r.Header.Get(mcpserver.HeaderLabSubject))
		if sub == "" {
			return mcpserver.RequestIdentity{}, nil
		}
		id := mcpserver.RequestIdentity{
			ExternalSubject: sub,
			Tenant:          strings.TrimSpace(r.Header.Get(mcpserver.HeaderLabTenant)),
			Source:          mcpserver.IdentitySourceLabHeader,
			Verified:        true,
		}
		got = id
		return id, nil
	}
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "lab-alice")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-1")
	})
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("lab subject should not 401: %s", rr.Body.String())
	}
	if !got.Present() || got.ExternalSubject != "lab-alice" {
		t.Fatalf("subject not set: %+v", got)
	}
	if got.Source != mcpserver.IdentitySourceLabHeader {
		t.Fatalf("source: %q", got.Source)
	}
	if got.Tenant != "tid-1" {
		t.Fatalf("tenant: %q", got.Tenant)
	}
}

// HOST-001: builtin lab extraction (no IdentityResolver) passes require-subject.
func TestNewHTTPHandler_LabIdentityBuiltinPasses(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "lab-bob")
	})
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("builtin lab should not 401: %s", rr.Body.String())
	}
}

// HOST-001: lab headers ignored when LabIdentity is off (fail closed — no spoof).
func TestNewHTTPHandler_LabHeaderIgnoredWithoutLabMode(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = false
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "spoofed-user")
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 when lab mode off, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// OAUTH-006 / GWY-002 residual lite: builtin lab extracts groups; lab-off ignores spoof.
func TestNewHTTPHandler_LabGroupsHeader(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	var got mcpserver.RequestIdentity
	cfg.AfterIdentity = func(ctx context.Context, id mcpserver.RequestIdentity) context.Context {
		got = id
		return ctx
	}
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "lab-alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "ops, dev, ops")
	})
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("lab+groups should not 401: %s", rr.Body.String())
	}
	if !got.Present() || got.ExternalSubject != "lab-alice" {
		t.Fatalf("identity: %+v", got)
	}
	if len(got.Groups) != 3 || got.Groups[0] != "ops" || got.Groups[1] != "dev" {
		t.Fatalf("groups: %v", got.Groups)
	}

	// Lab off: groups header alone cannot establish identity (spoof fail closed).
	cfg2 := mcpserver.DefaultHTTPConfig()
	cfg2.RequireSubject = true
	cfg2.LabIdentity = false
	var got2 mcpserver.RequestIdentity
	cfg2.AfterIdentity = func(ctx context.Context, id mcpserver.RequestIdentity) context.Context {
		got2 = id
		return ctx
	}
	h2, err := mcpserver.NewHTTPHandler(srv, cfg2)
	if err != nil {
		t.Fatal(err)
	}
	rr2 := postLoopback(t, h2, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "spoof")
		r.Header.Set(mcpserver.HeaderLabGroups, "admins")
	})
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 lab off, got %d", rr2.Code)
	}
	if got2.Present() || len(got2.Groups) != 0 {
		t.Fatalf("spoof must not set identity/groups: %+v", got2)
	}
	if strings.Contains(rr.Body.String(), "spoofed-user") {
		t.Fatalf("subject must not appear in error body: %s", rr.Body.String())
	}
}

// HOST-001: healthz/readyz unauthenticated, secret-free.
func TestNewHTTPHandler_HealthPathsUnauthenticated(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{mcpserver.HealthzPath, mcpserver.ReadyzPath} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = "127.0.0.1:8765"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d body=%s", path, rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if strings.Contains(body, canaryHTTPToken) {
			t.Fatalf("%s: canary in body: %s", path, body)
		}
		if !strings.Contains(body, `"status"`) {
			t.Fatalf("%s: body: %s", path, body)
		}
		// HOST-002: no tool inventory leakage on probes.
		for _, leak := range []string{"tools", "inventory", "jenkins_"} {
			if strings.Contains(body, leak) {
				t.Fatalf("%s: must not leak inventory field %q: %s", path, leak, body)
			}
		}
	}
}

// HOST-005: /readyz reports gateway_ready when ReadyCheck is set; /healthz stays ok.
func TestNewHTTPHandler_ReadyzGatewayReady(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.BearerToken = canaryHTTPToken
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
	// Not ready → 503 on readyz; healthz still 200.
	rr := get(mcpserver.ReadyzPath)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz not ready: want 503, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"not_ready"`) || !strings.Contains(rr.Body.String(), `"gateway_ready":false`) {
		t.Fatalf("readyz body: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canaryHTTPToken) {
		t.Fatalf("canary leaked: %s", rr.Body.String())
	}
	hz := get(mcpserver.HealthzPath)
	if hz.Code != http.StatusOK {
		t.Fatalf("healthz must stay 200 when not ready, got %d", hz.Code)
	}
	if strings.Contains(hz.Body.String(), "gateway_ready") {
		t.Fatalf("healthz must not include gateway_ready: %s", hz.Body.String())
	}
	// Ready → 200 with gateway_ready true.
	ready = true
	rr = get(mcpserver.ReadyzPath)
	if rr.Code != http.StatusOK {
		t.Fatalf("readyz ready: want 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"gateway_ready":true`) {
		t.Fatalf("readyz body: %s", rr.Body.String())
	}
}

// HOST-002: CORS wildcard origins fail closed at config validation.
func TestValidateHTTPConfig_NoCORSWildcard(t *testing.T) {
	t.Parallel()
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.Addr = "0.0.0.0:8081"
	cfg.AllowNonLocal = true
	cfg.BearerToken = canaryHTTPToken
	cfg.AllowedHosts = []string{"mcp.example.corp"}
	for _, origin := range []string{"*", "https://*.example.corp", "https://portal.example.corp/*"} {
		cfg.AllowedOrigins = []string{origin}
		err := mcpserver.ValidateHTTPConfig(cfg)
		if err == nil {
			t.Fatalf("expected wildcard origin %q to fail closed", origin)
		}
		if !strings.Contains(err.Error(), "wildcard") {
			t.Fatalf("expected wildcard error for %q, got: %v", origin, err)
		}
	}
	// Exact origin still OK.
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	if err := mcpserver.ValidateHTTPConfig(cfg); err != nil {
		t.Fatalf("exact origin must pass: %v", err)
	}
}

// HOST-001: non-local without subject → 401 even with shared secret.
func TestNewHTTPHandler_NonLocalRequiresSubject(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	cfg.AllowedHosts = []string{"mcp.example.corp"}
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !mcpserver.HTTPSubjectRequired(cfg) {
		t.Fatal("AllowNonLocal should require subject")
	}
	req := httptest.NewRequest(http.MethodPost, "http://mcp.example.corp/mcp", strings.NewReader(`{}`))
	req.Host = "mcp.example.corp"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canaryHTTPToken) {
		t.Fatalf("canary leaked: %s", rr.Body.String())
	}
}

// HOST-001: invalid IdentityResolver → 401 without token echo.
func TestNewHTTPHandler_ResolverError401Canary(t *testing.T) {
	t.Parallel()
	const canaryJWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWNyZXQtdG9rZW4tY2FuYXJ5In0.sig"
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.IdentityResolver = func(r *http.Request) (mcpserver.RequestIdentity, error) {
		return mcpserver.RequestIdentity{}, errAuthFail{}
	}
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryJWT)
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, canaryJWT) || strings.Contains(body, "secret-token-canary") {
		t.Fatalf("Regression: token leaked in body: %s", body)
	}
}

type errAuthFail struct{}

func (errAuthFail) Error() string { return "authentication failed" }

// Loopback pilot without require-subject remains open (KD-008 residual).
func TestNewHTTPHandler_LoopbackWithoutRequireSubjectUnchanged(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if mcpserver.HTTPSubjectRequired(cfg) {
		t.Fatal("default loopback must not require subject")
	}
	rr := postLoopback(t, h, nil)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("loopback pilot residual: must not 401 without subject: %s", rr.Body.String())
	}
}

func TestHTTPSubjectRequired(t *testing.T) {
	t.Parallel()
	cfg := mcpserver.DefaultHTTPConfig()
	if mcpserver.HTTPSubjectRequired(cfg) {
		t.Fatal("default off")
	}
	cfg.RequireSubject = true
	if !mcpserver.HTTPSubjectRequired(cfg) {
		t.Fatal("RequireSubject")
	}
	cfg2 := mcpserver.DefaultHTTPConfig()
	cfg2.AllowNonLocal = true
	if !mcpserver.HTTPSubjectRequired(cfg2) {
		t.Fatal("AllowNonLocal implies subject")
	}
}

func TestIdentityContextRoundTrip(t *testing.T) {
	t.Parallel()
	id := mcpserver.RequestIdentity{
		ExternalSubject: "sub-1",
		Source:          mcpserver.IdentitySourceLabHeader,
		Verified:        true,
	}
	ctx := mcpserver.ContextWithIdentity(nil, id)
	got := mcpserver.IdentityFromContext(ctx)
	if got.ExternalSubject != "sub-1" || !got.Verified {
		t.Fatalf("%+v", got)
	}
	if mcpserver.IdentityFromContext(nil).Present() {
		t.Fatal("nil ctx should be empty")
	}
}

// HOST-001: IdentityFingerprint is stable and changes when subject fields change.
func TestIdentityFingerprint_StableAndSensitive(t *testing.T) {
	t.Parallel()
	a := mcpserver.RequestIdentity{
		ExternalSubject:  "alice",
		Tenant:           "tid-1",
		WorkloadID:       "wl-1",
		JenkinsPrincipal: "j-alice",
	}
	b := a
	if mcpserver.IdentityFingerprint(a) != mcpserver.IdentityFingerprint(b) {
		t.Fatal("same identity must same fingerprint")
	}
	b.ExternalSubject = "bob"
	if mcpserver.IdentityFingerprint(a) == mcpserver.IdentityFingerprint(b) {
		t.Fatal("subject change must change fingerprint")
	}
	// Fingerprint is non-secret hash — never equal to cleartext subject.
	fp := mcpserver.IdentityFingerprint(a)
	if fp == "" || strings.Contains(fp, "alice") {
		t.Fatalf("fingerprint must be opaque hash, got %q", fp)
	}
	if len(fp) != 32 { // 16 bytes hex
		t.Fatalf("want 32 hex chars, got %d", len(fp))
	}
}

// HOST-001 / GWY-002 wire: mid-session subject swap on same Mcp-Session-Id → 401.
// First authenticated request establishes fingerprint; second with different
// subject fails closed. No tokens/subjects in the 401 body.
func TestNewHTTPHandler_MidSessionSubjectSwap401(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "sess-host001-mid-swap-1"

	// Request 1: Alice establishes session fingerprint.
	rr1 := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-a")
	})
	if rr1.Code == http.StatusUnauthorized {
		t.Fatalf("alice first request should not 401: %s", rr1.Body.String())
	}

	// Request 2: same session, same subject → still OK.
	rrSame := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-a")
	})
	if rrSame.Code == http.StatusUnauthorized {
		t.Fatalf("same subject rebind should not 401: %s", rrSame.Body.String())
	}

	// Request 3: same session, Bob → fail closed mid-session swap.
	rrSwap := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "bob")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-a")
	})
	if rrSwap.Code != http.StatusUnauthorized {
		t.Fatalf("Regression: mid-session subject swap must 401, got %d body=%s",
			rrSwap.Code, rrSwap.Body.String())
	}
	body := rrSwap.Body.String()
	if strings.Contains(body, canaryHTTPToken) {
		t.Fatalf("Regression: canary token leaked in swap 401: %s", body)
	}
	if strings.Contains(body, "alice") || strings.Contains(body, "bob") {
		t.Fatalf("Regression: subject leaked in swap 401: %s", body)
	}
}

// HOST-001: different MCP sessions may bind different subjects (no cross-session
// fingerprint collision). Same transport secret is not identity.
func TestNewHTTPHandler_DifferentSessionsIndependentSubjects(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rrA := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, "sess-a")
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
	})
	if rrA.Code == http.StatusUnauthorized {
		t.Fatalf("sess-a alice: %s", rrA.Body.String())
	}
	rrB := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, "sess-b")
		r.Header.Set(mcpserver.HeaderLabSubject, "bob")
	})
	if rrB.Code == http.StatusUnauthorized {
		t.Fatalf("sess-b bob (independent): %s", rrB.Body.String())
	}
}

// HOST-001: requests without Mcp-Session-Id (e.g. initialize) still require
// subject under RequireSubject but do not establish a bind — swap only applies
// once a session id is present.
func TestNewHTTPHandler_NoSessionID_SubjectStillRequiredNoBind(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// No session id, no subject → 401.
	rrMiss := postLoopback(t, h, nil)
	if rrMiss.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without subject, got %d", rrMiss.Code)
	}
	// No session id + subject → pass protect layer (no mid-session table yet).
	rrOK := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
	})
	if rrOK.Code == http.StatusUnauthorized {
		t.Fatalf("subject without session id should not 401: %s", rrOK.Body.String())
	}
	// Different subject still without session id → also OK (no bind key).
	rrOther := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "bob")
	})
	if rrOther.Code == http.StatusUnauthorized {
		t.Fatalf("no session id: subjects independent: %s", rrOther.Body.String())
	}
}

// HOST-001: health/ready remain exempt from subject and session fingerprint.
func TestNewHTTPHandler_HealthExemptFromSessionBind(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Establish a session as alice.
	_ = postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, "sess-health")
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
	})
	// Health with no auth, no subject, even if someone spoofs session id.
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+mcpserver.HealthzPath, nil)
	req.Host = "127.0.0.1:8765"
	req.Header.Set(mcpserver.HeaderMCPSessionID, "sess-health")
	req.Header.Set(mcpserver.HeaderLabSubject, "bob")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health must stay 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canaryHTTPToken) {
		t.Fatal("canary in health body")
	}
}

// HOST-001: RequireSubject + shared secret alone is insufficient even with a
// session id (session id is not identity).
func TestNewHTTPHandler_RequireSubjectSecretAndSessionNotIdentity(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.BearerToken = canaryHTTPToken
	// LabIdentity off — no spoof headers, no resolver.
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, "sess-no-subject")
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Regression: secret+session without subject must 401, got %d body=%s",
			rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canaryHTTPToken) {
		t.Fatalf("canary leaked: %s", rr.Body.String())
	}
}

// HOST-001: non-local implies RequireSubject; secret alone insufficient; with
// lab subject + session, mid-session swap still fails closed.
func TestNewHTTPHandler_NonLocalMidSessionSubjectSwap(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.AllowNonLocal = true
	cfg.AllowedOrigins = []string{"https://portal.example.corp"}
	cfg.AllowedHosts = []string{"mcp.example.corp"}
	cfg.BearerToken = canaryHTTPToken
	cfg.LabIdentity = true
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !mcpserver.HTTPSubjectRequired(cfg) {
		t.Fatal("non-local must require subject")
	}
	// Secret only → 401.
	reqSec := httptest.NewRequest(http.MethodPost, "http://mcp.example.corp/mcp", strings.NewReader(`{}`))
	reqSec.Host = "mcp.example.corp"
	reqSec.Header.Set("Content-Type", "application/json")
	reqSec.Header.Set("Accept", "application/json, text/event-stream")
	reqSec.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
	reqSec.Header.Set(mcpserver.HeaderMCPSessionID, "nl-sess-1")
	rrSec := httptest.NewRecorder()
	h.ServeHTTP(rrSec, reqSec)
	if rrSec.Code != http.StatusUnauthorized {
		t.Fatalf("non-local secret-only want 401, got %d", rrSec.Code)
	}

	postNL := func(sub string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://mcp.example.corp/mcp", strings.NewReader(`{}`))
		req.Host = "mcp.example.corp"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		req.Header.Set(mcpserver.HeaderMCPSessionID, "nl-sess-1")
		req.Header.Set(mcpserver.HeaderLabSubject, sub)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := postNL("alice"); rr.Code == http.StatusUnauthorized {
		t.Fatalf("alice: %s", rr.Body.String())
	}
	if rr := postNL("bob"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("Regression: non-local mid-session swap want 401, got %d body=%s",
			rr.Code, rr.Body.String())
	}
}

// Unit: sessionIdentityTable via exported fingerprint + handler path is covered
// above; IdentityFromContext still available after successful protect.
func TestNewHTTPHandler_IdentityInContextAfterBind(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	var seen mcpserver.RequestIdentity
	// Capture identity the protect layer would store: use a wrapping resolver
	// that mirrors lab extract, then verify fingerprint consistency.
	cfg.IdentityResolver = func(r *http.Request) (mcpserver.RequestIdentity, error) {
		sub := strings.TrimSpace(r.Header.Get(mcpserver.HeaderLabSubject))
		if sub == "" {
			return mcpserver.RequestIdentity{}, nil
		}
		id := mcpserver.RequestIdentity{
			ExternalSubject: sub,
			Tenant:          strings.TrimSpace(r.Header.Get(mcpserver.HeaderLabTenant)),
			Source:          mcpserver.IdentitySourceResolver,
			Verified:        true,
		}
		seen = id
		return id, nil
	}
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderMCPSessionID, "ctx-sess")
		r.Header.Set(mcpserver.HeaderLabSubject, "ctx-user")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-ctx")
	})
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("want pass: %s", rr.Body.String())
	}
	if !seen.Present() || seen.ExternalSubject != "ctx-user" {
		t.Fatalf("resolver identity: %+v", seen)
	}
	fp := mcpserver.IdentityFingerprint(seen)
	if fp == "" {
		t.Fatal("fingerprint empty")
	}
}

// HOST-001/003: ExpectedExternalSubject pins HTTP identity to process-bound
// gateway subject so multi-lab subjects cannot share one Obtain caller.
func TestNewHTTPHandler_ExpectedExternalSubjectPin(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.ExpectedExternalSubject = "bound-alice"
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Matching subject → pass.
	rrOK := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "bound-alice")
	})
	if rrOK.Code == http.StatusUnauthorized {
		t.Fatalf("matching subject must pass: %s", rrOK.Body.String())
	}
	// Mismatch → 401; body must not echo subjects or secrets.
	rrBad := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "other-bob")
	})
	if rrBad.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for mismatched subject, got %d body=%s", rrBad.Code, rrBad.Body.String())
	}
	body := rrBad.Body.String()
	for _, leak := range []string{"bound-alice", "other-bob", "ExpectedExternal"} {
		if strings.Contains(body, leak) {
			t.Fatalf("Regression: must not echo pin/subjects: %s", body)
		}
	}
}

// HOST multi-user: AfterIdentity enriches context; no ExpectedExternalSubject pin
// allows distinct lab subjects on the same process.
func TestNewHTTPHandler_AfterIdentityMultiUserNoPin(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	// Multi-user foundation: leave ExpectedExternalSubject empty.
	type callerKey struct{}
	var seenSubjects []string
	cfg.AfterIdentity = func(ctx context.Context, id mcpserver.RequestIdentity) context.Context {
		seenSubjects = append(seenSubjects, id.ExternalSubject)
		return context.WithValue(ctx, callerKey{}, id.ExternalSubject)
	}
	// Capture context value from an identity-aware inner via resolver path:
	// use a custom IdentityResolver that still returns lab-compatible ids and
	// assert AfterIdentity ran for both alice and bob (no pin reject).
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rrA := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "alice-mu")
	})
	if rrA.Code == http.StatusUnauthorized {
		t.Fatalf("alice must pass without pin: %s", rrA.Body.String())
	}
	rrB := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderLabSubject, "bob-mu")
	})
	if rrB.Code == http.StatusUnauthorized {
		t.Fatalf("bob must pass without pin: %s", rrB.Body.String())
	}
	if len(seenSubjects) < 2 {
		t.Fatalf("AfterIdentity hits=%v want alice+bob", seenSubjects)
	}
	foundA, foundB := false, false
	for _, s := range seenSubjects {
		if s == "alice-mu" {
			foundA = true
		}
		if s == "bob-mu" {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("AfterIdentity subjects=%v", seenSubjects)
	}
}
