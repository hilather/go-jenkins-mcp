package mcpserver_test

import (
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
