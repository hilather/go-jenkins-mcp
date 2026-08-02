package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
)

func TestSecurityHeaders_CSPAndNosniffOnRootAndHealth(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Version = "v-test"
	cfg.Commit = "c-test"
	cfg.UIBuild = "ui-test-build"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/", "/admin/v1/health"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status %d body=%s", path, rr.Code, rr.Body.String())
		}
		csp := rr.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("%s missing Content-Security-Policy", path)
		}
		if csp != admin.DefaultContentSecurityPolicy {
			t.Fatalf("%s CSP mismatch:\n got %q\nwant %q", path, csp, admin.DefaultContentSecurityPolicy)
		}
		// Automated check: CSP blocks unexpected script origins (no * / unsafe-eval).
		if strings.Contains(csp, "*") || strings.Contains(csp, "unsafe-eval") {
			t.Fatalf("%s CSP must not allow * or unsafe-eval: %q", path, csp)
		}
		if !strings.Contains(csp, "script-src 'self'") {
			t.Fatalf("%s CSP must restrict script-src to self: %q", path, csp)
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s CSP missing frame-ancestors: %q", path, csp)
		}
		if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s missing nosniff", path)
		}
		if rr.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s missing X-Frame-Options DENY", path)
		}
		if rr.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s missing Referrer-Policy", path)
		}
		if rr.Header().Get("Permissions-Policy") != admin.DefaultPermissionsPolicy {
			t.Fatalf("%s Permissions-Policy=%q", path, rr.Header().Get("Permissions-Policy"))
		}
	}

	// JSON API content-type must remain application/json (headers must not break it).
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil))
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("health Content-Type=%q want application/json", ct)
	}
	// HOST-007: health may include enabledModes []string; use flexible decode.
	var health map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["uiBuild"] != "ui-test-build" {
		t.Fatalf("uiBuild=%q", health["uiBuild"])
	}
}

func TestSecurityHeaders_VersionIncludesUIBuild(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Version = "v1"
	cfg.UIBuild = "spa-abc"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/version", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("version must include CSP")
	}
	var ver map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &ver); err != nil {
		t.Fatal(err)
	}
	if ver["version"] != "v1" || ver["uiBuild"] != "spa-abc" {
		t.Fatalf("version body=%v", ver)
	}
	// Secret canary
	if strings.Contains(rr.Body.String(), "Bearer ") {
		t.Fatal("version must not contain Bearer")
	}
}
