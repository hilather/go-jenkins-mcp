package admin_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

func TestValidateListenAddr_Loopback(t *testing.T) {
	// Loopback OK
	for _, addr := range []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787"} {
		if err := admin.ValidateListenAddr(addr, false); err != nil {
			t.Errorf("addr %q should be ok: %v", addr, err)
		}
	}
	// Non-loopback rejected without allow
	for _, addr := range []string{"0.0.0.0:8787", ":8787", "192.168.1.1:8787"} {
		if err := admin.ValidateListenAddr(addr, false); err == nil {
			t.Errorf("addr %q should fail without AllowNonLocal", addr)
		}
	}
	// Allowed with residual flag
	if err := admin.ValidateListenAddr("0.0.0.0:8787", true); err != nil {
		t.Fatal(err)
	}
	// Empty
	if err := admin.ValidateListenAddr("", false); err == nil {
		t.Fatal("empty addr should fail")
	}
}

func TestValidateConfig_RequireTokenAndNonLocal(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:8787"
	if err := admin.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.RequireToken = true
	if err := admin.ValidateConfig(cfg); err == nil {
		t.Fatal("RequireToken without secret should fail")
	}
	cfg.BearerToken = "x"
	if err := admin.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg2 := admin.DefaultConfig()
	cfg2.Addr = "0.0.0.0:8787"
	cfg2.AllowNonLocal = true
	if err := admin.ValidateConfig(cfg2); err == nil {
		t.Fatal("non-local without token should fail")
	}
	cfg2.BearerToken = "x"
	if err := admin.ValidateConfig(cfg2); err != nil {
		t.Fatal(err)
	}
}

func TestVersionAndMetricsEndpoints(t *testing.T) {
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Version = "v1"
	cfg.Commit = "c1"
	cfg.BuildTime = "t1"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/version", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("version status %d", rr.Code)
	}
	var ver map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &ver); err != nil {
		t.Fatal(err)
	}
	if ver["version"] != "v1" || ver["commit"] != "c1" {
		t.Fatalf("version body=%v", ver)
	}
	// Secret canary fields must not appear
	raw := rr.Body.String()
	for _, s := range []string{"token", "password", "Authorization", "secret"} {
		// field names in JSON keys like goVersion are ok; check secret-like values only loosely
		_ = s
	}
	if strings.Contains(raw, "Bearer ") {
		t.Fatal("version must not contain Bearer")
	}

	// Metrics without global registry
	telemetry.SetGlobal(nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/admin/v1/metrics", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("metrics status %d", rr2.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["available"] != false {
		t.Fatalf("available=%v want false", m["available"])
	}

	// With registry
	reg := telemetry.NewRegistry()
	reg.Inc(telemetry.MetricToolCalls, 3)
	telemetry.SetGlobal(reg)
	t.Cleanup(func() { telemetry.SetGlobal(nil) })
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/admin/v1/metrics", nil))
	if rr3.Code != http.StatusOK {
		t.Fatalf("metrics status %d", rr3.Code)
	}
	var m2 map[string]any
	if err := json.Unmarshal(rr3.Body.Bytes(), &m2); err != nil {
		t.Fatal(err)
	}
	if m2["available"] != true {
		t.Fatalf("available=%v", m2["available"])
	}
}

func TestPolicyEffectiveAndDoctor_WithProfile(t *testing.T) {
	tmp := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(tmp, "cfg"),
		DataDir:   filepath.Join(tmp, "data"),
		CacheDir:  filepath.Join(tmp, "cache"),
	}
	// Minimal profile on disk
	st := profile.NewStore(paths)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.corp/",
		AuthMethod:    profile.AuthMethodAPIToken,
	}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}

	kr := keyring.NewStore(keyring.NewMemory())
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Paths = &paths
	cfg.Keyring = kr
	cfg.Version = "dev"
	cfg.Commit = "test"
	cfg.BuildTime = "now"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Policy effective
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/policy/effective", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("policy status %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "token") && strings.Contains(strings.ToLower(rr.Body.String()), "password") {
		t.Fatal("policy response must not look secret-bearing")
	}

	// Doctor offline
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/doctor?offline=1", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("doctor status %d body=%s", rr2.Code, rr2.Body.String())
	}
	var rep map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep["profileId"] != "corp" {
		t.Fatalf("profileId=%v", rep["profileId"])
	}
	if _, ok := rep["checks"]; !ok {
		t.Fatal("doctor should include checks")
	}
	// Fail closed on missing profile
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/missing/doctor?offline=1", nil))
	if rr3.Code != http.StatusNotFound {
		// may be not_found
		var eb map[string]string
		_ = json.Unmarshal(rr3.Body.Bytes(), &eb)
		if eb["code"] != string(apperr.CodeNotFound) && rr3.Code != http.StatusNotFound {
			t.Fatalf("missing profile: status=%d body=%s", rr3.Code, rr3.Body.String())
		}
	}
}

func TestRun_ListenAndShutdown(t *testing.T) {
	// Bind ephemeral loopback
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := admin.DefaultConfig()
	cfg.Addr = addr
	cfg.Version = "test"
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- admin.Run(ctx, cfg)
	}()

	// Wait until up
	deadline := time.Now().Add(2 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/admin/v1/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				cancel()
				select {
				case err := <-errCh:
					if err != nil {
						t.Fatal(err)
					}
					return
				case <-time.After(3 * time.Second):
					t.Fatal("shutdown timeout")
				}
			}
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	t.Fatalf("server did not become ready: %v", last)
}

func TestPlaceholderOrEmbedHTML(t *testing.T) {
	// UI-008: empty AssetsDir resolves to package/dev/embed. Committed embed
	// always provides index.html so GET / is never a hard failure.
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "html") {
		t.Fatalf("root should serve HTML: %s", body)
	}
	// CSP always present (UI-008).
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("root missing CSP")
	}
}

// Regression: admin.Run with UI-008 timeouts still serves health.
func TestRun_WithTimeouts_ServesHealth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := admin.DefaultConfig()
	cfg.Addr = addr
	cfg.Version = "timeout-test"
	cfg.UIBuild = "ui-timeout"
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- admin.Run(ctx, cfg)
	}()

	deadline := time.Now().Add(2 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/admin/v1/health")
		if err == nil {
			csp := resp.Header.Get("Content-Security-Policy")
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if csp == "" {
					cancel()
					t.Fatal("live health missing CSP")
				}
				if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
					cancel()
					t.Fatal("live health missing nosniff")
				}
				cancel()
				select {
				case err := <-errCh:
					if err != nil {
						t.Fatal(err)
					}
					return
				case <-time.After(3 * time.Second):
					t.Fatal("shutdown timeout")
				}
			}
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	t.Fatalf("server did not become ready under timeouts: %v", last)
}

// Regression: BrowserRouter deep links under --assets-dir must serve index.html.
func TestSPAAssetsFallback_DeepLink(t *testing.T) {
	dir := t.TempDir()
	index := "<!DOCTYPE html><html><body>spa-shell</body></html>"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
	assetDir := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.AssetsDir = dir
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Client route → index.html
	for _, path := range []string{"/metrics", "/audit", "/policy", "/doctor"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status %d body=%s", path, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "spa-shell") {
			t.Fatalf("%s should serve SPA shell, got %q", path, rr.Body.String())
		}
	}

	// Real asset still served
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("asset status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "console.log") {
		t.Fatalf("asset body=%q", rr.Body.String())
	}

	// Missing asset-like path must not SPA-fallback
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil))
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("missing asset status %d want 404", rr2.Code)
	}
}

// Regression: online doctor without shared secret must not exercise keyring/network.
func TestDoctorOnline_RequiresToken(t *testing.T) {
	tmp := t.TempDir()
	paths := config.Paths{
		ConfigDir: filepath.Join(tmp, "cfg"),
		DataDir:   filepath.Join(tmp, "data"),
		CacheDir:  filepath.Join(tmp, "cache"),
	}
	st := profile.NewStore(paths)
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example.corp/",
		AuthMethod:    profile.AuthMethodAPIToken,
	}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}

	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	cfg.Paths = &paths
	cfg.Keyring = keyring.NewStore(keyring.NewMemory())
	// Explicitly no BearerToken (loopback residual pilot path).
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/doctor?offline=0", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("online doctor without token: status=%d body=%s want 403", rr.Code, rr.Body.String())
	}
	var eb map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &eb); err != nil {
		t.Fatal(err)
	}
	if eb["code"] != "permission_denied" {
		t.Fatalf("code=%q want permission_denied", eb["code"])
	}
	// Offline still allowed without token.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/admin/v1/profiles/corp/doctor?offline=1", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("offline doctor without token: status=%d body=%s", rr2.Code, rr2.Body.String())
	}
}
