package admin_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/admin/uiembed"
)

func TestResolveAssets_ExplicitFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>flag</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, admin.UIBuildFileName), []byte("from-flag\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := admin.ResolveAssets(dir)
	if res.Source != admin.AssetsSourceFlag {
		t.Fatalf("source=%s want flag", res.Source)
	}
	if res.Dir != filepath.Clean(dir) {
		t.Fatalf("dir=%q", res.Dir)
	}
	if res.UseEmbed {
		t.Fatal("flag must not use embed")
	}
	if res.UIBuild != "from-flag" {
		t.Fatalf("uiBuild=%q", res.UIBuild)
	}
}

func TestResolveAssets_EmptyFallsToEmbed(t *testing.T) {
	// With no package path and no dev dist under cwd, empty → embed.
	// (PackagedAssetsDir is absolute and typically absent in unit tests.)
	// If web/admin/dist exists in CWD from a prior make admin-ui, this test
	// may resolve to dev — assert embed OR dev OR package only.
	res := admin.ResolveAssets("")
	switch res.Source {
	case admin.AssetsSourceEmbed:
		if !res.UseEmbed {
			t.Fatal("embed source must set UseEmbed")
		}
		if res.UIBuild == "" {
			t.Fatal("embed UIBuild should be non-empty")
		}
		if !uiembed.Available() {
			t.Fatal("uiembed should be available")
		}
	case admin.AssetsSourceDev, admin.AssetsSourcePackage:
		if res.Dir == "" {
			t.Fatalf("source=%s dir empty", res.Source)
		}
	default:
		t.Fatalf("unexpected source %q", res.Source)
	}
}

func TestResolveAssets_DevDirWhenPresent(t *testing.T) {
	// Simulate package path preference with a temp dir via explicit flag only;
	// package/dev absolute/cwd paths are environment-dependent. Unit-test the
	// helper that checks index.html presence by writing a temp tree and using
	// ResolveAssets(explicit).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := admin.ResolveAssets(dir)
	if res.Source != admin.AssetsSourceFlag || res.Dir == "" {
		t.Fatalf("res=%+v", res)
	}
	// Directory without index.html is not a valid assets root for defaults;
	// explicit flag still returns the path (ValidateConfig enforces existence).
	empty := t.TempDir()
	res2 := admin.ResolveAssets(empty)
	if res2.Source != admin.AssetsSourceFlag {
		t.Fatalf("explicit empty dir still flag source: %+v", res2)
	}
}

func TestEmbedServesIndex_WithSecurityHeaders(t *testing.T) {
	// Empty AssetsDir → resolve to embed (unless package/dev present).
	// Force embed by using a non-existent explicit path is invalid ValidateConfig.
	// Instead: set no AssetsDir; if package/dev win, still check headers on /.
	cfg := admin.DefaultConfig()
	cfg.Addr = "127.0.0.1:0"
	// Leave AssetsDir empty so defaults apply.
	h, err := admin.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("root must have CSP")
	}
	body := rr.Body.String()
	// Embed placeholder or filesystem SPA — must be HTML.
	if !strings.Contains(strings.ToLower(body), "html") {
		snippet := body
		if len(snippet) > 80 {
			snippet = snippet[:80]
		}
		t.Fatalf("root body not HTML: %q", snippet)
	}
	// Health must expose uiBuild from resolution when not set on Config.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("health status %d", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "uiBuild") {
		t.Fatalf("health missing uiBuild: %s", rr2.Body.String())
	}
}

func TestUIEmbedPackage_Available(t *testing.T) {
	if !uiembed.Available() {
		t.Fatal("committed embed dist/index.html must make Available() true")
	}
	id := uiembed.UIBuild()
	if id == "" {
		t.Fatal("UIBuild empty")
	}
	if !uiembed.IsPlaceholder() && id == "embedded-placeholder" {
		t.Fatal("inconsistent placeholder")
	}
}

// Regression: default resolution prefers a cwd web/admin/dist with index.html over embed.
func TestResolveAssets_DevDirPreferredOverEmbed(t *testing.T) {
	tmp := t.TempDir()
	dev := filepath.Join(tmp, "web", "admin", "dist")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dev, "index.html"), []byte("<html>dev-spa</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dev, admin.UIBuildFileName), []byte("dev-build-1"), 0o644); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	res := admin.ResolveAssets("")
	// Package path may still win if /usr/share/... exists on the host (unusual).
	if res.Source == admin.AssetsSourcePackage {
		t.Skip("host has packaged admin-ui; cannot assert dev preference")
	}
	if res.Source != admin.AssetsSourceDev {
		t.Fatalf("source=%s want dev (dir=%q)", res.Source, res.Dir)
	}
	if res.UIBuild != "dev-build-1" {
		t.Fatalf("uiBuild=%q", res.UIBuild)
	}
	if res.UseEmbed {
		t.Fatal("dev must not use embed")
	}
}
