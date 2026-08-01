package admin

import (
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin/uiembed"
)

// PackagedAssetsDir is the default filesystem install path for admin SPA assets
// on Tier-1 packages (UI-008 / PKG-001). Present when package includes
// web/admin/dist under usr/share/jenkins-mcp/admin-ui.
const PackagedAssetsDir = "/usr/share/jenkins-mcp/admin-ui"

// DevAssetsDir is the residual developer path (cwd-relative) for local SPA
// builds without packaging (make admin-ui → web/admin/dist).
const DevAssetsDir = "web/admin/dist"

// UIBuildFileName is an optional secret-free stamp file in an assets root.
const UIBuildFileName = "UI_BUILD"

// AssetsSource identifies where SPA static files were resolved from (UI-008).
type AssetsSource string

const (
	AssetsSourceNone    AssetsSource = "none"
	AssetsSourceFlag    AssetsSource = "flag"
	AssetsSourcePackage AssetsSource = "package"
	AssetsSourceDev     AssetsSource = "dev"
	AssetsSourceEmbed   AssetsSource = "embed"
)

// ResolvedAssets is the result of default asset resolution (UI-008).
//
// Priority when explicit AssetsDir is empty:
//  1. PackagedAssetsDir if index.html exists (fresh install without npm)
//  2. DevAssetsDir if index.html exists (developer residual)
//  3. Embedded uiembed FS (always; may be placeholder or full SPA)
//
// Explicit --assets-dir always wins when non-empty (validated separately).
type ResolvedAssets struct {
	// Dir is a filesystem root when Source is flag|package|dev.
	Dir string
	// UseEmbed is true when serving from uiembed.FS.
	UseEmbed bool
	// UIBuild is the secret-free asset build id (may be empty).
	UIBuild string
	// Source is which layer won.
	Source AssetsSource
}

// ResolveAssets picks SPA static roots for admin serve (UI-008).
//
// explicit, when non-empty, is treated as --assets-dir (caller must have
// validated the directory exists). When empty, walks package → dev → embed.
func ResolveAssets(explicit string) ResolvedAssets {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return ResolvedAssets{
			Dir:     filepath.Clean(explicit),
			UIBuild: readUIBuildFile(explicit),
			Source:  AssetsSourceFlag,
		}
	}
	// Prefer packaged install path so fresh RPM/DEB/tarball installs serve the
	// full SPA without npm even when the binary only embeds a placeholder.
	if dir := firstExistingAssetsDir(PackagedAssetsDir); dir != "" {
		return ResolvedAssets{
			Dir:     dir,
			UIBuild: readUIBuildFile(dir),
			Source:  AssetsSourcePackage,
		}
	}
	if dir := firstExistingAssetsDir(DevAssetsDir); dir != "" {
		return ResolvedAssets{
			Dir:     dir,
			UIBuild: readUIBuildFile(dir),
			Source:  AssetsSourceDev,
		}
	}
	if uiembed.Available() {
		return ResolvedAssets{
			UseEmbed: true,
			UIBuild:  uiembed.UIBuild(),
			Source:   AssetsSourceEmbed,
		}
	}
	return ResolvedAssets{Source: AssetsSourceNone}
}

func firstExistingAssetsDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return ""
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		return ""
	}
	return filepath.Clean(dir)
}

func readUIBuildFile(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, UIBuildFileName))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// spaFSServer serves static files from fsys with SPA index.html fallback for
// client-side routes (same rules as spaFileServer).
func spaFSServer(fsys fs.FS) http.Handler {
	if fsys == nil {
		return http.NotFoundHandler()
	}
	files := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := r.URL.Path
		if p == "" {
			p = "/"
		}
		if p == "/admin/v1" || strings.HasPrefix(p, "/admin/v1/") {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(path.Clean("/"+p), "/")
		if rel == "" || rel == "." {
			files.ServeHTTP(w, r)
			return
		}
		if f, err := fsys.Open(rel); err == nil {
			st, stErr := f.Stat()
			_ = f.Close()
			if stErr == nil && !st.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		base := path.Base(rel)
		if i := strings.LastIndex(base, "."); i > 0 {
			ext := strings.ToLower(base[i:])
			if ext != ".html" {
				http.NotFound(w, r)
				return
			}
		}
		// Client route → index.html
		b, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(b)
	})
}
