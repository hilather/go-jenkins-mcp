// Package uiembed holds optional embedded admin SPA static assets (UI-008).
//
// The committed dist/ tree is a minimal placeholder so `go build` succeeds
// without Node. Release/package flows may replace dist/ with a full Vite build
// via `make admin-ui-embed` (build SPA → copy into this package) before compile.
//
// Do not commit node_modules. Operators may also ship filesystem assets under
// /usr/share/jenkins-mcp/admin-ui (packaging) without re-embedding.
package uiembed

import (
	"embed"
	"io/fs"
	"strings"
)

// dist holds static files served at GET / when no filesystem AssetsDir wins.
//
//go:embed all:dist
var dist embed.FS

// FS returns the embedded SPA root (contents of dist/).
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return dist
	}
	return sub
}

// Available reports whether the embed tree has an index.html.
func Available() bool {
	_, err := fs.Stat(FS(), "index.html")
	return err == nil
}

// UIBuild returns the secret-free UI asset build id from dist/UI_BUILD when
// present, else "embedded-placeholder". Never contains secrets.
func UIBuild() string {
	b, err := fs.ReadFile(FS(), "UI_BUILD")
	if err != nil {
		return "embedded-placeholder"
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "embedded-placeholder"
	}
	// Single line only; strip residual newlines/comments.
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "embedded-placeholder"
	}
	return s
}

// IsPlaceholder reports whether the embed is the committed minimal shell
// (not a full Vite production build). Packaging may prefer filesystem assets.
func IsPlaceholder() bool {
	id := UIBuild()
	return id == "embedded-placeholder" || id == "placeholder"
}
