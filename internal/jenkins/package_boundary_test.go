package jenkins_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FND-004: Jenkins client package must not import MCP or tools.
// Broader allow-list / cycle checks live in internal/depgraph.
func TestJenkinsPackageDoesNotImportMCP(t *testing.T) {
	dir := "."
	// When run as jenkins_test, sources are in parent (same package dir).
	// Discover via runtime: list .go files excluding tests in this package path.
	entries, err := os.ReadDir(dir)
	if err != nil {
		// package test runs with cwd = package dir
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(p, "modelcontextprotocol") ||
				strings.Contains(p, "/internal/tools") ||
				strings.Contains(p, "/internal/mcpserver") {
				t.Errorf("%s imports forbidden package %s", path, p)
			}
		}
	}
}
