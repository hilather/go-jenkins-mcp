package jenkins_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

func TestRouteMatrix_WriteGolden(t *testing.T) {
	if os.Getenv("UPDATE_ROUTE_MATRIX") != "1" {
		t.Skip("set UPDATE_ROUTE_MATRIX=1 to rewrite docs/tst/route-matrix.json")
	}
	b, err := jenkins.RouteMatrixJSON()
	if err != nil {
		t.Fatal(err)
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	path := filepath.Join(root, "docs", "tst", "route-matrix.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(b)+1)
}
