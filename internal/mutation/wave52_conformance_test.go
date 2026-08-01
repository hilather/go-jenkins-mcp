package mutation_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
)

// Wave 52 / MUT-001 conformance (Track D):
//   - Hard: DefaultTokenTTL, DefaultConfirmCooldown, DefaultMaxPreviewsPerMinute
//     package constants remain positive production defaults (Wave 48 Done* retention)
//   - Soft residual Track A: ResolveConfirmCooldown / EnvConfirmCooldown — if
//     present in package source → log progressive; if missing → t.Log only
//     (never call missing symbols; compile-safe on current main)
//   - Soft residual Track C: ResolveMaxPreviewsPerMinute — same progressive pattern

// TestWave52_Wave48Done_DefaultTokenTTLAndConfirmCooldown_Hard hard-asserts MUT-001
// package defaults remain positive and within sensible bounds. Must remain true
// after Wave 52 Tracks A/C operator resolve land (resolve must not change
// production defaults silently).
func TestWave52_Wave48Done_DefaultTokenTTLAndConfirmCooldown_Hard(t *testing.T) {
	t.Parallel()

	if mutation.DefaultTokenTTL <= 0 {
		t.Fatalf("DefaultTokenTTL must be positive, got %s", mutation.DefaultTokenTTL)
	}
	if mutation.DefaultTokenTTL != 2*time.Minute {
		t.Fatalf("DefaultTokenTTL=%s want 2m (MUT-001 expire quickly)", mutation.DefaultTokenTTL)
	}
	if mutation.DefaultTokenTTL > 15*time.Minute {
		t.Fatalf("DefaultTokenTTL=%s exceeds 15m sanity bound", mutation.DefaultTokenTTL)
	}

	if mutation.DefaultConfirmCooldown <= 0 {
		t.Fatalf("DefaultConfirmCooldown must be positive, got %s", mutation.DefaultConfirmCooldown)
	}
	if mutation.DefaultConfirmCooldown != 5*time.Second {
		t.Fatalf("DefaultConfirmCooldown=%s want 5s", mutation.DefaultConfirmCooldown)
	}
	if mutation.DefaultConfirmCooldown >= mutation.DefaultTokenTTL {
		t.Fatalf("DefaultConfirmCooldown %s must be < DefaultTokenTTL %s",
			mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL)
	}

	if mutation.DefaultMaxPreviewsPerMinute <= 0 {
		t.Fatalf("DefaultMaxPreviewsPerMinute must be positive, got %d", mutation.DefaultMaxPreviewsPerMinute)
	}
	if mutation.DefaultMaxPreviewsPerMinute != 30 {
		t.Fatalf("DefaultMaxPreviewsPerMinute=%d want 30", mutation.DefaultMaxPreviewsPerMinute)
	}

	// Stable reason / type codes used by residual canaries and audit.
	if mutation.ReasonConfirmCooldown != "confirm_cooldown" {
		t.Fatalf("ReasonConfirmCooldown drift: %q", mutation.ReasonConfirmCooldown)
	}
	if mutation.TypeConfirm != "mutation_confirm" {
		t.Fatalf("TypeConfirm drift: %q", mutation.TypeConfirm)
	}
}

// TestWave52_SoftResidual_TrackA_ResolveConfirmCooldown is a compile-safe soft residual
// for Wave 52 Track A ResolveConfirmCooldown / EnvConfirmCooldown operator paths.
// Uses AST inspection of package source so missing symbols never fail compile or
// test; if the symbols appear in source, progressive t.Log (hard resolve contract
// remains Track A's own tests). Soft residual only — never fails for absence.
func TestWave52_SoftResidual_TrackA_ResolveConfirmCooldown(t *testing.T) {
	t.Parallel()

	// Hard path above already locks DefaultConfirmCooldown = 5s.
	// Planned Track A surface (not claimed Done* by Track D):
	//   ResolveConfirmCooldown(flag, env) → duration
	//   EnvConfirmCooldown / serve flag
	found := mutationPackageHasExportedNames(t, "ResolveConfirmCooldown", "EnvConfirmCooldown")
	if !found {
		t.Logf("Wave 52 soft residual Track A: ResolveConfirmCooldown / EnvConfirmCooldown "+
			"not yet present in mutation package source "+
			"(DefaultConfirmCooldown=%s hard-asserted; Track A planned/in progress; not a failure)",
			mutation.DefaultConfirmCooldown)
		return
	}
	// Present: progressive note only — do not call via reflection (signature unknown
	// until Track A lands its hard tests). Existence is enough for soft residual.
	t.Logf("Wave 52 progressive Track A: ResolveConfirmCooldown and/or EnvConfirmCooldown "+
		"present in mutation package source (DefaultConfirmCooldown=%s; hard resolve "+
		"contract owned by Track A tests)",
		mutation.DefaultConfirmCooldown)
}

// TestWave52_SoftResidual_TrackC_ResolveMaxPreviewsPerMinute is a compile-safe soft
// residual for Wave 52 Track C ResolveMaxPreviewsPerMinute operator path. AST
// inspection only; never calls a missing symbol. Soft residual only — never fails
// for absence.
func TestWave52_SoftResidual_TrackC_ResolveMaxPreviewsPerMinute(t *testing.T) {
	t.Parallel()

	found := mutationPackageHasExportedNames(t, "ResolveMaxPreviewsPerMinute", "EnvMaxPreviewsPerMinute")
	if !found {
		t.Logf("Wave 52 soft residual Track C: ResolveMaxPreviewsPerMinute "+
			"not yet present in mutation package source "+
			"(DefaultMaxPreviewsPerMinute=%d hard-asserted; Track C planned/in progress; not a failure)",
			mutation.DefaultMaxPreviewsPerMinute)
		return
	}
	t.Logf("Wave 52 progressive Track C: ResolveMaxPreviewsPerMinute and/or "+
		"EnvMaxPreviewsPerMinute present in mutation package source "+
		"(DefaultMaxPreviewsPerMinute=%d; hard resolve contract owned by Track C tests)",
		mutation.DefaultMaxPreviewsPerMinute)
}

// mutationPackageHasExportedNames returns true if any of the given exported names
// appear as package-level func or const/var declarations in the mutation package
// source directory. Parse failures are soft (return false + log) so Track D stays
// green when the package layout changes unexpectedly.
func mutationPackageHasExportedNames(t *testing.T, names ...string) bool {
	t.Helper()
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}

	// Locate mutation package directory relative to this test file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Log("Wave 52 soft residual: runtime.Caller failed; treating symbols as absent")
		return false
	}
	dir := filepath.Dir(thisFile)

	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Logf("Wave 52 soft residual: read mutation dir: %v", err)
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".go" {
			continue
		}
		// Skip tests for production-symbol probe (resolve may land in non-test .go only).
		if len(name) > 8 && name[len(name)-8:] == "_test.go" {
			continue
		}
		path := filepath.Join(dir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil && want[d.Name.Name] {
					return true
				}
			case *ast.GenDecl:
				if d.Tok != token.CONST && d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, id := range vs.Names {
						if id != nil && want[id.Name] {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
