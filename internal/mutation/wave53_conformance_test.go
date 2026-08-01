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

// Wave 53 / MUT-001 conformance (Track D):
//   - Hard-assert Wave 52 Done*: ResolveConfirmCooldown defaults/min/abs;
//     ResolveMaxPreviewsPerMinute defaults/abs/0→default; DefaultTokenTTL=2m
//   - Soft residual Track A: ResolveTokenTTL / EnvTokenTTL / MinTokenTTL /
//     AbsoluteMaxTokenTTL — AST name probe; t.Log if missing (never fail for
//     absence; never call missing symbols; compile-safe on current baseline)

// TestWave53_Wave52Done_ResolveConfirmCooldown_Hard hard-asserts Wave 52 Track A
// Done*: ResolveConfirmCooldown default 5s, min 1s, absolute 5m, flag wins,
// 0→default, fail-closed below min / above absolute. Must not regress.
func TestWave53_Wave52Done_ResolveConfirmCooldown_Hard(t *testing.T) {
	t.Parallel()

	if mutation.DefaultConfirmCooldown != 5*time.Second {
		t.Fatalf("DefaultConfirmCooldown=%s want 5s", mutation.DefaultConfirmCooldown)
	}
	if mutation.MinConfirmCooldown != time.Second {
		t.Fatalf("MinConfirmCooldown=%s want 1s", mutation.MinConfirmCooldown)
	}
	if mutation.AbsoluteMaxConfirmCooldown != 5*time.Minute {
		t.Fatalf("AbsoluteMaxConfirmCooldown=%s want 5m", mutation.AbsoluteMaxConfirmCooldown)
	}
	if mutation.EnvConfirmCooldown != "JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN" {
		t.Fatalf("EnvConfirmCooldown drift: %q", mutation.EnvConfirmCooldown)
	}

	d, err := mutation.ResolveConfirmCooldown("", "")
	if err != nil || d != mutation.DefaultConfirmCooldown {
		t.Fatalf("default: d=%v err=%v want %v", d, err, mutation.DefaultConfirmCooldown)
	}
	d, err = mutation.ResolveConfirmCooldown("0", "30s")
	if err != nil || d != mutation.DefaultConfirmCooldown {
		t.Fatalf("flag 0→default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown("0s", "30s")
	if err != nil || d != mutation.DefaultConfirmCooldown {
		t.Fatalf("flag 0s→default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown("45s", "1m")
	if err != nil || d != 45*time.Second {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown("", "30s")
	if err != nil || d != 30*time.Second {
		t.Fatalf("env only: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown(mutation.MinConfirmCooldown.String(), "")
	if err != nil || d != mutation.MinConfirmCooldown {
		t.Fatalf("at min: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown(mutation.AbsoluteMaxConfirmCooldown.String(), "")
	if err != nil || d != mutation.AbsoluteMaxConfirmCooldown {
		t.Fatalf("at absolute: d=%v err=%v", d, err)
	}
	if _, err := mutation.ResolveConfirmCooldown("500ms", ""); err == nil {
		t.Fatal("below min must fail closed")
	}
	if _, err := mutation.ResolveConfirmCooldown("6m", ""); err == nil {
		t.Fatal("above absolute must fail closed")
	}
	if _, err := mutation.ResolveConfirmCooldown("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
	if _, err := mutation.ResolveConfirmCooldown("-1s", ""); err == nil {
		t.Fatal("negative must fail closed")
	}
}

// TestWave53_Wave52Done_ResolveMaxPreviewsPerMinute_Hard hard-asserts Wave 52
// Track C Done*: ResolveMaxPreviewsPerMinute default 30, absolute 300, 0→default
// (not unlimited), flag wins, fail-closed above absolute / negative / invalid.
func TestWave53_Wave52Done_ResolveMaxPreviewsPerMinute_Hard(t *testing.T) {
	t.Parallel()

	if mutation.DefaultMaxPreviewsPerMinute != 30 {
		t.Fatalf("DefaultMaxPreviewsPerMinute=%d want 30", mutation.DefaultMaxPreviewsPerMinute)
	}
	if mutation.AbsoluteMaxPreviewsPerMinute != 300 {
		t.Fatalf("AbsoluteMaxPreviewsPerMinute=%d want 300", mutation.AbsoluteMaxPreviewsPerMinute)
	}
	if mutation.EnvMaxPreviewsPerMinute != "JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE" {
		t.Fatalf("EnvMaxPreviewsPerMinute drift: %q", mutation.EnvMaxPreviewsPerMinute)
	}

	n, err := mutation.ResolveMaxPreviewsPerMinute("", "")
	if err != nil || n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("default: n=%d err=%v want %d", n, err, mutation.DefaultMaxPreviewsPerMinute)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("0", "100")
	if err != nil || n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("flag 0→default (not unlimited): n=%d err=%v", n, err)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("", "0")
	if err != nil || n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("env 0→default: n=%d err=%v", n, err)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("45", "100")
	if err != nil || n != 45 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("", "60")
	if err != nil || n != 60 {
		t.Fatalf("env only: n=%d err=%v", n, err)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("300", "")
	if err != nil || n != mutation.AbsoluteMaxPreviewsPerMinute {
		t.Fatalf("at absolute: n=%d err=%v want %d", n, err, mutation.AbsoluteMaxPreviewsPerMinute)
	}
	if _, err := mutation.ResolveMaxPreviewsPerMinute("301", ""); err == nil {
		t.Fatal("above absolute must fail closed")
	}
	if _, err := mutation.ResolveMaxPreviewsPerMinute("-1", ""); err == nil {
		t.Fatal("negative must fail closed")
	}
	if _, err := mutation.ResolveMaxPreviewsPerMinute("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
}

// TestWave53_Wave52Done_DefaultTokenTTL_Hard hard-asserts DefaultTokenTTL remains
// 2m (MUT-001 expire quickly) and ConfirmCooldown stays strictly below TokenTTL.
func TestWave53_Wave52Done_DefaultTokenTTL_Hard(t *testing.T) {
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
	if mutation.DefaultConfirmCooldown >= mutation.DefaultTokenTTL {
		t.Fatalf("DefaultConfirmCooldown %s must be < DefaultTokenTTL %s",
			mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL)
	}
}

// TestWave53_SoftResidual_TrackA_ResolveTokenTTL is a compile-safe soft residual
// for Wave 53 Track A ResolveTokenTTL / EnvTokenTTL / MinTokenTTL /
// AbsoluteMaxTokenTTL operator paths. AST inspection only; never calls a missing
// symbol. Soft residual only — never fails for absence.
func TestWave53_SoftResidual_TrackA_ResolveTokenTTL(t *testing.T) {
	t.Parallel()

	// Hard path above already locks DefaultTokenTTL = 2m.
	// Planned Track A surface (not claimed Done* by Track D):
	//   ResolveTokenTTL(flag, env) → duration
	//   EnvTokenTTL / MinTokenTTL / AbsoluteMaxTokenTTL / serve flag
	found := mutationPackageHasExportedNamesWave53(t,
		"ResolveTokenTTL", "EnvTokenTTL", "MinTokenTTL", "AbsoluteMaxTokenTTL")
	if !found {
		t.Logf("Wave 53 soft residual Track A: ResolveTokenTTL / EnvTokenTTL / "+
			"MinTokenTTL / AbsoluteMaxTokenTTL not yet present in mutation package source "+
			"(DefaultTokenTTL=%s hard-asserted; Track A planned/in progress; not a failure)",
			mutation.DefaultTokenTTL)
		return
	}
	// Present: progressive note only — do not call via reflection (signature unknown
	// until Track A lands its hard tests). Existence is enough for soft residual.
	t.Logf("Wave 53 progressive Track A: ResolveTokenTTL and/or EnvTokenTTL / "+
		"MinTokenTTL / AbsoluteMaxTokenTTL present in mutation package source "+
		"(DefaultTokenTTL=%s; hard resolve contract owned by Track A tests)",
		mutation.DefaultTokenTTL)
}

// mutationPackageHasExportedNamesWave53 returns true if any of the given exported
// names appear as package-level func or const/var declarations in the mutation
// package source directory. Parse failures are soft (return false + log) so Track
// D stays green when the package layout changes unexpectedly.
// Named distinctly from wave52 helper to avoid redeclaration in the same package.
func mutationPackageHasExportedNamesWave53(t *testing.T, names ...string) bool {
	t.Helper()
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Log("Wave 53 soft residual: runtime.Caller failed; treating symbols as absent")
		return false
	}
	dir := filepath.Dir(thisFile)

	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Logf("Wave 53 soft residual: read mutation dir: %v", err)
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
