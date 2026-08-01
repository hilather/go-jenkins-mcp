package tools

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
)

// Wave 53 / POL-005 + MCP-001 + NET-003 + MUT-001 + DIAG conformance (Track D):
//   - Hard-assert Wave 52 Done* operator_caps min/abs backoff ms keys +
//     survey/diagnose keys + default mutation constants
//   - Hard-assert AbsoluteMaxTargetBytes == AbsoluteMaxHardMaxBytes == 64MiB
//   - Soft residual Track A: TokenTTL operator resolve / progressive operator_caps
//     token TTL min/abs keys (AST or map-key; t.Log if missing)
//   - Soft residual Track B: operator_caps min_mutation_confirm_cooldown_ms /
//     absolute_max_mutation_* keys progressive
//   - Soft residual Track C: SoftTargetClampApplied symbol progressive (AST) —
//     if present, assert SoftTargetClampApplied(2e6, 1<<20)==true via progressive
//     path when the symbol is callable; compile-safe (never call missing symbols)

// TestWave53_Wave52Done_OperatorCapsMinAbsBackoffMutation_Hard hard-asserts
// Wave 52 Track B Done*: min/absolute backoff ms keys, survey/diagnose ceilings,
// and default mutation package honesty constants offline. Must not regress.
func TestWave53_Wave52Done_OperatorCapsMinAbsBackoffMutation_Hard(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var caps *diagnostics.SelfCheckItem
	for i := range rep.Items {
		if rep.Items[i].Name == "operator_caps_snapshot" {
			caps = &rep.Items[i]
			break
		}
	}
	if caps == nil || caps.Details == nil {
		t.Fatal("operator_caps_snapshot missing (Wave 43–52 Done* hard path)")
	}
	if caps.Status != diagnostics.SelfCheckOK {
		t.Fatalf("operator_caps_snapshot status=%s msg=%s", caps.Status, caps.Message)
	}

	// Wave 52 Track B: min/absolute backoff resolve bounds (ms).
	for _, k := range []string{
		"min_initial_backoff_ms",
		"absolute_max_initial_backoff_ms",
		"min_max_backoff_ms",
		"absolute_max_max_backoff_ms",
		"default_initial_backoff_ms",
		"default_max_backoff_ms",
		// Wave 50 concurrent honesty retention
		"absolute_max_concurrent",
		// Wave 51 survey/diagnose ceilings
		"default_survey_max_total_builds",
		"hard_survey_max_total_builds",
		"default_survey_max_jobs",
		"hard_survey_max_jobs",
		"default_survey_max_log_bytes_total",
		"hard_survey_max_log_bytes_total",
		"default_survey_max_wall_seconds",
		"hard_survey_max_wall_seconds",
		"default_diagnose_log_bytes",
		"hard_diagnose_log_bytes",
		"default_diagnose_max_findings",
		"hard_diagnose_max_findings",
		// Wave 52 mutation package honesty (offline defaults)
		"default_mutation_confirm_cooldown_ms",
		"default_mutation_max_previews_per_minute",
		"default_mutation_token_ttl_ms",
		// Soft target absolute (Wave 51 Track C)
		"default_target_bytes",
		"absolute_max_target_bytes",
	} {
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 52 Done* operator_caps key %s missing/non-positive: %+v", k, caps.Details[k])
		}
	}

	// Backoff contracts: min 10 / abs initial 2000; min max 100 / abs max 60000;
	// defaults initial 100 / max 5000.
	if n, ok := asIntTools(caps.Details["min_initial_backoff_ms"]); !ok || n != 10 {
		t.Fatalf("min_initial_backoff_ms want 10, got %+v", caps.Details["min_initial_backoff_ms"])
	}
	if n, ok := asIntTools(caps.Details["absolute_max_initial_backoff_ms"]); !ok || n != 2000 {
		t.Fatalf("absolute_max_initial_backoff_ms want 2000, got %+v", caps.Details["absolute_max_initial_backoff_ms"])
	}
	if n, ok := asIntTools(caps.Details["min_max_backoff_ms"]); !ok || n != 100 {
		t.Fatalf("min_max_backoff_ms want 100, got %+v", caps.Details["min_max_backoff_ms"])
	}
	if n, ok := asIntTools(caps.Details["absolute_max_max_backoff_ms"]); !ok || n != 60000 {
		t.Fatalf("absolute_max_max_backoff_ms want 60000, got %+v", caps.Details["absolute_max_max_backoff_ms"])
	}
	if n, ok := asIntTools(caps.Details["default_initial_backoff_ms"]); !ok || n != 100 {
		t.Fatalf("default_initial_backoff_ms want 100, got %+v", caps.Details["default_initial_backoff_ms"])
	}
	if n, ok := asIntTools(caps.Details["default_max_backoff_ms"]); !ok || n != 5000 {
		t.Fatalf("default_max_backoff_ms want 5000, got %+v", caps.Details["default_max_backoff_ms"])
	}
	// Mutation defaults: cooldown 5000 ms, previews 30, token TTL 120000 ms;
	// cooldown < token TTL.
	if n, ok := asIntTools(caps.Details["default_mutation_confirm_cooldown_ms"]); !ok || n != 5000 {
		t.Fatalf("default_mutation_confirm_cooldown_ms want 5000, got %+v",
			caps.Details["default_mutation_confirm_cooldown_ms"])
	}
	if n, ok := asIntTools(caps.Details["default_mutation_max_previews_per_minute"]); !ok || n != 30 {
		t.Fatalf("default_mutation_max_previews_per_minute want 30, got %+v",
			caps.Details["default_mutation_max_previews_per_minute"])
	}
	if n, ok := asIntTools(caps.Details["default_mutation_token_ttl_ms"]); !ok || n != 120000 {
		t.Fatalf("default_mutation_token_ttl_ms want 120000, got %+v",
			caps.Details["default_mutation_token_ttl_ms"])
	}
	cd, _ := asIntTools(caps.Details["default_mutation_confirm_cooldown_ms"])
	ttl, _ := asIntTools(caps.Details["default_mutation_token_ttl_ms"])
	if cd >= ttl {
		t.Fatalf("default mutation cooldown %d must be < token TTL %d", cd, ttl)
	}
	// Soft target absolute 64 MiB offline honesty.
	if n, ok := asIntTools(caps.Details["absolute_max_target_bytes"]); !ok || n != 64<<20 {
		t.Fatalf("absolute_max_target_bytes want 64MiB, got %+v", caps.Details["absolute_max_target_bytes"])
	}
	if caps.Details["live_target_bytes_available_offline"] != false {
		t.Fatalf("live_target_bytes_available_offline must be false offline: %+v", caps.Details)
	}
}

// TestWave53_Wave52Done_TargetBytesAbsolute_Hard hard-asserts AbsoluteMaxTargetBytes
// == AbsoluteMaxHardMaxBytes == 64 MiB (Wave 51 Track C Done* retention through
// Wave 52/53). Must not regress.
func TestWave53_Wave52Done_TargetBytesAbsolute_Hard(t *testing.T) {
	t.Parallel()

	if AbsoluteMaxHardMaxBytes != 64<<20 {
		t.Fatalf("AbsoluteMaxHardMaxBytes=%d want 64MiB", AbsoluteMaxHardMaxBytes)
	}
	if AbsoluteMaxTargetBytes != AbsoluteMaxHardMaxBytes {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want AbsoluteMaxHardMaxBytes=%d",
			AbsoluteMaxTargetBytes, AbsoluteMaxHardMaxBytes)
	}
	if AbsoluteMaxTargetBytes != 64<<20 {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want 64MiB", AbsoluteMaxTargetBytes)
	}
	if DefaultTargetBytes != 64*1024 {
		t.Fatalf("DefaultTargetBytes=%d want 64KiB", DefaultTargetBytes)
	}
}

// TestWave53_SoftResidual_TrackA_TokenTTL progressive soft residual for Wave 53
// Track A TokenTTL operator resolve (mutation package symbols) and progressive
// operator_caps min/abs mutation token TTL keys. AST + map-key probe only; never
// fails for absence; never calls missing symbols.
func TestWave53_SoftResidual_TrackA_TokenTTL(t *testing.T) {
	t.Parallel()

	// Progressive operator_caps keys Track A may add once TokenTTL resolve honesty
	// lands (min/absolute bounds exposure alongside default_mutation_token_ttl_ms).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}
	var caps *diagnostics.SelfCheckItem
	for i := range rep.Items {
		if rep.Items[i].Name == "operator_caps_snapshot" {
			caps = &rep.Items[i]
			break
		}
	}

	foundKeys := 0
	if caps != nil && caps.Details != nil {
		progressiveKeys := []string{
			"min_mutation_token_ttl_ms",
			"absolute_max_mutation_token_ttl_ms",
			"min_token_ttl_ms",
			"absolute_max_token_ttl_ms",
			"min_mutation_token_ttl_seconds",
			"absolute_max_mutation_token_ttl_seconds",
		}
		seen := map[string]bool{}
		for _, k := range progressiveKeys {
			v, ok := caps.Details[k]
			if !ok || seen[k] {
				continue
			}
			seen[k] = true
			foundKeys++
			t.Logf("Wave 53 progressive Track A: operator_caps key %s=%v", k, v)
			if !detailPositiveIntTools(caps.Details, k) {
				t.Fatalf("Wave 53 Track A key %s present but non-positive: %+v", k, v)
			}
		}
	}

	// Also AST-probe tools package for ResolveTokenTTL-style helpers (if resolve
	// lands in tools rather than mutation). Soft residual only.
	astTokenTTL := toolsPackageHasExportedNamesWave53(t,
		"ResolveTokenTTL", "EnvTokenTTL", "MinTokenTTL", "AbsoluteMaxTokenTTL")

	if foundKeys == 0 && !astTokenTTL {
		t.Log("Wave 53 soft residual Track A: ResolveTokenTTL / EnvTokenTTL / " +
			"MinTokenTTL / AbsoluteMaxTokenTTL and operator_caps min/abs token TTL " +
			"keys not yet present (Track A planned/in progress; not a failure)")
		return
	}
	if astTokenTTL {
		t.Log("Wave 53 progressive Track A: TokenTTL resolve symbol(s) present in " +
			"tools package source (hard resolve contract owned by Track A tests)")
	}
	if foundKeys > 0 {
		t.Logf("Wave 53 progressive Track A: %d operator_caps token TTL bound key(s) present", foundKeys)
	}
}

// TestWave53_SoftResidual_TrackB_MinAbsMutationKeys progressive soft residual for
// Wave 53 Track B operator_caps min_mutation_confirm_cooldown_ms /
// absolute_max_mutation_* honesty keys. If present → assert positive; if missing
// → t.Log only. Never fails for absence (Track B planned; not claimed Done* by
// Track D). Does not call missing package symbols.
func TestWave53_SoftResidual_TrackB_MinAbsMutationKeys(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := diagnostics.RunSecuritySelfCheck(ctx, diagnostics.SelfCheckOptions{SkipSupportBundleCanary: true})
	if err != nil {
		t.Fatal(err)
	}

	var caps *diagnostics.SelfCheckItem
	for i := range rep.Items {
		if rep.Items[i].Name == "operator_caps_snapshot" {
			caps = &rep.Items[i]
			break
		}
	}
	if caps == nil || caps.Details == nil {
		t.Log("Wave 53 soft residual Track B: operator_caps_snapshot unavailable for optional key probe")
		return
	}

	// Progressive keys Track B may add once min/absolute mutation honesty lands
	// (Wave 53 Track B). Defaults (default_mutation_*) are already hard above.
	progressivePositive := []string{
		"min_mutation_confirm_cooldown_ms",
		"absolute_max_mutation_confirm_cooldown_ms",
		"absolute_max_mutation_max_previews_per_minute",
		"absolute_max_mutation_previews_per_minute",
		"min_mutation_max_previews_per_minute",
		"absolute_max_mutation_token_ttl_ms",
		"min_mutation_token_ttl_ms",
		// Alternate naming residuals.
		"min_mutation_confirm_cooldown_milliseconds",
		"absolute_max_mutation_confirm_cooldown_milliseconds",
		"absolute_max_mutation_token_ttl_milliseconds",
	}

	found := 0
	seen := map[string]bool{}
	for _, k := range progressivePositive {
		v, ok := caps.Details[k]
		if !ok || seen[k] {
			continue
		}
		seen[k] = true
		found++
		t.Logf("Wave 53 progressive Track B: operator_caps key %s=%v", k, v)
		if !detailPositiveIntTools(caps.Details, k) {
			t.Fatalf("Wave 53 Track B key %s present but non-positive: %+v", k, v)
		}
	}
	if found == 0 {
		t.Log("Wave 53 soft residual Track B: min_mutation_confirm_cooldown_ms / " +
			"absolute_max_mutation_* operator_caps keys not yet present " +
			"(Track B planned/in progress; not a failure)")
	}
}

// TestWave53_SoftResidual_TrackC_SoftTargetClampApplied is a compile-safe soft
// residual for Wave 53 Track C SoftTargetClampApplied. Uses AST inspection of
// package source so missing symbols never fail compile or test.
//
// If SoftTargetClampApplied is present in production source, progressive path
// verifies the expected contract SoftTargetClampApplied(2e6, 1<<20)==true via
// the toolsPackage progressive call helper when a same-package callable is
// registered; otherwise existence is logged only (hard contract owned by Track C).
// Soft residual only — never fails for absence.
func TestWave53_SoftResidual_TrackC_SoftTargetClampApplied(t *testing.T) {
	t.Parallel()

	found := toolsPackageHasExportedNamesWave53(t, "SoftTargetClampApplied")
	if !found {
		t.Log("Wave 53 soft residual Track C: SoftTargetClampApplied not yet present " +
			"in tools package source (soft-target clamp log honesty planned/in progress; " +
			"not a failure; expected contract when landed: SoftTargetClampApplied(2e6, 1<<20)==true)")
		return
	}

	// Symbol present in production source. Prefer progressive call via optional
	// registry if Track C wires one; otherwise assert via direct call only when
	// the function is already linked into this package (compile requires symbol).
	// Compile-safe strategy: never reference SoftTargetClampApplied by name in
	// this file (would break baseline). Existence + expected contract is logged;
	// Track C unit tests own the hard SoftTargetClampApplied(2e6, 1<<20)==true assert.
	//
	// Progressive runtime assert when a test-hook is registered (optional).
	if fn := softTargetClampAppliedProgressive(); fn != nil {
		if !fn(2e6, 1<<20) {
			t.Fatalf("Wave 53 Track C SoftTargetClampApplied(2e6, 1<<20) present but returned false")
		}
		t.Log("Wave 53 progressive Track C: SoftTargetClampApplied(2e6, 1<<20)==true")
		return
	}
	t.Log("Wave 53 progressive Track C: SoftTargetClampApplied present in tools package " +
		"source (expected SoftTargetClampApplied(2e6, 1<<20)==true; hard call owned by " +
		"Track C tests / optional progressive hook softTargetClampAppliedProgressive)")
}

// softTargetClampAppliedProgressive returns a progressive callable for Track C
// SoftTargetClampApplied when registered. Default nil keeps Track D compile-safe
// and green when Track C has not landed a hook. Track C may assign this in an
// init or test helper once SoftTargetClampApplied exists:
//
//	softTargetClampAppliedHook = SoftTargetClampApplied
var softTargetClampAppliedHook func(targetBytes, hardMaxBytes int64) bool

func softTargetClampAppliedProgressive() func(targetBytes, hardMaxBytes int64) bool {
	return softTargetClampAppliedHook
}

// toolsPackageHasExportedNamesWave53 returns true if any of the given exported
// names appear as package-level func or const/var declarations in the tools
// package source directory (non-test .go only). Parse failures are soft.
func toolsPackageHasExportedNamesWave53(t *testing.T, names ...string) bool {
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
		t.Logf("Wave 53 soft residual: read tools dir: %v", err)
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
