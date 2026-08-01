package redact_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
)

func TestLoadEnterprisePatternsFileOK(t *testing.T) {
	// Installs package enterprise state — not parallel-safe with other redact state tests.
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.json")
	body := `[{"name":"corp_id","expr":"\\bCORP-[0-9]{6}\\b"},{"name":"badge","expr":"\\bBADGE-[A-Z]{4}\\b"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pats, err := redact.LoadEnterprisePatternsFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(pats) != 2 {
		t.Fatalf("want 2 patterns, got %d", len(pats))
	}
	if pats[0].Category != "corp_id" || pats[1].Category != "badge" {
		t.Fatalf("categories: %+v", pats)
	}
	// Install and verify redaction (no secrets in report).
	redact.SetEnterprisePatterns(redact.StaticEnterprise(pats))
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	out, rep := redact.RedactTextReport("id CORP-123456 badge BADGE-WXYZ end")
	if strings.Contains(out, "CORP-123456") || strings.Contains(out, "BADGE-WXYZ") {
		t.Fatalf("patterns missed: %q", out)
	}
	if rep.Counts["corp_id"] < 1 || rep.Counts["badge"] < 1 {
		t.Fatalf("counts: %+v", rep.Counts)
	}
	// Report keys are categories only — never matched secret material.
	for cat := range rep.Counts {
		if strings.Contains(cat, "123456") || strings.Contains(cat, "WXYZ") {
			t.Fatalf("report category leaked match: %q", cat)
		}
	}
}

func TestLoadEnterprisePatternsFileInvalidRegexFailClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	// Unbalanced group — must fail the whole file.
	body := `[{"name":"good","expr":"\\bok\\b"},{"name":"bad","expr":"("}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := redact.LoadEnterprisePatternsFile(path)
	if err == nil {
		t.Fatal("expected invalid regex to fail closed")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error should name pattern: %v", err)
	}
}

func TestLoadEnterprisePatternsFileInvalidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "obj.json")
	if err := os.WriteFile(path, []byte(`{"name":"x","expr":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := redact.LoadEnterprisePatternsFile(path)
	if err == nil {
		t.Fatal("object root must fail closed")
	}
}

func TestLoadEnterprisePatternsFileMissing(t *testing.T) {
	t.Parallel()
	_, err := redact.LoadEnterprisePatternsFile(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("missing file must fail closed")
	}
}

func TestLoadEnterprisePatternsEmptyArray(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	pats, err := redact.LoadEnterprisePatternsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pats) != 0 {
		t.Fatalf("want empty, got %d", len(pats))
	}
}

func TestApplyEnterprisePatternsFromEnvironUnset(t *testing.T) {
	// Mutates package + env — not parallel.
	t.Setenv(redact.EnvRedactPatternsFile, "")
	// Seed then clear via unset path.
	pats, _ := redact.CompileEnterprisePatterns([]struct{ Name, Expr string }{
		{Name: "seed", Expr: `\bSEED-SECRET\b`},
	})
	redact.SetEnterprisePatterns(redact.StaticEnterprise(pats))
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	n, err := redact.ApplyEnterprisePatternsFromEnviron()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("want 0, got %d", n)
	}
	out := redact.RedactText("SEED-SECRET still there")
	if !strings.Contains(out, "SEED-SECRET") {
		t.Fatalf("unset env should clear enterprise patterns: %q", out)
	}
}

func TestApplyEnterprisePatternsFromEnvironLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	body := `[{"name":"corp_id","expr":"\\bCORP-[0-9]{6}\\b"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(redact.EnvRedactPatternsFile, path)
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	n, err := redact.ApplyEnterprisePatternsFromEnviron()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1, got %d", n)
	}
	out := redact.RedactText("see CORP-654321")
	if strings.Contains(out, "CORP-654321") {
		t.Fatalf("not redacted: %q", out)
	}
}

func TestApplyEnterprisePatternsFromEnvironInvalidFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`[{"name":"x","expr":"("}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(redact.EnvRedactPatternsFile, path)
	// Pre-install a good pattern; failed apply must not leave us with bad state
	// and must return error (serve fails closed). Prior patterns may remain —
	// document: on error we do not call SetEnterprisePatterns.
	good, _ := redact.CompileEnterprisePatterns([]struct{ Name, Expr string }{
		{Name: "prior", Expr: `\bPRIOR-OK\b`},
	})
	redact.SetEnterprisePatterns(redact.StaticEnterprise(good))
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	n, err := redact.ApplyEnterprisePatternsFromEnviron()
	if err == nil {
		t.Fatal("invalid file must fail closed")
	}
	if n != 0 {
		t.Fatalf("want 0 on error, got %d", n)
	}
	// Prior patterns still active (no partial replace with bad compile).
	out := redact.RedactText("PRIOR-OK")
	if strings.Contains(out, "PRIOR-OK") {
		t.Fatalf("prior patterns should remain after failed load: %q", out)
	}
}

func TestValidateEnterprisePatternsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "v.json")
	if err := os.WriteFile(path, []byte(`[{"name":"a","expr":"a+"},{"name":"b","expr":"b+"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	n, names, err := redact.ValidateEnterprisePatternsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(names) != 2 {
		t.Fatalf("n=%d names=%v", n, names)
	}
	// Must not install package state as a side effect.
	// (Validate uses Load only; Set is not called.)
}

func TestLoadEnterprisePatternsOversized(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	// Just over the byte cap.
	pad := strings.Repeat("a", redact.MaxEnterprisePatternsFileBytes+10)
	body := `[{"name":"x","expr":"` + pad + `"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := redact.LoadEnterprisePatternsFile(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size error, got %v", err)
	}
}
