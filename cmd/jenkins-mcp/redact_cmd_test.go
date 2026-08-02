package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

func TestRedactValidatePatternsCLI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.json")
	body := `[{"name":"corp_id","expr":"\\bCORP-[0-9]{6}\\b"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRedactValidatePatterns([]string{"--file", path}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := runRedactValidatePatterns([]string{"--file", path, "--json"}); err != nil {
		t.Fatalf("validate json: %v", err)
	}
}

func TestRedactValidatePatternsCLIInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`[{"name":"x","expr":"("}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runRedactValidatePatterns([]string{"--file", path})
	if err == nil {
		t.Fatal("invalid regex must fail closed")
	}
	if !strings.Contains(err.Error(), "enterprise redact patterns") {
		t.Fatalf("want wrap message: %v", err)
	}
}

func TestRedactValidatePatternsCLIRequiresFile(t *testing.T) {
	err := runRedactValidatePatterns(nil)
	if err == nil {
		t.Fatal("expected --file required")
	}
}

func TestApplyServeEnterpriseRedactPatternsUnset(t *testing.T) {
	t.Setenv(redact.EnvRedactPatternsFile, "")
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	n, err := applyServeEnterpriseRedactPatterns()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("want 0, got %d", n)
	}
}

func TestApplyServeEnterpriseRedactPatternsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	body := `[{"name":"corp_id","expr":"\\bCORP-[0-9]{6}\\b"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(redact.EnvRedactPatternsFile, path)
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	n, err := applyServeEnterpriseRedactPatterns()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1, got %d", n)
	}
	out := redact.RedactText("CORP-111111")
	if strings.Contains(out, "CORP-111111") {
		t.Fatalf("serve helper did not install patterns: %q", out)
	}
}

func TestApplyServeEnterpriseRedactPatternsInvalidFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`not-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(redact.EnvRedactPatternsFile, path)
	t.Cleanup(func() { redact.SetEnterprisePatterns(nil) })

	n, err := applyServeEnterpriseRedactPatterns()
	if err == nil {
		t.Fatal("invalid file must fail closed serve helper")
	}
	if n != 0 {
		t.Fatalf("want 0, got %d", n)
	}
	// Error surface must not include secret-like payloads from the file body
	// beyond a generic invalid JSON message (file was "not-json").
	msg := err.Error()
	if strings.Contains(msg, "password") || strings.Contains(msg, "Bearer ") {
		t.Fatalf("unexpected secret-like error: %s", msg)
	}
}

func TestRunRedactDispatch(t *testing.T) {
	if err := runRedact([]string{"-h"}); err != nil {
		t.Fatal(err)
	}
	err := runRedact(nil)
	if err == nil {
		t.Fatal("expected subcommand required")
	}
	err = runRedact([]string{"nope"})
	if err == nil {
		t.Fatal("expected unknown subcommand")
	}
}
