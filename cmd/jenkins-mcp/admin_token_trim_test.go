package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: loadAdminToken used strings.TrimSpace on the whole file while
// the Streamable HTTP token loader deliberately strips only a single trailing
// newline ("do not TrimSpace the whole secret (spaces may be intentional)").
// The doc comment on loadAdminToken claims "Same rules as Streamable HTTP
// token" — now actually true: a token file with intentional leading/trailing
// spaces loads identically on both surfaces.
func TestLoadAdminToken_PreservesIntentionalSpaces(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("  spaced-token  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadAdminToken("", p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "  spaced-token  " {
		t.Fatalf("token must keep intentional spaces (single trailing newline stripped): %q", got)
	}
}

// CRLF and newline conventions still strip (parity with serve_http_token.go).
func TestLoadAdminToken_StripsSingleTrailingNewline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("tok\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadAdminToken("", p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "tok" {
		t.Fatalf("got %q", got)
	}
}
