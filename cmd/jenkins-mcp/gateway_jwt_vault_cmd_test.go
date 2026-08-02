package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

// canaryJWTVaultCLI is a unique JWT-looking lab token that must never appear in
// CLI list/status/put/delete stdout or error strings (HOST-010 secret canary).
const canaryJWTVaultCLI = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.CANARY_JWT_VAULT_CLI_never_list.sig"

func TestGatewayJWTVault_DispatchAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt_vault.json")
	t.Setenv(envGatewayJWTVaultToken, canaryJWTVaultCLI)

	// Nested put via runGateway.
	out, err := captureStdoutErr(t, func() error {
		return runGateway([]string{
			"jwt-vault", "put",
			"--subject", "tenant|alice|corp",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	assertNoJWTCanary(t, out)
	if !strings.Contains(out, "jwt-vault put ok") {
		t.Fatalf("stdout %q", out)
	}

	// set alias + compose subject parts; rotate via --token-env.
	t.Setenv("HOST010_ROTATE_JWT", canaryJWTVaultCLI+"-rotated")
	out, err = captureStdoutErr(t, func() error {
		return runGatewayJWTVault([]string{
			"set",
			"--tenant", "tenant",
			"--subject-id", "alice",
			"--profile", "corp",
			"--token-env", "HOST010_ROTATE_JWT",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	assertNoJWTCanary(t, out)
	if strings.Contains(out, canaryJWTVaultCLI+"-rotated") {
		t.Fatal("rotated token leaked in set stdout")
	}

	v, err := gateway.NewFileJWTVault(path)
	if err != nil {
		t.Fatal(err)
	}
	tok, ok, err := v.Get(context.Background(), "tenant|alice|corp")
	if err != nil || !ok || tok != canaryJWTVaultCLI+"-rotated" {
		t.Fatalf("get after rotate: tok_ok=%v ok=%v err=%v", tok == canaryJWTVaultCLI+"-rotated", ok, err)
	}

	// list: subject keys only.
	out, err = captureStdoutErr(t, func() error {
		return runGatewayJWTVault([]string{"list", "--vault-path", path})
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertNoJWTCanary(t, out)
	if strings.Contains(out, canaryJWTVaultCLI) || strings.Contains(out, "rotated") {
		t.Fatal("token leaked in list")
	}
	if !strings.Contains(out, "tenant|alice|corp") {
		t.Fatalf("list missing subject key: %q", out)
	}

	// status exists=true.
	out, err = captureStdoutErr(t, func() error {
		return runGatewayJWTVault([]string{
			"status",
			"--subject", "tenant|alice|corp",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	assertNoJWTCanary(t, out)
	if !strings.Contains(out, "exists=true") {
		t.Fatalf("status want exists=true: %q", out)
	}

	// exists alias for missing key.
	out, err = captureStdoutErr(t, func() error {
		return runGatewayJWTVault([]string{
			"exists",
			"--tenant", "tenant",
			"--subject-id", "bob",
			"--profile", "corp",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !strings.Contains(out, "exists=false") {
		t.Fatalf("exists want false: %q", out)
	}

	// revoke via nested delete.
	out, err = captureStdoutErr(t, func() error {
		return runGateway([]string{
			"jwt-vault", "revoke",
			"--subject", "tenant|alice|corp",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	assertNoJWTCanary(t, out)
	_, ok, err = v.Get(context.Background(), "tenant|alice|corp")
	if err != nil || ok {
		t.Fatalf("expected deleted ok=%v err=%v", ok, err)
	}
}

func TestGatewayJWTVault_PutFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.json")

	// Missing token env.
	t.Setenv(envGatewayJWTVaultToken, "")
	_, err := captureStdoutErr(t, func() error {
		return runGatewayJWTVaultPut([]string{
			"--subject", "t|u|p",
			"--vault-path", path,
		})
	})
	if err == nil {
		t.Fatal("expected missing token error")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}

	// token-env with equals rejected (token-on-argv footgun).
	_, err = captureStdoutErr(t, func() error {
		return runGatewayJWTVaultPut([]string{
			"--subject", "t|u|p",
			"--token-env", "FOO=" + canaryJWTVaultCLI,
			"--vault-path", path,
		})
	})
	if err == nil {
		t.Fatal("expected equals reject")
	}
	if strings.Contains(err.Error(), canaryJWTVaultCLI) {
		t.Fatal("canary leaked in error")
	}

	// ID token rejected by vault Put (not CLI argv).
	// Compact JWT with typ/id_token markers is rejected inside JWTVault.Put.
	idTok := "eyJhbGciOiJub25lIn0.eyJ0b2tlbl91c2UiOiJpZF90b2tlbiJ9."
	t.Setenv(envGatewayJWTVaultToken, idTok)
	_, err = captureStdoutErr(t, func() error {
		return runGatewayJWTVaultPut([]string{
			"--subject", "t|u|p",
			"--vault-path", path,
		})
	})
	if err == nil {
		t.Fatal("id_token must be rejected")
	}
	if strings.Contains(err.Error(), idTok) {
		t.Fatal("id token leaked in error")
	}
}

func TestGatewayJWTVault_Help(t *testing.T) {
	out, err := captureStdoutErr(t, func() error {
		return runGatewayJWTVault([]string{"help"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "jwt-vault") || !strings.Contains(out, "HOST-010") {
		t.Fatalf("help missing: %q", out)
	}
}

func assertNoJWTCanary(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, canaryJWTVaultCLI) {
		t.Fatalf("JWT canary leaked into surface: %q", truncateForLog(s, 120))
	}
	if strings.Contains(s, "eyJ") {
		// list/status must never print JWT-looking material.
		t.Fatalf("JWT-looking material in surface: %q", truncateForLog(s, 120))
	}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
