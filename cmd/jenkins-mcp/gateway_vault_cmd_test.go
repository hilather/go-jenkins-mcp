package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// canaryVaultCLIToken is a unique token value that must never appear in CLI
// list/status/put/delete stdout or error strings (HOST-009 secret canary).
const canaryVaultCLIToken = "CANARY_VAULT_CLI_token_never_list_status_zz42"

func TestGatewayVault_DispatchAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	t.Setenv(envGatewayVaultToken, canaryVaultCLIToken)

	// Nested put via runGateway.
	out, err := captureStdoutErr(t, func() error {
		return runGateway([]string{
			"vault", "put",
			"--subject", "tenant|alice|corp",
			"--user", "alice-j",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	assertNoCanary(t, out)
	if !strings.Contains(out, "vault put ok") {
		t.Fatalf("stdout %q", out)
	}

	// set alias + compose subject parts; rotate token via --token-env.
	t.Setenv("HOST009_ROTATE_TOKEN", canaryVaultCLIToken+"-rotated")
	out, err = captureStdoutErr(t, func() error {
		return runGatewayVault([]string{
			"set",
			"--tenant", "tenant",
			"--subject-id", "alice",
			"--profile", "corp",
			"--user", "alice-j",
			"--token-env", "HOST009_ROTATE_TOKEN",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	assertNoCanary(t, out)

	v, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	u, tok, ok, err := v.Get(context.Background(), "tenant|alice|corp")
	if err != nil || !ok || u != "alice-j" || tok != canaryVaultCLIToken+"-rotated" {
		t.Fatalf("get after rotate: u=%q tok_ok=%v ok=%v err=%v", u, tok == canaryVaultCLIToken+"-rotated", ok, err)
	}
	// Token must not leak via canary check on empty string still — re-check rotate token separately.
	if strings.Contains(out, canaryVaultCLIToken+"-rotated") {
		t.Fatal("rotated token leaked in set stdout")
	}

	// list: subject keys only.
	out, err = captureStdoutErr(t, func() error {
		return runGatewayVault([]string{"list", "--vault-path", path})
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertNoCanary(t, out)
	if strings.Contains(out, canaryVaultCLIToken+"-rotated") {
		t.Fatal("token leaked in list")
	}
	if strings.Contains(out, "alice-j") {
		t.Fatal("username must not appear in list (keys only)")
	}
	if !strings.Contains(out, "tenant|alice|corp") {
		t.Fatalf("list missing subject key: %q", out)
	}

	// status exists=true.
	out, err = captureStdoutErr(t, func() error {
		return runGatewayVault([]string{
			"status",
			"--subject", "tenant|alice|corp",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	assertNoCanary(t, out)
	if strings.Contains(out, canaryVaultCLIToken) || strings.Contains(out, "alice-j") {
		t.Fatalf("status leaked secret material: %q", out)
	}
	if !strings.Contains(out, "exists=true") {
		t.Fatalf("status want exists=true: %q", out)
	}

	// exists alias for missing key.
	out, err = captureStdoutErr(t, func() error {
		return runGatewayVault([]string{
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
	assertNoCanary(t, out)
	if !strings.Contains(out, "exists=false") {
		t.Fatalf("exists want false: %q", out)
	}

	// revoke via nested delete.
	out, err = captureStdoutErr(t, func() error {
		return runGateway([]string{
			"vault", "revoke",
			"--subject", "tenant|alice|corp",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	assertNoCanary(t, out)
	if strings.Contains(out, canaryVaultCLIToken) {
		t.Fatal("token leaked in revoke stdout")
	}
	_, _, ok, err = v.Get(context.Background(), "tenant|alice|corp")
	if err != nil || ok {
		t.Fatalf("expected deleted ok=%v err=%v", ok, err)
	}

	// status after delete.
	out, err = captureStdoutErr(t, func() error {
		return runGatewayVault([]string{
			"status", "--subject", "tenant|alice|corp", "--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("status after delete: %v", err)
	}
	if !strings.Contains(out, "exists=false") {
		t.Fatalf("after delete: %q", out)
	}
}

func TestGatewayVault_PutTableDriven(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.json")

	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		wantErr bool
		code    apperr.Code
		canary  string
	}{
		{
			name: "default env token",
			env:  map[string]string{envGatewayVaultToken: canaryVaultCLIToken},
			args: []string{
				"--subject", "t|u|p",
				"--user", "u-j",
				"--vault-path", path,
			},
		},
		{
			name: "token-env override",
			env:  map[string]string{"ALT_TOK": canaryVaultCLIToken + "-alt"},
			args: []string{
				"--subject", "t|u2|p",
				"--user", "u2-j",
				"--token-env", "ALT_TOK",
				"--vault-path", path,
			},
			canary: canaryVaultCLIToken + "-alt",
		},
		{
			name: "compose parts",
			env:  map[string]string{envGatewayVaultToken: canaryVaultCLIToken},
			args: []string{
				"--tenant", "acme",
				"--subject-id", "user-3",
				"--profile", "corp",
				"--user", "u3",
				"--vault-path", path,
			},
		},
		{
			name:    "missing subject",
			env:     map[string]string{envGatewayVaultToken: canaryVaultCLIToken},
			args:    []string{"--user", "u", "--vault-path", path},
			wantErr: true,
			code:    apperr.CodeInvalidArgument,
		},
		{
			name:    "missing user",
			env:     map[string]string{envGatewayVaultToken: canaryVaultCLIToken},
			args:    []string{"--subject", "k", "--vault-path", path},
			wantErr: true,
			code:    apperr.CodeInvalidArgument,
		},
		{
			name:    "empty default token env",
			env:     map[string]string{envGatewayVaultToken: ""},
			args:    []string{"--subject", "k", "--user", "u", "--vault-path", path},
			wantErr: true,
			code:    apperr.CodeInvalidArgument,
		},
		{
			name: "token-env with equals rejected",
			env:  map[string]string{},
			args: []string{
				"--subject", "k",
				"--user", "u",
				"--token-env", "FOO=" + canaryVaultCLIToken,
				"--vault-path", path,
			},
			wantErr: true,
			code:    apperr.CodeInvalidArgument,
			canary:  canaryVaultCLIToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clear default token env so empty case is real.
			t.Setenv(envGatewayVaultToken, "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			canary := tc.canary
			if canary == "" {
				canary = canaryVaultCLIToken
			}
			out, err := captureStdoutErr(t, func() error {
				return runGatewayVaultPut(tc.args)
			})
			if strings.Contains(out, canary) {
				t.Fatal("canary in stdout")
			}
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Fatal("canary in error")
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tc.code != "" && apperr.CodeOf(err) != tc.code {
					t.Fatalf("code got %s want %s err=%v", apperr.CodeOf(err), tc.code, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
		})
	}
}

func TestGatewayVault_ListEmptyAndMulti(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.json")

	// Empty vault → empty list, not error.
	out, err := captureStdoutErr(t, func() error {
		return runGatewayVaultList([]string{"--vault-path", path})
	})
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("want empty list, got %q", out)
	}

	t.Setenv(envGatewayVaultToken, canaryVaultCLIToken)
	if err := runGatewayVaultPut([]string{
		"--subject", "t|a|p", "--user", "a-j", "--vault-path", path,
	}); err != nil {
		t.Fatal(err)
	}
	if err := runGatewayVaultPut([]string{
		"--subject", "t|b|p", "--user", "b-j", "--vault-path", path,
	}); err != nil {
		t.Fatal(err)
	}

	out, err = captureStdoutErr(t, func() error {
		return runGatewayVaultList([]string{"--vault-path", path})
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoCanary(t, out)
	if strings.Contains(out, "a-j") || strings.Contains(out, "b-j") {
		t.Fatalf("usernames in list: %q", out)
	}
	// Sorted order.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[0] != "t|a|p" || lines[1] != "t|b|p" {
		t.Fatalf("list lines: %#v", lines)
	}
}

func TestGatewayVault_LegacyAliases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.json")
	t.Setenv("HOST009_LEGACY", canaryVaultCLIToken)

	out, err := captureStdoutErr(t, func() error {
		return runGateway([]string{
			"vault-put",
			"--subject", "legacy|user|corp",
			"--user", "lu",
			"--token-env", "HOST009_LEGACY",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("legacy put: %v", err)
	}
	assertNoCanary(t, out)

	out, err = captureStdoutErr(t, func() error {
		return runGateway([]string{
			"vault-delete",
			"--subject", "legacy|user|corp",
			"--vault-path", path,
		})
	})
	if err != nil {
		t.Fatalf("legacy delete: %v", err)
	}
	assertNoCanary(t, out)
}

func TestGatewayVault_UnknownSubcommand(t *testing.T) {
	err := runGatewayVault([]string{"wipe-all"})
	if err == nil {
		t.Fatal("expected error")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v", err)
	}
}

func TestGatewayVault_ResolveSubjectKey(t *testing.T) {
	tests := []struct {
		subject, tenant, sid, profile, want string
		err                                 bool
	}{
		{subject: "a|b|c", want: "a|b|c"},
		{tenant: "t", sid: "s", profile: "p", want: "t|s|p"},
		{sid: "only-subject", want: "|only-subject|"},
		{err: true},
		{tenant: "t", profile: "p", err: true}, // no subject-id
	}
	for i, tc := range tests {
		got, err := resolveVaultSubjectKey(tc.subject, tc.tenant, tc.sid, tc.profile)
		if tc.err {
			if err == nil {
				t.Fatalf("%d: expected error", i)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%d: got %q err=%v want %q", i, got, err, tc.want)
		}
	}
}

func captureStdoutErr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	var runErr error
	out := captureStdout(t, func() {
		runErr = fn()
	})
	return out, runErr
}

func assertNoCanary(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(s, canaryVaultCLIToken) {
		t.Fatalf("canary token leaked in output: %q", s)
	}
}
