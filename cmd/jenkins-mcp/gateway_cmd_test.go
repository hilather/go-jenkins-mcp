package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
)

const canaryCLIToken = "CANARY_CLI_HOST009_token_never_in_output_zz9"

func TestGatewayQualifyOffline(t *testing.T) {
	// Capture stdout JSON summary.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGatewayQualify([]string{"--offline"})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("run: %v\nstdout=%s", errRun, buf.String())
	}
	var sum qualify.Summary
	if err := json.Unmarshal(buf.Bytes(), &sum); err != nil {
		t.Fatalf("json: %v body=%s", err, buf.String())
	}
	if !sum.OK || sum.Failed != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	if strings.Contains(buf.String(), qualify.CanaryToken) {
		t.Fatal("canary in CLI output")
	}
}

func TestGatewayQualifyRequiresOffline(t *testing.T) {
	err := runGatewayQualify(nil)
	if err == nil {
		t.Fatal("expected --offline required")
	}
}

func TestGatewayUnknownSubcommand(t *testing.T) {
	err := runGateway([]string{"nope"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGatewayVaultPutDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	t.Setenv("HOST009_TEST_TOKEN", canaryCLIToken)

	// Capture stdout.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errPut := runGatewayVaultPut([]string{
		"--subject", "tenant|alice|corp",
		"--user", "alice-j",
		"--token-env", "HOST009_TEST_TOKEN",
		"--vault-path", path,
	})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errPut != nil {
		t.Fatalf("put: %v", errPut)
	}
	out := buf.String()
	if strings.Contains(out, canaryCLIToken) {
		t.Fatal("token leaked in vault-put stdout")
	}
	if !strings.Contains(out, "vault-put ok") {
		t.Fatalf("stdout %q", out)
	}

	// Obtain via file vault.
	v, err := gateway.NewFileAPITokenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	u, tok, ok, err := v.Get(context.Background(), "tenant|alice|corp")
	if err != nil || !ok || u != "alice-j" || tok != canaryCLIToken {
		t.Fatalf("get: u=%q ok=%v err=%v", u, ok, err)
	}

	// Delete.
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w2
	errDel := runGatewayVaultDelete([]string{"--subject", "tenant|alice|corp", "--vault-path", path})
	_ = w2.Close()
	os.Stdout = old
	buf.Reset()
	_, _ = io.Copy(&buf, r2)
	_ = r2.Close()
	if errDel != nil {
		t.Fatalf("delete: %v", errDel)
	}
	if strings.Contains(buf.String(), canaryCLIToken) {
		t.Fatal("token leaked in vault-delete stdout")
	}
	_, _, ok, err = v.Get(context.Background(), "tenant|alice|corp")
	if err != nil || ok {
		t.Fatalf("expected deleted ok=%v err=%v", ok, err)
	}
}

func TestGatewayVaultPut_RequiresTokenEnvNotValue(t *testing.T) {
	err := runGatewayVaultPut([]string{
		"--subject", "k",
		"--user", "u",
		// missing token-env
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), canaryCLIToken) {
		t.Fatal("canary")
	}
	// Empty env var.
	t.Setenv("HOST009_EMPTY", "")
	err = runGatewayVaultPut([]string{
		"--subject", "k",
		"--user", "u",
		"--token-env", "HOST009_EMPTY",
		"--vault-path", filepath.Join(t.TempDir(), "v.json"),
	})
	if err == nil {
		t.Fatal("expected empty env fail")
	}
}

func TestGatewayVaultPut_RejectsTokenEnvWithEquals(t *testing.T) {
	err := runGatewayVaultPut([]string{
		"--subject", "k",
		"--user", "u",
		"--token-env", "FOO=" + canaryCLIToken,
	})
	if err == nil {
		t.Fatal("expected reject")
	}
	if strings.Contains(err.Error(), canaryCLIToken) {
		t.Fatal("canary in error")
	}
}
