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

// OAUTH-010 / GWY-001: progressive consent residual CLI (secret-free JSON).
func TestGatewayConsentResidual(t *testing.T) {
	// Point consent store path at empty temp so CLI does not touch real XDG data.
	dir := t.TempDir()
	t.Setenv(gateway.EnvConsentSessionStorePath, filepath.Join(dir, "missing-consent.json"))

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGatewayConsentResidual(nil)
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
	out := buf.String()
	if strings.Contains(out, canaryCLIToken) || strings.Contains(out, qualify.CanaryToken) {
		t.Fatal("canary in consent-residual output")
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, out)
	}
	pc, ok := payload["progressive_consent"].(map[string]any)
	if !ok {
		t.Fatalf("want progressive_consent object: %+v", payload)
	}
	if pc["browser_3lo_automated"] != false {
		t.Fatalf("browser_3lo_automated: %+v", pc)
	}
	if pc["metadata_path_done_star"] != true {
		t.Fatalf("metadata_path_done_star: %+v", pc)
	}
	if pc["process_local_consent_metadata_store"] != true {
		t.Fatalf("process_local_consent_metadata_store: %+v", pc)
	}
	if pc["durable_consent_session_store"] != false || pc["multi_replica_consent_correlation"] != false {
		t.Fatalf("AgentCore durable / multi-replica must stay residual: %+v", pc)
	}
	note, _ := pc["residual_note"].(string)
	if !strings.Contains(note, "OAUTH-010") || !strings.Contains(strings.ToLower(note), "not automated") {
		t.Fatalf("residual_note honesty: %q", note)
	}
	if !strings.Contains(strings.ToLower(note), "process-local") {
		t.Fatalf("want process-local honesty: %q", note)
	}
	// Store residual block present (empty when no file).
	if _, ok := payload["consent_store"]; !ok {
		t.Fatalf("want consent_store: %+v", payload)
	}
	if payload["consent_sessions_count"] != float64(0) {
		t.Fatalf("want empty sessions: %+v", payload["consent_sessions_count"])
	}
	// Forbidden secret markers.
	for _, bad := range []string{"access_token=", "refresh_token=", "client_secret=", "Authorization: Bearer"} {
		if strings.Contains(out, bad) {
			t.Fatalf("forbidden %q in output", bad)
		}
	}
}

// Regression: consent-residual lists file-backed metadata only (never tokens).
func TestGatewayConsentResidual_ListsFileMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "consent_sessions.json")
	store, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=cli-list",
			SessionID:        "sess-cli-residual-1",
			Provider:         "agentcore",
		},
		SubjectKey: "tenant|alice|corp",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvConsentSessionStorePath, path)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGatewayConsentResidual(nil)
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("run: %v\n%s", errRun, buf.String())
	}
	out := buf.String()
	if strings.Contains(out, canaryCLIToken) || strings.Contains(out, "access_token=") {
		t.Fatal("canary/token in consent-residual list output")
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, out)
	}
	if payload["consent_sessions_count"] != float64(1) {
		t.Fatalf("count: %+v payload=%s", payload["consent_sessions_count"], out)
	}
	sessions, ok := payload["consent_sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("sessions: %+v", payload["consent_sessions"])
	}
	row, _ := sessions[0].(map[string]any)
	if row["session_id"] != "sess-cli-residual-1" {
		t.Fatalf("row: %+v", row)
	}
	if _, hasURL := row["authorization_url"]; hasURL {
		t.Fatal("CLI StatusMap must not dump full authorization_url")
	}
	if row["has_authorization_url"] != true {
		t.Fatalf("want has_authorization_url: %+v", row)
	}
}

func TestGatewayConsentResidual_ViaDispatch(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGateway([]string{"consent-residual"})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("dispatch: %v", errRun)
	}
	if !strings.Contains(buf.String(), "metadata_path_done_star") {
		t.Fatalf("stdout: %s", buf.String())
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
	if !strings.Contains(out, "vault put ok") {
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
