package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// GWY-002 / HOST-003 force re-auth residual lite: subject-invalidate CLI.
func TestGatewaySubjectInvalidate(t *testing.T) {
	// Isolate process principal cache mutations to a known key.
	sk := gateway.SubjectKeyParts("tid-cli", "alice-cli", "corp")
	gateway.ProcessPrincipalCache().Set(sk, "alice-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })

	// Plant canary env that must never appear in output.
	t.Setenv("HOST009_FAKE_TOKEN", canaryCLIToken)
	t.Setenv(gateway.EnvGatewayTokenCachePath, "") // principal-only path

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGatewaySubjectInvalidate([]string{"--subject-key", sk})
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
		t.Fatal("canary in subject-invalidate output")
	}
	for _, bad := range []string{"access_token=", "refresh_token=", "client_secret=", "Authorization: Bearer"} {
		if strings.Contains(out, bad) {
			t.Fatalf("forbidden %q in output", bad)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, out)
	}
	if payload["subject_key"] != sk {
		t.Fatalf("subject_key: %+v", payload["subject_key"])
	}
	if payload["principal_cleared"] != true {
		t.Fatalf("principal_cleared: %+v", payload)
	}
	if payload["token_cache_cleared"] != false {
		t.Fatalf("token_cache_cleared without path: %+v", payload)
	}
	if payload["token_cache_path_configured"] != false {
		t.Fatalf("path configured: %+v", payload)
	}
	if payload["principal_cache_path_configured"] != false {
		t.Fatalf("principal path configured: %+v", payload)
	}
	note, _ := payload["residual_note"].(string)
	if !strings.Contains(note, "multi-pod") || !strings.Contains(strings.ToLower(note), "not live") {
		t.Fatalf("residual honesty: %q", note)
	}
	if _, ok := gateway.ProcessPrincipalCache().Get(sk); ok {
		t.Fatal("principal must be cleared in process cache")
	}
}

// HOST-008 lite: subject-invalidate with PRINCIPAL_CACHE_PATH deletes shared file entry.
func TestGatewaySubjectInvalidate_WithFilePrincipalCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "principal_cache.json")
	fpc, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	alice := gateway.SubjectKeyParts("tid-fpc", "alice-fpc", "corp")
	bob := gateway.SubjectKeyParts("tid-fpc", "bob-fpc", "corp")
	fpc.Set(alice, "alice-j")
	fpc.Set(bob, "bob-j")

	t.Setenv(gateway.EnvGatewayPrincipalCachePath, path)
	t.Setenv(gateway.EnvGatewayTokenCachePath, "")
	t.Cleanup(func() {
		t.Setenv(gateway.EnvGatewayPrincipalCachePath, "")
	})

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGateway([]string{"subject-invalidate", "--subject-key", alice})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("run: %v\n%s", errRun, buf.String())
	}
	out := buf.String()
	if strings.Contains(out, canaryCLIToken) || strings.Contains(out, path) {
		// Residual honesty: never print path value (may be long host path).
		if strings.Contains(out, canaryCLIToken) {
			t.Fatal("canary in subject-invalidate output")
		}
		// path may appear only if operator subject_key equals path — not here.
		if strings.Contains(out, path) {
			t.Fatal("principal cache path value must not appear in CLI JSON")
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, out)
	}
	if payload["principal_cleared"] != true {
		t.Fatalf("principal_cleared: %+v", payload)
	}
	if payload["principal_cache_path_configured"] != true {
		t.Fatalf("principal_cache_path_configured: %+v", payload)
	}
	// Re-open file: alice gone, bob remains.
	fpc2, err := gateway.NewFilePrincipalCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fpc2.Get(alice); ok {
		t.Fatal("alice principal must be deleted from file cache")
	}
	if p, ok := fpc2.Get(bob); !ok || p != "bob-j" {
		t.Fatalf("bob must remain: ok=%v p=%q", ok, p)
	}
}

func TestGatewaySubjectInvalidate_WithFileTokenCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tok-cache.json")
	ftc, err := gateway.NewFileTokenCache(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	alice := gateway.CacheKey{Tenant: "tid-f", User: "alice-f", Workload: "wl", Profile: "corp"}
	bob := gateway.CacheKey{Tenant: "tid-f", User: "bob-f", Workload: "wl", Profile: "corp"}
	exp := time.Now().Add(time.Hour)
	ftc.Set(alice, gateway.CachedToken{AccessToken: canaryCLIToken + "-a", ExpiresAt: exp})
	ftc.Set(bob, gateway.CachedToken{AccessToken: canaryCLIToken + "-b", ExpiresAt: exp})

	sk := alice.NamespaceSubjectKey()
	gateway.ProcessPrincipalCache().Set(sk, "alice-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })
	t.Setenv(gateway.EnvGatewayTokenCachePath, path)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGateway([]string{"subject-invalidate", "--subject-key", sk})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("run: %v\n%s", errRun, buf.String())
	}
	out := buf.String()
	if strings.Contains(out, canaryCLIToken) {
		t.Fatal("canary token leaked in CLI JSON")
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, out)
	}
	if payload["token_cache_cleared"] != true {
		t.Fatalf("want token_cache cleared: %+v", payload)
	}
	if payload["token_cache_path_configured"] != true {
		t.Fatalf("path: %+v", payload)
	}
	// Re-open file cache to verify alice gone, bob remains.
	ftc2, err := gateway.NewFileTokenCache(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ftc2.Get(alice); ok {
		t.Fatal("alice token must be deleted from file cache")
	}
	if _, ok := ftc2.Get(bob); !ok {
		t.Fatal("bob token must remain")
	}
}

func TestGatewaySubjectInvalidate_RequiresSubject(t *testing.T) {
	err := runGatewaySubjectInvalidate(nil)
	if err == nil {
		t.Fatal("expected error without subject")
	}
}

func TestGatewaySubjectInvalidate_ComposeParts(t *testing.T) {
	sk := gateway.SubjectKeyParts("t-compose", "sub-compose", "corp")
	gateway.ProcessPrincipalCache().Set(sk, "u-j")
	t.Cleanup(func() { gateway.ProcessPrincipalCache().Delete(sk) })

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGatewaySubjectInvalidate([]string{
		"--tenant", "t-compose", "--subject-id", "sub-compose", "--profile", "corp",
	})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("run: %v\n%s", errRun, buf.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v", err)
	}
	if payload["subject_key"] != sk {
		t.Fatalf("subject_key: %+v", payload["subject_key"])
	}
	if _, ok := gateway.ProcessPrincipalCache().Get(sk); ok {
		t.Fatal("must clear")
	}
}

// Unified residual-status CLI: secret-free JSON combining mode matrix, multi-user/HA/multi-pod,
// progressive consent, rate knobs, principal_cache count. Mode B residual id always present.
func TestGatewayResidualStatus(t *testing.T) {
	// Plant canaries that must never appear in output (env residual path only).
	t.Setenv("JENKINS_MCP_GATEWAY_MULTI_USER", "1")
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeJWTRSBearer))
	t.Setenv("HOST009_FAKE_TOKEN", canaryCLIToken)
	t.Setenv("Authorization", "Bearer "+canaryCLIToken)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGatewayResidualStatus(nil)
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
		t.Fatal("canary in residual-status output")
	}
	for _, bad := range []string{"access_token=", "refresh_token=", "client_secret=", "Authorization: Bearer", "Bearer " + canaryCLIToken} {
		if strings.Contains(out, bad) {
			t.Fatalf("forbidden %q in residual-status output", bad)
		}
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, out)
	}

	// Mode B residual id always present (oauth009_offline).
	if rid, _ := payload["residual_id"].(string); rid != "oauth009_offline" {
		t.Fatalf("residual_id=%v want oauth009_offline", payload["residual_id"])
	}
	if payload["oauth009_offline"] != true {
		t.Fatalf("oauth009_offline: %+v", payload["oauth009_offline"])
	}
	if payload["mode_b_live_rs_qualified"] != false {
		t.Fatalf("mode_b_live_rs_qualified must be false: %+v", payload["mode_b_live_rs_qualified"])
	}
	if payload["mode_b_enabled"] != true {
		t.Fatalf("mode_b_enabled want true with JWT mode env: %+v", payload["mode_b_enabled"])
	}

	// residual_ids list must include Mode B + other honesty ids.
	ids, ok := payload["residual_ids"].([]any)
	if !ok || len(ids) == 0 {
		t.Fatalf("residual_ids: %+v", payload["residual_ids"])
	}
	foundOAuth009 := false
	for _, id := range ids {
		if s, _ := id.(string); s == "oauth009_offline" {
			foundOAuth009 = true
			break
		}
	}
	if !foundOAuth009 {
		t.Fatalf("residual_ids missing oauth009_offline: %+v", ids)
	}

	// Multi-user / HA / multi-pod honesty.
	if payload["multi_user_enabled"] != true {
		t.Fatalf("multi_user_enabled: %+v", payload["multi_user_enabled"])
	}
	if payload["ha_multi_replica"] != false {
		t.Fatalf("ha_multi_replica must be false: %+v", payload["ha_multi_replica"])
	}
	if payload["session_affinity_recommended"] != true {
		t.Fatalf("session_affinity_recommended: %+v", payload["session_affinity_recommended"])
	}
	if payload["multi_pod_vault_residual"] != true {
		t.Fatalf("multi_pod_vault_residual must always be true: %+v", payload["multi_pod_vault_residual"])
	}

	// Progressive consent residual object.
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

	// Rate knobs present (names match admin health residual fields).
	if _, ok := payload["rateEnabled"].(bool); !ok {
		t.Fatalf("rateEnabled: %+v", payload["rateEnabled"])
	}
	// shared_subject_rate_file / shared_principal_cache_file are env path residual
	// (false when unset; HOST-008 lite). Never path values.
	if payload["shared_subject_rate_file"] != false {
		t.Fatalf("shared_subject_rate_file default false: %+v", payload["shared_subject_rate_file"])
	}
	if payload["shared_principal_cache_file"] != false {
		t.Fatalf("shared_principal_cache_file default false: %+v", payload["shared_principal_cache_file"])
	}
	if _, ok := payload["ratePerMinute"].(float64); !ok {
		// json numbers → float64
		t.Fatalf("ratePerMinute: %+v", payload["ratePerMinute"])
	}
	if _, ok := payload["rateBurst"].(float64); !ok {
		t.Fatalf("rateBurst: %+v", payload["rateBurst"])
	}

	// principal_cache_entries is count only (number); never subjects/tokens.
	if _, ok := payload["principal_cache_entries"].(float64); !ok {
		t.Fatalf("principal_cache_entries: %+v", payload["principal_cache_entries"])
	}
	// Process-local honesty: CLI residual-status count is this process, not remote serve.
	pcNote, _ := payload["principal_cache_process_note"].(string)
	if pcNote == "" {
		t.Fatal("principal_cache_process_note must be present")
	}
	if !strings.Contains(strings.ToLower(pcNote), "this process") {
		t.Fatalf("principal_cache_process_note process-local honesty: %q", pcNote)
	}
	// Empty hygiene env → omit max/ttl (unlimited residual default).
	if _, ok := payload["principal_cache_max_entries"]; ok {
		t.Fatalf("unlimited default must omit principal_cache_max_entries: %+v", payload["principal_cache_max_entries"])
	}
	if _, ok := payload["principal_cache_ttl_seconds"]; ok {
		t.Fatalf("no TTL default must omit principal_cache_ttl_seconds: %+v", payload["principal_cache_ttl_seconds"])
	}

	// Honesty note + live-pin-blockers pointer.
	note, _ := payload["residual_note"].(string)
	if !strings.Contains(note, "live-pin-blockers") && !strings.Contains(fmt.Sprint(payload["doc"]), "live-pin-blockers") {
		t.Fatalf("want live-pin-blockers pointer in residual_note or doc: note=%q doc=%v", note, payload["doc"])
	}
	doc, _ := payload["doc"].(string)
	if !strings.Contains(doc, "live-pin-blockers.md") {
		t.Fatalf("doc pointer: %q", doc)
	}
	if strings.Contains(strings.ToLower(out), "production go complete") {
		t.Fatal("must not claim production GO complete")
	}
}

// shared_subject_rate_file flips true when path set; path never appears in JSON.
func TestGatewayResidualStatus_SharedSubjectRateFileEnv(t *testing.T) {
	marker := "cli-subject-rate-path-canary-NEVER"
	path := filepath.Join(t.TempDir(), marker+".dat")
	t.Setenv(gateway.EnvGatewaySubjectRatePath, path)
	t.Setenv("HOST009_FAKE_TOKEN", canaryCLIToken)

	out := buildGatewayResidualStatus(os.Getenv)
	if out["shared_subject_rate_file"] != true {
		t.Fatalf("shared_subject_rate_file want true: %+v", out["shared_subject_rate_file"])
	}
	// Default-path call without env must stay false (fresh getenv with empty path).
	clear := buildGatewayResidualStatus(func(string) string { return "" })
	if clear["shared_subject_rate_file"] != false {
		t.Fatalf("shared_subject_rate_file default false: %+v", clear["shared_subject_rate_file"])
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	if strings.Contains(s, marker) || strings.Contains(s, path) {
		t.Fatal("Regression: SUBJECT_RATE_PATH leaked into residual-status")
	}
	for _, bad := range []string{canaryCLIToken, "access_token=", "refresh_token=", "Bearer " + canaryCLIToken} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q", bad)
		}
	}
	if _, ok := out["principal_cache_process_note"].(string); !ok {
		t.Fatal("principal_cache_process_note required")
	}
}

func TestGatewayResidualStatus_ViaDispatch(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGateway([]string{"residual-status"})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("dispatch: %v", errRun)
	}
	if !strings.Contains(buf.String(), "oauth009_offline") {
		t.Fatalf("stdout missing Mode B residual id: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "ha_multi_replica") {
		t.Fatalf("stdout missing ha_multi_replica: %s", buf.String())
	}
}

func TestGatewayResidualStatus_PrincipalCacheHygieneEnv(t *testing.T) {
	// Optional MaxEntries + TTL knobs surface as secret-free residual fields only.
	t.Setenv(gateway.EnvGatewayPrincipalCacheMax, "256")
	t.Setenv(gateway.EnvGatewayPrincipalCacheTTL, "2h")
	out := buildGatewayResidualStatus(os.Getenv)
	if out["principal_cache_max_entries"] != 256 {
		t.Fatalf("principal_cache_max_entries: %+v", out["principal_cache_max_entries"])
	}
	if out["principal_cache_ttl_seconds"] != 7200 {
		t.Fatalf("principal_cache_ttl_seconds: %+v", out["principal_cache_ttl_seconds"])
	}
	// buildGatewayResidualStatus uses Len() → int (never subjects dump).
	if _, ok := out["principal_cache_entries"].(int); !ok {
		t.Fatalf("principal_cache_entries type: %T %v", out["principal_cache_entries"], out["principal_cache_entries"])
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	// Must not dump subject inventory or tokens.
	for _, bad := range []string{canaryCLIToken, "alice-j", "tenant|subject", "access_token="} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with hygiene env", bad)
		}
	}
}

// HOST-008 residual lite: subject_rate_max_subjects surfaces when env set; omit when unlimited.
func TestGatewayResidualStatus_SubjectRateMaxSubjects(t *testing.T) {
	// Empty / unset → omit field (unlimited default).
	t.Setenv(gateway.EnvGatewaySubjectRateMaxSubjects, "")
	out := buildGatewayResidualStatus(os.Getenv)
	if _, ok := out["subject_rate_max_subjects"]; ok {
		t.Fatalf("unlimited must omit subject_rate_max_subjects: %+v", out["subject_rate_max_subjects"])
	}
	t.Setenv(gateway.EnvGatewaySubjectRateMaxSubjects, "4096")
	out = buildGatewayResidualStatus(os.Getenv)
	if out["subject_rate_max_subjects"] != 4096 {
		t.Fatalf("subject_rate_max_subjects: %+v", out["subject_rate_max_subjects"])
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	for _, bad := range []string{canaryCLIToken, "access_token=", "Bearer "} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status with max subjects", bad)
		}
	}
}

func TestGatewayResidualStatus_ModeBResidualIdAlways(t *testing.T) {
	// Even with Mode A env (or default), residual_id oauth009_offline must be present.
	t.Setenv(gateway.EnvGatewayCredentialMode, string(gateway.CredentialModeAPITokenVault))
	t.Setenv("JENKINS_MCP_GATEWAY_MULTI_USER", "")
	out := buildGatewayResidualStatus(os.Getenv)
	if out["residual_id"] != "oauth009_offline" {
		t.Fatalf("residual_id=%v", out["residual_id"])
	}
	if out["oauth009_offline"] != true {
		t.Fatalf("oauth009_offline=%v", out["oauth009_offline"])
	}
	if out["mode_b_enabled"] != false {
		t.Fatalf("mode_b_enabled should be false for Mode A: %v", out["mode_b_enabled"])
	}
	if out["ha_multi_replica"] != false {
		t.Fatal("ha_multi_replica must be false")
	}
	// Canary token values must never appear (honesty text may name forbidden fields).
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	for _, bad := range []string{canaryCLIToken, qualify.CanaryToken, "access_token=", "refresh_token=", "Bearer " + canaryCLIToken} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %q in residual-status map", bad)
		}
	}
}

func TestGatewayResidualStatus_MultiPodFromK8sEnv(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	out := buildGatewayResidualStatus(os.Getenv)
	if out["kubernetes_env_detected"] != true {
		t.Fatalf("kubernetes_env_detected: %v", out["kubernetes_env_detected"])
	}
	if out["multi_pod_vault_residual"] != true {
		t.Fatal("multi_pod_vault_residual always true")
	}
	cl, _ := out["multi_pod_residual_checklist"].(string)
	if cl == "" || !strings.Contains(strings.ToLower(cl), "multi-pod") {
		t.Fatalf("want multi_pod_residual_checklist: %q", cl)
	}
	// Never embed the k8s host or tokens.
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), "10.0.0.1") {
		t.Fatal("must not embed KUBERNETES_SERVICE_HOST value")
	}
}

// OAUTH-010: consent-purge default expires TTL metadata; secret-free summary.
func TestGatewayConsentPurge_ExpiredAndSessionAndAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "consent_sessions.json")
	// Seed file as if written while live, then clock advanced past ExpiresAt
	// (persist skips already-expired Puts; real TTL uses future ExpiresAt on write).
	now := time.Now().UTC()
	seed := fmt.Sprintf(`{
  "version": 1,
  "entries": {
    "sess-purge-live": {
      "authorization_url": "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=purge-live",
      "session_id": "sess-purge-live",
      "provider": "agentcore",
      "stored_at": %q,
      "expires_at": %q
    },
    "sess-purge-exp": {
      "authorization_url": "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=purge-exp",
      "session_id": "sess-purge-exp",
      "provider": "agentcore",
      "stored_at": %q,
      "expires_at": %q
    }
  }
}
`, now.Add(-time.Hour).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano),
		now.Add(-2*time.Hour).Format(time.RFC3339Nano), now.Add(-time.Minute).Format(time.RFC3339Nano))
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gateway.EnvConsentSessionStorePath, path)
	t.Setenv("HOST009_FAKE_TOKEN", canaryCLIToken)

	// Default: purge expired only.
	var errRun error
	out := captureStdout(t, func() {
		errRun = runGatewayConsentPurge(nil)
	})
	if errRun != nil {
		t.Fatalf("purge expired: %v\n%s", errRun, out)
	}
	assertConsentPurgeSecretFree(t, out)
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("json: %v body=%s", err, out)
	}
	if payload["action"] != "purge_expired" {
		t.Fatalf("action: %+v", payload["action"])
	}
	if payload["deleted_count"] != float64(1) {
		t.Fatalf("deleted_count: %+v", payload["deleted_count"])
	}
	if payload["remaining_count"] != float64(1) {
		t.Fatalf("remaining_count: %+v", payload["remaining_count"])
	}
	if payload["stores_tokens"] != false || payload["metadata_only"] != true {
		t.Fatalf("honesty flags: %+v", payload)
	}
	if payload["file_basename"] != "consent_sessions.json" {
		t.Fatalf("file_basename: %+v", payload["file_basename"])
	}
	// Full path must not appear if it would leak home-style paths unnecessarily;
	// basename residual is enough. Never tokens.
	if strings.Contains(out, canaryCLIToken) || strings.Contains(out, "access_token=") {
		t.Fatal("token/canary in purge output")
	}

	// --session-id deletes live session.
	out = captureStdout(t, func() {
		errRun = runGatewayConsentPurge([]string{"--session-id", "sess-purge-live"})
	})
	if errRun != nil {
		t.Fatalf("session delete: %v\n%s", errRun, out)
	}
	assertConsentPurgeSecretFree(t, out)
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != "delete_session" || payload["deleted_count"] != float64(1) {
		t.Fatalf("session delete: %+v", payload)
	}
	if payload["remaining_count"] != float64(0) {
		t.Fatalf("remaining after session delete: %+v", payload["remaining_count"])
	}

	// Re-seed and --all.
	store2, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store2.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize?state=a",
			SessionID:        "sess-all-1",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store2.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize?state=b",
			SessionID:        "sess-all-2",
		},
	}); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		errRun = runGatewayConsentPurge([]string{"--all"})
	})
	if errRun != nil {
		t.Fatalf("clear all: %v\n%s", errRun, out)
	}
	assertConsentPurgeSecretFree(t, out)
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["action"] != "clear_all" || payload["deleted_count"] != float64(2) {
		t.Fatalf("clear all: %+v", payload)
	}
	if payload["remaining_count"] != float64(0) {
		t.Fatalf("remaining after --all: %+v", payload["remaining_count"])
	}
}

func TestGatewayConsentPurge_AllAndSessionExclusive(t *testing.T) {
	err := runGatewayConsentPurge([]string{"--all", "--session-id", "x"})
	if err == nil {
		t.Fatal("want mutual exclusion error")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v", err)
	}
}

func TestGatewayConsentPurge_ViaDispatchAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	t.Setenv(gateway.EnvConsentSessionStorePath, path)
	var errRun error
	out := captureStdout(t, func() {
		errRun = runGateway([]string{"consent-expire", "--path", path})
	})
	if errRun != nil {
		t.Fatalf("dispatch: %v\n%s", errRun, out)
	}
	assertConsentPurgeSecretFree(t, out)
	if !strings.Contains(out, "purge_expired") {
		t.Fatalf("stdout: %s", out)
	}
	if !strings.Contains(out, "deleted_count") || !strings.Contains(out, "remaining_count") {
		t.Fatalf("want summary fields: %s", out)
	}
}

func TestGatewayConsentPurge_PathFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "explicit.json")
	store, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize?state=p",
			SessionID:        "sess-path-1",
		},
	}); err != nil {
		t.Fatal(err)
	}
	// Env points elsewhere — --path must win.
	t.Setenv(gateway.EnvConsentSessionStorePath, filepath.Join(dir, "other.json"))
	var errRun error
	out := captureStdout(t, func() {
		errRun = runGatewayConsentPurge([]string{"--path", path, "--all"})
	})
	if errRun != nil {
		t.Fatalf("path all: %v\n%s", errRun, out)
	}
	assertConsentPurgeSecretFree(t, out)
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["deleted_count"] != float64(1) {
		t.Fatalf("deleted: %+v body=%s", payload["deleted_count"], out)
	}
	// File should be empty metadata after clear.
	reloaded, err := gateway.NewFileBackedConsentSessionStore(0, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.List()) != 0 {
		t.Fatal("path --all must clear file")
	}
}

func assertConsentPurgeSecretFree(t *testing.T, out string) {
	t.Helper()
	for _, bad := range []string{
		canaryCLIToken,
		qualify.CanaryToken,
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"Authorization: Bearer",
	} {
		if strings.Contains(out, bad) {
			t.Fatalf("forbidden %q in consent-purge output", bad)
		}
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
