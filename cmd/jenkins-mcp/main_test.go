package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/app"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// Wave 37: serve hard-max bootstrap resolve uses tools.ResolveHardMaxBytes
// (default → env → flag). Invalid values fail closed.
// Wave 38: AbsoluteMaxHardMaxBytes fail-closed ceiling.
func TestResolveServeHardMaxBytes_Wiring(t *testing.T) {
	t.Parallel()
	// Same call shape as runServe after flag parse.
	n, err := tools.ResolveHardMaxBytes("", "")
	if err != nil || n != tools.DefaultHardMaxBytes {
		t.Fatalf("default: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveHardMaxBytes("2097152", "1048576")
	if err != nil || n != 2097152 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveHardMaxBytes("", "3145728")
	if err != nil || n != 3145728 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = tools.ResolveHardMaxBytes("", "nope")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), tools.EnvHardMaxBytes) && !strings.Contains(err.Error(), "hard max") {
		t.Fatalf("error should name source: %v", err)
	}
	// Env constant is the documented operator surface.
	if tools.EnvHardMaxBytes != "JENKINS_MCP_HARD_MAX_BYTES" {
		t.Fatalf("env name drift: %q", tools.EnvHardMaxBytes)
	}
	// Wave 38: above absolute cap fails closed (serve bootstrap).
	over := "67108865" // AbsoluteMaxHardMaxBytes(64MiB)+1
	_, err = tools.ResolveHardMaxBytes(over, "")
	if err == nil {
		t.Fatal("above AbsoluteMaxHardMaxBytes must fail closed at serve resolve")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "hard max") {
		t.Fatalf("over-cap error: %v", err)
	}
	// At cap ok.
	n, err = tools.ResolveHardMaxBytes("67108864", "") // 64<<20
	if err != nil || n != tools.AbsoluteMaxHardMaxBytes {
		t.Fatalf("at AbsoluteMaxHardMaxBytes: n=%d err=%v want %d", n, err, tools.AbsoluteMaxHardMaxBytes)
	}
}

// Wave 41: serve list_jobs collect max pages resolve (default → env → flag;
// AbsoluteMaxListJobsCollectMaxPages fail-closed).
func TestResolveServeListJobsCollectMaxPages_Wiring(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveListJobsCollectMaxPages("", "")
	if err != nil || n != tools.DefaultListJobsCollectMaxPages {
		t.Fatalf("default: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveListJobsCollectMaxPages("80", "120")
	if err != nil || n != 80 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveListJobsCollectMaxPages("", "100")
	if err != nil || n != 100 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = tools.ResolveListJobsCollectMaxPages("", "nope")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), tools.EnvListJobsCollectMaxPages) && !strings.Contains(err.Error(), "collect") {
		t.Fatalf("error should name source: %v", err)
	}
	if tools.EnvListJobsCollectMaxPages != "JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES" {
		t.Fatalf("env name drift: %q", tools.EnvListJobsCollectMaxPages)
	}
	over := "201" // AbsoluteMaxListJobsCollectMaxPages(200)+1
	_, err = tools.ResolveListJobsCollectMaxPages(over, "")
	if err == nil {
		t.Fatal("above AbsoluteMaxListJobsCollectMaxPages must fail closed at serve resolve")
	}
	n, err = tools.ResolveListJobsCollectMaxPages("200", "")
	if err != nil || n != tools.AbsoluteMaxListJobsCollectMaxPages {
		t.Fatalf("at AbsoluteMax: n=%d err=%v want %d", n, err, tools.AbsoluteMaxListJobsCollectMaxPages)
	}
}

// Wave 42: serve nodes/views collect max pages resolve (default → env → flag;
// absolute 200 fail-closed; env name drift guards).
func TestResolveServeNodesViewsCollectMaxPages_Wiring(t *testing.T) {
	t.Parallel()

	// Nodes
	n, err := tools.ResolveNodesCollectMaxPages("", "")
	if err != nil || n != tools.DefaultNodesCollectMaxPages {
		t.Fatalf("nodes default: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveNodesCollectMaxPages("80", "120")
	if err != nil || n != 80 {
		t.Fatalf("nodes flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveNodesCollectMaxPages("", "100")
	if err != nil || n != 100 {
		t.Fatalf("nodes env: n=%d err=%v", n, err)
	}
	_, err = tools.ResolveNodesCollectMaxPages("", "nope")
	if err == nil {
		t.Fatal("nodes invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), tools.EnvNodesCollectMaxPages) && !strings.Contains(err.Error(), "collect") {
		t.Fatalf("nodes error should name source: %v", err)
	}
	if tools.EnvNodesCollectMaxPages != "JENKINS_MCP_NODES_COLLECT_MAX_PAGES" {
		t.Fatalf("nodes env name drift: %q", tools.EnvNodesCollectMaxPages)
	}
	_, err = tools.ResolveNodesCollectMaxPages("201", "")
	if err == nil {
		t.Fatal("above AbsoluteMaxNodesCollectMaxPages must fail closed")
	}
	n, err = tools.ResolveNodesCollectMaxPages("200", "")
	if err != nil || n != tools.AbsoluteMaxNodesCollectMaxPages {
		t.Fatalf("nodes at AbsoluteMax: n=%d err=%v want %d", n, err, tools.AbsoluteMaxNodesCollectMaxPages)
	}

	// Views
	n, err = tools.ResolveViewsCollectMaxPages("", "")
	if err != nil || n != tools.DefaultViewsCollectMaxPages {
		t.Fatalf("views default: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveViewsCollectMaxPages("90", "110")
	if err != nil || n != 90 {
		t.Fatalf("views flag wins: n=%d err=%v", n, err)
	}
	if tools.EnvViewsCollectMaxPages != "JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES" {
		t.Fatalf("views env name drift: %q", tools.EnvViewsCollectMaxPages)
	}
	_, err = tools.ResolveViewsCollectMaxPages("201", "")
	if err == nil {
		t.Fatal("above AbsoluteMaxViewsCollectMaxPages must fail closed")
	}
	n, err = tools.ResolveViewsCollectMaxPages("200", "")
	if err != nil || n != tools.AbsoluteMaxViewsCollectMaxPages {
		t.Fatalf("views at AbsoluteMax: n=%d err=%v want %d", n, err, tools.AbsoluteMaxViewsCollectMaxPages)
	}
}

func TestCacheVerifyRepairFlagParseSmoke(t *testing.T) {
	t.Parallel()
	// Flag sets accept expected options without panicking; invalid profile is an arg error.
	err := runCacheVerify([]string{"--full", "--sample", "2"})
	if err == nil {
		t.Fatal("expected --profile required")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("unexpected: %v", err)
	}
	err = runCacheRepair([]string{"--index-only"})
	if err == nil {
		t.Fatal("expected --profile required")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("unexpected: %v", err)
	}
	// Subcommand dispatch rejects unknown.
	err = runCache([]string{"prune"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown subcommand: %v", err)
	}
}

func TestPilotCheckFlagParseSmoke(t *testing.T) {
	t.Parallel()
	// REL-001: pilot-check requires --profile; no secrets in arg errors.
	err := runPilotCheck([]string{"--offline", "--sample", "1"})
	if err == nil {
		t.Fatal("expected --profile required")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("unexpected: %v", err)
	}
	const canary = "CANARY_TOKEN_pilot_check_must_not_echo"
	err = runPilotCheck([]string{"--profile", "", "--offline"})
	if err == nil {
		t.Fatal("expected profile required for empty id path")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatal("canary must not appear in pilot-check errors")
	}
}

func TestReorderFlagArgs(t *testing.T) {
	t.Parallel()
	got := reorderFlagArgs([]string{"corp", "--url", "https://j.example", "--display-name", "Corp"}, map[string]bool{
		"url": true, "display-name": true,
	})
	want := []string{"--url", "https://j.example", "--display-name", "Corp", "corp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Already flags-first stays stable enough to parse.
	got = reorderFlagArgs([]string{"--url", "https://j.example", "corp"}, map[string]bool{"url": true})
	want = []string{"--url", "https://j.example", "corp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// = form
	got = reorderFlagArgs([]string{"corp", "--url=https://j.example"}, map[string]bool{"url": true})
	want = []string{"--url=https://j.example", "corp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTransportConfigFromProfile_NET004(t *testing.T) {
	t.Parallel()
	p := &profile.Profile{
		CABundlePath:   "/etc/ssl/ca.pem",
		ProxyURL:       "http://proxy.corp:8080",
		NoProxy:        []string{"localhost"},
		ClientCertFile: "/etc/ssl/c.crt",
		ClientKeyFile:  "/etc/ssl/c.key",
	}
	cfg := transportConfigFromProfile(p, "", "", false)
	if cfg.CABundlePath != "/etc/ssl/ca.pem" || cfg.ProxyURL != "http://proxy.corp:8080" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.ClientCertFile != "/etc/ssl/c.crt" || cfg.ClientKeyFile != "/etc/ssl/c.key" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.DiagnosticInsecureTLS {
		t.Fatal("must not set diagnostic insecure from profile alone")
	}
	// CLI overrides profile.
	cfg = transportConfigFromProfile(p, "/tmp/cli-ca.pem", "direct", true)
	if cfg.CABundlePath != "/tmp/cli-ca.pem" || cfg.ProxyURL != "direct" {
		t.Fatalf("cli override: %+v", cfg)
	}
	if !cfg.DiagnosticInsecureTLS {
		t.Fatal("CLI diag flag should set DiagnosticInsecureTLS (env gate applied at NewTransport)")
	}
	// nil profile + CLI only
	cfg = transportConfigFromProfile(nil, "/cli.pem", "http://p:1", false)
	if cfg.CABundlePath != "/cli.pem" || cfg.ProxyURL != "http://p:1" {
		t.Fatalf("%+v", cfg)
	}
}

func TestServeLogRedactionInstalledPath(t *testing.T) {
	// Regression KD-004: same wiring as runServe (log → redact.NewWriter).
	// Use a local logger so parallel package tests are not affected.
	var buf bytes.Buffer
	lg := log.New(redact.NewWriter(&buf), "", 0)

	const canary = "kd004-serve-path-canary-token-MUST-ABSENT"
	lg.Printf("Using Jenkins auth for user: %s", "alice")
	lg.Printf("accidental Authorization: Bearer %s", canary)
	lg.Printf("accidental api_token=%s", canary)

	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("Regression KD-004: token canary in serve log path: %q", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("username required on serve auth line: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected redaction marker: %q", out)
	}
}

func TestLoginStatusNeverIncludesLOGIN_TOKEN(t *testing.T) {
	// Regression KD-004: login success keeps username but must never echo
	// JENKINS_MCP_LOGIN_TOKEN (or any secret) into the status line.
	const canary = "JENKINS_MCP_LOGIN_TOKEN_canary_kd004_must_never_appear_in_status"
	t.Setenv("JENKINS_MCP_LOGIN_TOKEN", canary)

	line := formatAPITokenLoginStatus("corp", "alice", "alice")
	if strings.Contains(line, canary) {
		t.Fatalf("login status leaked LOGIN_TOKEN canary: %q", line)
	}
	if strings.Contains(line, "JENKINS_MCP_LOGIN_TOKEN") {
		t.Fatalf("login status must not mention token env var: %q", line)
	}
	if !strings.Contains(line, `user "alice"`) || !strings.Contains(line, `principal "alice"`) {
		t.Fatalf("username/principal required: %q", line)
	}
	// If someone mistakenly logged the env var with a secret-shaped label, redactor scrubs it.
	// Local logger avoids package log.SetOutput races with parallel tests.
	var logBuf bytes.Buffer
	lg := log.New(redact.NewWriter(&logBuf), "", 0)
	// Labeled form (api_token=) matches built-in detectors; bare env dumps are residual.
	lg.Printf("mistaken login debug api_token=%s user=alice", os.Getenv("JENKINS_MCP_LOGIN_TOKEN"))
	got := logBuf.String()
	if strings.Contains(got, canary) {
		t.Fatalf("Regression KD-004: LOGIN_TOKEN canary in log line: %q", got)
	}
	if !strings.Contains(got, "user=alice") {
		t.Fatalf("username should remain after redaction: %q", got)
	}
}

func TestPrintStatusSanitized(t *testing.T) {
	// Capture stdout for status formatting (AUTH-003 / OAUTH-007: no token).
	const canary = "CANARY_TOKEN_status_cli_must_not_print_abc"
	st := auth.Status{
		ProfileID:         "corp",
		Method:            auth.MethodAPIToken,
		Authenticated:     true,
		HasCredential:     true,
		HasRefresh:        false,
		User:              "alice",
		PrincipalID:       "alice",
		PrincipalFullName: "Alice",
		ExpiresAt:         time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	// Ensure canary is not somehow embedded in status fields.
	out := captureStdout(t, func() { printStatus(st) })
	if strings.Contains(out, canary) {
		t.Fatalf("token canary in status output: %s", out)
	}
	for _, want := range []string{
		"profile:         corp",
		"method:          api_token",
		"authenticated:   true",
		"has_credential:  true",
		"has_refresh:     false",
		"username:        alice",
		"principal_id:    alice",
		"principal_name:  Alice",
		"expires_at:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// Negative: never print a raw "token" value field.
	if strings.Contains(out, "token:") || strings.Contains(out, "api_token:") {
		t.Fatalf("token field leaked in status:\n%s", out)
	}
}

func TestPrintStatusOIDC(t *testing.T) {
	const canary = "OIDC_ACCESS_CANARY_status_must_not_print"
	st := auth.Status{
		ProfileID:     "corp",
		Method:        auth.MethodOIDC,
		Authenticated: true,
		HasCredential: true,
		HasRefresh:    true,
		User:          "alice",
		ExpiresAt:     time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC),
	}
	out := captureStdout(t, func() { printStatus(st) })
	if strings.Contains(out, canary) {
		t.Fatal("canary in status")
	}
	for _, want := range []string{
		"method:          oidc",
		"has_refresh:     true",
		"authenticated:   true",
		"expires_at:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "access_token") || strings.Contains(out, "refresh_token") {
		t.Fatalf("token field names leaked:\n%s", out)
	}
}

func TestPrintStatusUnauthenticated(t *testing.T) {
	st := auth.Status{
		ProfileID:        "corp",
		Method:           auth.MethodAPIToken,
		Authenticated:    false,
		HasCredential:    false,
		User:             "alice",
		ErrorCode:        "authentication",
		ErrorMessageSafe: "authentication failed",
		RecoveryHint:     "jenkins-mcp login --profile corp",
	}
	out := captureStdout(t, func() { printStatus(st) })
	if !strings.Contains(out, "has_credential:  false") {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(out, "errorCode:       authentication") {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(out, "recovery:        jenkins-mcp login --profile corp") {
		t.Fatalf("%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

func TestLoadProfileFrameCrypto_FailClosed(t *testing.T) {
	t.Parallel()
	// Encryption required via env/profile without key version → authentication.
	p := &profile.Profile{
		ConfigVersion:   profile.CurrentConfigVersion,
		ID:              "corp",
		JenkinsURL:      "https://jenkins.example.com",
		AuthMethod:      profile.AuthMethodAPIToken,
		CacheEncryption: true,
		// CacheKeyVersion deliberately 0 — invalid for enabled encryption at load path.
		CacheKeyVersion: 0,
	}
	// Validate would reject save; loadProfileFrameCrypto still fail-closes.
	_, err := loadProfileFrameCrypto(p)
	if err == nil {
		t.Fatal("expected fail closed")
	}
	if !strings.Contains(err.Error(), "cache") && !strings.Contains(err.Error(), "key") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestResolveServeArtifactsHardCap_Wiring(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveArtifactsHardCap("", "")
	if err != nil || n != 500 { // jenkins.DefaultArtifactsHardCap
		t.Fatalf("default: n=%d err=%v want 500", n, err)
	}
	n, err = tools.ResolveArtifactsHardCap("800", "1200")
	if err != nil || n != 800 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveArtifactsHardCap("", "1000")
	if err != nil || n != 1000 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = tools.ResolveArtifactsHardCap("", "nope")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), tools.EnvArtifactsHardCap) && !strings.Contains(err.Error(), "artifacts") {
		t.Fatalf("error should name source: %v", err)
	}
	if tools.EnvArtifactsHardCap != "JENKINS_MCP_ARTIFACTS_HARD_CAP" {
		t.Fatalf("env name drift: %q", tools.EnvArtifactsHardCap)
	}
	over := "2001" // AbsoluteMaxArtifactsHardCap(2000)+1
	_, err = tools.ResolveArtifactsHardCap(over, "")
	if err == nil {
		t.Fatal("above AbsoluteMaxArtifactsHardCap must fail closed at serve resolve")
	}
	n, err = tools.ResolveArtifactsHardCap("2000", "")
	if err != nil || n != 2000 {
		t.Fatalf("at AbsoluteMax: n=%d err=%v want 2000", n, err)
	}
}

func TestResolveServeArtifactsListBodyBytes_Wiring(t *testing.T) {
	t.Parallel()
	n, err := tools.ResolveArtifactsListBodyBytes("", "")
	if err != nil || n != 2<<20 { // jenkins.DefaultArtifactListBodyBytes
		t.Fatalf("default: n=%d err=%v want 2MiB", n, err)
	}
	n, err = tools.ResolveArtifactsListBodyBytes("3145728", "4194304")
	if err != nil || n != 3<<20 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveArtifactsListBodyBytes("", "4194304")
	if err != nil || n != 4<<20 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = tools.ResolveArtifactsListBodyBytes("", "nope")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), tools.EnvArtifactsListBodyBytes) && !strings.Contains(err.Error(), "artifact") {
		t.Fatalf("error should name source: %v", err)
	}
	if tools.EnvArtifactsListBodyBytes != "JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES" {
		t.Fatalf("env name drift: %q", tools.EnvArtifactsListBodyBytes)
	}
	over := strconv.Itoa((8 << 20) + 1) // AbsoluteMaxArtifactListBodyBytes(8MiB)+1
	_, err = tools.ResolveArtifactsListBodyBytes(over, "")
	if err == nil {
		t.Fatal("above AbsoluteMaxArtifactListBodyBytes must fail closed at serve resolve")
	}
	n, err = tools.ResolveArtifactsListBodyBytes(strconv.Itoa(8<<20), "")
	if err != nil || n != 8<<20 {
		t.Fatalf("at AbsoluteMax: n=%d err=%v want 8MiB", n, err)
	}
}

// Wave 44 Track C: serve HTTP MaxBodyBytes resolve uses mcpserver.ResolveHTTPMaxBodyBytes
// (default → env → flag; AbsoluteMaxBodyBytes 16 MiB fail-closed).
func TestResolveServeHTTPMaxBodyBytes_Wiring(t *testing.T) {
	t.Parallel()
	n, err := mcpserver.ResolveHTTPMaxBodyBytes("", "")
	if err != nil || n != mcpserver.DefaultMaxBodyBytes {
		t.Fatalf("default: n=%d err=%v want %d", n, err, mcpserver.DefaultMaxBodyBytes)
	}
	n, err = mcpserver.ResolveHTTPMaxBodyBytes("6291456", "8388608")
	if err != nil || n != 6<<20 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = mcpserver.ResolveHTTPMaxBodyBytes("", "8388608")
	if err != nil || n != 8<<20 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = mcpserver.ResolveHTTPMaxBodyBytes("", "nope")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), mcpserver.EnvHTTPMaxBodyBytes) && !strings.Contains(err.Error(), "body") {
		t.Fatalf("error should name source: %v", err)
	}
	if mcpserver.EnvHTTPMaxBodyBytes != "JENKINS_MCP_HTTP_MAX_BODY_BYTES" {
		t.Fatalf("env name drift: %q", mcpserver.EnvHTTPMaxBodyBytes)
	}
	over := strconv.FormatInt(mcpserver.AbsoluteMaxBodyBytes+1, 10)
	_, err = mcpserver.ResolveHTTPMaxBodyBytes(over, "")
	if err == nil {
		t.Fatal("above AbsoluteMaxBodyBytes must fail closed at serve resolve")
	}
	n, err = mcpserver.ResolveHTTPMaxBodyBytes(strconv.FormatInt(mcpserver.AbsoluteMaxBodyBytes, 10), "")
	if err != nil || n != mcpserver.AbsoluteMaxBodyBytes {
		t.Fatalf("at AbsoluteMax: n=%d err=%v want %d", n, err, mcpserver.AbsoluteMaxBodyBytes)
	}
}

// Wave 46 Track A: serve MaxJSONBodyBytes resolve uses jenkins.ResolveMaxJSONBodyBytes
// (default → env → flag; AbsoluteMaxJSONBodyBytes 128 MiB fail-closed).
func TestResolveServeMaxJSONBodyBytes_Wiring(t *testing.T) {
	t.Parallel()
	n, err := jenkins.ResolveMaxJSONBodyBytes("", "")
	if err != nil || n != jenkins.DefaultMaxJSONBodyBytes {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultMaxJSONBodyBytes)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("50331648", "67108864")
	if err != nil || n != 48<<20 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes("", "67108864")
	if err != nil || n != 64<<20 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	_, err = jenkins.ResolveMaxJSONBodyBytes("", "nope")
	if err == nil {
		t.Fatal("invalid env must fail closed")
	}
	if !strings.Contains(err.Error(), jenkins.EnvMaxJSONBodyBytes) && !strings.Contains(err.Error(), "json") {
		t.Fatalf("error should name source: %v", err)
	}
	if jenkins.EnvMaxJSONBodyBytes != "JENKINS_MCP_MAX_JSON_BODY_BYTES" {
		t.Fatalf("env name drift: %q", jenkins.EnvMaxJSONBodyBytes)
	}
	over := strconv.FormatInt(jenkins.AbsoluteMaxJSONBodyBytes+1, 10)
	_, err = jenkins.ResolveMaxJSONBodyBytes(over, "")
	if err == nil {
		t.Fatal("above AbsoluteMaxJSONBodyBytes must fail closed at serve resolve")
	}
	n, err = jenkins.ResolveMaxJSONBodyBytes(strconv.FormatInt(jenkins.AbsoluteMaxJSONBodyBytes, 10), "")
	if err != nil || n != jenkins.AbsoluteMaxJSONBodyBytes {
		t.Fatalf("at AbsoluteMax: n=%d err=%v want %d", n, err, jenkins.AbsoluteMaxJSONBodyBytes)
	}
}

// Wave 47 Track A: serve MaxRetries resolve (explicit 0 disables; absolute 10 fail-closed).
func TestResolveServeMaxRetries_Wiring(t *testing.T) {
	t.Parallel()
	n, err := jenkins.ResolveMaxRetries("", "")
	if err != nil || n != jenkins.DefaultMaxRetries {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultMaxRetries)
	}
	n, err = jenkins.ResolveMaxRetries("0", "5")
	if err != nil || n != 0 {
		t.Fatalf("flag 0 disables: n=%d err=%v", n, err)
	}
	n, err = jenkins.ResolveMaxRetries("3", "1")
	if err != nil || n != 3 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := jenkins.ResolveMaxRetries("11", ""); err == nil {
		t.Fatal("above AbsoluteMaxRetries must fail closed")
	}
	if jenkins.EnvMaxRetries != "JENKINS_MCP_MAX_RETRIES" {
		t.Fatalf("env name drift: %q", jenkins.EnvMaxRetries)
	}
}

// Wave 47/51 Track C: soft TargetBytes resolve (default 64KiB; absolute 64MiB fail-closed).
func TestResolveServeTargetBytes_Wiring(t *testing.T) {
	t.Parallel()
	if tools.AbsoluteMaxTargetBytes != tools.AbsoluteMaxHardMaxBytes {
		t.Fatalf("AbsoluteMaxTargetBytes=%d want AbsoluteMaxHardMaxBytes=%d",
			tools.AbsoluteMaxTargetBytes, tools.AbsoluteMaxHardMaxBytes)
	}
	n, err := tools.ResolveTargetBytes("", "")
	if err != nil || n != tools.DefaultTargetBytes {
		t.Fatalf("default: n=%d err=%v want %d", n, err, tools.DefaultTargetBytes)
	}
	n, err = tools.ResolveTargetBytes("131072", "65536")
	if err != nil || n != 131072 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveTargetBytes("0", "131072")
	if err != nil || n != tools.DefaultTargetBytes {
		t.Fatalf("flag 0 → default: n=%d err=%v", n, err)
	}
	// Above former 1 MiB soft absolute still resolves under 64 MiB.
	n, err = tools.ResolveTargetBytes(strconv.Itoa(tools.DefaultHardMaxBytes+1), "")
	if err != nil || n != tools.DefaultHardMaxBytes+1 {
		t.Fatalf("above old 1MiB soft abs: n=%d err=%v", n, err)
	}
	n, err = tools.ResolveTargetBytes(strconv.Itoa(tools.AbsoluteMaxTargetBytes), "")
	if err != nil || n != tools.AbsoluteMaxTargetBytes {
		t.Fatalf("at AbsoluteMaxTargetBytes: n=%d err=%v", n, err)
	}
	if _, err := tools.ResolveTargetBytes(strconv.Itoa(tools.AbsoluteMaxTargetBytes+1), ""); err == nil {
		t.Fatal("above AbsoluteMaxTargetBytes must fail closed")
	}
	if tools.EnvTargetBytes != "JENKINS_MCP_TARGET_BYTES" {
		t.Fatalf("env name drift: %q", tools.EnvTargetBytes)
	}
}

// Wave 48 Track A: circuit failure threshold resolve (0→default; absolute 50 fail-closed).
func TestResolveServeCircuitFailureThreshold_Wiring(t *testing.T) {
	t.Parallel()
	n, err := jenkins.ResolveCircuitFailureThreshold("", "")
	if err != nil || n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultCircuitFailureThreshold)
	}
	n, err = jenkins.ResolveCircuitFailureThreshold("0", "10")
	if err != nil || n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("flag 0 → default: n=%d err=%v", n, err)
	}
	n, err = jenkins.ResolveCircuitFailureThreshold("8", "3")
	if err != nil || n != 8 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := jenkins.ResolveCircuitFailureThreshold("51", ""); err == nil {
		t.Fatal("above AbsoluteMaxCircuitFailureThreshold must fail closed")
	}
	if jenkins.EnvCircuitFailureThreshold != "JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD" {
		t.Fatalf("env name drift: %q", jenkins.EnvCircuitFailureThreshold)
	}
}

// Wave 49 Track A: circuit open duration resolve (0→default; min 1s; max 5m fail-closed).
func TestResolveServeCircuitOpenDuration_Wiring(t *testing.T) {
	t.Parallel()
	d, err := jenkins.ResolveCircuitOpenDuration("", "")
	if err != nil || d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("default: d=%v err=%v", d, err)
	}
	d, err = jenkins.ResolveCircuitOpenDuration("0", "1m")
	if err != nil || d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("0→default: d=%v err=%v", d, err)
	}
	d, err = jenkins.ResolveCircuitOpenDuration("30s", "1m")
	if err != nil || d != 30*time.Second {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	if _, err := jenkins.ResolveCircuitOpenDuration("500ms", ""); err == nil {
		t.Fatal("below min must fail closed")
	}
	if _, err := jenkins.ResolveCircuitOpenDuration("6m", ""); err == nil {
		t.Fatal("above max must fail closed")
	}
	if jenkins.EnvCircuitOpenDuration != "JENKINS_MCP_CIRCUIT_OPEN_DURATION" {
		t.Fatalf("env name: %q", jenkins.EnvCircuitOpenDuration)
	}
}

// Wave 49 Track C: cache maintenance interval absolute bounds (min 30s max 1h).
func TestResolveServeCacheMaintenanceInterval_Wiring(t *testing.T) {
	t.Parallel()
	d, err := app.ResolveMaintenanceInterval("", "")
	if err != nil || d != app.DefaultMaintenanceInterval {
		t.Fatalf("default: d=%v err=%v", d, err)
	}
	d, err = app.ResolveMaintenanceInterval("2m", "10m")
	if err != nil || d != 2*time.Minute {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	if _, err := app.ResolveMaintenanceInterval("10s", ""); err == nil {
		t.Fatal("below min 30s must fail closed")
	}
	if _, err := app.ResolveMaintenanceInterval("2h", ""); err == nil {
		t.Fatal("above max 1h must fail closed")
	}
	if app.EnvCacheMaintenanceInterval != "JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL" {
		t.Fatalf("env name: %q", app.EnvCacheMaintenanceInterval)
	}
}

// Wave 50 Track A: MaxConcurrent resolve (0=unlimited; absolute 256 fail-closed).
func TestResolveServeMaxConcurrent_Wiring(t *testing.T) {
	t.Parallel()
	n, err := jenkins.ResolveMaxConcurrent("", "")
	if err != nil || n != jenkins.DefaultMaxConcurrent {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultMaxConcurrent)
	}
	n, err = jenkins.ResolveMaxConcurrent("0", "16")
	if err != nil || n != 0 {
		t.Fatalf("flag 0=unlimited: n=%d err=%v", n, err)
	}
	n, err = jenkins.ResolveMaxConcurrent("32", "8")
	if err != nil || n != 32 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := jenkins.ResolveMaxConcurrent("257", ""); err == nil {
		t.Fatal("above AbsoluteMaxConcurrent must fail closed")
	}
	if jenkins.EnvMaxConcurrent != "JENKINS_MCP_MAX_CONCURRENT" {
		t.Fatalf("env name: %q", jenkins.EnvMaxConcurrent)
	}
}

// Wave 51 Track A: InitialBackoff resolve (0→default; min 10ms; max 2s fail-closed).
func TestResolveServeInitialBackoff_Wiring(t *testing.T) {
	t.Parallel()
	d, err := jenkins.ResolveInitialBackoff("", "")
	if err != nil || d != jenkins.DefaultInitialBackoff {
		t.Fatalf("default: d=%v err=%v", d, err)
	}
	d, err = jenkins.ResolveInitialBackoff("0", "250ms")
	if err != nil || d != jenkins.DefaultInitialBackoff {
		t.Fatalf("0→default: d=%v err=%v", d, err)
	}
	d, err = jenkins.ResolveInitialBackoff("500ms", "1s")
	if err != nil || d != 500*time.Millisecond {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	if _, err := jenkins.ResolveInitialBackoff("1ms", ""); err == nil {
		t.Fatal("below min must fail closed")
	}
	if _, err := jenkins.ResolveInitialBackoff("3s", ""); err == nil {
		t.Fatal("above max must fail closed")
	}
	if jenkins.EnvInitialBackoff != "JENKINS_MCP_INITIAL_BACKOFF" {
		t.Fatalf("env name: %q", jenkins.EnvInitialBackoff)
	}
}

// Wave 51 Track A: MaxBackoff resolve (0→default; min 100ms; max 1m fail-closed).
func TestResolveServeMaxBackoff_Wiring(t *testing.T) {
	t.Parallel()
	d, err := jenkins.ResolveMaxBackoff("", "")
	if err != nil || d != jenkins.DefaultMaxBackoff {
		t.Fatalf("default: d=%v err=%v", d, err)
	}
	d, err = jenkins.ResolveMaxBackoff("0", "10s")
	if err != nil || d != jenkins.DefaultMaxBackoff {
		t.Fatalf("0→default: d=%v err=%v", d, err)
	}
	d, err = jenkins.ResolveMaxBackoff("15s", "30s")
	if err != nil || d != 15*time.Second {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	if _, err := jenkins.ResolveMaxBackoff("50ms", ""); err == nil {
		t.Fatal("below min must fail closed")
	}
	if _, err := jenkins.ResolveMaxBackoff("2m", ""); err == nil {
		t.Fatal("above max must fail closed")
	}
	if jenkins.EnvMaxBackoff != "JENKINS_MCP_MAX_BACKOFF" {
		t.Fatalf("env name: %q", jenkins.EnvMaxBackoff)
	}
	// Ordering: max < initial fails closed at serve (EnsureMaxBackoffAtLeastInitial).
	if err := jenkins.EnsureMaxBackoffAtLeastInitial(2*time.Second, 500*time.Millisecond); err == nil {
		t.Fatal("max < initial must fail closed")
	}
	if err := jenkins.EnsureMaxBackoffAtLeastInitial(jenkins.DefaultInitialBackoff, jenkins.DefaultMaxBackoff); err != nil {
		t.Fatalf("default ordering: %v", err)
	}
}

// Wave 52 Track A: ConfirmCooldown resolve (0→default; min 1s; max 5m fail-closed).
func TestResolveServeMutationConfirmCooldown_Wiring(t *testing.T) {
	t.Parallel()
	d, err := mutation.ResolveConfirmCooldown("", "")
	if err != nil || d != mutation.DefaultConfirmCooldown {
		t.Fatalf("default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown("0", "30s")
	if err != nil || d != mutation.DefaultConfirmCooldown {
		t.Fatalf("0→default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown("0s", "30s")
	if err != nil || d != mutation.DefaultConfirmCooldown {
		t.Fatalf("0s→default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveConfirmCooldown("20s", "2m")
	if err != nil || d != 20*time.Second {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	if _, err := mutation.ResolveConfirmCooldown("500ms", ""); err == nil {
		t.Fatal("below min must fail closed")
	}
	if _, err := mutation.ResolveConfirmCooldown("6m", ""); err == nil {
		t.Fatal("above max must fail closed")
	}
	if mutation.EnvConfirmCooldown != "JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN" {
		t.Fatalf("env name: %q", mutation.EnvConfirmCooldown)
	}
	// Live Set path (same call shape as runServe after resolve).
	prev := mutation.ConfirmCooldown()
	defer func() {
		if prev > 0 {
			mutation.SetConfirmCooldown(prev)
		} else {
			// Best-effort restore: Set maps non-positive to default (serve always Sets).
			mutation.SetConfirmCooldown(mutation.DefaultConfirmCooldown)
		}
	}()
	mutation.SetConfirmCooldown(d)
	if got := mutation.ConfirmCooldown(); got != 20*time.Second {
		t.Fatalf("Set after resolve: got %v want 20s", got)
	}
}

// Wave 52 Track C / MUT-001: serve MaxPreviewsPerMinute resolve (0→default; absolute 300 fail-closed).
func TestResolveServeMutationMaxPreviewsPerMinute_Wiring(t *testing.T) {
	t.Parallel()
	n, err := mutation.ResolveMaxPreviewsPerMinute("", "")
	if err != nil || n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("default: n=%d err=%v want %d", n, err, mutation.DefaultMaxPreviewsPerMinute)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("0", "100")
	if err != nil || n != mutation.DefaultMaxPreviewsPerMinute {
		t.Fatalf("flag 0→default: n=%d err=%v", n, err)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("45", "100")
	if err != nil || n != 45 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = mutation.ResolveMaxPreviewsPerMinute("", "60")
	if err != nil || n != 60 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	if _, err := mutation.ResolveMaxPreviewsPerMinute("301", ""); err == nil {
		t.Fatal("above AbsoluteMaxPreviewsPerMinute must fail closed")
	}
	if _, err := mutation.ResolveMaxPreviewsPerMinute("-1", ""); err == nil {
		t.Fatal("negative must fail closed")
	}
	if mutation.EnvMaxPreviewsPerMinute != "JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE" {
		t.Fatalf("env name: %q", mutation.EnvMaxPreviewsPerMinute)
	}
	if mutation.AbsoluteMaxPreviewsPerMinute != 300 {
		t.Fatalf("AbsoluteMaxPreviewsPerMinute=%d want 300", mutation.AbsoluteMaxPreviewsPerMinute)
	}
}

// OBS-001 / pilot: log-level resolve (default info; flag wins; invalid fail-closed).
func TestResolveServeLogLevel_Wiring(t *testing.T) {
	t.Parallel()
	lv, err := telemetry.ResolveLogLevel("", "")
	if err != nil || lv != telemetry.LevelInfo {
		t.Fatalf("default: lv=%v err=%v", lv, err)
	}
	lv, err = telemetry.ResolveLogLevel("debug", "error")
	if err != nil || lv != telemetry.LevelDebug {
		t.Fatalf("flag wins: lv=%v err=%v", lv, err)
	}
	if _, err := telemetry.ResolveLogLevel("nope", ""); err == nil {
		t.Fatal("invalid must fail closed")
	}
	// Serve maps plain resolve errors to apperr.CodeInvalidArgument.
	if telemetry.EnvLogLevel != "JENKINS_MCP_LOG_LEVEL" {
		t.Fatalf("env: %q", telemetry.EnvLogLevel)
	}
}

// Wave 53 Track A: TokenTTL resolve (0→default; min 10s; max 15m fail-closed).
func TestResolveServeMutationTokenTTL_Wiring(t *testing.T) {
	t.Parallel()
	d, err := mutation.ResolveTokenTTL("", "")
	if err != nil || d != mutation.DefaultTokenTTL {
		t.Fatalf("default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveTokenTTL("0", "30s")
	if err != nil || d != mutation.DefaultTokenTTL {
		t.Fatalf("0→default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveTokenTTL("0s", "30s")
	if err != nil || d != mutation.DefaultTokenTTL {
		t.Fatalf("0s→default: d=%v err=%v", d, err)
	}
	d, err = mutation.ResolveTokenTTL("1m", "5m")
	if err != nil || d != time.Minute {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	if _, err := mutation.ResolveTokenTTL("5s", ""); err == nil {
		t.Fatal("below min must fail closed")
	}
	if _, err := mutation.ResolveTokenTTL("16m", ""); err == nil {
		t.Fatal("above max must fail closed")
	}
	if mutation.EnvTokenTTL != "JENKINS_MCP_MUTATION_TOKEN_TTL" {
		t.Fatalf("env name: %q", mutation.EnvTokenTTL)
	}
	// Live Set path (same call shape as runServe after resolve).
	prev := mutation.TokenTTL()
	defer func() {
		if prev > 0 {
			mutation.SetTokenTTL(prev)
		} else {
			// Best-effort restore: Set maps non-positive to default (serve always Sets).
			mutation.SetTokenTTL(mutation.DefaultTokenTTL)
		}
	}()
	mutation.SetTokenTTL(d)
	if got := mutation.TokenTTL(); got != time.Minute {
		t.Fatalf("Set after resolve: got %v want 1m", got)
	}
}

// MUT-001 residual fix: serve fail-closed when ConfirmCooldown ≥ TokenTTL
// (same call shape as runServe after both resolve).
func TestEnsureServeMutationConfirmCooldownLessThanTokenTTL_Wiring(t *testing.T) {
	t.Parallel()
	// Defaults ok (5s < 2m).
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(
		mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	// Resolved operator pair ok when cooldown < ttl.
	cooldown, err := mutation.ResolveConfirmCooldown("20s", "")
	if err != nil {
		t.Fatal(err)
	}
	ttl, err := mutation.ResolveTokenTTL("1m", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(cooldown, ttl); err != nil {
		t.Fatalf("20s < 1m must succeed: %v", err)
	}
	// Equal fails closed.
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(30*time.Second, 30*time.Second); err == nil {
		t.Fatal("equal must fail closed")
	}
	// Cooldown > ttl fails closed.
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(2*time.Minute, 30*time.Second); err == nil {
		t.Fatal("cooldown > ttl must fail closed")
	}
}

// Wave 52 Track C / MUT-001: serve MaxPreviewsPerMinute resolve (0→default; absolute 300 fail-closed).
func TestSoftTargetClampApplied_ServeWiring(t *testing.T) {
	t.Parallel()
	// Mirrors serve: resolved target vs bootstrap hard, then Normalize.
	bootstrapHardMax := tools.DefaultHardMaxBytes
	resolvedAbove, err := tools.ResolveTargetBytes(strconv.Itoa(tools.DefaultHardMaxBytes+1), "")
	if err != nil {
		t.Fatal(err)
	}
	if !tools.SoftTargetClampApplied(resolvedAbove, bootstrapHardMax) {
		t.Fatalf("resolved %d > bootstrap %d must clamp", resolvedAbove, bootstrapHardMax)
	}
	b := tools.Budgets{TargetBytes: resolvedAbove, HardMaxBytes: bootstrapHardMax}.Normalize()
	if b.TargetBytes != bootstrapHardMax {
		t.Fatalf("post-Normalize TargetBytes=%d want %d", b.TargetBytes, bootstrapHardMax)
	}
	// Default soft under default hard: no clamp (clamped=false still logged by serve).
	resolvedDefault, err := tools.ResolveTargetBytes("", "")
	if err != nil {
		t.Fatal(err)
	}
	if tools.SoftTargetClampApplied(resolvedDefault, bootstrapHardMax) {
		t.Fatalf("default target %d must not clamp under bootstrap %d",
			resolvedDefault, bootstrapHardMax)
	}
	// Equal: not clamped.
	if tools.SoftTargetClampApplied(bootstrapHardMax, bootstrapHardMax) {
		t.Fatal("equal target/hard must not report clamp")
	}
}

// Wave 48 Track A: circuit failure threshold resolve (0→default; absolute 50 fail-closed).
