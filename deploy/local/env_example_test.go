// Package local_deploy tests deploy/local residual-honest packaging (HOST-012 polish).
// File-level checks only — no Docker required (offline CI gate via go test ./...).
package local_deploy_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// deploy/local/env_example_test.go → repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

// Regression: deploy/local .env.example must list residual gateway multi-user /
// file-cache / rate / JWKS env names (non-secret only) so operators need not invent them.
func TestEnvExample_ListsResidualGatewayKnobs(t *testing.T) {
	t.Parallel()
	path := filepath.Join(repoRoot(t), "deploy/local/.env.example")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	body := string(raw)
	// Never document secrets in the example.
	for _, bad := range []string{
		"client_secret",
		"CLIENT_SECRET",
		"JENKINS_MCP_AUTH=",
		"refresh_token=",
		"api_token=",
		"Bearer ",
	} {
		if strings.Contains(body, bad) {
			t.Fatalf("secret-like material in .env.example: %q", bad)
		}
	}
	// Required residual-honest lab flags (commented or set — names must appear).
	for _, want := range []string{
		"JENKINS_MCP_GATEWAY_MULTI_USER",
		"JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH",
		"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH",
		"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX",
		"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_TTL",
		"JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS",
		"JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH",
		"JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS",
		"JENKINS_MCP_HTTP_JWKS_CACHE_PATH",
		"JENKINS_MCP_HTTP_JWKS_MAX_STALE",
		"JENKINS_MCP_SUBJECT_RATE_PER_MINUTE",
		"JENKINS_MCP_SUBJECT_RATE_BURST",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing env name %s in .env.example", want)
		}
	}
	// Honesty: multi-user / same-host lite residual, not production multi-pod or live Entra.
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "residual") {
		t.Fatal(".env.example should note residual honesty")
	}
	if !strings.Contains(lower, "multi-pod") && !strings.Contains(lower, "not multi-pod") {
		t.Fatal(".env.example should note not multi-pod / multi-pod residual")
	}
	if !strings.Contains(lower, "live-pin-blockers") && !strings.Contains(lower, "live entra") {
		t.Fatal(".env.example should point at live-pin-blockers or live Entra residual")
	}
	// Paths should prefer volume-backed XDG data (local stack), not invent host /var.
	if strings.Contains(body, "JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH=") &&
		!strings.Contains(body, "/home/nonroot/.local/share/jenkins-mcp/") {
		t.Fatal("file-cache path examples should use local-data XDG under /home/nonroot/.local/share/jenkins-mcp/")
	}
}

// Regression: compose must pass residual knobs into mcp / mcp-http so uncommented
// .env values flow (scripts/local-docker.sh already uses --env-file).
func TestCompose_PassesResidualGatewayEnvs(t *testing.T) {
	t.Parallel()
	path := filepath.Join(repoRoot(t), "deploy/local/docker-compose.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"JENKINS_MCP_GATEWAY_MULTI_USER",
		"JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH",
		"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH",
		"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_MAX",
		"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_TTL",
		"JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS",
		"JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH",
		"JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS",
		"JENKINS_MCP_HTTP_JWKS_CACHE_PATH",
		"JENKINS_MCP_HTTP_JWKS_MAX_STALE",
		`user: "65532:65532"`,
		"127.0.0.1:",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("compose missing %q", want)
		}
	}
	// No secret injection: allow comments; forbid env assignment of JENKINS_MCP_AUTH.
	for _, line := range strings.Split(body, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "JENKINS_MCP_AUTH:") || strings.Contains(trim, "JENKINS_MCP_AUTH=") {
			t.Fatalf("compose must not set JENKINS_MCP_AUTH: %s", trim)
		}
	}
}

// Regression: README must document residual knobs and point at live-pin-blockers.
func TestREADME_DocumentsResidualKnobsAndLivePinBlockers(t *testing.T) {
	t.Parallel()
	path := filepath.Join(repoRoot(t), "deploy/local/README.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH",
		"JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH",
		"JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH",
		"JENKINS_MCP_HTTP_JWKS_CACHE_PATH",
		"live-pin-blockers",
		"multi-pod",
		"not live Entra",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("README missing %q", want)
		}
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "residual") {
		t.Fatal("README should note residual honesty for gateway knobs")
	}
}
