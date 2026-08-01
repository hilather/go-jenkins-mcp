// Package gateway_deploy tests GWY-004 packaging residual honesty for deploy/gateway.
// File-level checks only — no Docker required (offline CI gate).
package gateway_deploy_test

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
	// deploy/gateway/env_example_test.go → repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

// Regression: GWY-004 .env.example must list multi-user, JWKS max stale, path
// prefix, REQUIRE_SIGNED_POLICY, and subject rate envs (non-secret only).
func TestEnvExample_ListsGatewayLabFlags(t *testing.T) {
	t.Parallel()
	path := filepath.Join(repoRoot(t), "deploy/gateway/.env.example")
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
		"JENKINS_MCP_HTTP_JWKS_MAX_STALE",
		"JENKINS_MCP_HTTP_PATH_PREFIX",
		"JENKINS_MCP_REQUIRE_SIGNED_POLICY",
		"JENKINS_MCP_SUBJECT_MAX_CONCURRENT",
		"JENKINS_MCP_SUBJECT_PROCESS_MAX_CONCURRENT",
		"JENKINS_MCP_SUBJECT_RATE_PER_MINUTE",
		"JENKINS_MCP_SUBJECT_RATE_BURST",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing env name %s in .env.example", want)
		}
	}
	// Honesty: multi-user is foundation residual, not production GO.
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "residual") && !strings.Contains(lower, "not production") {
		t.Fatal(".env.example should note multi-user residual honesty")
	}
}

// Regression: compose + Dockerfile keep non-root + health probe posture.
func TestCompose_NonRootAndHealth(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	composePath := filepath.Join(root, "deploy/gateway/docker-compose.yml")
	raw, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		`user: "65532:65532"`,
		"read_only: true",
		"no-new-privileges",
		"healthcheck:",
		"JENKINS_MCP_GATEWAY_MULTI_USER",
		"JENKINS_MCP_HTTP_JWKS_MAX_STALE",
		"JENKINS_MCP_HTTP_PATH_PREFIX",
		"JENKINS_MCP_REQUIRE_SIGNED_POLICY",
		"JENKINS_MCP_SUBJECT_MAX_CONCURRENT",
		"JENKINS_MCP_SUBJECT_RATE_PER_MINUTE",
		"JENKINS_MCP_SUBJECT_RATE_BURST",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("compose missing %q", want)
		}
	}
	// No secret injection: allow "never ... JENKINS_MCP_AUTH" comments; forbid env assignment.
	for _, line := range strings.Split(body, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "JENKINS_MCP_AUTH:") || strings.Contains(trim, "JENKINS_MCP_AUTH=") {
			t.Fatalf("compose must not set JENKINS_MCP_AUTH: %s", trim)
		}
	}

	dfPath := filepath.Join(root, "deploy/gateway/Dockerfile")
	df, err := os.ReadFile(dfPath)
	if err != nil {
		t.Fatal(err)
	}
	dfBody := string(df)
	if !strings.Contains(dfBody, "nonroot") {
		t.Fatal("Dockerfile must use distroless nonroot")
	}
	if !strings.Contains(dfBody, "USER nonroot") {
		t.Fatal("Dockerfile must set USER nonroot")
	}
}

// Regression: kustomize stays single-replica with HTTP probes (HOST-008 honesty).
func TestKustomize_SingleReplicaProbes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(repoRoot(t), "deploy/gateway/kustomize/deployment.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, "replicas: 1") {
		t.Fatal("must keep replicas: 1 (HOST-008 Tier A)")
	}
	if !strings.Contains(body, "runAsNonRoot: true") {
		t.Fatal("must runAsNonRoot")
	}
	if !strings.Contains(body, "path: /healthz") || !strings.Contains(body, "path: /readyz") {
		t.Fatal("must have /healthz and /readyz probes")
	}
	if !strings.Contains(body, "JENKINS_MCP_GATEWAY_MULTI_USER") {
		t.Fatal("kustomize should document MULTI_USER lab flag (commented ok)")
	}
}
