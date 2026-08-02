package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: UPSTREAM-EXIT hard-retire of seed -auth / JENKINS_MCP_AUTH bootstrap.
// Serve must fail closed with migration text and never accept secrets from argv/env.

func TestServeRejectsLegacyAuthFlag(t *testing.T) {
	bin := buildJenkinsMCP(t)
	cmd := exec.Command(bin, "serve", "--url", "http://127.0.0.1:9", "--auth", "user:CANARY_cli_auth_secret_xyz", "--stdio")
	cmd.Env = filterEnv(os.Environ(), "JENKINS_MCP_AUTH")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; out=%s", out)
	}
	s := string(out)
	if strings.Contains(s, "CANARY_cli_auth_secret_xyz") {
		t.Fatalf("must not echo secret: %s", s)
	}
	if !strings.Contains(s, "removed") && !strings.Contains(s, "login --profile") {
		t.Fatalf("want migration message, got: %s", s)
	}
}

func TestServeRejectsLegacyAuthEnv(t *testing.T) {
	bin := buildJenkinsMCP(t)
	cmd := exec.Command(bin, "serve", "--url", "http://127.0.0.1:9", "--stdio")
	env := filterEnv(os.Environ(), "JENKINS_MCP_AUTH")
	env = append(env, "JENKINS_MCP_AUTH=alice:CANARY_env_auth_secret_xyz")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; out=%s", out)
	}
	s := string(out)
	if strings.Contains(s, "CANARY_env_auth_secret_xyz") {
		t.Fatalf("must not echo secret: %s", s)
	}
	if !strings.Contains(s, "removed") && !strings.Contains(s, "login --profile") {
		t.Fatalf("want migration message, got: %s", s)
	}
}

func TestServeRejectsNoProfile(t *testing.T) {
	bin := buildJenkinsMCP(t)
	cmd := exec.Command(bin, "serve", "--url", "http://127.0.0.1:9", "--stdio")
	cmd.Env = filterEnv(os.Environ(), "JENKINS_MCP_AUTH")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; out=%s", out)
	}
	s := string(out)
	if !strings.Contains(s, "profile") {
		t.Fatalf("want profile required, got: %s", s)
	}
}

func TestCLIHelpDoesNotAdvertiseLegacyAuth(t *testing.T) {
	bin := buildJenkinsMCP(t)
	cmd := exec.Command(bin, "help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// help may exit 0 or non-zero depending on wiring
		_ = err
	}
	s := string(out)
	// Must not present as supported serve method.
	if strings.Contains(s, "JENKINS_MCP_AUTH=user:token") {
		t.Fatalf("help still advertises JENKINS_MCP_AUTH bootstrap:\n%s", s)
	}
	if strings.Contains(s, "serve --url URL --auth user:token") {
		t.Fatalf("help still advertises --auth bootstrap:\n%s", s)
	}
}

func buildJenkinsMCP(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "jenkins-mcp")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = filepath.Join(findModuleRoot(t), "cmd", "jenkins-mcp")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func filterEnv(env []string, drop string) []string {
	var out []string
	for _, e := range env {
		key, _, _ := strings.Cut(e, "=")
		if key == drop {
			continue
		}
		out = append(out, e)
	}
	return out
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
