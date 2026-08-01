package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry/fleet"
)

func TestTelemetryStatusDisabledByDefault(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv(fleet.EnvTelemetry, "")
	t.Setenv(fleet.EnvTelemetryURL, "")

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runTelemetry([]string{"status"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(stdout, "enabled:               false") {
		t.Fatalf("expected disabled status, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "categories_exported:") {
		t.Fatal("expected categories for operator inspection")
	}
	if !strings.Contains(stdout, "tokens") || !strings.Contains(stdout, "logs") {
		t.Fatalf("forbidden categories missing:\n%s", stdout)
	}
}

func TestTelemetryStatusJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv(fleet.EnvTelemetry, "1")
	t.Setenv(fleet.EnvTelemetryURL, "https://user:s3cret@telemetry.example/v1")

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runTelemetry([]string{"status", "--json"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	var st fleet.Status
	if err := json.Unmarshal([]byte(stdout), &st); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	if !st.Enabled {
		t.Fatal("expected enabled")
	}
	if !st.ExportURLConfigured {
		t.Fatal("url configured")
	}
	if strings.Contains(stdout, "s3cret") || strings.Contains(stdout, "user:") {
		t.Fatalf("credential leaked in status: %s", stdout)
	}
	if st.ExportURLHost != "telemetry.example" {
		t.Fatalf("host=%q", st.ExportURLHost)
	}
	if strings.Contains(st.Residual, "local queue only") {
		t.Fatalf("local-queue residual should be absent when URL set: %q", st.Residual)
	}
}

func TestTelemetryStatusLocalQueueOnlyResidual(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv(fleet.EnvTelemetry, "1")
	t.Setenv(fleet.EnvTelemetryURL, "")

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runTelemetry([]string{"status"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(stdout, "enabled:               true") {
		t.Fatalf("expected enabled:\n%s", stdout)
	}
	if !strings.Contains(stdout, "local queue only") {
		t.Fatalf("expected local-queue residual note:\n%s", stdout)
	}
	if !strings.Contains(stdout, "privacy review") {
		t.Fatalf("expected operator privacy residual:\n%s", stdout)
	}
}

func TestTelemetryShowLastSnapshot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	fleet.ResetInstallIDCache()

	paths, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	q, err := fleet.NewQueueFromPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	const canary = "CANARY_TOKEN_telemetry_show_must_not_echo"
	ev := fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-0000000000aa",
		Version:        "show-test",
		AuthMethod:     "oidc_bearer",
		Counters: map[string]int64{
			telemetry.MetricToolCalls:     4,
			telemetry.MetricPolicyDenials: 1,
			"secret:" + canary:            99,
		},
	})
	if !q.Enqueue(ev) {
		t.Fatal("enqueue")
	}

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runTelemetry([]string{"show", "--json"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	if strings.Contains(stdout, canary) {
		t.Fatal("canary leaked in show output")
	}
	var got fleet.Event
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if got.Counters[telemetry.MetricToolCalls] != 4 {
		t.Fatalf("counters: %+v", got.Counters)
	}
	if _, ok := got.Counters["secret:"+canary]; ok {
		t.Fatal("secret counter in show")
	}
	if got.AuthMethod != fleet.AuthMethodOIDCBearer {
		t.Fatalf("auth=%q", got.AuthMethod)
	}
}

func TestTelemetryShowMissing(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))

	err := runTelemetry([]string{"show"})
	if err == nil {
		t.Fatal("expected not found")
	}
	if !strings.Contains(err.Error(), "no telemetry snapshot") {
		t.Fatalf("err=%v", err)
	}
}

func TestTelemetryUnknownSubcommand(t *testing.T) {
	err := runTelemetry([]string{"export-all"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("err=%v", err)
	}
}
