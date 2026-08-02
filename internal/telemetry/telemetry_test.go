package telemetry_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

func TestCounterIncrement(t *testing.T) {
	t.Parallel()
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 1)
	m.Inc(telemetry.MetricToolCalls, 2)
	m.Inc(telemetry.MetricMCPToolDeny, 1)
	m.Inc(telemetry.MetricJenkinsHTTPRequestsTotal, 5)
	m.AddBytes(telemetry.MetricJenkinsHTTPWireBytesTotal, 100)
	m.AddBytes(telemetry.MetricJenkinsHTTPDecodedBytesTotal, 80)
	m.Inc(telemetry.MetricMCPToolOK, 1)
	m.Inc(telemetry.MetricCacheHits, 3)
	// Negative ignored.
	m.Inc(telemetry.MetricToolCalls, -1)

	if got := m.GetCounter(telemetry.MetricToolCalls); got != 3 {
		t.Fatalf("tool_calls=%d", got)
	}
	if got := m.GetCounter(telemetry.MetricPolicyDenials); got != 1 {
		t.Fatalf("mcp_tool_deny/policy_denials alias=%d", got)
	}
	if got := m.GetCounter(telemetry.MetricBytesWire); got != 100 {
		t.Fatalf("wire bytes alias=%d", got)
	}
	if got := m.GetCounter(telemetry.MetricJenkinsHTTPDecodedBytesTotal); got != 80 {
		t.Fatalf("decoded bytes=%d", got)
	}
	if got := m.GetCounter(telemetry.MetricCacheHits); got != 3 {
		t.Fatalf("cache_hits=%d", got)
	}

	snap := m.Snapshot()
	if snap.Counters[telemetry.MetricJenkinsRequests] != 5 {
		t.Fatalf("snapshot jenkins_http_requests_total=%v", snap.Counters)
	}
	// Snapshot is a copy.
	m.Inc(telemetry.MetricToolCalls, 10)
	if snap.Counters[telemetry.MetricToolCalls] != 3 {
		t.Fatalf("snapshot mutated: %d", snap.Counters[telemetry.MetricToolCalls])
	}
}

func TestRegistrySnapshotAndContext(t *testing.T) {
	t.Parallel()
	r := telemetry.NewRegistry()
	r.Inc(telemetry.MetricToolCalls, 1)
	ctx := telemetry.WithRegistry(context.Background(), r)
	got := telemetry.RegistryFromContext(ctx)
	if got == nil || got.Snapshot().Counters[telemetry.MetricToolCalls] != 1 {
		t.Fatalf("ctx registry: %+v", got)
	}
	if telemetry.RegistryFromContext(context.Background()) != nil {
		t.Fatal("expected nil")
	}
}

func TestLoggerRedactsSecrets(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := telemetry.NewLogger(&buf, telemetry.LevelDebug)
	const canary = "super-secret-token-value-OBS001"
	log.Info("auth check", "authorization", "Bearer "+canary, "user", "alice")
	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("secret leaked in log: %s", out)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["level"] != "info" || rec["msg"] != "auth check" {
		t.Fatalf("record=%v", rec)
	}
	if rec["user"] != "alice" {
		t.Fatalf("user field: %v", rec["user"])
	}
	auth, _ := rec["authorization"].(string)
	if !strings.Contains(auth, "[REDACTED]") {
		t.Fatalf("expected redacted authorization: %q", auth)
	}
}

func TestLoggerMinLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := telemetry.NewLogger(&buf, telemetry.LevelWarn)
	log.Info("hidden")
	log.Debug("hidden2")
	log.Warn("visible")
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("info/debug should be filtered")
	}
	if !strings.Contains(buf.String(), "visible") {
		t.Fatal("warn missing")
	}
}

func TestLoggerWithStaticFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := telemetry.NewLogger(&buf, telemetry.LevelInfo).With("component", "serve", "profile", "corp")
	log.Info("starting")
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["component"] != "serve" || rec["profile"] != "corp" {
		t.Fatalf("%v", rec)
	}
}

func TestNilSafeMetrics(t *testing.T) {
	t.Parallel()
	var m *telemetry.Metrics
	m.Inc(telemetry.MetricToolCalls, 1)
	if m.GetCounter(telemetry.MetricToolCalls) != 0 {
		t.Fatal("nil metrics")
	}
	var r *telemetry.Registry
	r.Inc(telemetry.MetricToolCalls, 1)
	_ = r.Snapshot()
	r.Info("noop")
}
