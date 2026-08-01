package telemetry_test

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

func TestResolveLogLevel(t *testing.T) {
	t.Parallel()
	lv, err := telemetry.ResolveLogLevel("", "")
	if err != nil || lv != telemetry.LevelInfo {
		t.Fatalf("default: lv=%v err=%v", lv, err)
	}
	lv, err = telemetry.ResolveLogLevel("debug", "error")
	if err != nil || lv != telemetry.LevelDebug {
		t.Fatalf("flag wins: lv=%v err=%v", lv, err)
	}
	lv, err = telemetry.ResolveLogLevel("", "WARN")
	if err != nil || lv != telemetry.LevelWarn {
		t.Fatalf("env warn: lv=%v err=%v", lv, err)
	}
	lv, err = telemetry.ResolveLogLevel("  ", "error")
	if err != nil || lv != telemetry.LevelError {
		t.Fatalf("flag whitespace falls to env: lv=%v err=%v", lv, err)
	}
	if _, err := telemetry.ResolveLogLevel("trace", ""); err == nil {
		t.Fatal("invalid must fail closed")
	}
	if telemetry.EnvLogLevel != "JENKINS_MCP_LOG_LEVEL" {
		t.Fatalf("env name: %q", telemetry.EnvLogLevel)
	}
}
