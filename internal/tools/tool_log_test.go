package tools

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

func TestLogToolError_SecretFreeModelMessage(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	lg := telemetry.NewLogger(&buf, telemetry.LevelDebug)
	st := regState{logger: lg}
	// Deliberately secret-shaped message — ModelMessage/redact must scrub.
	err := apperr.New(apperr.CodeUpstreamProtocol, "upstream failed Authorization: Bearer supersecrettokenvalue0001")
	logToolError(st, "tool_dispatch_error", err,
		"tool", "jenkins_get_build",
		"effect", "read",
		"phase", "handler",
		"duration_ms", "12",
	)
	out := buf.String()
	if out == "" {
		t.Fatal("expected structured log line")
	}
	if strings.Contains(out, "supersecrettokenvalue0001") || strings.Contains(strings.ToLower(out), "bearer super") {
		t.Fatalf("secret leaked in tool log: %s", out)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatalf("json: %v line=%q", err, out)
	}
	if rec["level"] != "error" || rec["msg"] != "tool_dispatch_error" {
		t.Fatalf("record: %+v", rec)
	}
	if rec["tool"] != "jenkins_get_build" || rec["error_code"] == "" {
		t.Fatalf("missing tool/code: %+v", rec)
	}
}

func TestLogToolDebug_RespectsMinLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	lg := telemetry.NewLogger(&buf, telemetry.LevelInfo)
	st := regState{logger: lg}
	logToolDebug(st, "tool_dispatch_start", "tool", "x", "effect", "read")
	if buf.Len() != 0 {
		t.Fatalf("debug must be suppressed at info: %q", buf.String())
	}
	logToolWarn(st, "tool_dispatch_deny", "tool", "x", "reason", "read_only", "duration_ms", "1")
	if !strings.Contains(buf.String(), "tool_dispatch_deny") {
		t.Fatalf("warn missing: %q", buf.String())
	}
}

func TestDurationMS(t *testing.T) {
	t.Parallel()
	start := time.Now().Add(-50 * time.Millisecond)
	s := durationMS(start)
	if s == "" || s[0] == '-' {
		t.Fatalf("duration_ms=%q", s)
	}
}

func TestEmitToolDeny_LogsWarn(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	lg := telemetry.NewLogger(&buf, telemetry.LevelDebug)
	st := regState{logger: lg}
	emitToolDeny(t.Context(), st, "jenkins_start_job", "mutate", "read_only", time.Now())
	if !strings.Contains(buf.String(), `"msg":"tool_dispatch_deny"`) {
		t.Fatalf("deny log missing: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "read_only") {
		t.Fatalf("reason missing: %q", buf.String())
	}
}
