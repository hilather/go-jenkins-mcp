package telemetry_test

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

func TestSafeServeLogRedactsBearer(t *testing.T) {
	// Exercise format→redact without mutating package log.SetOutput (parallel-safe).
	const canary = "kd004-safe-serve-log-canary-token-ZZZ"
	// Username before Authorization so header redaction cannot eat it.
	msg := fmt.Sprintf("user=%s gateway auth Authorization: Bearer %s", "alice", canary)
	out := redact.RedactText(msg)
	if strings.Contains(out, canary) {
		t.Fatalf("canary leaked via redact path used by SafeServeLog: %q", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("username should remain: %q", out)
	}
	if !strings.Contains(out, redact.Replacement) {
		t.Fatalf("expected redaction marker: %q", out)
	}
	// Also smoke-call SafeServeLog (writes package log; no canary in args that
	// would matter if another test races on stderr).
	telemetry.SafeServeLog("user=%s gateway status ok", "alice")
}

func TestLogPrintfThroughRedactingWriter(t *testing.T) {
	// Serve path unit test: local log.Logger with redact.NewWriter (same as
	// log.SetOutput(redact.NewWriter(os.Stderr)) in runServe) — no global mutation.
	var buf bytes.Buffer
	lg := log.New(redact.NewWriter(&buf), "", 0)

	const canary = "kd004-log-printf-canary-token-must-absent"
	lg.Printf("Using Jenkins auth for user: %s", "bob")
	lg.Printf("misconfigured debug Authorization: Bearer %s", canary)
	lg.Printf("api_token=%s should not leak", canary)

	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("Regression KD-004: token canary present in log output: %q", out)
	}
	if !strings.Contains(out, "bob") {
		t.Fatalf("username missing: %q", out)
	}
	if !strings.Contains(out, "Using Jenkins auth for user") {
		t.Fatalf("expected auth startup line: %q", out)
	}
}
