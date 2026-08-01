package jenkins

import (
	"testing"
	"time"
)

// Wave 48 / NET-003: MaxRetries Wave 47 + CircuitFailureThreshold Wave 48.

func TestWave48_MaxRetriesAndCircuitThreshold_Hard(t *testing.T) {
	t.Parallel()
	if DefaultMaxRetries != 2 || AbsoluteMaxRetries != 10 {
		t.Fatalf("retries defaults %d / abs %d", DefaultMaxRetries, AbsoluteMaxRetries)
	}
	r, err := ResolveMaxRetries("0", "5")
	if err != nil || r != 0 {
		t.Fatalf("retries 0: n=%d err=%v", r, err)
	}
	if IsIdempotentRetryMethod("POST") {
		t.Fatal("POST must never auto-retry")
	}

	if DefaultCircuitFailureThreshold != 5 {
		t.Fatalf("DefaultCircuitFailureThreshold=%d", DefaultCircuitFailureThreshold)
	}
	if AbsoluteMaxCircuitFailureThreshold != 50 {
		t.Fatalf("AbsoluteMaxCircuitFailureThreshold=%d", AbsoluteMaxCircuitFailureThreshold)
	}
	if EnvCircuitFailureThreshold != "JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD" {
		t.Fatalf("env name: %q", EnvCircuitFailureThreshold)
	}
	n, err := ResolveCircuitFailureThreshold("", "")
	if err != nil || n != DefaultCircuitFailureThreshold {
		t.Fatalf("circuit default: n=%d err=%v", n, err)
	}
	n, err = ResolveCircuitFailureThreshold("0", "10")
	if err != nil || n != DefaultCircuitFailureThreshold {
		t.Fatalf("circuit 0→default: n=%d err=%v", n, err)
	}
	n, err = ResolveCircuitFailureThreshold("8", "3")
	if err != nil || n != 8 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := ResolveCircuitFailureThreshold("51", ""); err == nil {
		t.Fatal("above absolute must fail closed")
	}
	if DefaultCircuitOpenDuration != 15*time.Second {
		t.Fatalf("DefaultCircuitOpenDuration=%v want 15s", DefaultCircuitOpenDuration)
	}
}
