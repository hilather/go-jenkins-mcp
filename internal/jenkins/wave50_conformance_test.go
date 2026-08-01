package jenkins

import (
	"testing"
	"time"
)

// Wave 50 / NET-003: CircuitOpenDuration Wave 49 + MaxConcurrent Wave 50.

func TestWave50_MaxConcurrentAndOpenDuration_Hard(t *testing.T) {
	t.Parallel()
	d, err := ResolveCircuitOpenDuration("", "")
	if err != nil || d != DefaultCircuitOpenDuration {
		t.Fatalf("open default: d=%v err=%v", d, err)
	}

	if DefaultMaxConcurrent != 0 {
		t.Fatalf("DefaultMaxConcurrent=%d want 0 unlimited", DefaultMaxConcurrent)
	}
	if AbsoluteMaxConcurrent != 256 {
		t.Fatalf("AbsoluteMaxConcurrent=%d", AbsoluteMaxConcurrent)
	}
	if EnvMaxConcurrent != "JENKINS_MCP_MAX_CONCURRENT" {
		t.Fatalf("env name: %q", EnvMaxConcurrent)
	}
	n, err := ResolveMaxConcurrent("", "")
	if err != nil || n != 0 {
		t.Fatalf("default unlimited: n=%d err=%v", n, err)
	}
	n, err = ResolveMaxConcurrent("0", "16")
	if err != nil || n != 0 {
		t.Fatalf("flag 0 unlimited: n=%d err=%v", n, err)
	}
	n, err = ResolveMaxConcurrent("32", "8")
	if err != nil || n != 32 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := ResolveMaxConcurrent("257", ""); err == nil {
		t.Fatal("above absolute must fail closed")
	}
	if DefaultInitialBackoff != 100*time.Millisecond {
		t.Fatalf("DefaultInitialBackoff=%v", DefaultInitialBackoff)
	}
	if DefaultMaxBackoff != 5*time.Second {
		t.Fatalf("DefaultMaxBackoff=%v", DefaultMaxBackoff)
	}
}
