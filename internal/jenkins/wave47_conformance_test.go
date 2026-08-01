package jenkins

import (
	"testing"
)

// Wave 47 / NET-003 conformance: MaxJSON Wave 46 + MaxRetries Wave 47.

func TestWave47_MaxJSONAndMaxRetries_Hard(t *testing.T) {
	t.Parallel()
	if DefaultMaxJSONBodyBytes != 32<<20 {
		t.Fatalf("DefaultMaxJSONBodyBytes=%d", DefaultMaxJSONBodyBytes)
	}
	if AbsoluteMaxJSONBodyBytes != 128<<20 {
		t.Fatalf("AbsoluteMaxJSONBodyBytes=%d", AbsoluteMaxJSONBodyBytes)
	}
	n, err := ResolveMaxJSONBodyBytes("", "")
	if err != nil || n != DefaultMaxJSONBodyBytes {
		t.Fatalf("json resolve default: n=%d err=%v", n, err)
	}

	if DefaultMaxRetries != 2 {
		t.Fatalf("DefaultMaxRetries=%d", DefaultMaxRetries)
	}
	if AbsoluteMaxRetries != 10 {
		t.Fatalf("AbsoluteMaxRetries=%d", AbsoluteMaxRetries)
	}
	if EnvMaxRetries != "JENKINS_MCP_MAX_RETRIES" {
		t.Fatalf("env name: %q", EnvMaxRetries)
	}
	r, err := ResolveMaxRetries("", "")
	if err != nil || r != DefaultMaxRetries {
		t.Fatalf("retries default: n=%d err=%v", r, err)
	}
	r, err = ResolveMaxRetries("0", "5")
	if err != nil || r != 0 {
		t.Fatalf("explicit 0: n=%d err=%v", r, err)
	}
	if _, err := ResolveMaxRetries("11", ""); err == nil {
		t.Fatal("above AbsoluteMaxRetries must fail closed")
	}
	if IsIdempotentRetryMethod("POST") {
		t.Fatal("POST must never be auto-retry eligible")
	}
}
