package jenkins

import (
	"testing"
)

// Wave 46 / NET-003 conformance:
//   - Hard-assert DefaultMaxJSONBodyBytes 32 MiB
//   - Hard-assert AbsoluteMaxJSONBodyBytes 128 MiB + ResolveMaxJSONBodyBytes

func TestWave46_MaxJSONBodyBytes_Hard(t *testing.T) {
	t.Parallel()
	if DefaultMaxJSONBodyBytes != 32<<20 {
		t.Fatalf("DefaultMaxJSONBodyBytes=%d want 32MiB", DefaultMaxJSONBodyBytes)
	}
	if AbsoluteMaxJSONBodyBytes != 128<<20 {
		t.Fatalf("AbsoluteMaxJSONBodyBytes=%d want 128MiB", AbsoluteMaxJSONBodyBytes)
	}
	if AbsoluteMaxJSONBodyBytes <= DefaultMaxJSONBodyBytes {
		t.Fatalf("absolute %d must exceed default %d", AbsoluteMaxJSONBodyBytes, DefaultMaxJSONBodyBytes)
	}
	if EnvMaxJSONBodyBytes != "JENKINS_MCP_MAX_JSON_BODY_BYTES" {
		t.Fatalf("env name drift: %q", EnvMaxJSONBodyBytes)
	}
	cfg := DefaultResilienceConfig()
	if cfg.MaxJSONBodyBytes != DefaultMaxJSONBodyBytes {
		t.Fatalf("DefaultResilienceConfig body=%d", cfg.MaxJSONBodyBytes)
	}
	if cfg.MaxRetries != DefaultMaxRetries {
		t.Fatalf("DefaultMaxRetries=%d want %d", cfg.MaxRetries, DefaultMaxRetries)
	}
	if cfg.CircuitFailureThreshold != DefaultCircuitFailureThreshold {
		t.Fatalf("circuit threshold=%d want %d", cfg.CircuitFailureThreshold, DefaultCircuitFailureThreshold)
	}

	n, err := ResolveMaxJSONBodyBytes("", "")
	if err != nil || n != DefaultMaxJSONBodyBytes {
		t.Fatalf("default resolve: n=%d err=%v", n, err)
	}
	n, err = ResolveMaxJSONBodyBytes("50331648", "67108864")
	if err != nil || n != 48<<20 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := ResolveMaxJSONBodyBytes("134217729", ""); err == nil { // 128MiB+1
		t.Fatal("above absolute must fail closed")
	}
	if _, err := ResolveMaxJSONBodyBytes("nope", ""); err == nil {
		t.Fatal("invalid must fail closed")
	}
}
