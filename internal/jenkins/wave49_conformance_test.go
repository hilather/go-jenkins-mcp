package jenkins

import (
	"testing"
	"time"
)

// Wave 49 / NET-003 conformance (Track D):
//   - Hard-assert Wave 48 Done* CircuitFailureThreshold resolve (default 5,
//     absolute 50, 0→default, flag wins, fail-closed over absolute)
//   - Soft residual for Wave 49 Track A ResolveCircuitOpenDuration — compile-safe
//     t.Log only (symbol not present on current main; never fail for absence)

// TestWave49_Wave48Done_CircuitFailureThreshold_Hard hard-asserts Wave 48 Track A
// Done*: ResolveCircuitFailureThreshold default 5, absolute 50, explicit 0 →
// default, flag/env precedence, fail-closed above absolute. Also retains Wave 47
// MaxRetries and DefaultCircuitOpenDuration package constant (15s).
func TestWave49_Wave48Done_CircuitFailureThreshold_Hard(t *testing.T) {
	t.Parallel()

	// Wave 47 MaxRetries retention.
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

	// Wave 48 CircuitFailureThreshold resolve.
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
	n, err = ResolveCircuitFailureThreshold("", "12")
	if err != nil || n != 12 {
		t.Fatalf("env only: n=%d err=%v", n, err)
	}
	if _, err := ResolveCircuitFailureThreshold("51", ""); err == nil {
		t.Fatal("above absolute must fail closed")
	}
	if _, err := ResolveCircuitFailureThreshold("-1", ""); err == nil {
		t.Fatal("negative must fail closed")
	}
	if _, err := ResolveCircuitFailureThreshold("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}

	// Package open-duration constant (Wave 48 soft residual hardened as constant;
	// Wave 49 Track A may add ResolveCircuitOpenDuration — not claimed Done* here).
	if DefaultCircuitOpenDuration != 15*time.Second {
		t.Fatalf("DefaultCircuitOpenDuration=%v want 15s", DefaultCircuitOpenDuration)
	}
	cfg := DefaultResilienceConfig()
	if cfg.CircuitFailureThreshold != DefaultCircuitFailureThreshold {
		t.Fatalf("DefaultResilienceConfig.CircuitFailureThreshold=%d", cfg.CircuitFailureThreshold)
	}
	if cfg.CircuitOpenDuration != DefaultCircuitOpenDuration {
		t.Fatalf("DefaultResilienceConfig.CircuitOpenDuration=%v", cfg.CircuitOpenDuration)
	}
}

// TestWave49_SoftResidual_TrackA_ResolveCircuitOpenDuration is a compile-safe soft
// residual note for Wave 49 Track A ResolveCircuitOpenDuration (flag/env absolute
// resolve). Track D never references symbols that may not exist yet; when Track A
// lands, its own hard tests own the resolve contract. Soft residual only — never
// fails for absence.
func TestWave49_SoftResidual_TrackA_ResolveCircuitOpenDuration(t *testing.T) {
	t.Parallel()
	// Hard path above already locks DefaultCircuitOpenDuration = 15s.
	// Planned Track A surface (not claimed Done* by Track D):
	//   ResolveCircuitOpenDuration(flag, env) → duration
	//   AbsoluteMaxCircuitOpenDuration / EnvCircuitOpenDuration / serve flag
	// Soft residual: t.Log only so this package compiles and passes without A.
	t.Logf("Wave 49 soft residual Track A: ResolveCircuitOpenDuration planned "+
		"(DefaultCircuitOpenDuration=%s hard-asserted; Track A not claimed Done* by Track D; not a failure)",
		DefaultCircuitOpenDuration)
}
