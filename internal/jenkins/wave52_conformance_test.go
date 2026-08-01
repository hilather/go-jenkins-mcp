package jenkins

import (
	"testing"
	"time"
)

// Wave 52 / NET-003 + MUT-001 conformance (Track D):
//   - Hard-assert Wave 50 Done* MaxConcurrent resolve (default 0 unlimited;
//     absolute 256 fail-closed) + open-duration / backoff constant retention
//   - Hard-assert Wave 51 Done* ResolveInitialBackoff + ResolveMaxBackoff
//     (defaults/min/abs/EnsureMaxBackoffAtLeastInitial)
//   - Soft residual notes for Wave 52 mutation operator resolve (Tracks A/C live
//     in mutation package; Track B operator_caps min/abs backoff in tools/
//     diagnostics) — never fail for absence

// TestWave52_Wave50Done_MaxConcurrentResolve_Hard hard-asserts Wave 50 Track A
// Done*: ResolveMaxConcurrent default 0 unlimited, absolute 256, flag wins,
// fail-closed above absolute; plus DefaultInitialBackoff / DefaultMaxBackoff
// package constants. Must remain true after Wave 52 parallel tracks merge.
func TestWave52_Wave50Done_MaxConcurrentResolve_Hard(t *testing.T) {
	t.Parallel()

	// Wave 49 open-duration retention (used with concurrent resolve at serve).
	d, err := ResolveCircuitOpenDuration("", "")
	if err != nil || d != DefaultCircuitOpenDuration {
		t.Fatalf("open default: d=%v err=%v", d, err)
	}

	if DefaultMaxConcurrent != 0 {
		t.Fatalf("DefaultMaxConcurrent=%d want 0 unlimited", DefaultMaxConcurrent)
	}
	if AbsoluteMaxConcurrent != 256 {
		t.Fatalf("AbsoluteMaxConcurrent=%d want 256", AbsoluteMaxConcurrent)
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
	n, err = ResolveMaxConcurrent("", "64")
	if err != nil || n != 64 {
		t.Fatalf("env only: n=%d err=%v", n, err)
	}
	n, err = ResolveMaxConcurrent("256", "")
	if err != nil || n != AbsoluteMaxConcurrent {
		t.Fatalf("at absolute: n=%d err=%v want %d", n, err, AbsoluteMaxConcurrent)
	}
	if _, err := ResolveMaxConcurrent("257", ""); err == nil {
		t.Fatal("above absolute must fail closed")
	}
	if _, err := ResolveMaxConcurrent("-1", ""); err == nil {
		t.Fatal("negative must fail closed")
	}
	if _, err := ResolveMaxConcurrent("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}

	// Wave 50 Track B package constants (operator_caps honesty source).
	if DefaultInitialBackoff != 100*time.Millisecond {
		t.Fatalf("DefaultInitialBackoff=%v want 100ms", DefaultInitialBackoff)
	}
	if DefaultMaxBackoff != 5*time.Second {
		t.Fatalf("DefaultMaxBackoff=%v want 5s", DefaultMaxBackoff)
	}
	if DefaultMaxBackoff < DefaultInitialBackoff {
		t.Fatalf("DefaultMaxBackoff %v < DefaultInitialBackoff %v",
			DefaultMaxBackoff, DefaultInitialBackoff)
	}
}

// TestWave52_Wave51Done_BackoffResolve_Hard hard-asserts Wave 51 Track A Done*:
// ResolveInitialBackoff + ResolveMaxBackoff operator paths (defaults, flag wins,
// min/absolute fail-closed, EnsureMaxBackoffAtLeastInitial ordering).
func TestWave52_Wave51Done_BackoffResolve_Hard(t *testing.T) {
	t.Parallel()

	if MinInitialBackoff != 10*time.Millisecond {
		t.Fatalf("MinInitialBackoff=%v want 10ms", MinInitialBackoff)
	}
	if AbsoluteMaxInitialBackoff != 2*time.Second {
		t.Fatalf("AbsoluteMaxInitialBackoff=%v want 2s", AbsoluteMaxInitialBackoff)
	}
	if EnvInitialBackoff != "JENKINS_MCP_INITIAL_BACKOFF" {
		t.Fatalf("env initial: %q", EnvInitialBackoff)
	}
	if MinMaxBackoff != 100*time.Millisecond {
		t.Fatalf("MinMaxBackoff=%v want 100ms", MinMaxBackoff)
	}
	if AbsoluteMaxMaxBackoff != time.Minute {
		t.Fatalf("AbsoluteMaxMaxBackoff=%v want 1m", AbsoluteMaxMaxBackoff)
	}
	if EnvMaxBackoff != "JENKINS_MCP_MAX_BACKOFF" {
		t.Fatalf("env max: %q", EnvMaxBackoff)
	}

	d, err := ResolveInitialBackoff("", "")
	if err != nil || d != DefaultInitialBackoff {
		t.Fatalf("initial default: d=%v err=%v", d, err)
	}
	d, err = ResolveInitialBackoff("0", "250ms")
	if err != nil || d != DefaultInitialBackoff {
		t.Fatalf("initial 0→default: d=%v err=%v", d, err)
	}
	d, err = ResolveInitialBackoff("500ms", "1s")
	if err != nil || d != 500*time.Millisecond {
		t.Fatalf("initial flag wins: d=%v err=%v", d, err)
	}
	if _, err := ResolveInitialBackoff("1ms", ""); err == nil {
		t.Fatal("initial below min must fail closed")
	}
	if _, err := ResolveInitialBackoff("3s", ""); err == nil {
		t.Fatal("initial above absolute must fail closed")
	}

	d, err = ResolveMaxBackoff("", "")
	if err != nil || d != DefaultMaxBackoff {
		t.Fatalf("max default: d=%v err=%v", d, err)
	}
	d, err = ResolveMaxBackoff("0", "10s")
	if err != nil || d != DefaultMaxBackoff {
		t.Fatalf("max 0→default: d=%v err=%v", d, err)
	}
	d, err = ResolveMaxBackoff("15s", "30s")
	if err != nil || d != 15*time.Second {
		t.Fatalf("max flag wins: d=%v err=%v", d, err)
	}
	if _, err := ResolveMaxBackoff("50ms", ""); err == nil {
		t.Fatal("max below min must fail closed")
	}
	if _, err := ResolveMaxBackoff("2m", ""); err == nil {
		t.Fatal("max above absolute must fail closed")
	}

	if err := EnsureMaxBackoffAtLeastInitial(DefaultInitialBackoff, DefaultMaxBackoff); err != nil {
		t.Fatalf("default ordering: %v", err)
	}
	if err := EnsureMaxBackoffAtLeastInitial(2*time.Second, 500*time.Millisecond); err == nil {
		t.Fatal("max < initial must fail closed")
	}
}

// TestWave52_SoftResidual_TrackA_C_MutationOperatorResolveNote is a compile-safe
// soft residual note for Wave 52 Tracks A/C mutation operator resolve
// (ResolveConfirmCooldown / ResolveMaxPreviewsPerMinute). Those symbols live in
// the mutation package when landed; Track D never references them here so this
// package compiles and passes without A/C. Soft residual only — never fails for
// absence.
func TestWave52_SoftResidual_TrackA_C_MutationOperatorResolveNote(t *testing.T) {
	t.Parallel()
	// Hard paths above lock Wave 50 MaxConcurrent + Wave 51 backoff resolve.
	// Planned Wave 52 surfaces (not claimed Done* by Track D):
	//   mutation.ResolveConfirmCooldown / EnvConfirmCooldown (Track A)
	//   mutation.ResolveMaxPreviewsPerMinute (Track C)
	//   operator_caps min/abs backoff ms keys (Track B; tools/diagnostics)
	t.Logf("Wave 52 soft residual (jenkins): MaxConcurrent + backoff resolve hard-asserted; "+
		"Track A ResolveConfirmCooldown / Track C ResolveMaxPreviewsPerMinute / "+
		"Track B operator_caps min/abs backoff ms are mutation/tools residuals "+
		"(not claimed Done* by Track D; not a failure); MinInitialBackoff=%s AbsoluteMaxInitialBackoff=%s",
		MinInitialBackoff, AbsoluteMaxInitialBackoff)
}
