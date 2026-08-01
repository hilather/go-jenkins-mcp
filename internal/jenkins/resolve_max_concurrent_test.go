package jenkins_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// Wave 50 Track A: ResolveMaxConcurrent precedence default → env → flag (flag wins).
func TestResolveMaxConcurrent_Precedence(t *testing.T) {
	t.Parallel()

	n, err := jenkins.ResolveMaxConcurrent("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxConcurrent {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultMaxConcurrent)
	}
	if n != 0 {
		t.Fatalf("default must be 0 (unlimited): got %d", n)
	}

	n, err = jenkins.ResolveMaxConcurrent("", "32")
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatalf("env: got %d want 32", n)
	}

	n, err = jenkins.ResolveMaxConcurrent("16", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 16 {
		t.Fatalf("flag: got %d want 16", n)
	}

	// Flag wins over env.
	n, err = jenkins.ResolveMaxConcurrent("8", "64")
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("flag wins: got %d want 8", n)
	}

	// Whitespace treated as unset → default unlimited.
	n, err = jenkins.ResolveMaxConcurrent("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxConcurrent {
		t.Fatalf("whitespace: got %d want default %d", n, jenkins.DefaultMaxConcurrent)
	}
}

// Explicit "0" means unlimited concurrency (0), not default-substitution of a
// positive limit. Empty at all layers also yields 0.
// Contrast MaxRetries where 0 disables GET/HEAD auto-retry.
// Contrast MaxJSONBodyBytes where "0" means default body size.
func TestResolveMaxConcurrent_ZeroMeansUnlimited(t *testing.T) {
	t.Parallel()

	// Flag "0" wins over env and means unlimited (not remapped to a positive default).
	n, err := jenkins.ResolveMaxConcurrent("0", "32")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("flag 0: got %d want 0 (unlimited)", n)
	}

	// Env "0" when flag unset.
	n, err = jenkins.ResolveMaxConcurrent("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("env 0: got %d want 0", n)
	}

	// Empty flag does not override env "0".
	n, err = jenkins.ResolveMaxConcurrent("  ", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("whitespace flag + env 0: got %d want 0", n)
	}

	// Empty both → default 0 unlimited (same numeric value as explicit 0).
	n, err = jenkins.ResolveMaxConcurrent("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("empty both: got %d want 0 (default unlimited)", n)
	}

	// Positive flag over unlimited env.
	n, err = jenkins.ResolveMaxConcurrent("4", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("flag 4 over env 0: got %d want 4", n)
	}
}

func TestResolveMaxConcurrent_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-number"},
		{"bad flag", "2x", ""},
		{"negative env", "", "-1"},
		{"negative flag", "-10", "2"},
		{"float", "", "1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jenkins.ResolveMaxConcurrent(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "concurrent") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 50 Track A: absolute process fail-closed ceiling (AbsoluteMaxConcurrent).
func TestResolveMaxConcurrent_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(jenkins.AbsoluteMaxConcurrent)
	overFlag := strconv.Itoa(jenkins.AbsoluteMaxConcurrent + 1)
	overEnv := strconv.Itoa(jenkins.AbsoluteMaxConcurrent * 2)
	absurd := "10000"

	// At absolute cap: ok.
	n, err := jenkins.ResolveMaxConcurrent(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != jenkins.AbsoluteMaxConcurrent {
		t.Fatalf("at cap: got %d want %d", n, jenkins.AbsoluteMaxConcurrent)
	}
	n, err = jenkins.ResolveMaxConcurrent("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != jenkins.AbsoluteMaxConcurrent {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap (0 unlimited is always ≤ absolute).
	n, err = jenkins.ResolveMaxConcurrent("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxConcurrent {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultMaxConcurrent)
	}
	if n > jenkins.AbsoluteMaxConcurrent {
		t.Fatalf("default %d exceeds absolute max %d", n, jenkins.AbsoluteMaxConcurrent)
	}

	// Flag above cap fails closed.
	_, err = jenkins.ResolveMaxConcurrent(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "concurrent") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention concurrent / maximum / bound: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	// Env above cap fails closed.
	_, err = jenkins.ResolveMaxConcurrent("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd thousands fail closed.
	_, err = jenkins.ResolveMaxConcurrent(absurd, "")
	if err == nil {
		t.Fatal("absurd concurrent must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = jenkins.ResolveMaxConcurrent("16", overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != 16 {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = jenkins.ResolveMaxConcurrent(overFlag, "16")
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
	// Explicit 0 (unlimited) wins over over-cap env.
	n, err = jenkins.ResolveMaxConcurrent("0", overEnv)
	if err != nil {
		t.Fatalf("flag 0 unlimited should win over over-cap env: %v", err)
	}
	if n != 0 {
		t.Fatalf("got %d want 0", n)
	}
}

func TestResolveMaxConcurrent_EnvName(t *testing.T) {
	t.Parallel()
	if jenkins.EnvMaxConcurrent != "JENKINS_MCP_MAX_CONCURRENT" {
		t.Fatalf("env name drift: %q", jenkins.EnvMaxConcurrent)
	}
	if jenkins.AbsoluteMaxConcurrent != 256 {
		t.Fatalf("absolute max drift: %d want 256", jenkins.AbsoluteMaxConcurrent)
	}
	if jenkins.DefaultMaxConcurrent != 0 {
		t.Fatalf("default drift: %d want 0 (unlimited)", jenkins.DefaultMaxConcurrent)
	}
	if jenkins.AbsoluteMaxConcurrent <= 0 {
		t.Fatalf("absolute %d must be positive", jenkins.AbsoluteMaxConcurrent)
	}
	// Absolute is a positive ceiling; default unlimited (0) is always under it.
	if jenkins.DefaultMaxConcurrent > jenkins.AbsoluteMaxConcurrent {
		t.Fatalf("default %d must not exceed absolute %d",
			jenkins.DefaultMaxConcurrent, jenkins.AbsoluteMaxConcurrent)
	}
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.MaxConcurrent != jenkins.DefaultMaxConcurrent {
		t.Fatalf("DefaultResilienceConfig.MaxConcurrent=%d", cfg.MaxConcurrent)
	}
}

// Wave 50 Track A: normalizeResilienceConfig clamps oversize MaxConcurrent
// (defense-in-depth for library callers bypassing ResolveMaxConcurrent).
func TestNormalizeResilienceConfig_MaxConcurrentAbsoluteClamp(t *testing.T) {
	t.Parallel()
	r := jenkins.NewResilience(jenkins.ResilienceConfig{
		MaxConcurrent: jenkins.AbsoluteMaxConcurrent + 50,
	})
	got := r.Config().MaxConcurrent
	if got != jenkins.AbsoluteMaxConcurrent {
		t.Fatalf("oversize clamp: got %d want absolute %d", got, jenkins.AbsoluteMaxConcurrent)
	}
	// At cap preserved.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		MaxConcurrent: jenkins.AbsoluteMaxConcurrent,
	})
	if r.Config().MaxConcurrent != jenkins.AbsoluteMaxConcurrent {
		t.Fatalf("at cap: got %d", r.Config().MaxConcurrent)
	}
	// Explicit 0 preserved (unlimited; not remapped to a positive default).
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxConcurrent: 0})
	if r.Config().MaxConcurrent != 0 {
		t.Fatalf("zero must stay 0 (unlimited): got %d", r.Config().MaxConcurrent)
	}
	// Negative → 0 unlimited.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxConcurrent: -1})
	if r.Config().MaxConcurrent != 0 {
		t.Fatalf("negative → 0 unlimited: got %d", r.Config().MaxConcurrent)
	}
	// Positive under cap preserved; semaphore installed.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxConcurrent: 4})
	if r.Config().MaxConcurrent != 4 {
		t.Fatalf("under cap: got %d want 4", r.Config().MaxConcurrent)
	}
}
