package jenkins_test

import (
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// Wave 51 Track A: ResolveInitialBackoff precedence default → env → flag.
func TestResolveInitialBackoff_Precedence(t *testing.T) {
	t.Parallel()

	d, err := jenkins.ResolveInitialBackoff("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("default: got %v want %v", d, jenkins.DefaultInitialBackoff)
	}

	d, err = jenkins.ResolveInitialBackoff("", "250ms")
	if err != nil {
		t.Fatal(err)
	}
	if d != 250*time.Millisecond {
		t.Fatalf("env: got %v want 250ms", d)
	}

	d, err = jenkins.ResolveInitialBackoff("500ms", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != 500*time.Millisecond {
		t.Fatalf("flag: got %v want 500ms", d)
	}

	// Flag wins over env.
	d, err = jenkins.ResolveInitialBackoff("200ms", "1s")
	if err != nil {
		t.Fatal(err)
	}
	if d != 200*time.Millisecond {
		t.Fatalf("flag wins: got %v want 200ms", d)
	}

	// Whitespace treated as unset.
	d, err = jenkins.ResolveInitialBackoff("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("whitespace: got %v", d)
	}

	// Second form accepted.
	d, err = jenkins.ResolveInitialBackoff("1s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != time.Second {
		t.Fatalf("1s: got %v", d)
	}
}

// Explicit "0" / "0s" means default (cannot disable base delay by 0 — fail-closed).
func TestResolveInitialBackoff_ZeroMeansDefault(t *testing.T) {
	t.Parallel()

	d, err := jenkins.ResolveInitialBackoff("0", "250ms")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("flag 0: got %v want default %v", d, jenkins.DefaultInitialBackoff)
	}

	d, err = jenkins.ResolveInitialBackoff("0s", "250ms")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("flag 0s: got %v want default %v", d, jenkins.DefaultInitialBackoff)
	}

	d, err = jenkins.ResolveInitialBackoff("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("env 0: got %v want default %v", d, jenkins.DefaultInitialBackoff)
	}

	d, err = jenkins.ResolveInitialBackoff("", "0s")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("env 0s: got %v want default %v", d, jenkins.DefaultInitialBackoff)
	}

	d, err = jenkins.ResolveInitialBackoff("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("empty both: got %v want default %v", d, jenkins.DefaultInitialBackoff)
	}
}

func TestResolveInitialBackoff_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-duration"},
		{"bad flag", "2x", ""},
		{"negative env", "", "-1ms"},
		{"negative flag", "-10ms", "100ms"},
		{"bare number", "", "100"},
		{"below min flag", "1ms", ""},
		{"below min env", "", "5ms"},
		{"above max flag", "3s", ""},
		{"above max env", "", "10s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jenkins.ResolveInitialBackoff(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "initial") && !strings.Contains(msg, "invalid") && !strings.Contains(msg, "backoff") {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 51 Track A: absolute process fail-closed ceiling + min floor.
func TestResolveInitialBackoff_Bounds(t *testing.T) {
	t.Parallel()
	minStr := jenkins.MinInitialBackoff.String()
	capStr := jenkins.AbsoluteMaxInitialBackoff.String()
	overFlag := (jenkins.AbsoluteMaxInitialBackoff + time.Millisecond).String()
	overEnv := (jenkins.AbsoluteMaxInitialBackoff * 2).String()
	belowMin := (jenkins.MinInitialBackoff - time.Millisecond).String()

	d, err := jenkins.ResolveInitialBackoff(minStr, "")
	if err != nil {
		t.Fatalf("at min flag: %v", err)
	}
	if d != jenkins.MinInitialBackoff {
		t.Fatalf("at min: got %v want %v", d, jenkins.MinInitialBackoff)
	}
	d, err = jenkins.ResolveInitialBackoff("", minStr)
	if err != nil {
		t.Fatalf("at min env: %v", err)
	}
	if d != jenkins.MinInitialBackoff {
		t.Fatalf("at min env: got %v", d)
	}

	d, err = jenkins.ResolveInitialBackoff(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if d != jenkins.AbsoluteMaxInitialBackoff {
		t.Fatalf("at cap: got %v want %v", d, jenkins.AbsoluteMaxInitialBackoff)
	}
	d, err = jenkins.ResolveInitialBackoff("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if d != jenkins.AbsoluteMaxInitialBackoff {
		t.Fatalf("at cap env: got %v", d)
	}

	d, err = jenkins.ResolveInitialBackoff("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("default: got %v want %v", d, jenkins.DefaultInitialBackoff)
	}
	if d < jenkins.MinInitialBackoff || d > jenkins.AbsoluteMaxInitialBackoff {
		t.Fatalf("default %v outside [%v, %v]", d, jenkins.MinInitialBackoff, jenkins.AbsoluteMaxInitialBackoff)
	}

	_, err = jenkins.ResolveInitialBackoff(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "initial") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention initial / maximum / bound: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	_, err = jenkins.ResolveInitialBackoff("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	_, err = jenkins.ResolveInitialBackoff(belowMin, "")
	if err == nil {
		t.Fatal("flag below min must fail closed")
	}
	msg = strings.ToLower(err.Error())
	if !strings.Contains(msg, "minimum") && !strings.Contains(msg, "below") {
		t.Fatalf("below-min error should mention minimum: %v", err)
	}

	d, err = jenkins.ResolveInitialBackoff(jenkins.DefaultInitialBackoff.String(), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if d != jenkins.DefaultInitialBackoff {
		t.Fatalf("got %v", d)
	}
	_, err = jenkins.ResolveInitialBackoff(overFlag, jenkins.DefaultInitialBackoff.String())
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveInitialBackoff_EnvName(t *testing.T) {
	t.Parallel()
	if jenkins.EnvInitialBackoff != "JENKINS_MCP_INITIAL_BACKOFF" {
		t.Fatalf("env name drift: %q", jenkins.EnvInitialBackoff)
	}
	if jenkins.MinInitialBackoff != 10*time.Millisecond {
		t.Fatalf("min drift: %v want 10ms", jenkins.MinInitialBackoff)
	}
	if jenkins.AbsoluteMaxInitialBackoff != 2*time.Second {
		t.Fatalf("absolute max drift: %v want 2s", jenkins.AbsoluteMaxInitialBackoff)
	}
	if jenkins.DefaultInitialBackoff != 100*time.Millisecond {
		t.Fatalf("default drift: %v want 100ms", jenkins.DefaultInitialBackoff)
	}
	if jenkins.MinInitialBackoff > jenkins.DefaultInitialBackoff {
		t.Fatalf("min %v must not exceed default %v",
			jenkins.MinInitialBackoff, jenkins.DefaultInitialBackoff)
	}
	if jenkins.AbsoluteMaxInitialBackoff <= jenkins.DefaultInitialBackoff {
		t.Fatalf("absolute %v must exceed default %v",
			jenkins.AbsoluteMaxInitialBackoff, jenkins.DefaultInitialBackoff)
	}
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.InitialBackoff != jenkins.DefaultInitialBackoff {
		t.Fatalf("DefaultResilienceConfig.InitialBackoff=%v", cfg.InitialBackoff)
	}
}

// Wave 51 Track A: normalizeResilienceConfig clamps InitialBackoff to
// [Min, AbsoluteMax] (defense-in-depth for library callers bypassing Resolve).
func TestNormalizeResilienceConfig_InitialBackoffClamp(t *testing.T) {
	t.Parallel()
	r := jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.AbsoluteMaxInitialBackoff + time.Second,
		MaxBackoff:     jenkins.AbsoluteMaxMaxBackoff,
	})
	got := r.Config().InitialBackoff
	if got != jenkins.AbsoluteMaxInitialBackoff {
		t.Fatalf("oversize clamp: got %v want absolute %v", got, jenkins.AbsoluteMaxInitialBackoff)
	}
	// Below min clamps up.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.MinInitialBackoff / 2,
		MaxBackoff:     jenkins.DefaultMaxBackoff,
	})
	if r.Config().InitialBackoff != jenkins.MinInitialBackoff {
		t.Fatalf("below min clamp: got %v want min %v", r.Config().InitialBackoff, jenkins.MinInitialBackoff)
	}
	// At min/max preserved.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.MinInitialBackoff,
		MaxBackoff:     jenkins.DefaultMaxBackoff,
	})
	if r.Config().InitialBackoff != jenkins.MinInitialBackoff {
		t.Fatalf("at min: got %v", r.Config().InitialBackoff)
	}
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.AbsoluteMaxInitialBackoff,
		MaxBackoff:     jenkins.DefaultMaxBackoff,
	})
	if r.Config().InitialBackoff != jenkins.AbsoluteMaxInitialBackoff {
		t.Fatalf("at cap: got %v", r.Config().InitialBackoff)
	}
	// Explicit 0 → default (cannot disable).
	r = jenkins.NewResilience(jenkins.ResilienceConfig{InitialBackoff: 0})
	if r.Config().InitialBackoff != jenkins.DefaultInitialBackoff {
		t.Fatalf("zero → default: got %v", r.Config().InitialBackoff)
	}
	// Negative → default.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{InitialBackoff: -time.Millisecond})
	if r.Config().InitialBackoff != jenkins.DefaultInitialBackoff {
		t.Fatalf("negative → default: got %v", r.Config().InitialBackoff)
	}
}
