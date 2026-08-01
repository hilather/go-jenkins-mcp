package jenkins_test

import (
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// Wave 51 Track A: ResolveMaxBackoff precedence default → env → flag.
func TestResolveMaxBackoff_Precedence(t *testing.T) {
	t.Parallel()

	d, err := jenkins.ResolveMaxBackoff("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("default: got %v want %v", d, jenkins.DefaultMaxBackoff)
	}

	d, err = jenkins.ResolveMaxBackoff("", "10s")
	if err != nil {
		t.Fatal(err)
	}
	if d != 10*time.Second {
		t.Fatalf("env: got %v want 10s", d)
	}

	d, err = jenkins.ResolveMaxBackoff("15s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != 15*time.Second {
		t.Fatalf("flag: got %v want 15s", d)
	}

	// Flag wins over env.
	d, err = jenkins.ResolveMaxBackoff("8s", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != 8*time.Second {
		t.Fatalf("flag wins: got %v want 8s", d)
	}

	// Whitespace treated as unset.
	d, err = jenkins.ResolveMaxBackoff("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("whitespace: got %v", d)
	}

	// Minute form accepted.
	d, err = jenkins.ResolveMaxBackoff("1m", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != time.Minute {
		t.Fatalf("1m: got %v", d)
	}
}

// Explicit "0" / "0s" means default (cannot disable cap by 0 — fail-closed).
func TestResolveMaxBackoff_ZeroMeansDefault(t *testing.T) {
	t.Parallel()

	d, err := jenkins.ResolveMaxBackoff("0", "10s")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("flag 0: got %v want default %v", d, jenkins.DefaultMaxBackoff)
	}

	d, err = jenkins.ResolveMaxBackoff("0s", "10s")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("flag 0s: got %v want default %v", d, jenkins.DefaultMaxBackoff)
	}

	d, err = jenkins.ResolveMaxBackoff("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("env 0: got %v want default %v", d, jenkins.DefaultMaxBackoff)
	}

	d, err = jenkins.ResolveMaxBackoff("", "0s")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("env 0s: got %v want default %v", d, jenkins.DefaultMaxBackoff)
	}

	d, err = jenkins.ResolveMaxBackoff("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("empty both: got %v want default %v", d, jenkins.DefaultMaxBackoff)
	}
}

func TestResolveMaxBackoff_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-duration"},
		{"bad flag", "2x", ""},
		{"negative env", "", "-1s"},
		{"negative flag", "-10s", "5s"},
		{"bare number", "", "5"},
		{"below min flag", "50ms", ""},
		{"below min env", "", "99ms"},
		{"above max flag", "2m", ""},
		{"above max env", "", "10m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jenkins.ResolveMaxBackoff(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "max") && !strings.Contains(msg, "invalid") && !strings.Contains(msg, "backoff") {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 51 Track A: absolute process fail-closed ceiling + min floor.
func TestResolveMaxBackoff_Bounds(t *testing.T) {
	t.Parallel()
	minStr := jenkins.MinMaxBackoff.String()
	capStr := jenkins.AbsoluteMaxMaxBackoff.String()
	overFlag := (jenkins.AbsoluteMaxMaxBackoff + time.Second).String()
	overEnv := (jenkins.AbsoluteMaxMaxBackoff * 2).String()
	belowMin := (jenkins.MinMaxBackoff - time.Millisecond).String()

	d, err := jenkins.ResolveMaxBackoff(minStr, "")
	if err != nil {
		t.Fatalf("at min flag: %v", err)
	}
	if d != jenkins.MinMaxBackoff {
		t.Fatalf("at min: got %v want %v", d, jenkins.MinMaxBackoff)
	}
	d, err = jenkins.ResolveMaxBackoff("", minStr)
	if err != nil {
		t.Fatalf("at min env: %v", err)
	}
	if d != jenkins.MinMaxBackoff {
		t.Fatalf("at min env: got %v", d)
	}

	d, err = jenkins.ResolveMaxBackoff(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if d != jenkins.AbsoluteMaxMaxBackoff {
		t.Fatalf("at cap: got %v want %v", d, jenkins.AbsoluteMaxMaxBackoff)
	}
	d, err = jenkins.ResolveMaxBackoff("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if d != jenkins.AbsoluteMaxMaxBackoff {
		t.Fatalf("at cap env: got %v", d)
	}

	d, err = jenkins.ResolveMaxBackoff("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("default: got %v want %v", d, jenkins.DefaultMaxBackoff)
	}
	if d < jenkins.MinMaxBackoff || d > jenkins.AbsoluteMaxMaxBackoff {
		t.Fatalf("default %v outside [%v, %v]", d, jenkins.MinMaxBackoff, jenkins.AbsoluteMaxMaxBackoff)
	}

	_, err = jenkins.ResolveMaxBackoff(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "max") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention max / maximum / bound: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	_, err = jenkins.ResolveMaxBackoff("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	_, err = jenkins.ResolveMaxBackoff(belowMin, "")
	if err == nil {
		t.Fatal("flag below min must fail closed")
	}
	msg = strings.ToLower(err.Error())
	if !strings.Contains(msg, "minimum") && !strings.Contains(msg, "below") {
		t.Fatalf("below-min error should mention minimum: %v", err)
	}

	d, err = jenkins.ResolveMaxBackoff(jenkins.DefaultMaxBackoff.String(), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if d != jenkins.DefaultMaxBackoff {
		t.Fatalf("got %v", d)
	}
	_, err = jenkins.ResolveMaxBackoff(overFlag, jenkins.DefaultMaxBackoff.String())
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveMaxBackoff_EnvName(t *testing.T) {
	t.Parallel()
	if jenkins.EnvMaxBackoff != "JENKINS_MCP_MAX_BACKOFF" {
		t.Fatalf("env name drift: %q", jenkins.EnvMaxBackoff)
	}
	if jenkins.MinMaxBackoff != 100*time.Millisecond {
		t.Fatalf("min drift: %v want 100ms", jenkins.MinMaxBackoff)
	}
	if jenkins.AbsoluteMaxMaxBackoff != time.Minute {
		t.Fatalf("absolute max drift: %v want 1m", jenkins.AbsoluteMaxMaxBackoff)
	}
	if jenkins.DefaultMaxBackoff != 5*time.Second {
		t.Fatalf("default drift: %v want 5s", jenkins.DefaultMaxBackoff)
	}
	if jenkins.MinMaxBackoff > jenkins.DefaultMaxBackoff {
		t.Fatalf("min %v must not exceed default %v",
			jenkins.MinMaxBackoff, jenkins.DefaultMaxBackoff)
	}
	if jenkins.AbsoluteMaxMaxBackoff <= jenkins.DefaultMaxBackoff {
		t.Fatalf("absolute %v must exceed default %v",
			jenkins.AbsoluteMaxMaxBackoff, jenkins.DefaultMaxBackoff)
	}
	// Default max ≥ default initial (ordering sanity).
	if jenkins.DefaultMaxBackoff < jenkins.DefaultInitialBackoff {
		t.Fatalf("DefaultMaxBackoff %v < DefaultInitialBackoff %v",
			jenkins.DefaultMaxBackoff, jenkins.DefaultInitialBackoff)
	}
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.MaxBackoff != jenkins.DefaultMaxBackoff {
		t.Fatalf("DefaultResilienceConfig.MaxBackoff=%v", cfg.MaxBackoff)
	}
}

// Wave 51 Track A: normalizeResilienceConfig clamps MaxBackoff to
// [Min, AbsoluteMax] and raises Max when Max < Initial.
func TestNormalizeResilienceConfig_MaxBackoffClamp(t *testing.T) {
	t.Parallel()
	r := jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.DefaultInitialBackoff,
		MaxBackoff:     jenkins.AbsoluteMaxMaxBackoff + time.Hour,
	})
	got := r.Config().MaxBackoff
	if got != jenkins.AbsoluteMaxMaxBackoff {
		t.Fatalf("oversize clamp: got %v want absolute %v", got, jenkins.AbsoluteMaxMaxBackoff)
	}
	// Below min clamps up.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.MinInitialBackoff,
		MaxBackoff:     jenkins.MinMaxBackoff / 2,
	})
	if r.Config().MaxBackoff != jenkins.MinMaxBackoff {
		t.Fatalf("below min clamp: got %v want min %v", r.Config().MaxBackoff, jenkins.MinMaxBackoff)
	}
	// At min/max preserved.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.MinInitialBackoff,
		MaxBackoff:     jenkins.MinMaxBackoff,
	})
	if r.Config().MaxBackoff != jenkins.MinMaxBackoff {
		t.Fatalf("at min: got %v", r.Config().MaxBackoff)
	}
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: jenkins.DefaultInitialBackoff,
		MaxBackoff:     jenkins.AbsoluteMaxMaxBackoff,
	})
	if r.Config().MaxBackoff != jenkins.AbsoluteMaxMaxBackoff {
		t.Fatalf("at cap: got %v", r.Config().MaxBackoff)
	}
	// Explicit 0 → default.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxBackoff: 0})
	if r.Config().MaxBackoff != jenkins.DefaultMaxBackoff {
		t.Fatalf("zero → default: got %v", r.Config().MaxBackoff)
	}
	// Negative → default.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxBackoff: -time.Second})
	if r.Config().MaxBackoff != jenkins.DefaultMaxBackoff {
		t.Fatalf("negative → default: got %v", r.Config().MaxBackoff)
	}
	// Inverted: Max < Initial → raise Max to Initial (library path only).
	// Use Initial within AbsoluteMaxInitialBackoff so it survives clamp.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		InitialBackoff: 500 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond, // below Initial after min clamp stays 200ms? Wait MinMax is 100ms so 200 stays
	})
	// Max 200ms < Initial 500ms → Max raised to 500ms.
	if r.Config().InitialBackoff != 500*time.Millisecond {
		t.Fatalf("initial: got %v", r.Config().InitialBackoff)
	}
	if r.Config().MaxBackoff != 500*time.Millisecond {
		t.Fatalf("inverted max raised to initial: got %v want 500ms", r.Config().MaxBackoff)
	}
}

// Wave 51 Track A: EnsureMaxBackoffAtLeastInitial fail-closed ordering.
func TestEnsureMaxBackoffAtLeastInitial(t *testing.T) {
	t.Parallel()
	if err := jenkins.EnsureMaxBackoffAtLeastInitial(
		jenkins.DefaultInitialBackoff, jenkins.DefaultMaxBackoff); err != nil {
		t.Fatalf("defaults ok: %v", err)
	}
	if err := jenkins.EnsureMaxBackoffAtLeastInitial(time.Second, time.Second); err != nil {
		t.Fatalf("equal ok: %v", err)
	}
	err := jenkins.EnsureMaxBackoffAtLeastInitial(2*time.Second, 500*time.Millisecond)
	if err == nil {
		t.Fatal("max < initial must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "max") || !strings.Contains(msg, "initial") {
		t.Fatalf("error should mention max and initial: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}
}
