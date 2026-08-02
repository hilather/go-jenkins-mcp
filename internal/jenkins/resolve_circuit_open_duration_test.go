package jenkins_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Wave 49 Track A: ResolveCircuitOpenDuration precedence default → env → flag.
func TestResolveCircuitOpenDuration_Precedence(t *testing.T) {
	t.Parallel()

	d, err := jenkins.ResolveCircuitOpenDuration("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("default: got %v want %v", d, jenkins.DefaultCircuitOpenDuration)
	}

	d, err = jenkins.ResolveCircuitOpenDuration("", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != 30*time.Second {
		t.Fatalf("env: got %v want 30s", d)
	}

	d, err = jenkins.ResolveCircuitOpenDuration("45s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != 45*time.Second {
		t.Fatalf("flag: got %v want 45s", d)
	}

	// Flag wins over env.
	d, err = jenkins.ResolveCircuitOpenDuration("20s", "2m")
	if err != nil {
		t.Fatal(err)
	}
	if d != 20*time.Second {
		t.Fatalf("flag wins: got %v want 20s", d)
	}

	// Whitespace treated as unset.
	d, err = jenkins.ResolveCircuitOpenDuration("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("whitespace: got %v", d)
	}

	// Minute form accepted.
	d, err = jenkins.ResolveCircuitOpenDuration("1m", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != time.Minute {
		t.Fatalf("1m: got %v", d)
	}
}

// Explicit "0" / "0s" means default (cannot disable open period by 0 — fail-closed).
func TestResolveCircuitOpenDuration_ZeroMeansDefault(t *testing.T) {
	t.Parallel()

	// Flag "0" wins over env but maps to default, not disable.
	d, err := jenkins.ResolveCircuitOpenDuration("0", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("flag 0: got %v want default %v", d, jenkins.DefaultCircuitOpenDuration)
	}

	// Flag "0s" same.
	d, err = jenkins.ResolveCircuitOpenDuration("0s", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("flag 0s: got %v want default %v", d, jenkins.DefaultCircuitOpenDuration)
	}

	// Env "0" when flag unset.
	d, err = jenkins.ResolveCircuitOpenDuration("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("env 0: got %v want default %v", d, jenkins.DefaultCircuitOpenDuration)
	}

	// Env "0s".
	d, err = jenkins.ResolveCircuitOpenDuration("", "0s")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("env 0s: got %v want default %v", d, jenkins.DefaultCircuitOpenDuration)
	}

	// Empty both → default.
	d, err = jenkins.ResolveCircuitOpenDuration("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("empty both: got %v want default %v", d, jenkins.DefaultCircuitOpenDuration)
	}
}

func TestResolveCircuitOpenDuration_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-duration"},
		{"bad flag", "2x", ""},
		{"negative env", "", "-1s"},
		{"negative flag", "-10s", "30s"},
		{"bare number", "", "15"},
		{"below min flag", "500ms", ""},
		{"below min env", "", "999ms"},
		{"above max flag", "6m", ""},
		{"above max env", "", "10m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jenkins.ResolveCircuitOpenDuration(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "circuit") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 49 Track A: absolute process fail-closed ceiling + min floor.
func TestResolveCircuitOpenDuration_Bounds(t *testing.T) {
	t.Parallel()
	minStr := jenkins.MinCircuitOpenDuration.String()
	capStr := jenkins.AbsoluteMaxCircuitOpenDuration.String()
	overFlag := (jenkins.AbsoluteMaxCircuitOpenDuration + time.Second).String()
	overEnv := (jenkins.AbsoluteMaxCircuitOpenDuration * 2).String()
	belowMin := (jenkins.MinCircuitOpenDuration - time.Millisecond).String()

	// At min: ok.
	d, err := jenkins.ResolveCircuitOpenDuration(minStr, "")
	if err != nil {
		t.Fatalf("at min flag: %v", err)
	}
	if d != jenkins.MinCircuitOpenDuration {
		t.Fatalf("at min: got %v want %v", d, jenkins.MinCircuitOpenDuration)
	}
	d, err = jenkins.ResolveCircuitOpenDuration("", minStr)
	if err != nil {
		t.Fatalf("at min env: %v", err)
	}
	if d != jenkins.MinCircuitOpenDuration {
		t.Fatalf("at min env: got %v", d)
	}

	// At absolute cap: ok.
	d, err = jenkins.ResolveCircuitOpenDuration(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if d != jenkins.AbsoluteMaxCircuitOpenDuration {
		t.Fatalf("at cap: got %v want %v", d, jenkins.AbsoluteMaxCircuitOpenDuration)
	}
	d, err = jenkins.ResolveCircuitOpenDuration("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if d != jenkins.AbsoluteMaxCircuitOpenDuration {
		t.Fatalf("at cap env: got %v", d)
	}

	// Default under absolute cap and at/above min.
	d, err = jenkins.ResolveCircuitOpenDuration("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("default: got %v want %v", d, jenkins.DefaultCircuitOpenDuration)
	}
	if d < jenkins.MinCircuitOpenDuration || d > jenkins.AbsoluteMaxCircuitOpenDuration {
		t.Fatalf("default %v outside [%v, %v]", d, jenkins.MinCircuitOpenDuration, jenkins.AbsoluteMaxCircuitOpenDuration)
	}

	// Flag above cap fails closed.
	_, err = jenkins.ResolveCircuitOpenDuration(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "circuit") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention circuit / maximum / bound: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	// Env above cap fails closed.
	_, err = jenkins.ResolveCircuitOpenDuration("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Below min fails closed.
	_, err = jenkins.ResolveCircuitOpenDuration(belowMin, "")
	if err == nil {
		t.Fatal("flag below min must fail closed")
	}
	msg = strings.ToLower(err.Error())
	if !strings.Contains(msg, "minimum") && !strings.Contains(msg, "below") {
		t.Fatalf("below-min error should mention minimum: %v", err)
	}

	// Flag under cap wins even when env is over cap.
	d, err = jenkins.ResolveCircuitOpenDuration(jenkins.DefaultCircuitOpenDuration.String(), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if d != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("got %v", d)
	}
	// Flag over cap fails even when env is sane.
	_, err = jenkins.ResolveCircuitOpenDuration(overFlag, jenkins.DefaultCircuitOpenDuration.String())
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveCircuitOpenDuration_EnvName(t *testing.T) {
	t.Parallel()
	if jenkins.EnvCircuitOpenDuration != "JENKINS_MCP_CIRCUIT_OPEN_DURATION" {
		t.Fatalf("env name drift: %q", jenkins.EnvCircuitOpenDuration)
	}
	if jenkins.MinCircuitOpenDuration != time.Second {
		t.Fatalf("min drift: %v want 1s", jenkins.MinCircuitOpenDuration)
	}
	if jenkins.AbsoluteMaxCircuitOpenDuration != 5*time.Minute {
		t.Fatalf("absolute max drift: %v want 5m", jenkins.AbsoluteMaxCircuitOpenDuration)
	}
	if jenkins.DefaultCircuitOpenDuration != 15*time.Second {
		t.Fatalf("default drift: %v want 15s", jenkins.DefaultCircuitOpenDuration)
	}
	if jenkins.MinCircuitOpenDuration > jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("min %v must not exceed default %v",
			jenkins.MinCircuitOpenDuration, jenkins.DefaultCircuitOpenDuration)
	}
	if jenkins.AbsoluteMaxCircuitOpenDuration <= jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("absolute %v must exceed default %v",
			jenkins.AbsoluteMaxCircuitOpenDuration, jenkins.DefaultCircuitOpenDuration)
	}
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.CircuitOpenDuration != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("DefaultResilienceConfig.CircuitOpenDuration=%v", cfg.CircuitOpenDuration)
	}
}

// Wave 49 Track A: normalizeResilienceConfig clamps CircuitOpenDuration to
// [Min, AbsoluteMax] (defense-in-depth for library callers bypassing Resolve).
func TestNormalizeResilienceConfig_CircuitOpenDurationClamp(t *testing.T) {
	t.Parallel()
	r := jenkins.NewResilience(jenkins.ResilienceConfig{
		CircuitOpenDuration: jenkins.AbsoluteMaxCircuitOpenDuration + time.Hour,
	})
	got := r.Config().CircuitOpenDuration
	if got != jenkins.AbsoluteMaxCircuitOpenDuration {
		t.Fatalf("oversize clamp: got %v want absolute %v", got, jenkins.AbsoluteMaxCircuitOpenDuration)
	}
	// Below min clamps up.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		CircuitOpenDuration: jenkins.MinCircuitOpenDuration / 2,
	})
	if r.Config().CircuitOpenDuration != jenkins.MinCircuitOpenDuration {
		t.Fatalf("below min clamp: got %v want min %v", r.Config().CircuitOpenDuration, jenkins.MinCircuitOpenDuration)
	}
	// At min/max preserved.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		CircuitOpenDuration: jenkins.MinCircuitOpenDuration,
	})
	if r.Config().CircuitOpenDuration != jenkins.MinCircuitOpenDuration {
		t.Fatalf("at min: got %v", r.Config().CircuitOpenDuration)
	}
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		CircuitOpenDuration: jenkins.AbsoluteMaxCircuitOpenDuration,
	})
	if r.Config().CircuitOpenDuration != jenkins.AbsoluteMaxCircuitOpenDuration {
		t.Fatalf("at cap: got %v", r.Config().CircuitOpenDuration)
	}
	// Explicit 0 → default (cannot disable).
	r = jenkins.NewResilience(jenkins.ResilienceConfig{CircuitOpenDuration: 0})
	if r.Config().CircuitOpenDuration != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("zero → default: got %v", r.Config().CircuitOpenDuration)
	}
	// Negative → default.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{CircuitOpenDuration: -time.Second})
	if r.Config().CircuitOpenDuration != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("negative → default: got %v", r.Config().CircuitOpenDuration)
	}
}
