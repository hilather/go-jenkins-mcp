package jenkins_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Wave 48 Track A: ResolveCircuitFailureThreshold precedence default → env → flag.
func TestResolveCircuitFailureThreshold_Precedence(t *testing.T) {
	t.Parallel()

	n, err := jenkins.ResolveCircuitFailureThreshold("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultCircuitFailureThreshold)
	}

	n, err = jenkins.ResolveCircuitFailureThreshold("", "10")
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("env: got %d want 10", n)
	}

	n, err = jenkins.ResolveCircuitFailureThreshold("7", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("flag: got %d want 7", n)
	}

	// Flag wins over env.
	n, err = jenkins.ResolveCircuitFailureThreshold("3", "20")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("flag wins: got %d want 3", n)
	}

	// Whitespace treated as unset.
	n, err = jenkins.ResolveCircuitFailureThreshold("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("whitespace: got %d", n)
	}
}

// Explicit "0" means default (cannot disable circuit by 0 — fail-closed).
// Contrast ResolveMaxRetries where "0" disables GET/HEAD auto-retry.
func TestResolveCircuitFailureThreshold_ZeroMeansDefault(t *testing.T) {
	t.Parallel()

	// Flag "0" wins over env but maps to default, not disable.
	n, err := jenkins.ResolveCircuitFailureThreshold("0", "10")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("flag 0: got %d want default %d", n, jenkins.DefaultCircuitFailureThreshold)
	}

	// Env "0" when flag unset.
	n, err = jenkins.ResolveCircuitFailureThreshold("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("env 0: got %d want default %d", n, jenkins.DefaultCircuitFailureThreshold)
	}

	// Empty both → default.
	n, err = jenkins.ResolveCircuitFailureThreshold("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("empty both: got %d want default %d", n, jenkins.DefaultCircuitFailureThreshold)
	}
}

func TestResolveCircuitFailureThreshold_FailClosed(t *testing.T) {
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
			_, err := jenkins.ResolveCircuitFailureThreshold(tc.flag, tc.env)
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

// Wave 48 Track A: absolute process fail-closed ceiling.
func TestResolveCircuitFailureThreshold_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(jenkins.AbsoluteMaxCircuitFailureThreshold)
	overFlag := strconv.Itoa(jenkins.AbsoluteMaxCircuitFailureThreshold + 1)
	overEnv := strconv.Itoa(jenkins.AbsoluteMaxCircuitFailureThreshold * 2)
	absurd := "1000"

	// At absolute cap: ok.
	n, err := jenkins.ResolveCircuitFailureThreshold(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != jenkins.AbsoluteMaxCircuitFailureThreshold {
		t.Fatalf("at cap: got %d want %d", n, jenkins.AbsoluteMaxCircuitFailureThreshold)
	}
	n, err = jenkins.ResolveCircuitFailureThreshold("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != jenkins.AbsoluteMaxCircuitFailureThreshold {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap.
	n, err = jenkins.ResolveCircuitFailureThreshold("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultCircuitFailureThreshold)
	}
	if n > jenkins.AbsoluteMaxCircuitFailureThreshold {
		t.Fatalf("default %d exceeds absolute max %d", n, jenkins.AbsoluteMaxCircuitFailureThreshold)
	}

	// Flag above cap fails closed.
	_, err = jenkins.ResolveCircuitFailureThreshold(overFlag, "")
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
	_, err = jenkins.ResolveCircuitFailureThreshold("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd values fail closed.
	_, err = jenkins.ResolveCircuitFailureThreshold(absurd, "")
	if err == nil {
		t.Fatal("absurd threshold must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = jenkins.ResolveCircuitFailureThreshold(strconv.Itoa(jenkins.DefaultCircuitFailureThreshold), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = jenkins.ResolveCircuitFailureThreshold(overFlag, strconv.Itoa(jenkins.DefaultCircuitFailureThreshold))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveCircuitFailureThreshold_EnvName(t *testing.T) {
	t.Parallel()
	if jenkins.EnvCircuitFailureThreshold != "JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD" {
		t.Fatalf("env name drift: %q", jenkins.EnvCircuitFailureThreshold)
	}
	if jenkins.AbsoluteMaxCircuitFailureThreshold != 50 {
		t.Fatalf("absolute max drift: %d want 50", jenkins.AbsoluteMaxCircuitFailureThreshold)
	}
	if jenkins.DefaultCircuitFailureThreshold != 5 {
		t.Fatalf("default drift: %d want 5", jenkins.DefaultCircuitFailureThreshold)
	}
	if jenkins.AbsoluteMaxCircuitFailureThreshold <= jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("absolute %d must exceed default %d",
			jenkins.AbsoluteMaxCircuitFailureThreshold, jenkins.DefaultCircuitFailureThreshold)
	}
	if jenkins.DefaultCircuitOpenDuration != 15*time.Second {
		t.Fatalf("DefaultCircuitOpenDuration drift: %v want 15s", jenkins.DefaultCircuitOpenDuration)
	}
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.CircuitFailureThreshold != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("DefaultResilienceConfig.CircuitFailureThreshold=%d", cfg.CircuitFailureThreshold)
	}
	if cfg.CircuitOpenDuration != jenkins.DefaultCircuitOpenDuration {
		t.Fatalf("DefaultResilienceConfig.CircuitOpenDuration=%v", cfg.CircuitOpenDuration)
	}
}

// Wave 48 Track A: normalizeResilienceConfig clamps oversize CircuitFailureThreshold
// (defense-in-depth for library callers bypassing Resolve).
func TestNormalizeResilienceConfig_CircuitFailureThresholdAbsoluteClamp(t *testing.T) {
	t.Parallel()
	r := jenkins.NewResilience(jenkins.ResilienceConfig{
		CircuitFailureThreshold: jenkins.AbsoluteMaxCircuitFailureThreshold + 100,
	})
	got := r.Config().CircuitFailureThreshold
	if got != jenkins.AbsoluteMaxCircuitFailureThreshold {
		t.Fatalf("oversize clamp: got %d want absolute %d", got, jenkins.AbsoluteMaxCircuitFailureThreshold)
	}
	// At cap preserved.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		CircuitFailureThreshold: jenkins.AbsoluteMaxCircuitFailureThreshold,
	})
	if r.Config().CircuitFailureThreshold != jenkins.AbsoluteMaxCircuitFailureThreshold {
		t.Fatalf("at cap: got %d", r.Config().CircuitFailureThreshold)
	}
	// Explicit 0 → default (cannot disable).
	r = jenkins.NewResilience(jenkins.ResilienceConfig{CircuitFailureThreshold: 0})
	if r.Config().CircuitFailureThreshold != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("zero → default: got %d", r.Config().CircuitFailureThreshold)
	}
	// Negative → default.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{CircuitFailureThreshold: -1})
	if r.Config().CircuitFailureThreshold != jenkins.DefaultCircuitFailureThreshold {
		t.Fatalf("negative → default: got %d", r.Config().CircuitFailureThreshold)
	}
}
