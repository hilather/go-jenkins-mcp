package jenkins_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Wave 47 Track A: ResolveMaxRetries precedence default → env → flag (flag wins).
func TestResolveMaxRetries_Precedence(t *testing.T) {
	t.Parallel()

	n, err := jenkins.ResolveMaxRetries("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxRetries {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultMaxRetries)
	}

	n, err = jenkins.ResolveMaxRetries("", "5")
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("env: got %d want 5", n)
	}

	n, err = jenkins.ResolveMaxRetries("3", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("flag: got %d want 3", n)
	}

	// Flag wins over env.
	n, err = jenkins.ResolveMaxRetries("1", "9")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("flag wins: got %d want 1", n)
	}

	// Whitespace treated as unset.
	n, err = jenkins.ResolveMaxRetries("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxRetries {
		t.Fatalf("whitespace: got %d", n)
	}
}

// Explicit "0" means zero retries (disable GET/HEAD auto-retry), not default.
// Contrast ResolveMaxJSONBodyBytes where "0" means default.
func TestResolveMaxRetries_ZeroMeansDisable(t *testing.T) {
	t.Parallel()

	// Flag "0" wins over env and means disable (not default 2).
	n, err := jenkins.ResolveMaxRetries("0", "5")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("flag 0: got %d want 0 (disable auto-retry)", n)
	}

	// Env "0" when flag unset.
	n, err = jenkins.ResolveMaxRetries("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("env 0: got %d want 0", n)
	}

	// Empty flag does not override env "0".
	n, err = jenkins.ResolveMaxRetries("  ", "0")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("whitespace flag + env 0: got %d want 0", n)
	}

	// Empty both → default 2 (not 0).
	n, err = jenkins.ResolveMaxRetries("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxRetries {
		t.Fatalf("empty both: got %d want default %d", n, jenkins.DefaultMaxRetries)
	}
}

func TestResolveMaxRetries_FailClosed(t *testing.T) {
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
			_, err := jenkins.ResolveMaxRetries(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "retries") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 47 Track A: absolute process fail-closed ceiling (AbsoluteMaxRetries).
func TestResolveMaxRetries_AbsoluteCap(t *testing.T) {
	t.Parallel()
	capStr := strconv.Itoa(jenkins.AbsoluteMaxRetries)
	overFlag := strconv.Itoa(jenkins.AbsoluteMaxRetries + 1)
	overEnv := strconv.Itoa(jenkins.AbsoluteMaxRetries * 2)
	absurd := "1000"

	// At absolute cap: ok.
	n, err := jenkins.ResolveMaxRetries(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if n != jenkins.AbsoluteMaxRetries {
		t.Fatalf("at cap: got %d want %d", n, jenkins.AbsoluteMaxRetries)
	}
	n, err = jenkins.ResolveMaxRetries("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if n != jenkins.AbsoluteMaxRetries {
		t.Fatalf("at cap env: got %d", n)
	}

	// Default under absolute cap.
	n, err = jenkins.ResolveMaxRetries("", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != jenkins.DefaultMaxRetries {
		t.Fatalf("default: got %d want %d", n, jenkins.DefaultMaxRetries)
	}
	if n > jenkins.AbsoluteMaxRetries {
		t.Fatalf("default %d exceeds absolute max %d", n, jenkins.AbsoluteMaxRetries)
	}

	// Flag above cap fails closed.
	_, err = jenkins.ResolveMaxRetries(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "retries") ||
		(!strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute")) {
		t.Fatalf("over-cap flag error should mention retries / maximum / bound: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	// Env above cap fails closed.
	_, err = jenkins.ResolveMaxRetries("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Absurd storm values fail closed.
	_, err = jenkins.ResolveMaxRetries(absurd, "")
	if err == nil {
		t.Fatal("absurd retries must fail closed under AbsoluteMax")
	}

	// Flag under cap wins even when env is over cap.
	n, err = jenkins.ResolveMaxRetries(strconv.Itoa(jenkins.DefaultMaxRetries), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if n != jenkins.DefaultMaxRetries {
		t.Fatalf("got %d", n)
	}
	// Flag over cap fails even when env is sane.
	_, err = jenkins.ResolveMaxRetries(overFlag, strconv.Itoa(jenkins.DefaultMaxRetries))
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveMaxRetries_EnvName(t *testing.T) {
	t.Parallel()
	if jenkins.EnvMaxRetries != "JENKINS_MCP_MAX_RETRIES" {
		t.Fatalf("env name drift: %q", jenkins.EnvMaxRetries)
	}
	if jenkins.AbsoluteMaxRetries != 10 {
		t.Fatalf("absolute max drift: %d want 10", jenkins.AbsoluteMaxRetries)
	}
	if jenkins.DefaultMaxRetries != 2 {
		t.Fatalf("default drift: %d want 2", jenkins.DefaultMaxRetries)
	}
	if jenkins.AbsoluteMaxRetries <= jenkins.DefaultMaxRetries {
		t.Fatalf("absolute %d must exceed default %d",
			jenkins.AbsoluteMaxRetries, jenkins.DefaultMaxRetries)
	}
	cfg := jenkins.DefaultResilienceConfig()
	if cfg.MaxRetries != jenkins.DefaultMaxRetries {
		t.Fatalf("DefaultResilienceConfig.MaxRetries=%d", cfg.MaxRetries)
	}
}

// Wave 47 Track A: normalizeResilienceConfig clamps oversize MaxRetries
// (defense-in-depth for library callers bypassing ResolveMaxRetries).
func TestNormalizeResilienceConfig_MaxRetriesAbsoluteClamp(t *testing.T) {
	t.Parallel()
	r := jenkins.NewResilience(jenkins.ResilienceConfig{
		MaxRetries: jenkins.AbsoluteMaxRetries + 50,
	})
	got := r.Config().MaxRetries
	if got != jenkins.AbsoluteMaxRetries {
		t.Fatalf("oversize clamp: got %d want absolute %d", got, jenkins.AbsoluteMaxRetries)
	}
	// At cap preserved.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{
		MaxRetries: jenkins.AbsoluteMaxRetries,
	})
	if r.Config().MaxRetries != jenkins.AbsoluteMaxRetries {
		t.Fatalf("at cap: got %d", r.Config().MaxRetries)
	}
	// Explicit 0 preserved (disable auto-retry; not remapped to default).
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxRetries: 0})
	if r.Config().MaxRetries != 0 {
		t.Fatalf("zero must stay 0 (disable): got %d", r.Config().MaxRetries)
	}
	// Negative → default.
	r = jenkins.NewResilience(jenkins.ResilienceConfig{MaxRetries: -1})
	if r.Config().MaxRetries != jenkins.DefaultMaxRetries {
		t.Fatalf("negative → default: got %d", r.Config().MaxRetries)
	}
}

// Wave 48: normalizeResilienceConfig clamps oversize CircuitFailureThreshold
