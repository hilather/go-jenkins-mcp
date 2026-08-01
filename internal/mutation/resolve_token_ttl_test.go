package mutation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 53 Track A: ResolveTokenTTL precedence default → env → flag.
func TestResolveTokenTTL_Precedence(t *testing.T) {
	t.Parallel()

	d, err := mutation.ResolveTokenTTL("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("default: got %v want %v", d, mutation.DefaultTokenTTL)
	}

	d, err = mutation.ResolveTokenTTL("", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != 30*time.Second {
		t.Fatalf("env: got %v want 30s", d)
	}

	d, err = mutation.ResolveTokenTTL("45s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != 45*time.Second {
		t.Fatalf("flag: got %v want 45s", d)
	}

	// Flag wins over env.
	d, err = mutation.ResolveTokenTTL("1m", "5m")
	if err != nil {
		t.Fatal(err)
	}
	if d != time.Minute {
		t.Fatalf("flag wins: got %v want 1m", d)
	}

	// Whitespace treated as unset.
	d, err = mutation.ResolveTokenTTL("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("whitespace: got %v", d)
	}

	// Minute form accepted.
	d, err = mutation.ResolveTokenTTL("5m", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != 5*time.Minute {
		t.Fatalf("5m: got %v", d)
	}
}

// Explicit "0" / "0s" means default (cannot disable TTL by 0 — fail-closed).
func TestResolveTokenTTL_ZeroMeansDefault(t *testing.T) {
	t.Parallel()

	// Flag "0" wins over env but maps to default, not disable.
	d, err := mutation.ResolveTokenTTL("0", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("flag 0: got %v want default %v", d, mutation.DefaultTokenTTL)
	}

	d, err = mutation.ResolveTokenTTL("0s", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("flag 0s: got %v want default %v", d, mutation.DefaultTokenTTL)
	}

	d, err = mutation.ResolveTokenTTL("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("env 0: got %v want default %v", d, mutation.DefaultTokenTTL)
	}

	d, err = mutation.ResolveTokenTTL("", "0s")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("env 0s: got %v want default %v", d, mutation.DefaultTokenTTL)
	}

	d, err = mutation.ResolveTokenTTL("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("empty both: got %v want default %v", d, mutation.DefaultTokenTTL)
	}
}

func TestResolveTokenTTL_FailClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, flag, env string
	}{
		{"bad env", "", "not-a-duration"},
		{"bad flag", "2x", ""},
		{"negative env", "", "-1s"},
		{"negative flag", "-10s", "30s"},
		{"bare number", "", "15"},
		{"below min flag", "5s", ""},
		{"below min env", "", "9s"},
		{"above max flag", "16m", ""},
		{"above max env", "", "20m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := mutation.ResolveTokenTTL(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "token") && !strings.Contains(msg, "ttl") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
			// Non-secret: no password/credential leakage in resolve errors.
			if strings.Contains(msg, "password") || strings.Contains(msg, "secret") || strings.Contains(msg, "credential") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 53 Track A: absolute process fail-closed ceiling + min floor.
func TestResolveTokenTTL_Bounds(t *testing.T) {
	t.Parallel()
	minStr := mutation.MinTokenTTL.String()
	capStr := mutation.AbsoluteMaxTokenTTL.String()
	overFlag := (mutation.AbsoluteMaxTokenTTL + time.Second).String()
	overEnv := (mutation.AbsoluteMaxTokenTTL * 2).String()
	belowMin := (mutation.MinTokenTTL - time.Second).String()

	// At min: ok.
	d, err := mutation.ResolveTokenTTL(minStr, "")
	if err != nil {
		t.Fatalf("at min flag: %v", err)
	}
	if d != mutation.MinTokenTTL {
		t.Fatalf("at min: got %v want %v", d, mutation.MinTokenTTL)
	}
	d, err = mutation.ResolveTokenTTL("", minStr)
	if err != nil {
		t.Fatalf("at min env: %v", err)
	}
	if d != mutation.MinTokenTTL {
		t.Fatalf("at min env: got %v", d)
	}

	// At absolute cap: ok.
	d, err = mutation.ResolveTokenTTL(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if d != mutation.AbsoluteMaxTokenTTL {
		t.Fatalf("at cap: got %v want %v", d, mutation.AbsoluteMaxTokenTTL)
	}
	d, err = mutation.ResolveTokenTTL("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if d != mutation.AbsoluteMaxTokenTTL {
		t.Fatalf("at cap env: got %v", d)
	}

	// Default under absolute cap and at/above min.
	d, err = mutation.ResolveTokenTTL("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("default: got %v want %v", d, mutation.DefaultTokenTTL)
	}
	if d < mutation.MinTokenTTL || d > mutation.AbsoluteMaxTokenTTL {
		t.Fatalf("default %v outside [%v, %v]", d, mutation.MinTokenTTL, mutation.AbsoluteMaxTokenTTL)
	}

	// Flag above cap fails closed.
	_, err = mutation.ResolveTokenTTL(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "token") && !strings.Contains(msg, "ttl") {
		t.Fatalf("over-cap flag error should mention token/ttl: %v", err)
	}
	if !strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute") {
		t.Fatalf("over-cap flag error should mention maximum/bound: %v", err)
	}
	if strings.Contains(msg, "password") || strings.Contains(msg, "secret") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	// Env above cap fails closed.
	_, err = mutation.ResolveTokenTTL("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Below min fails closed.
	_, err = mutation.ResolveTokenTTL(belowMin, "")
	if err == nil {
		t.Fatal("flag below min must fail closed")
	}
	msg = strings.ToLower(err.Error())
	if !strings.Contains(msg, "minimum") && !strings.Contains(msg, "below") {
		t.Fatalf("below-min error should mention minimum: %v", err)
	}

	// Flag under cap wins even when env is over cap.
	d, err = mutation.ResolveTokenTTL(mutation.DefaultTokenTTL.String(), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if d != mutation.DefaultTokenTTL {
		t.Fatalf("got %v", d)
	}
	// Flag over cap fails even when env is sane.
	_, err = mutation.ResolveTokenTTL(overFlag, mutation.DefaultTokenTTL.String())
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveTokenTTL_EnvNameAndConstants(t *testing.T) {
	t.Parallel()
	if mutation.EnvTokenTTL != "JENKINS_MCP_MUTATION_TOKEN_TTL" {
		t.Fatalf("env name drift: %q", mutation.EnvTokenTTL)
	}
	if mutation.MinTokenTTL != 10*time.Second {
		t.Fatalf("min drift: %v want 10s", mutation.MinTokenTTL)
	}
	if mutation.AbsoluteMaxTokenTTL != 15*time.Minute {
		t.Fatalf("absolute max drift: %v want 15m", mutation.AbsoluteMaxTokenTTL)
	}
	if mutation.DefaultTokenTTL != 2*time.Minute {
		t.Fatalf("default drift: %v want 2m", mutation.DefaultTokenTTL)
	}
	if mutation.MinTokenTTL > mutation.DefaultTokenTTL {
		t.Fatalf("min %v must not exceed default %v",
			mutation.MinTokenTTL, mutation.DefaultTokenTTL)
	}
	if mutation.AbsoluteMaxTokenTTL <= mutation.DefaultTokenTTL {
		t.Fatalf("absolute %v must exceed default %v",
			mutation.AbsoluteMaxTokenTTL, mutation.DefaultTokenTTL)
	}
	// Package defaults: DefaultConfirmCooldown (5s) < DefaultTokenTTL (2m).
	// Serve fail-closed: EnsureConfirmCooldownLessThanTokenTTL after both resolve.
	if mutation.DefaultConfirmCooldown >= mutation.DefaultTokenTTL {
		t.Fatalf("DefaultConfirmCooldown %s must be < DefaultTokenTTL %s",
			mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL)
	}
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(
		mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL); err != nil {
		t.Fatalf("default ordering Ensure: %v", err)
	}
}

// MUT-001 residual fix: confirm cooldown must be strictly < token TTL at serve.
func TestEnsureConfirmCooldownLessThanTokenTTL(t *testing.T) {
	t.Parallel()

	// cooldown < ttl → ok
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(5*time.Second, 2*time.Minute); err != nil {
		t.Fatalf("cooldown < ttl must succeed: %v", err)
	}
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(
		mutation.MinConfirmCooldown, mutation.MinTokenTTL); err != nil {
		t.Fatalf("min cooldown < min ttl must succeed: %v", err)
	}
	// just under equality
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(29*time.Second, 30*time.Second); err != nil {
		t.Fatalf("29s < 30s must succeed: %v", err)
	}

	// equal → fail closed
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(30*time.Second, 30*time.Second); err == nil {
		t.Fatal("cooldown == ttl must fail closed")
	} else if !strings.Contains(err.Error(), "must be <") {
		t.Fatalf("equal error should cite ordering, got: %v", err)
	}

	// cooldown > ttl → fail closed
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(1*time.Minute, 30*time.Second); err == nil {
		t.Fatal("cooldown > ttl must fail closed")
	} else if !strings.Contains(err.Error(), "must be <") {
		t.Fatalf("greater error should cite ordering, got: %v", err)
	}
	// Secret-free: error must not look like a token / credential leak.
	err := mutation.EnsureConfirmCooldownLessThanTokenTTL(2*time.Minute, 10*time.Second)
	if err == nil {
		t.Fatal("cooldown > ttl must fail closed")
	}
	msg := err.Error()
	for _, bad := range []string{"Bearer", "password", "api_token", "secret"} {
		if strings.Contains(strings.ToLower(msg), bad) {
			t.Fatalf("error must be secret-free, got: %q", msg)
		}
	}
	// Durations appear for operator diagnosis (non-secret).
	if !strings.Contains(msg, "2m") || !strings.Contains(msg, "10s") {
		t.Fatalf("error should include resolved durations, got: %q", msg)
	}
}

// Wave 53 Track A: SetTokenTTL applies live value used by NewManager zero Config.TTL.
// Not parallel: mutates process-level live TTL.
func TestSetTokenTTL_AppliesLiveCap(t *testing.T) {
	defer mutation.ResetTokenTTLForTest()

	// Set a non-default positive live value (above min).
	mutation.SetTokenTTL(30 * time.Second)
	if got := mutation.TokenTTL(); got != 30*time.Second {
		t.Fatalf("live after set: got %v want 30s", got)
	}

	// NewManager with Config.TTL≤0 prefers process live (30s).
	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		TTL:             0,  // use live 30s
		ConfirmCooldown: -1, // off so re-confirm path not under test
		Now:             now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "live-ttl"}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if prev.ExpiresInSeconds != 30 {
		t.Fatalf("ExpiresInSeconds: got %d want 30 (live TTL)", prev.ExpiresInSeconds)
	}
	// Still valid just under 30s.
	advance(29 * time.Second)
	if _, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent); err != nil {
		t.Fatalf("should be valid under live 30s TTL: %v", err)
	}

	// Fresh token then expire past live 30s.
	prev2, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	advance(30*time.Second + time.Millisecond)
	if _, err := m.Confirm(context.Background(), prev2.ConfirmationToken, intent); err == nil {
		t.Fatal("live 30s TTL should expire token")
	}

	// Non-positive Set → DefaultTokenTTL.
	mutation.SetTokenTTL(0)
	if got := mutation.TokenTTL(); got != mutation.DefaultTokenTTL {
		t.Fatalf("Set(0) → default: got %v", got)
	}

	// Oversize clamps to absolute max.
	mutation.SetTokenTTL(mutation.AbsoluteMaxTokenTTL + time.Hour)
	if got := mutation.TokenTTL(); got != mutation.AbsoluteMaxTokenTTL {
		t.Fatalf("oversize clamp: got %v want %v", got, mutation.AbsoluteMaxTokenTTL)
	}

	// Below min clamps up.
	mutation.SetTokenTTL(mutation.MinTokenTTL / 2)
	if got := mutation.TokenTTL(); got != mutation.MinTokenTTL {
		t.Fatalf("below-min clamp: got %v want %v", got, mutation.MinTokenTTL)
	}
}

// NewManager Config.TTL explicit positive ignores process live.
// Not parallel: mutates process-level live TTL.
func TestNewManager_ExplicitTokenTTLOverridesLive(t *testing.T) {
	defer mutation.ResetTokenTTLForTest()
	mutation.SetTokenTTL(5 * time.Minute)

	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	// Explicit 20s Config wins over live 5m.
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		TTL:             20 * time.Second,
		ConfirmCooldown: -1,
		Now:             now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "explicit-ttl"}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if prev.ExpiresInSeconds != 20 {
		t.Fatalf("ExpiresInSeconds: got %d want 20 (explicit Config)", prev.ExpiresInSeconds)
	}
	advance(20*time.Second + time.Millisecond)
	if _, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent); err == nil {
		t.Fatal("explicit 20s TTL should expire token")
	}

	// Negative Config.TTL still maps to live (when positive) — no unlimited TTL hatch.
	// Spec: Config TTL ≤0 → process live if positive else DefaultTokenTTL.
	mNeg := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		TTL:             -1,
		ConfirmCooldown: -1,
		Now:             now,
	})
	prevNeg, err := mNeg.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	// Live is still 5m from Set above.
	if prevNeg.ExpiresInSeconds != int((5 * time.Minute).Seconds()) {
		t.Fatalf("negative Config.TTL should prefer live 5m: got %d", prevNeg.ExpiresInSeconds)
	}
}

// NewManager with Config.TTL≤0 and unset process live uses DefaultTokenTTL.
// Not parallel: mutates process-level live TTL.
func TestNewManager_ZeroTTL_UsesDefaultWhenLiveUnset(t *testing.T) {
	defer mutation.ResetTokenTTLForTest()
	// Ensure live is unset (not Set to default).
	mutation.ResetTokenTTLForTest()
	if got := mutation.TokenTTL(); got != 0 {
		t.Fatalf("live should be unset (0), got %v", got)
	}

	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate: policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		TTL:  0,
		Now:  now,
	})
	prev, err := m.Preview(context.Background(), mutation.Intent{
		Action:  mutation.ActionStartJob,
		JobName: "default-ttl",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSec := int(mutation.DefaultTokenTTL.Seconds())
	if prev.ExpiresInSeconds != wantSec {
		t.Fatalf("ExpiresInSeconds: got %d want %d (DefaultTokenTTL)", prev.ExpiresInSeconds, wantSec)
	}
}
