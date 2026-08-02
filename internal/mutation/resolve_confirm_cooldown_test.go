package mutation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Wave 52 Track A: ResolveConfirmCooldown precedence default → env → flag.
func TestResolveConfirmCooldown_Precedence(t *testing.T) {
	t.Parallel()

	d, err := mutation.ResolveConfirmCooldown("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("default: got %v want %v", d, mutation.DefaultConfirmCooldown)
	}

	d, err = mutation.ResolveConfirmCooldown("", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != 30*time.Second {
		t.Fatalf("env: got %v want 30s", d)
	}

	d, err = mutation.ResolveConfirmCooldown("45s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != 45*time.Second {
		t.Fatalf("flag: got %v want 45s", d)
	}

	// Flag wins over env.
	d, err = mutation.ResolveConfirmCooldown("20s", "2m")
	if err != nil {
		t.Fatal(err)
	}
	if d != 20*time.Second {
		t.Fatalf("flag wins: got %v want 20s", d)
	}

	// Whitespace treated as unset.
	d, err = mutation.ResolveConfirmCooldown("  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("whitespace: got %v", d)
	}

	// Minute form accepted.
	d, err = mutation.ResolveConfirmCooldown("1m", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != time.Minute {
		t.Fatalf("1m: got %v", d)
	}
}

// Explicit "0" / "0s" means default (cannot disable cooldown by 0 — fail-closed).
func TestResolveConfirmCooldown_ZeroMeansDefault(t *testing.T) {
	t.Parallel()

	// Flag "0" wins over env but maps to default, not disable.
	d, err := mutation.ResolveConfirmCooldown("0", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("flag 0: got %v want default %v", d, mutation.DefaultConfirmCooldown)
	}

	d, err = mutation.ResolveConfirmCooldown("0s", "30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("flag 0s: got %v want default %v", d, mutation.DefaultConfirmCooldown)
	}

	d, err = mutation.ResolveConfirmCooldown("", "0")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("env 0: got %v want default %v", d, mutation.DefaultConfirmCooldown)
	}

	d, err = mutation.ResolveConfirmCooldown("", "0s")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("env 0s: got %v want default %v", d, mutation.DefaultConfirmCooldown)
	}

	d, err = mutation.ResolveConfirmCooldown("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("empty both: got %v want default %v", d, mutation.DefaultConfirmCooldown)
	}
}

func TestResolveConfirmCooldown_FailClosed(t *testing.T) {
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
			_, err := mutation.ResolveConfirmCooldown(tc.flag, tc.env)
			if err == nil {
				t.Fatal("expected error")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "confirm") && !strings.Contains(msg, "cooldown") && !strings.Contains(msg, "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
				t.Fatalf("error must not mention secrets: %v", err)
			}
		})
	}
}

// Wave 52 Track A: absolute process fail-closed ceiling + min floor.
func TestResolveConfirmCooldown_Bounds(t *testing.T) {
	t.Parallel()
	minStr := mutation.MinConfirmCooldown.String()
	capStr := mutation.AbsoluteMaxConfirmCooldown.String()
	overFlag := (mutation.AbsoluteMaxConfirmCooldown + time.Second).String()
	overEnv := (mutation.AbsoluteMaxConfirmCooldown * 2).String()
	belowMin := (mutation.MinConfirmCooldown - time.Millisecond).String()

	// At min: ok.
	d, err := mutation.ResolveConfirmCooldown(minStr, "")
	if err != nil {
		t.Fatalf("at min flag: %v", err)
	}
	if d != mutation.MinConfirmCooldown {
		t.Fatalf("at min: got %v want %v", d, mutation.MinConfirmCooldown)
	}
	d, err = mutation.ResolveConfirmCooldown("", minStr)
	if err != nil {
		t.Fatalf("at min env: %v", err)
	}
	if d != mutation.MinConfirmCooldown {
		t.Fatalf("at min env: got %v", d)
	}

	// At absolute cap: ok.
	d, err = mutation.ResolveConfirmCooldown(capStr, "")
	if err != nil {
		t.Fatalf("at cap flag: %v", err)
	}
	if d != mutation.AbsoluteMaxConfirmCooldown {
		t.Fatalf("at cap: got %v want %v", d, mutation.AbsoluteMaxConfirmCooldown)
	}
	d, err = mutation.ResolveConfirmCooldown("", capStr)
	if err != nil {
		t.Fatalf("at cap env: %v", err)
	}
	if d != mutation.AbsoluteMaxConfirmCooldown {
		t.Fatalf("at cap env: got %v", d)
	}

	// Default under absolute cap and at/above min.
	d, err = mutation.ResolveConfirmCooldown("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("default: got %v want %v", d, mutation.DefaultConfirmCooldown)
	}
	if d < mutation.MinConfirmCooldown || d > mutation.AbsoluteMaxConfirmCooldown {
		t.Fatalf("default %v outside [%v, %v]", d, mutation.MinConfirmCooldown, mutation.AbsoluteMaxConfirmCooldown)
	}

	// Flag above cap fails closed.
	_, err = mutation.ResolveConfirmCooldown(overFlag, "")
	if err == nil {
		t.Fatal("flag above absolute max must fail closed")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "confirm") && !strings.Contains(msg, "cooldown") {
		t.Fatalf("over-cap flag error should mention confirm/cooldown: %v", err)
	}
	if !strings.Contains(msg, "maximum") && !strings.Contains(msg, "bound") && !strings.Contains(msg, "absolute") {
		t.Fatalf("over-cap flag error should mention maximum/bound: %v", err)
	}
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("error must not mention secrets: %v", err)
	}

	// Env above cap fails closed.
	_, err = mutation.ResolveConfirmCooldown("", overEnv)
	if err == nil {
		t.Fatal("env above absolute max must fail closed")
	}

	// Below min fails closed.
	_, err = mutation.ResolveConfirmCooldown(belowMin, "")
	if err == nil {
		t.Fatal("flag below min must fail closed")
	}
	msg = strings.ToLower(err.Error())
	if !strings.Contains(msg, "minimum") && !strings.Contains(msg, "below") {
		t.Fatalf("below-min error should mention minimum: %v", err)
	}

	// Flag under cap wins even when env is over cap.
	d, err = mutation.ResolveConfirmCooldown(mutation.DefaultConfirmCooldown.String(), overEnv)
	if err != nil {
		t.Fatalf("flag under cap should win over over-cap env: %v", err)
	}
	if d != mutation.DefaultConfirmCooldown {
		t.Fatalf("got %v", d)
	}
	// Flag over cap fails even when env is sane.
	_, err = mutation.ResolveConfirmCooldown(overFlag, mutation.DefaultConfirmCooldown.String())
	if err == nil {
		t.Fatal("over-cap flag must fail even when env is under cap")
	}
}

func TestResolveConfirmCooldown_EnvNameAndConstants(t *testing.T) {
	t.Parallel()
	if mutation.EnvConfirmCooldown != "JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN" {
		t.Fatalf("env name drift: %q", mutation.EnvConfirmCooldown)
	}
	if mutation.MinConfirmCooldown != time.Second {
		t.Fatalf("min drift: %v want 1s", mutation.MinConfirmCooldown)
	}
	if mutation.AbsoluteMaxConfirmCooldown != 5*time.Minute {
		t.Fatalf("absolute max drift: %v want 5m", mutation.AbsoluteMaxConfirmCooldown)
	}
	if mutation.DefaultConfirmCooldown != 5*time.Second {
		t.Fatalf("default drift: %v want 5s", mutation.DefaultConfirmCooldown)
	}
	if mutation.MinConfirmCooldown > mutation.DefaultConfirmCooldown {
		t.Fatalf("min %v must not exceed default %v",
			mutation.MinConfirmCooldown, mutation.DefaultConfirmCooldown)
	}
	if mutation.AbsoluteMaxConfirmCooldown <= mutation.DefaultConfirmCooldown {
		t.Fatalf("absolute %v must exceed default %v",
			mutation.AbsoluteMaxConfirmCooldown, mutation.DefaultConfirmCooldown)
	}
	// DefaultTokenTTL remains the confirmation window; serve fail-closes when
	// resolved cooldown ≥ TTL (EnsureConfirmCooldownLessThanTokenTTL).
	if mutation.DefaultConfirmCooldown >= mutation.DefaultTokenTTL {
		t.Fatalf("DefaultConfirmCooldown %s must be < DefaultTokenTTL %s",
			mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL)
	}
	if err := mutation.EnsureConfirmCooldownLessThanTokenTTL(
		mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL); err != nil {
		t.Fatalf("default ordering Ensure: %v", err)
	}
}

// Wave 52 Track A: SetConfirmCooldown applies live value used by NewManager zero Config.
// Not parallel: mutates process-level live cooldown.
func TestSetConfirmCooldown_AppliesLiveCap(t *testing.T) {
	defer mutation.ResetConfirmCooldownForTest()

	// Set a non-default positive live value.
	mutation.SetConfirmCooldown(2 * time.Second)
	if got := mutation.ConfirmCooldown(); got != 2*time.Second {
		t.Fatalf("live after set: got %v want 2s", got)
	}

	// NewManager with Config.ConfirmCooldown==0 prefers process live (2s).
	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		ConfirmCooldown: 0, // use live 2s
		Now:             now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "live-cd"}
	prev1, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev1.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	prev2, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev2.ConfirmationToken, intent); err == nil {
		t.Fatal("live 2s cooldown should deny immediate re-confirm")
	}
	// Still inside default 5s window: after only 2s+ the live cooldown should allow.
	advance(2*time.Second + time.Millisecond)
	if _, err := m.Confirm(context.Background(), prev2.ConfirmationToken, intent); err != nil {
		t.Fatalf("after live 2s cooldown: %v", err)
	}

	// Non-positive Set → DefaultConfirmCooldown.
	mutation.SetConfirmCooldown(0)
	if got := mutation.ConfirmCooldown(); got != mutation.DefaultConfirmCooldown {
		t.Fatalf("Set(0) → default: got %v", got)
	}

	// Oversize clamps to absolute max.
	mutation.SetConfirmCooldown(mutation.AbsoluteMaxConfirmCooldown + time.Hour)
	if got := mutation.ConfirmCooldown(); got != mutation.AbsoluteMaxConfirmCooldown {
		t.Fatalf("oversize clamp: got %v want %v", got, mutation.AbsoluteMaxConfirmCooldown)
	}

	// Below min clamps up.
	mutation.SetConfirmCooldown(mutation.MinConfirmCooldown / 2)
	if got := mutation.ConfirmCooldown(); got != mutation.MinConfirmCooldown {
		t.Fatalf("below-min clamp: got %v want %v", got, mutation.MinConfirmCooldown)
	}
}

// NewManager Config.ConfirmCooldown explicit positive ignores process live.
// Not parallel: mutates process-level live cooldown.
func TestNewManager_ExplicitConfirmCooldownOverridesLive(t *testing.T) {
	defer mutation.ResetConfirmCooldownForTest()
	mutation.SetConfirmCooldown(30 * time.Second)

	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	// Explicit 1s Config wins over live 30s.
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		ConfirmCooldown: time.Second,
		Now:             now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "explicit-cd"}
	p1, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), p1.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	p2, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), p2.ConfirmationToken, intent); err == nil {
		t.Fatal("1s cooldown should deny immediate re-confirm")
	}
	advance(time.Second + time.Millisecond)
	if _, err := m.Confirm(context.Background(), p2.ConfirmationToken, intent); err != nil {
		t.Fatalf("after explicit 1s: %v", err)
	}

	// Negative Config still disables (library test hatch) even when live is set.
	mOff := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		ConfirmCooldown: -1,
		Now:             now,
	})
	p3, err := mOff.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mOff.Confirm(context.Background(), p3.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	p4, err := mOff.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	// Immediate re-confirm should succeed with cooldown off.
	if _, err := mOff.Confirm(context.Background(), p4.ConfirmationToken, intent); err != nil {
		t.Fatalf("negative ConfirmCooldown should disable: %v", err)
	}
}
