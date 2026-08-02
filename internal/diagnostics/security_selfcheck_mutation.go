package diagnostics

import (
	"context"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// checkMutationConfirmCooldownResidual is Wave 48 Track C / MUT-001 residual
// honesty: proves offline that DefaultTokenTTL and DefaultConfirmCooldown are
// positive, NewManager with zero rate/cooldown fields enforces production
// confirm cooldown (Preview+Confirm once succeeds; immediate re-Confirm for the
// same target is denied with confirm_cooldown), and mutations remain opt-in /
// RO by default (no surprise registration without --allow-mutations).
//
// Pure offline: no network, no Jenkins, no real remote mutations. Bool/int
// details only (secret-free). Fail closed if cooldown is not enforced.
func checkMutationConfirmCooldownResidual() SelfCheckItem {
	const (
		name    = "mutation_confirm_cooldown_residual"
		control = "MUT-001"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	// --- Production defaults positive (TTL + confirm cooldown) ---
	if mutation.DefaultTokenTTL <= 0 {
		return fail("DefaultTokenTTL must be positive (MUT-001 token TTL)")
	}
	if mutation.DefaultConfirmCooldown <= 0 {
		return fail("DefaultConfirmCooldown must be positive (MUT-001 confirm cooldown)")
	}
	ttlSec := int(mutation.DefaultTokenTTL / time.Second)
	if ttlSec <= 0 {
		return fail("DefaultTokenTTL must be at least 1 second")
	}
	cdSec := int(mutation.DefaultConfirmCooldown / time.Second)
	if cdSec <= 0 {
		return fail("DefaultConfirmCooldown must be at least 1 second")
	}

	// --- Opt-in residual: zero Inputs leave mutations unregistered (POL-001) ---
	// Honesty: cooldown/TTL only matter when mutations are explicitly allowed;
	// pilot default remains RO / no surprise mutation registration.
	zeroGate := policy.NewReadOnlyGate(policy.Inputs{})
	if zeroGate.AllowMutationsOptIn() || zeroGate.ShouldRegisterMutations() {
		return fail("mutations opt-in default broken (zero Inputs would register mutations)")
	}

	// --- Manager with production defaults (zero ConfirmCooldown/TTL fields) ---
	// AllowMutations only for this in-process dry-run; no Jenkins HTTP.
	mem := &audit.Memory{}
	// Fixed clock: deterministic offline canary (immediate re-confirm stays in cooldown).
	fixedNow := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	m := mutation.NewManager(mutation.Config{
		Gate:        policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:       mem,
		ProfileID:   "selfcheck",
		PrincipalID: "offline",
		// TTL / MaxPreviewsPerMinute / ConfirmCooldown left zero → production defaults.
		Now: func() time.Time { return fixedNow },
	})
	if m == nil {
		return fail("NewManager must return non-nil with production defaults")
	}

	ctx := context.Background()
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "selfcheck-cooldown-target"}

	prev1, err := m.Preview(ctx, intent)
	if err != nil {
		return fail("Preview with AllowMutations must succeed offline (no Jenkins)")
	}
	if prev1 == nil || strings.TrimSpace(prev1.ConfirmationToken) == "" {
		return fail("Preview must return a non-empty confirmation token")
	}
	// Confirmation tokens are used only for Confirm; never placed in report details.
	if _, err := m.Confirm(ctx, prev1.ConfirmationToken, intent); err != nil {
		return fail("first Confirm after Preview must succeed offline")
	}

	// Immediate second preview+confirm for same target within default cooldown → deny.
	prev2, err := m.Preview(ctx, intent)
	if err != nil {
		return fail("second Preview for same target must succeed (cooldown applies to Confirm only)")
	}
	if prev2 == nil || strings.TrimSpace(prev2.ConfirmationToken) == "" {
		return fail("second Preview must return a non-empty confirmation token")
	}

	_, err = m.Confirm(ctx, prev2.ConfirmationToken, intent)
	if err == nil {
		return fail("default confirm cooldown must deny immediate re-Confirm for same target")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		return fail("confirm cooldown denial must be policy_denial")
	}
	msg := strings.ToLower(apperr.ModelMessage(err))
	if !strings.Contains(msg, "cooldown") {
		return fail("confirm cooldown error must mention cooldown (fail closed)")
	}
	// Audit reason code when sink present (stable, non-secret).
	if !auditHasReason(mem, mutation.ReasonConfirmCooldown) {
		return fail("audit must record confirm_cooldown reason on cooldown deny")
	}

	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "MUT-001 confirm cooldown + token TTL lite offline; mutations remain opt-in / RO default residual",
		Control: control,
		Details: map[string]any{
			"default_token_ttl_seconds":        ttlSec,
			"default_confirm_cooldown_seconds": cdSec,
			"cooldown_enforced":                true,
			"mutations_opt_in_default":         true, // honesty: still require --allow-mutations
			"residual_gateway_multi_tenant":    false,
			"residual_live_remote_mutation":    false,
		},
	}
}

// auditHasReason reports whether mem recorded a deny (or any) event with reason.
func auditHasReason(mem *audit.Memory, reason string) bool {
	if mem == nil || reason == "" {
		return false
	}
	for _, e := range mem.Events() {
		if e.ReasonCode == reason {
			return true
		}
	}
	return false
}
