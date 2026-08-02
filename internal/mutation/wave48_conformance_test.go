package mutation_test

import (
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/mutation"
)

// Wave 48 / MUT-001 conformance (Track D):
//   - Hard: DefaultTokenTTL and DefaultConfirmCooldown are positive production defaults
//   - Soft residual note: Wave 48 Track C mutation_confirm_cooldown_residual
//     self-check canary lives in diagnostics (not this package) — never fail for absence

// TestWave48_DefaultTokenTTLAndConfirmCooldown_Hard hard-asserts MUT-001 package
// defaults remain positive and within sensible bounds. Must remain true after
// Wave 48 Track C residual canary lands (canary must not change defaults silently).
func TestWave48_DefaultTokenTTLAndConfirmCooldown_Hard(t *testing.T) {
	t.Parallel()

	if mutation.DefaultTokenTTL <= 0 {
		t.Fatalf("DefaultTokenTTL must be positive, got %s", mutation.DefaultTokenTTL)
	}
	if mutation.DefaultTokenTTL != 2*time.Minute {
		t.Fatalf("DefaultTokenTTL=%s want 2m (MUT-001 expire quickly)", mutation.DefaultTokenTTL)
	}
	// Confirmation window should stay short (≤ 15m sanity bound).
	if mutation.DefaultTokenTTL > 15*time.Minute {
		t.Fatalf("DefaultTokenTTL=%s exceeds 15m sanity bound", mutation.DefaultTokenTTL)
	}

	if mutation.DefaultConfirmCooldown <= 0 {
		t.Fatalf("DefaultConfirmCooldown must be positive, got %s", mutation.DefaultConfirmCooldown)
	}
	if mutation.DefaultConfirmCooldown != 5*time.Second {
		t.Fatalf("DefaultConfirmCooldown=%s want 5s", mutation.DefaultConfirmCooldown)
	}
	// Cooldown should be shorter than token TTL (confirm-then-reconfirm window).
	if mutation.DefaultConfirmCooldown >= mutation.DefaultTokenTTL {
		t.Fatalf("DefaultConfirmCooldown %s must be < DefaultTokenTTL %s",
			mutation.DefaultConfirmCooldown, mutation.DefaultTokenTTL)
	}

	if mutation.DefaultMaxPreviewsPerMinute <= 0 {
		t.Fatalf("DefaultMaxPreviewsPerMinute must be positive, got %d", mutation.DefaultMaxPreviewsPerMinute)
	}

	// Stable reason / type codes used by residual canaries and audit.
	if mutation.ReasonConfirmCooldown != "confirm_cooldown" {
		t.Fatalf("ReasonConfirmCooldown drift: %q", mutation.ReasonConfirmCooldown)
	}
	if mutation.TypeConfirm != "mutation_confirm" {
		t.Fatalf("TypeConfirm drift: %q", mutation.TypeConfirm)
	}
}

// TestWave48_SoftResidual_TrackC_SelfCheckItemNote records that Wave 48 Track C
// mutation_confirm_cooldown_residual offline self-check is a diagnostics concern
// (package defaults above are hard). Soft residual only; never fails for absence
// of the self-check item (Track C planned; not claimed Done* by Track D).
func TestWave48_SoftResidual_TrackC_SelfCheckItemNote(t *testing.T) {
	t.Parallel()
	t.Logf("Wave 48 soft residual (mutation): DefaultTokenTTL=%s DefaultConfirmCooldown=%s present; "+
		"Track C mutation_confirm_cooldown_residual self-check canary is diagnostics residual "+
		"(Wave 47 update_lkg_residual Done* pattern; Track C planned/in progress; not a failure)",
		mutation.DefaultTokenTTL, mutation.DefaultConfirmCooldown)
}
