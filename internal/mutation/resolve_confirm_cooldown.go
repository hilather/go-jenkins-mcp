package mutation

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Confirm-cooldown operator bounds (Wave 52 Track A / MUT-001).
// DefaultConfirmCooldown (5s) remains in manager.go.
const (
	// MinConfirmCooldown is the shortest allowed confirm cooldown
	// (Wave 52 Track A / MUT-001). Below this, ResolveConfirmCooldown fails
	// closed at serve start (not clamped silently). SetConfirmCooldown clamps
	// library callers that bypass Resolve as belt-and-suspenders.
	MinConfirmCooldown = 1 * time.Second
	// AbsoluteMaxConfirmCooldown is the process absolute fail-closed ceiling
	// for ConfirmCooldown (Wave 52 Track A / MUT-001). Oversize flag/env is
	// rejected at serve start (not clamped silently). SetConfirmCooldown clamps
	// library callers that bypass Resolve as belt-and-suspenders.
	AbsoluteMaxConfirmCooldown = 5 * time.Minute
	// EnvConfirmCooldown is the serve env for the mutation confirm cooldown
	// (Wave 52 Track A / MUT-001). CLI --mutation-confirm-cooldown overrides
	// when set. Empty/0/"0s" → DefaultConfirmCooldown. Invalid, negative,
	// below-min, and oversize values fail closed at serve start.
	EnvConfirmCooldown = "JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN"
)

// liveConfirmCooldownNanos holds the process-level confirm cooldown after
// serve Resolve + SetConfirmCooldown. Zero means unset (NewManager falls back
// to DefaultConfirmCooldown when Config.ConfirmCooldown is 0).
var liveConfirmCooldownNanos atomic.Int64

// SetConfirmCooldown sets the process confirm cooldown after a successful
// ResolveConfirmCooldown (serve start). Non-positive d stores
// DefaultConfirmCooldown. Below-min / oversize values are clamped to
// [MinConfirmCooldown, AbsoluteMaxConfirmCooldown] as belt-and-suspenders
// (resolve already fail-closed). Operator resolve never yields 0; library
// Config negative still disables cooldown per Manager for tests.
func SetConfirmCooldown(d time.Duration) {
	if d <= 0 {
		d = DefaultConfirmCooldown
	}
	if d < MinConfirmCooldown {
		d = MinConfirmCooldown
	}
	if d > AbsoluteMaxConfirmCooldown {
		d = AbsoluteMaxConfirmCooldown
	}
	liveConfirmCooldownNanos.Store(int64(d))
}

// ConfirmCooldown returns the process-level live confirm cooldown set by
// SetConfirmCooldown, or 0 when never set (unset). Diagnostics/tests and
// NewManager consult this when Config.ConfirmCooldown is 0.
func ConfirmCooldown() time.Duration {
	n := liveConfirmCooldownNanos.Load()
	if n <= 0 {
		return 0
	}
	return time.Duration(n)
}

// ResolveConfirmCooldown resolves the mutation confirm cooldown
// (Wave 52 Track A / MUT-001).
//
// Precedence (later wins): DefaultConfirmCooldown → envVal → flagVal.
// Empty / whitespace means unset at that layer. Values are Go duration strings
// (e.g. "5s", "30s", "1m") like ResolveCircuitOpenDuration.
// Zero (explicit "0" or "0s") at the winning layer means DefaultConfirmCooldown —
// the cooldown cannot be disabled by 0 (fail-closed safety). Negative or
// unparseable values fail closed (error); never clamp silently. After resolve,
// d must be in [MinConfirmCooldown, AbsoluteMaxConfirmCooldown]; out-of-range
// values error with a non-secret message citing the bound.
//
// Residual honesty: library Config.ConfirmCooldown may still be negative to turn
// cooldown off for tests; the operator resolve path cannot set 0/disable.
// After ResolveConfirmCooldown + ResolveTokenTTL, serve calls
// EnsureConfirmCooldownLessThanTokenTTL (cooldown must be strictly < token TTL).
func ResolveConfirmCooldown(flagVal, envVal string) (time.Duration, error) {
	d := DefaultConfirmCooldown
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseConfirmCooldownValue(raw, "env "+EnvConfirmCooldown)
		if err != nil {
			return 0, err
		}
		d = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseConfirmCooldownValue(raw, "flag --mutation-confirm-cooldown")
		if err != nil {
			return 0, err
		}
		d = v
	}
	// Bounds check after layer merge (0 already mapped to default).
	if d < MinConfirmCooldown {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation confirm cooldown is below minimum "+
				MinConfirmCooldown.String()+" (got "+d.String()+")")
	}
	if d > AbsoluteMaxConfirmCooldown {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation confirm cooldown exceeds absolute maximum bound ("+
				AbsoluteMaxConfirmCooldown.String()+")")
	}
	return d, nil
}

func parseConfirmCooldownValue(raw, source string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid mutation confirm cooldown from "+source+
				" (use Go duration, e.g. 5s, 30s, 1m, or 0 for default): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation confirm cooldown from "+source+" must not be negative")
	}
	// Explicit 0 / 0s → default: cannot disable cooldown by 0 (fail-closed).
	if d == 0 {
		return DefaultConfirmCooldown, nil
	}
	return d, nil
}
