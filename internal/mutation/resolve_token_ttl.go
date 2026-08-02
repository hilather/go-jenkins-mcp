package mutation

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Token-TTL operator bounds (Wave 53 Track A / MUT-001).
// DefaultTokenTTL (2m) remains in manager.go.
const (
	// MinTokenTTL is the shortest allowed confirmation token TTL
	// (Wave 53 Track A / MUT-001). Below this, ResolveTokenTTL fails
	// closed at serve start (not clamped silently). SetTokenTTL clamps
	// library callers that bypass Resolve as belt-and-suspenders.
	MinTokenTTL = 10 * time.Second
	// AbsoluteMaxTokenTTL is the process absolute fail-closed ceiling
	// for confirmation token TTL (Wave 53 Track A / MUT-001; matches Wave 48
	// 15m sanity bound). Oversize flag/env is rejected at serve start
	// (not clamped silently). SetTokenTTL clamps library callers that
	// bypass Resolve as belt-and-suspenders.
	AbsoluteMaxTokenTTL = 15 * time.Minute
	// EnvTokenTTL is the serve env for the mutation confirmation token TTL
	// (Wave 53 Track A / MUT-001). CLI --mutation-token-ttl overrides
	// when set. Empty/0/"0s" → DefaultTokenTTL. Invalid, negative,
	// below-min, and oversize values fail closed at serve start.
	EnvTokenTTL = "JENKINS_MCP_MUTATION_TOKEN_TTL"
)

// liveTokenTTLNanos holds the process-level confirmation token TTL after
// serve Resolve + SetTokenTTL. Zero means unset (NewManager falls back
// to DefaultTokenTTL when Config.TTL ≤ 0).
var liveTokenTTLNanos atomic.Int64

// SetTokenTTL sets the process confirmation token TTL after a successful
// ResolveTokenTTL (serve start). Non-positive d stores DefaultTokenTTL.
// Below-min / oversize values are clamped to [MinTokenTTL, AbsoluteMaxTokenTTL]
// as belt-and-suspenders (resolve already fail-closed). Operator resolve
// never yields 0; library Config TTL ≤0 still maps to live if positive else
// DefaultTokenTTL (cannot disable / infinite via 0).
func SetTokenTTL(d time.Duration) {
	if d <= 0 {
		d = DefaultTokenTTL
	}
	if d < MinTokenTTL {
		d = MinTokenTTL
	}
	if d > AbsoluteMaxTokenTTL {
		d = AbsoluteMaxTokenTTL
	}
	liveTokenTTLNanos.Store(int64(d))
}

// TokenTTL returns the process-level live confirmation token TTL set by
// SetTokenTTL, or 0 when never set (unset). Diagnostics/tests and
// NewManager consult this when Config.TTL ≤ 0.
func TokenTTL() time.Duration {
	n := liveTokenTTLNanos.Load()
	if n <= 0 {
		return 0
	}
	return time.Duration(n)
}

// ResolveTokenTTL resolves the mutation confirmation token TTL
// (Wave 53 Track A / MUT-001).
//
// Precedence (later wins): DefaultTokenTTL → envVal → flagVal.
// Empty / whitespace means unset at that layer. Values are Go duration strings
// (e.g. "30s", "2m", "5m") like ResolveConfirmCooldown.
// Zero (explicit "0" or "0s") at the winning layer means DefaultTokenTTL —
// the TTL cannot be disabled by 0 (fail-closed safety). Negative or
// unparseable values fail closed (error); never clamp silently. After resolve,
// d must be in [MinTokenTTL, AbsoluteMaxTokenTTL]; out-of-range
// values error with a non-secret message citing the bound.
//
// Residual honesty: library Config.TTL ≤0 still maps to process live TokenTTL()
// when positive else DefaultTokenTTL (no infinite/disabled TTL path). Operator
// resolve path cannot set 0/disable. After ResolveConfirmCooldown + ResolveTokenTTL,
// serve must call EnsureConfirmCooldownLessThanTokenTTL so cooldown cannot
// exhaust (or equal) token TTL. Package defaults remain DefaultConfirmCooldown
// 5s < DefaultTokenTTL 2m.
func ResolveTokenTTL(flagVal, envVal string) (time.Duration, error) {
	d := DefaultTokenTTL
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseTokenTTLValue(raw, "env "+EnvTokenTTL)
		if err != nil {
			return 0, err
		}
		d = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseTokenTTLValue(raw, "flag --mutation-token-ttl")
		if err != nil {
			return 0, err
		}
		d = v
	}
	// Bounds check after layer merge (0 already mapped to default).
	if d < MinTokenTTL {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation token TTL is below minimum "+
				MinTokenTTL.String()+" (got "+d.String()+")")
	}
	if d > AbsoluteMaxTokenTTL {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation token TTL exceeds absolute maximum bound ("+
				AbsoluteMaxTokenTTL.String()+")")
	}
	return d, nil
}

// EnsureConfirmCooldownLessThanTokenTTL fails closed when confirmCooldown ≥
// tokenTTL after both have been resolved independently (MUT-001 residual fix).
// Confirm cooldown must be strictly shorter than the confirmation token TTL so
// cooldown cannot exhaust (or equal) the token window. Non-secret message only;
// never logs credentials or tokens. Library Config negative cooldown remains a
// test escape hatch; the operator serve path uses this instead of silent ignore.
func EnsureConfirmCooldownLessThanTokenTTL(confirmCooldown, tokenTTL time.Duration) error {
	if confirmCooldown >= tokenTTL {
		return apperr.New(apperr.CodeInvalidArgument,
			"mutation confirm cooldown ("+confirmCooldown.String()+
				") must be < mutation token TTL ("+tokenTTL.String()+")")
	}
	return nil
}

func parseTokenTTLValue(raw, source string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid mutation token TTL from "+source+
				" (use Go duration, e.g. 30s, 2m, 5m, or 0 for default): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"mutation token TTL from "+source+" must not be negative")
	}
	// Explicit 0 / 0s → default: cannot disable TTL by 0 (fail-closed).
	if d == 0 {
		return DefaultTokenTTL, nil
	}
	return d, nil
}
