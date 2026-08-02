package jenkins

import (
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ResolveInitialBackoff resolves the GET/HEAD retry base delay before the first
// retry (Wave 51 Track A / NET-003).
//
// Precedence (later wins): DefaultInitialBackoff → envVal → flagVal.
// Empty / whitespace means unset at that layer. Values are Go duration strings
// (e.g. "100ms", "250ms", "1s") like ResolveCircuitOpenDuration.
// Zero (explicit "0" or "0s") at the winning layer means DefaultInitialBackoff
// — the base delay cannot be disabled by 0 (fail-closed safety). Negative or
// unparseable values fail closed (error); never clamp silently. After resolve,
// d must be in [MinInitialBackoff, AbsoluteMaxInitialBackoff]; out-of-range
// values error with a non-secret message citing the bound.
//
// Callers that also resolve MaxBackoff must ensure MaxBackoff ≥ InitialBackoff
// after both resolve (EnsureMaxBackoffAtLeastInitial). POST never auto-retries
// regardless of this value (IsIdempotentRetryMethod unchanged).
func ResolveInitialBackoff(flagVal, envVal string) (time.Duration, error) {
	d := DefaultInitialBackoff
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseInitialBackoffValue(raw, "env "+EnvInitialBackoff)
		if err != nil {
			return 0, err
		}
		d = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseInitialBackoffValue(raw, "flag --initial-backoff")
		if err != nil {
			return 0, err
		}
		d = v
	}
	// Bounds check after layer merge (0 already mapped to default).
	if d < MinInitialBackoff {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins initial backoff is below minimum "+
				MinInitialBackoff.String()+" (got "+d.String()+")")
	}
	if d > AbsoluteMaxInitialBackoff {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins initial backoff exceeds absolute maximum bound ("+
				AbsoluteMaxInitialBackoff.String()+")")
	}
	return d, nil
}

func parseInitialBackoffValue(raw, source string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid jenkins initial backoff from "+source+
				" (use Go duration, e.g. 100ms, 250ms, 1s, or 0 for default): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins initial backoff from "+source+" must not be negative")
	}
	// Explicit 0 / 0s → default: cannot disable the base delay by 0 (fail-closed).
	if d == 0 {
		return DefaultInitialBackoff, nil
	}
	return d, nil
}
