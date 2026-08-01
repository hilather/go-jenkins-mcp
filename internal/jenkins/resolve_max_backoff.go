package jenkins

import (
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ResolveMaxBackoff resolves the GET/HEAD exponential backoff / Retry-After cap
// (Wave 51 Track A / NET-003).
//
// Precedence (later wins): DefaultMaxBackoff → envVal → flagVal.
// Empty / whitespace means unset at that layer. Values are Go duration strings
// (e.g. "5s", "30s", "1m") like ResolveCircuitOpenDuration.
// Zero (explicit "0" or "0s") at the winning layer means DefaultMaxBackoff —
// the cap cannot be disabled by 0 (fail-closed safety). Negative or
// unparseable values fail closed (error); never clamp silently. After resolve,
// d must be in [MinMaxBackoff, AbsoluteMaxMaxBackoff]; out-of-range values
// error with a non-secret message citing the bound.
//
// Callers that also resolve InitialBackoff must ensure MaxBackoff ≥
// InitialBackoff after both resolve (EnsureMaxBackoffAtLeastInitial). POST
// never auto-retries regardless of this value (IsIdempotentRetryMethod
// unchanged).
func ResolveMaxBackoff(flagVal, envVal string) (time.Duration, error) {
	d := DefaultMaxBackoff
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseMaxBackoffValue(raw, "env "+EnvMaxBackoff)
		if err != nil {
			return 0, err
		}
		d = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseMaxBackoffValue(raw, "flag --max-backoff")
		if err != nil {
			return 0, err
		}
		d = v
	}
	// Bounds check after layer merge (0 already mapped to default).
	if d < MinMaxBackoff {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max backoff is below minimum "+
				MinMaxBackoff.String()+" (got "+d.String()+")")
	}
	if d > AbsoluteMaxMaxBackoff {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max backoff exceeds absolute maximum bound ("+
				AbsoluteMaxMaxBackoff.String()+")")
	}
	return d, nil
}

// EnsureMaxBackoffAtLeastInitial fails closed when maxBackoff < initialBackoff
// after both have been resolved independently (Wave 51 Track A / NET-003).
// Non-secret message only; never logs credentials. normalizeResilienceConfig
// raises MaxBackoff for library callers; the operator serve path uses this
// instead of silent clamp.
func EnsureMaxBackoffAtLeastInitial(initial, max time.Duration) error {
	if max < initial {
		return apperr.New(apperr.CodeInvalidArgument,
			"jenkins max backoff ("+max.String()+") must be >= initial backoff ("+
				initial.String()+")")
	}
	return nil
}

func parseMaxBackoffValue(raw, source string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid jenkins max backoff from "+source+
				" (use Go duration, e.g. 5s, 30s, 1m, or 0 for default): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max backoff from "+source+" must not be negative")
	}
	// Explicit 0 / 0s → default: cannot disable the cap by 0 (fail-closed).
	if d == 0 {
		return DefaultMaxBackoff, nil
	}
	return d, nil
}
