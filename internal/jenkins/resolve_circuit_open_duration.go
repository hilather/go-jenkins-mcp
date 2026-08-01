package jenkins

import (
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ResolveCircuitOpenDuration resolves how long the per-client circuit breaker
// stays open before a half-open probe (Wave 49 Track A / NET-003).
//
// Precedence (later wins): DefaultCircuitOpenDuration → envVal → flagVal.
// Empty / whitespace means unset at that layer. Values are Go duration strings
// (e.g. "15s", "1m", "30s") like ParseIdentityReverifyTTL.
// Zero (explicit "0" or "0s") at the winning layer means DefaultCircuitOpenDuration
// — the open period cannot be disabled by 0 (fail-closed safety). Negative or
// unparseable values fail closed (error); never clamp silently. After resolve,
// d must be in [MinCircuitOpenDuration, AbsoluteMaxCircuitOpenDuration];
// out-of-range values error with a non-secret message citing the bound.
//
// Circuit still opens only on consecutive 5xx/transport failures. POST never
// auto-retries regardless of this open duration (IsIdempotentRetryMethod unchanged).
func ResolveCircuitOpenDuration(flagVal, envVal string) (time.Duration, error) {
	d := DefaultCircuitOpenDuration
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseCircuitOpenDurationValue(raw, "env "+EnvCircuitOpenDuration)
		if err != nil {
			return 0, err
		}
		d = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseCircuitOpenDurationValue(raw, "flag --circuit-open-duration")
		if err != nil {
			return 0, err
		}
		d = v
	}
	// Bounds check after layer merge (0 already mapped to default).
	if d < MinCircuitOpenDuration {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins circuit open duration is below minimum "+
				MinCircuitOpenDuration.String()+" (got "+d.String()+")")
	}
	if d > AbsoluteMaxCircuitOpenDuration {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins circuit open duration exceeds absolute maximum bound ("+
				AbsoluteMaxCircuitOpenDuration.String()+")")
	}
	return d, nil
}

func parseCircuitOpenDurationValue(raw, source string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid jenkins circuit open duration from "+source+
				" (use Go duration, e.g. 15s, 1m, or 0 for default): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins circuit open duration from "+source+" must not be negative")
	}
	// Explicit 0 / 0s → default: cannot disable the open period by 0 (fail-closed).
	if d == 0 {
		return DefaultCircuitOpenDuration, nil
	}
	return d, nil
}
