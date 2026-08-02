package jenkins

import (
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ResolveCircuitFailureThreshold resolves consecutive 5xx/transport failures
// before the per-client circuit breaker opens (Wave 48 Track A / NET-003).
//
// Precedence (later wins): DefaultCircuitFailureThreshold → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means DefaultCircuitFailureThreshold
// — the circuit cannot be disabled by 0 (fail-closed safety). Negative or
// non-integer values fail closed (error); never clamp silently. After resolve,
// n must be ≤ AbsoluteMaxCircuitFailureThreshold; oversize values error with a
// non-secret message citing the absolute maximum (no secrets).
//
// Circuit still opens only on consecutive 5xx/transport failures. POST never
// auto-retries regardless of this threshold (IsIdempotentRetryMethod unchanged).
func ResolveCircuitFailureThreshold(flagVal, envVal string) (int, error) {
	n := DefaultCircuitFailureThreshold
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseCircuitFailureThresholdValue(raw, "env "+EnvCircuitFailureThreshold)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseCircuitFailureThresholdValue(raw, "flag --circuit-failure-threshold")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxCircuitFailureThreshold {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins circuit failure threshold exceeds absolute maximum bound ("+
				strconv.Itoa(AbsoluteMaxCircuitFailureThreshold)+")")
	}
	return n, nil
}

func parseCircuitFailureThresholdValue(raw, source string) (int, error) {
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid jenkins circuit failure threshold from "+source+
				" (positive integer, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins circuit failure threshold from "+source+" must not be negative")
	}
	// Explicit 0 → default: cannot disable the circuit by 0 (fail-closed).
	if v == 0 {
		return DefaultCircuitFailureThreshold, nil
	}
	return v, nil
}
