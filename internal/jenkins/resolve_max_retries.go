package jenkins

import (
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// ResolveMaxRetries resolves extra GET/HEAD auto-retries after the first
// attempt (Wave 47 Track A / NET-003).
//
// Precedence (later wins): DefaultMaxRetries → envVal → flagVal.
// Empty / whitespace means unset at that layer.
//
// Unlike ResolveMaxJSONBodyBytes (where explicit "0" means default), explicit
// "0" at the winning layer means zero extra retries — disable auto-retry for
// GET/HEAD (total attempts = 1). Empty/whitespace never means 0; it falls
// through to the next lower layer or DefaultMaxRetries (2).
//
// Non-negative integers are accepted. Negative or non-integer values fail
// closed (error); never clamp silently. After resolve, n must be ≤
// AbsoluteMaxRetries; oversize values error with a non-secret message citing
// the absolute maximum (no secrets).
//
// POST/PUT/PATCH/DELETE are never auto-retried regardless of this value
// (IsIdempotentRetryMethod unchanged).
func ResolveMaxRetries(flagVal, envVal string) (int, error) {
	n := DefaultMaxRetries
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseMaxRetriesValue(raw, "env "+EnvMaxRetries)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseMaxRetriesValue(raw, "flag --max-retries")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxRetries {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max retries exceeds absolute maximum bound ("+
				strconv.Itoa(AbsoluteMaxRetries)+")")
	}
	return n, nil
}

func parseMaxRetriesValue(raw, source string) (int, error) {
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid jenkins max retries from "+source+
				" (non-negative integer; 0 disables GET/HEAD auto-retry; empty = default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max retries from "+source+" must not be negative")
	}
	// Explicit 0 is a valid operator choice: disable auto-retry (unlike
	// MaxJSONBodyBytes where 0 means default).
	return v, nil
}
