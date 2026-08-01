package jenkins

import (
	"strconv"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ResolveMaxConcurrent resolves the per-client Jenkins concurrency semaphore
// (Wave 50 Track A / NET-003).
//
// Precedence (later wins): DefaultMaxConcurrent → envVal → flagVal.
// Empty / whitespace means unset at that layer.
//
// Explicit "0" at the winning layer means unlimited concurrency (0), not
// default-substitution of a positive limit. Empty at all layers also yields
// 0 (DefaultMaxConcurrent). Contrast MaxRetries: there 0 disables GET/HEAD
// auto-retry; here 0 means unlimited. Contrast MaxJSONBodyBytes: there
// explicit "0" maps to default body size.
//
// Non-negative integers are accepted. Negative or non-integer values fail
// closed (error); never clamp silently. After resolve, n must be ≤
// AbsoluteMaxConcurrent; oversize values error with a non-secret message
// citing the absolute maximum (no secrets).
//
// POST/PUT/PATCH/DELETE are never auto-retried regardless of this value
// (IsIdempotentRetryMethod unchanged).
func ResolveMaxConcurrent(flagVal, envVal string) (int, error) {
	n := DefaultMaxConcurrent
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseMaxConcurrentValue(raw, "env "+EnvMaxConcurrent)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseMaxConcurrentValue(raw, "flag --max-concurrent")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxConcurrent {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max concurrent exceeds absolute maximum bound ("+
				strconv.Itoa(AbsoluteMaxConcurrent)+")")
	}
	return n, nil
}

func parseMaxConcurrentValue(raw, source string) (int, error) {
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid jenkins max concurrent from "+source+
				" (non-negative integer; 0 = unlimited concurrency; empty = default unlimited): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"jenkins max concurrent from "+source+" must not be negative")
	}
	// Explicit 0 is a valid operator choice: unlimited concurrency (unlike
	// MaxJSONBodyBytes where 0 means default; unlike MaxRetries where 0
	// disables auto-retry — here 0 means unlimited, same as the package default).
	return v, nil
}
