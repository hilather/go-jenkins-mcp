package auth

import (
	"fmt"
	"strings"
)

// JWKSOutageDecision is the offline contract evaluation for JWKS unavailability.
type JWKSOutageDecision struct {
	// Acceptable is true only when behavior is fail_closed (production contract).
	Acceptable bool
	// Behavior is the normalized label (fail_closed | fail_open | unknown).
	Behavior string
	// Reason is a short non-secret explanation.
	Reason string
}

// EvaluateJWKSOutageBehavior classifies a resource-server JWKS-outage setting.
// Only RequiredJWKSOutageBehavior (fail_closed) is production-acceptable.
func EvaluateJWKSOutageBehavior(behavior string) JWKSOutageDecision {
	b := strings.ToLower(strings.TrimSpace(behavior))
	switch b {
	case JWKSOutageFailClosed:
		return JWKSOutageDecision{
			Acceptable: true,
			Behavior:   JWKSOutageFailClosed,
			Reason:     "JWKS outage fails closed (required production contract)",
		}
	case JWKSOutageFailOpen:
		return JWKSOutageDecision{
			Acceptable: false,
			Behavior:   JWKSOutageFailOpen,
			Reason:     "JWKS outage fails open (unacceptable; tokens accepted without verification)",
		}
	case "":
		return JWKSOutageDecision{
			Acceptable: false,
			Behavior:   "unknown",
			Reason:     "JWKS outage behavior unset (treat as fail-open risk)",
		}
	default:
		return JWKSOutageDecision{
			Acceptable: false,
			Behavior:   b,
			Reason:     "JWKS outage behavior is not fail_closed",
		}
	}
}

// JWKSAvailability models offline JWKS fetch/cache outcomes for contract tests.
type JWKSAvailability string

const (
	// JWKSAvailable — usable key set present.
	JWKSAvailable JWKSAvailability = "available"
	// JWKSUnreachable — network/HTTP failure fetching JWKS.
	JWKSUnreachable JWKSAvailability = "unreachable"
	// JWKSEmpty — document present but no usable keys.
	JWKSEmpty JWKSAvailability = "empty"
	// JWKSNil — caller supplied nil JWKS pointer.
	JWKSNil JWKSAvailability = "nil"
)

// JWKSOutageVerifyResult is whether JWT verification may proceed under outage.
type JWKSOutageVerifyResult struct {
	// MayVerify is true only when keys are available (never on outage/empty/nil).
	MayVerify bool
	// FailClosed is true when verification is refused under unavailability.
	FailClosed bool
	// Reason is a short non-secret explanation.
	Reason string
}

// EvaluateJWKSOutageForVerification is the pure MCP-side contract:
// when JWKS is unavailable, JWT access-token verification must fail closed
// (MayVerify=false). Fail-open (verify without keys) is never allowed.
func EvaluateJWKSOutageForVerification(avail JWKSAvailability) JWKSOutageVerifyResult {
	switch avail {
	case JWKSAvailable:
		return JWKSOutageVerifyResult{
			MayVerify:  true,
			FailClosed: false,
			Reason:     "JWKS available; verification may proceed",
		}
	case JWKSUnreachable, JWKSEmpty, JWKSNil:
		return JWKSOutageVerifyResult{
			MayVerify:  false,
			FailClosed: true,
			Reason:     fmt.Sprintf("JWKS %s: fail closed (do not accept JWT without verification)", avail),
		}
	default:
		return JWKSOutageVerifyResult{
			MayVerify:  false,
			FailClosed: true,
			Reason:     "unknown JWKS availability: fail closed",
		}
	}
}
