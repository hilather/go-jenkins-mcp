package apperr

// Code is a stable, machine-readable failure class exposed to tools and hosts.
// Values are snake_case and contract-tested; do not rename without an ADR.
type Code string

const (
	// CodeAuthentication — missing, expired, or rejected credentials.
	CodeAuthentication Code = "authentication"
	// CodeAuthorization — authenticated but not permitted by Jenkins or MCP policy layer mapping.
	CodeAuthorization Code = "authorization"
	// CodeNotFound — resource does not exist.
	CodeNotFound Code = "not_found"
	// CodeCapabilityMissing — controller or plugin capability required for the operation is absent.
	CodeCapabilityMissing Code = "capability_missing"
	// CodeThrottled — rate limited by local policy or upstream.
	CodeThrottled Code = "throttled"
	// CodeTimeout — deadline exceeded.
	CodeTimeout Code = "timeout"
	// CodeCancelled — context cancelled by host or caller.
	CodeCancelled Code = "cancelled"
	// CodeCorruptCache — local cache/index is unreadable or inconsistent.
	CodeCorruptCache Code = "corrupt_cache"
	// CodeQuota — local or remote quota exceeded.
	CodeQuota Code = "quota"
	// CodePolicyDenial — MCP policy or read-only gate denied the action (fail closed).
	CodePolicyDenial Code = "policy_denial"
	// CodeUpstreamProtocol — unexpected HTTP/JSON/protocol from Jenkins or peers.
	CodeUpstreamProtocol Code = "upstream_protocol"
	// CodeInvalidArgument — caller supplied invalid tool arguments (validation).
	CodeInvalidArgument Code = "invalid_argument"
	// CodeInternal — unexpected local failure; prefer a more specific code when known.
	CodeInternal Code = "internal"
)

// AllCodes is the closed set of documented stable codes (contract tests).
func AllCodes() []Code {
	return []Code{
		CodeAuthentication,
		CodeAuthorization,
		CodeNotFound,
		CodeCapabilityMissing,
		CodeThrottled,
		CodeTimeout,
		CodeCancelled,
		CodeCorruptCache,
		CodeQuota,
		CodePolicyDenial,
		CodeUpstreamProtocol,
		CodeInvalidArgument,
		CodeInternal,
	}
}

// Valid reports whether c is a known stable code.
func (c Code) Valid() bool {
	for _, k := range AllCodes() {
		if c == k {
			return true
		}
	}
	return false
}

// DefaultMessage returns a short, safe, model-visible default for the code.
func (c Code) DefaultMessage() string {
	switch c {
	case CodeAuthentication:
		return "authentication failed"
	case CodeAuthorization:
		return "not authorized for this operation"
	case CodeNotFound:
		return "resource not found"
	case CodeCapabilityMissing:
		return "required capability is not available"
	case CodeThrottled:
		return "request throttled; retry later"
	case CodeTimeout:
		return "operation timed out"
	case CodeCancelled:
		return "operation cancelled"
	case CodeCorruptCache:
		return "local cache is corrupt or unreadable"
	case CodeQuota:
		return "quota exceeded"
	case CodePolicyDenial:
		return "denied by policy"
	case CodeUpstreamProtocol:
		return "upstream protocol error"
	case CodeInvalidArgument:
		return "invalid argument"
	case CodeInternal:
		return "internal error"
	default:
		return "error"
	}
}
