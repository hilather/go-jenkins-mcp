package gateway

import "strings"

// Mode selects how the gateway obtains a Jenkins-audience credential (GWY-001).
//
// Modes describe the intended AgentCore / Entra path only. Stock Jenkins is
// never the authorization server for any mode (ADR 0003).
type Mode string

const (
	// ModeAuthorizationCode is user-delegated 3LO (authorization-code + consent).
	// Consent metadata may be returned; the authorization code and tokens must
	// never be exposed to MCP tools or logs.
	ModeAuthorizationCode Mode = "authorization_code"

	// ModeTokenExchange is RFC 8693-style token exchange for a Jenkins-audience
	// access token (AgentCore OBO path).
	ModeTokenExchange Mode = "token_exchange"

	// ModeOBO is an alias label for on-behalf-of / JWT grant exchange.
	// Prefer ModeTokenExchange in new config; both are accepted.
	ModeOBO Mode = "obo"
)

// Valid reports whether m is a known acquisition mode.
func (m Mode) Valid() bool {
	switch NormalizeMode(m) {
	case ModeAuthorizationCode, ModeTokenExchange:
		return true
	default:
		return false
	}
}

// NormalizeMode maps aliases (obo → token_exchange) and trims whitespace.
func NormalizeMode(m Mode) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(string(m)))) {
	case ModeAuthorizationCode, "auth_code", "3lo":
		return ModeAuthorizationCode
	case ModeTokenExchange, ModeOBO, "token-exchange", "on_behalf_of":
		return ModeTokenExchange
	default:
		return Mode(strings.ToLower(strings.TrimSpace(string(m))))
	}
}

// String returns the canonical mode name.
func (m Mode) String() string {
	n := NormalizeMode(m)
	if n == "" {
		return ""
	}
	return string(n)
}
