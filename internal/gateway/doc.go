// Package gateway provides the optional managed-gateway / AgentCore foundation
// (GWY-001/002): credential provider interfaces, config validation that never
// treats stock Jenkins as an OAuth authorization server, token-cache contracts,
// consent URL metadata, pluggable TokenFetcher (offline mock / HTTP), and
// binding of inbound claims to MCP policy subjects (including OAUTH-006 group
// overage residual metadata).
//
// Default construction is fail-closed: NewAgentCoreProvider sets Live=false and
// Fetcher=nil (Obtain → not_configured). Tests and future operators inject a
// TokenFetcher (FuncTokenFetcher mock or HTTPTokenFetcher) and set Live=true
// for an offline-testable obtain path. Live Entra / AgentCore production pin
// remains GWY-003 residual — this package does not call real Entra by default.
// Offline qualification lives in package gateway/qualify (GWY-003 lite).
//
// Architecture pointers:
//   - docs/gateway/README.md
//   - docs/gateway/qualification.md
//   - docs/auth-architecture.md §2.3
//   - ADR 0003 (Jenkins is not an OAuth authorization server)
package gateway
