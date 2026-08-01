// Package gateway provides the optional managed-gateway / AgentCore foundation
// (GWY-001/002) plus Mode A personal API token vault (HOST-009):
// credential provider interfaces, config validation that never treats stock
// Jenkins as an OAuth authorization server, token-cache contracts, consent URL
// metadata, pluggable TokenFetcher (offline mock / HTTP), per-subject
// APITokenVault (memory/file), and binding of inbound claims to MCP policy
// subjects (including OAUTH-006 group overage residual metadata).
//
// Default construction is fail-closed: NewAgentCoreProvider sets Live=false and
// Fetcher=nil (Obtain → not_configured). Mode A NewAPITokenVaultProvider also
// starts Live=false; RequireAPITokenVaultSetup enables Live for vault Obtain.
// Tests and operators inject a TokenFetcher (FuncTokenFetcher / HTTPTokenFetcher)
// or APITokenVault and set Live=true for offline-testable obtain paths. Live
// Entra / AgentCore production pin remains GWY-003 residual. Offline
// qualification lives in package gateway/qualify (GWY-003 lite).
//
// Architecture pointers:
//   - docs/gateway/README.md
//   - docs/gateway/qualification.md
//   - docs/auth-architecture.md §2.3
//   - docs/roadmap/server-team-hosted.md (modes A/B/C)
//   - ADR 0003 (Jenkins is not an OAuth authorization server)
//   - ADR 0009 (personal API token)
package gateway
