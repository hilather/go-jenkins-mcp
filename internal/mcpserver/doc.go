// Package mcpserver wraps the official MCP Go SDK: stdio (default) and optional
// Streamable HTTP with localhost / origin / body protections.
//
// Tool registration lives in internal/tools and operates on *mcp.Server.
// Jenkins client packages must not import this package (FND-004).
//
// Transports:
//   - RunStdio — Cursor default (ADR 0002); LoggingTransport to stderr.
//   - RunHTTP  — optional Streamable HTTP behind explicit --http; not pilot default.
//
// HTTP mode is for local debugging and future gateway paths. Optional
// shared-secret gate (HTTPConfig.BearerToken / --http-token-env|--http-token-file)
// is KD-008 lite — transport only, not multi-user identity. HOST-001:
// RequireSubject / gateway / non-local require per-request RequestIdentity from
// lab headers (JENKINS_MCP_LAB_IDENTITY=1) or an IdentityResolver (JWT/JWKS).
// When RequireSubject is on, Mcp-Session-Id binds to IdentityFingerprint on the
// first authenticated request; mid-session subject change fails closed (401).
// IdentityFromContext exposes the accepted RequestIdentity to handlers.
// HOST-002: optional HTTPConfig.PathPrefix / --http-path-prefix /
// JENKINS_MCP_HTTP_PATH_PREFIX mounts MCP under a reverse-proxy path (stripped
// before the SDK); /healthz and /readyz remain at root and under the prefix.
// X-Forwarded-Host / X-Forwarded-Prefix are not trusted by default
// (HTTPConfig.TrustedProxy residual, default false — fail closed).
// AfterIdentity (optional) enriches request context after trusted identity for
// multi-user gateway (Caller + policy.Subject injection by serve). Contract
// tests: multi_user_http_test.go (protect→inner) + multi_user_tools_call_test.go
// (Streamable tools/call Alice/Bob AuthProviderCtx, session-scoped Connect ctx).
// Residual: loopback without require-token/subject still open to local processes;
// continuous JWKS rotation under load incomplete; live Entra residual; live
// edge reverse-proxy origin pin residual; per-POST (intra-session) handler-ctx
// rebind not the multi-user model (session-scoped Connect context is); prefer
// stdio for pilot (ADR 0002).
package mcpserver
