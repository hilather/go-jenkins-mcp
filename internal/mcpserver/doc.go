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
// Residual: loopback without require-token/subject still open to local processes;
// continuous JWKS rotation under load incomplete; live Entra residual; prefer
// stdio for pilot (ADR 0002).
package mcpserver
