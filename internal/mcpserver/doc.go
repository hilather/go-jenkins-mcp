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
// HTTP mode is for local debugging and future gateway paths. It is not a
// production multi-tenant surface. Optional shared-secret gate (HTTPConfig.BearerToken /
// --http-token-env|--http-token-file) is KD-008 lite — not per-user auth.
// Residual: empty token leaves the socket open to local processes; prefer stdio
// (ADR 0002). Never multi-tenant OAuth on this path.
package mcpserver
