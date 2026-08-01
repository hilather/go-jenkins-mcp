# ADR 0006: Official MCP Go SDK pin and protocol versions

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering  
- **Related:** FND-006; architecture §16 quality/conformance notes; [ADR 0002](0002-local-stdio-default.md)  

## Context

The product speaks Model Context Protocol to Cursor and optional gateways. Using an unofficial fork or unpinned SDK risks protocol drift, security gaps, and non-reproducible builds. The seed already depends on the official module `github.com/modelcontextprotocol/go-sdk`.

## Decision

1. **Pin the official SDK** in `go.mod`:

   ```text
   github.com/modelcontextprotocol/go-sdk v1.1.0
   ```

   This is an MIT-licensed, upstream module from the Model Context Protocol org (not a fork).

2. **Declared protocol versions supported by this pin** (from SDK `mcp` package `supportedProtocolVersions` / `latestProtocolVersion` at v1.1.0):

   | Protocol version | Role in SDK v1.1.0 |
   |------------------|--------------------|
   | `2025-06-18` | Latest / preferred negotiate |
   | `2025-03-26` | Supported |
   | `2024-11-05` | Supported (legacy SSE-era baseline) |

3. **Transports we expose:**  
   - **Default:** stdio (`mcp.StdioTransport`) — see ADR 0002.  
   - **Optional:** Streamable HTTP (`mcp.NewStreamableHTTPHandler`) behind explicit `-http` flag only.

4. **Conformance posture:**  
   - Rely on the official SDK’s own server conformance suite at the pinned version for wire JSON-RPC/schema behavior.  
   - Maintain a **repo smoke test** (no live Jenkins): construct `mcp.NewServer`, register tools, in-memory client connect, `ListTools`, and assert negotiated protocol version ∈ declared set.  
   - Maintain an **offline protocol matrix** (Wave 20 / FND-006 residual reduced; no Cursor binary or Docker):
     - `internal/tools/mcp_protocol_matrix_test.go` — Initialize (version + server name), ListTools under RO (mutations absent; sample read tools present), CallTool success (`jenkins_get_jobs` + httptest fixture), invalid args → `invalid_argument` (no secrets), unknown tool fail-closed, CallTool cancel mid-flight.
     - `internal/mcpserver/protocol_matrix_test.go` — loopback `RunHTTP` + Streamable HTTP client Initialize/ListTools.
   - Maintain an **offline stdio binary host-lifecycle smoke** (Wave 25 + Wave 33 / FND-006 residual reduced further; no Cursor product binary or Docker):
     - `make stdio-smoke` → `scripts/mcp-stdio-smoke.sh` + `scripts/mcpstdiosmoke` — build/spawn real `jenkins-mcp` over stdio (`mcp.CommandTransport`), httptest Jenkins, **host-lifecycle matrix**: Initialize + ListTools RO + CallTool success (`jenkins_get_jobs`) / invalid args / unknown tool / cancel mid-flight + ListTools again + shutdown; secret canary. Opt-in (not default unit CI). Uses deprecated `JENKINS_MCP_AUTH` bootstrap so headless hosts need no Secret Service.
   - Full **Cursor product binary / host** stdio lifecycle smoke (startup, discovery, tool calls, cancellation, shutdown against a real Cursor MCP host / `mcpServers` config) remains an integration gate — not automated by unit matrix or offline binary host-lifecycle smoke.

5. **Upgrade / downgrade policy:**  
   - Prefer newest **stable** v1.x after: `go test ./...`, tool schema check, stdio smoke, and note of any protocol version list change in this ADR (amend or supersede).  
   - Do not jump to `v0.x` or replace with a third-party MCP library without a new ADR.  
   - As of this writing, newer stables exist on the module proxy (e.g. v1.7.x line); **we intentionally remain on v1.1.0** until an upgrade is validated against this codebase and the supported Cursor fleet. Record the upgrade in this ADR when performed.  
   - Downgrade below v1.1.0 requires security/architecture review (loss of protocol fixes).

6. **Cancellation:** tool handlers receive `context.Context` from the SDK; handlers and Jenkins client calls must honor cancellation (enforced in later tasks; smoke does not substitute for full cancel integration tests).

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Hand-rolled JSON-RPC MCP | High maintenance; easy non-conformance. |
| Unofficial / community Go MCP forks | Supply-chain and protocol skew risk. |
| Always track latest SDK without pin | Non-reproducible builds; surprise breaks. |
| Immediate upgrade to newest v1.x | Desirable long-term; deferred to keep Phase 0 docs-first and seed-compatible until validated. |

## Consequences

- Builds are reproducible via `go.mod` / `go.sum`.  
- Protocol support matrix is explicit for support docs and Cursor compatibility notes.  
- HTTP mode still needs product hardening (KD-008 / MCP-001); SDK pin does not equal production HTTP safety.  
- Residual: official SDK conformance suite is not re-executed inside this repo’s CI; offline protocol matrix covers Initialize/ListTools/CallTool/cancel/HTTP loopback; Wave 25 + Wave 33 add opt-in **binary** stdio host-lifecycle smoke (**Done***). **Cursor product binary / host stdio CI remains open** (see `docs/packaging.md`, `docs/phase2-progress.md`).

## Module reference

| Field | Value |
|-------|-------|
| Module | `github.com/modelcontextprotocol/go-sdk` |
| Pinned version | `v1.1.0` |
| Import path used | `github.com/modelcontextprotocol/go-sdk/mcp` |
| License | MIT |
