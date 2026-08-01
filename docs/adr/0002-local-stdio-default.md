# ADR 0002: Local stdio as default MCP transport

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering  
- **Related:** architecture §1, §5, §19; FND-006; FND-008; MCP-001; KD-008  

## Context

Cursor’s primary local integration path starts an MCP server as a child process and speaks JSON-RPC over **stdio**. A listening HTTP surface expands attack area (origin, CSRF, body size, multi-tenant session confusion) and is unnecessary for the default per-user pilot.

## Decision

1. **Default transport is stdio** (`-stdio` true when no `-http` address is set).  
2. Cursor configuration uses `command` / `args` / `env` only; no local daemon or port in normal mode.  
3. **Streamable HTTP** remains available only when explicitly enabled (e.g. `-http <addr>`). It is a feature path for managed-gateway or advanced local debugging, not the pilot default.  
4. HTTP mode, when shipped, must gain localhost/origin/body/session protections (MCP-001). **Partial (internal/mcpserver):** loopback bind by default, Host/Origin checks on non-GET, body size cap; residual is unauthenticated socket / no multi-tenant session auth (KD-008). Do not document Streamable HTTP as production-ready multi-tenant.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| HTTP-only local server | Larger attack surface; fights Cursor’s default stdio host model. |
| Always-on dual transport | Accidental open ports; harder fail-closed policy. |
| gRPC / custom wire | Non-standard for MCP hosts; breaks Cursor integration. |

## Consequences

- Pilot packaging and docs emphasize stdio lifecycle, cancellation, and shutdown.  
- Gateway/managed deployment may use Streamable HTTP *after* hardening and identity binding.  
- Residual risk: current seed HTTP path lacks origin/body guards; do not enable on non-loopback interfaces.
