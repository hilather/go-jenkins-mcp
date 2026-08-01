# ADR 0001: Package layout and bounded contexts

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering  
- **Related:** architecture §4.3; FND-004; FND-008  

## Context

The seed (`simonfxr/go-jenkins-mcp`) concentrated most behavior in a single large `main.go`. Enterprise work needs independent testability for Jenkins HTTP, MCP tool contracts, auth/keyring, policy, storage, and diagnostics without circular imports or tools issuing raw HTTP.

## Decision

Use a **cmd + internal bounded-context** layout:

```text
cmd/jenkins-mcp/          # process entry, flags, transport selection
internal/app/             # composition / wiring (future)
internal/config/
internal/profile/
internal/auth/
internal/keyring/
internal/jenkins/         # Jenkins API client only — no MCP imports
internal/capabilities/
internal/mcpserver/       # MCP server lifecycle / middleware (future)
internal/tools/           # tool registration + handlers — no raw HTTP
internal/policy/
internal/logmirror/
internal/store/
internal/archive/
internal/search/
internal/diagnostics/
internal/redact/
internal/audit/
internal/telemetry/
internal/update/
pkg/contracts/            # only if stable public contracts are required
```

**Hard package rules:**

1. `internal/jenkins` must not import MCP SDK types or `internal/tools`.  
2. `internal/tools` must not construct raw HTTP requests; it calls the Jenkins client (or higher services).  
3. Storage and archive implementations are replaceable behind narrow interfaces (`ArchiveStore`, etc.).  
4. `cmd/jenkins-mcp` wires dependencies; business logic does not live in `main` long-term.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Keep monolith `main.go` | Blocks unit testing, policy injection, and dual deployment (stdio vs gateway). |
| Public `pkg/` for everything | Over-exposes unstable APIs; prefer `internal/` until contracts stabilize. |
| Shared “utils” dumping ground | Creates hidden coupling across auth, HTTP, and storage. |

## Consequences

- Clear dependency direction supports fail-closed policy and dual transport modes.  
- Refactors can land package-by-package (FND-004 partial → complete).  
- New contributors must respect boundaries; CI package-boundary tests enforce Jenkins/MCP isolation.  
- Residual: not all architecture packages exist yet; empty packages may be added as scaffolding without behavior.
