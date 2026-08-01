# ADR 0004: Global read-only default and deny-only MCP RBAC

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering (security co-owner)  
- **Related:** architecture §1 KD 4–5, §7; POL-001–POL-005; FND-008  

## Context

Seed tools include mutations (`jenkins_start_job`, `jenkins_stop_build`, etc.). Enterprise pilot requires a hard safety boundary so models and misconfiguration cannot mutate Jenkins unless explicitly enabled. MCP-side controls must never elevate beyond Jenkins permissions.

## Decision

### Global read-only

1. **Default for pilot: read-only is on** (built-in default true).  
2. Effective read-only is **most restrictive wins** across: built-in default, signed enterprise `force_read_only`, profile, `--read-only` / `JENKINS_MCP_READ_ONLY=true`, emergency safe mode.  
3. When read-only is active: mutation tools are omitted from discovery; crafted direct invocations are denied at dispatch and Jenkins-client boundaries; audit records the denial source.  
4. No generic user-facing `--read-write` kill-switch that defeats signed enterprise force flags.

### Deny-only MCP RBAC (future implementation)

1. Effective access is always:

   ```text
   Jenkins permissions
     AND global read-only mode
     AND MCP policy / RBAC
     AND operation budgets
   ```

2. MCP RBAC is **restricting only** (deny / omit). It **cannot grant** access Jenkins denied.  
3. Signed enterprise policy is preferred for fleet control; local profile can only further restrict unless a separately approved mutation framework is enabled.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Discovery-hide only (no dispatch deny) | Crafted JSON-RPC bypass. |
| MCP RBAC as additive grants | Violates “intersection never union”; elevates beyond Jenkins. |
| Default read-write | Unsafe for pilot and model-driven tools. |

## Consequences

- POL-001 landed: default RO, discovery omit of start/stop, dispatch `policy_denial`, enterprise force stub.  
- Deny-only MCP RBAC remains POL-002+; mutations still require a future MUT epic + explicit opt-in that cannot defeat force RO.  
- Tool registry metadata must classify side-effect class for policy.  
- Security review required for any ADR change that weakens RO precedence or introduces elevating RBAC.
