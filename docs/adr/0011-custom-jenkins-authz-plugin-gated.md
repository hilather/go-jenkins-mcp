# ADR 0011: Custom Jenkins authorization-server plugin is decision-gated

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering (security co-owner; funding gate with product)  
- **Related:** architecture §6.6–6.7; AUTH-000; FND-008; [ADR 0003](0003-jenkins-not-oauth-authorization-server.md); [ADR 0013](0013-jas-default-no-go-enforcement.md); [JAS-001](../auth/jas-no-go.md)

## Context

Some gateway contracts might appear to require Jenkins itself to expose OAuth authorization-server endpoints (consent, codes, tokens). Building that inside Jenkins is a **separate security product**, not a minor MCP feature. Assuming it exists would mis-scope the pilot.

## Decision

1. **Do not assume** a custom Jenkins OAuth **authorization server** plugin in baseline architecture, schedules, or “supported auth modes.”  
2. Qualification order remains:  
   1. External IdP + Jenkins JWT resource-server validation  
   2. AgentCore user-delegated 3LO against **Entra** (AS endpoints are Entra’s)  
   3. OBO / token exchange for Jenkins-audience tokens  
   4. Narrow broker / exchange endpoint if required  
   5. **Only then**, a full Jenkins AS plugin if (and only if) a **funded security-owner decision** explicitly approves it  
3. Prefer a **narrow resource filter or token-exchange endpoint** over a full AS if a plugin is inevitable.  
4. If full 3LO-on-Jenkins is approved, the plugin backlog must include consent, client registration, redirect validation, token issuance/rotation/revocation, scopes, audit, and secure storage — tracked as its own epic with security review, not as a checkbox inside MCP tool work.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Build full Jenkins AS in MCP timeline | Scope explosion; critical security surface without owners. |
| Pretend stock Jenkins is already an AS | False claims; broken integrations (ADR 0003). |
| Forever forbid any Jenkins plugin | Too absolute; leave gated contingency for true gateway blockers. |

## Consequences

- AUTH and gateway docs mark the plugin as **conditional / decision-gated**.  
- No code path depends on Jenkins issuing OAuth access tokens to MCP clients unless the gate passes.  
- Product language distinguishes AgentCore-Entra 3LO (approved direction) from Jenkins-as-AS (contingency only).
