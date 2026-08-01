# ADR 0003: Jenkins is not an OAuth authorization server (no native 3LO)

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering (security co-owner for wording and auth design)  
- **Related:** architecture §1, §6.3–6.7; AUTH-000; FND-008; ADR 0011  

## Context

Enterprise notes and product language sometimes treat “Jenkins OIDC login” as if Jenkins were a three-legged OAuth (3LO) authorization server for third-party clients. That is incorrect for stock Jenkins and misleads implementers into building consent/token flows that Jenkins does not provide.

## Decision

1. **Jenkins core is a protected API / resource server candidate, not a general OAuth authorization server.**  
2. Documentation, ADRs, CLI help, and code comments **must never** describe ordinary Jenkins OIDC UI login, `oic-auth`, `github-oauth`, or similar realms as “MCP 3LO” or “Jenkins-issued OAuth access tokens for third-party apps.”  
3. Supported identity directions:  
   - **Phase 1:** personal Jenkins API token (Basic) from OS credential store.  
   - **Later:** Authorization Code + PKCE against **external IdP** (e.g. Entra); Jenkins validates a **Jenkins-audience** JWT as resource server.  
   - **Gateway:** AgentCore user-delegated 3LO/OBO against the **external** AS, not stock Jenkins.  
4. A full Jenkins authorization-server plugin is **out of baseline scope** and is only a decision-gated contingency (see [ADR 0011](0011-custom-jenkins-authz-plugin-gated.md)).

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Treat Jenkins OIDC UI as 3LO | Wrong protocol role; no authz code/token endpoint contract for MCP clients. |
| Use `oidc-provider` plugin as MCP IdP | Issues workload identity *from builds outward*; opposite direction. |
| Assume custom AS plugin exists | Not funded/approved; see ADR 0011. |

## Consequences

- AUTH-000 and security docs use precise terminology (resource server vs authorization server).  
- Local OAuth work targets Entra/approved IdP + PKCE, not Jenkins consent screens.  
- Reviewers reject PRs or docs that reintroduce “native Jenkins 3LO” claims.  
- Summary for implementers: [`../auth-architecture.md`](../auth-architecture.md).  
- Threat model: [`../security/threat-model.md`](../security/threat-model.md).  
- Jenkins-as-AS default no-go + enforcement: [`../auth/jas-no-go.md`](../auth/jas-no-go.md), [ADR 0013](0013-jas-default-no-go-enforcement.md).  
- Automated terminology guard: `go test ./internal/auth -run Terminology`.
