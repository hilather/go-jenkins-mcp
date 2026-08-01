# ADR 0013: Jenkins-as-authorization-server default no-go is enforced in code

- **Status:** Accepted  
- **Date:** 2026-08-01  
- **Owner:** engineering (security co-owner for auth wording)  
- **Related:** [ADR 0003](0003-jenkins-not-oauth-authorization-server.md), [ADR 0011](0011-custom-jenkins-authz-plugin-gated.md), [JAS-001 threat model](../auth/jas-no-go.md), OAUTH-011, architecture §6.6–6.7  

## Context

ADR 0003 and ADR 0011 establish that stock Jenkins is not a native 3LO authorization server and that a full Jenkins-hosted AS plugin is decision-gated with **default no-go**. Operators can still mis-point OIDC issuer or AgentCore AS URLs at the Jenkins controller. Documentation alone is insufficient; configuration validation must fail closed.

## Decision

1. **Default remains no-go** for Jenkins as OAuth authorization server (reaffirm ADR 0011).  
2. Canonical pure helper: `auth.RejectJenkinsAsAuthorizationServer(jenkinsURL, asURL)` rejects co-hosted AS/issuer/endpoint URLs (same controller host).  
3. **Must** be applied by:  
   - local profile OIDC validation (issuer host ≠ Jenkins host)  
   - OIDC discovery endpoint validation  
   - gateway AgentCore AS base URL and absolute authorize/token endpoints  
   - offline doctor check `jenkins_as_as` for structural misconfiguration  
4. Preferred AS endpoints remain **Entra / approved external IdP** (and AgentCore providers that point at those), not stock Jenkins.  
5. Full AS plugin work (JAS-002…005) proceeds **only** after an OAUTH-011 **go** decision; this ADR does not authorize that implementation.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Docs-only prohibition | Misconfiguration ships until first runtime failure; high support cost. |
| Allow Jenkins issuer “for labs” | Lab shortcuts leak into profiles; fail closed with test fixtures using separate hosts. |
| Implement full Jenkins AS now | Scope explosion; ADR 0011 default no-go. |

## Consequences

- Capability matrix path `custom_jenkins_as_plugin` stays `no_go_default`.  
- Threat model and conditional protocol profile live in [`docs/auth/jas-no-go.md`](../auth/jas-no-go.md).  
- Tests: `go test ./internal/auth -run 'RejectJenkins|JASNoGo|Terminology|Capability'`, gateway config reject cases, profile Jenkins-as-issuer, doctor `jenkins_as_as`.  
- Residual: JAS-002…005 and live security sign-off for a future **go** remain unstarted under default no-go.
