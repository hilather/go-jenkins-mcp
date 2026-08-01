# ADR 0009: Personal API token in Linux Secret Service first; external IdP later

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering (security co-owner)  
- **Related:** architecture §6; AUTH-*; FND-008; [ADR 0003](0003-jenkins-not-oauth-authorization-server.md)  

## Context

The MCP must call Jenkins as a **person**, not a shared robot account. Shipping OAuth/PKCE before a working local credential path delays the pilot. Secrets must not live in CLI flags, committed config, or logs.

## Decision

1. **First supported local credential path:** personal Jenkins **username + API token**, stored in the OS secret store.  
2. **Tier-1 secret store:** **Linux Secret Service** (`libsecret` / `org.freedesktop.secrets`) on Rocky/Ubuntu Desktop sessions; document headless/server unlock patterns (session keyring, or policy-controlled protected file only when Secret Service is unavailable).  
3. **Tier-2:** macOS Keychain only when the optional macOS build is exercised.  
4. **Forbidden as primary enterprise examples:** long-lived secrets in argv, plaintext config in git, shared/generic service accounts for interactive users.  
5. Environment-variable secrets (e.g. seed `JENKINS_MCP_AUTH`) are **compatibility / transition only**, policy-controlled, and omitted from enterprise happy-path docs.  
6. **Later:** Authorization Code + PKCE against external IdP (Entra); refresh material in keyring; access tokens in memory; Jenkins as resource server. External IdP does not replace the need for per-user identity.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| OAuth-only at day one | Blocks pilot; depends on IdP + Jenkins JWT filter readiness. |
| Shared bot token in config | Prohibited identity model; audit and blast-radius failure. |
| Secrets only in env vars | Leak via process listings, crash dumps, support bundles. |

## Consequences

- `login` / keyring tasks implement Secret Service before Entra PKCE UX.  
- Seed CLI `-auth` / env remain temporary; enterprise path migrates off them.  
- Canary tests must ensure tokens never appear in logs, errors, or MCP results.
