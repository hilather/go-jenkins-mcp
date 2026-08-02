# Threat model and data classification (SEC-001)

**Status:** Draft for security/platform review (Phase 0 lock)  
**Related:** [auth architecture](../auth-architecture.md), [ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md), architecture §§1, 6, 19  
**Deployments:** local per-user stdio (default) and optional managed gateway  

This document turns product assumptions into a reviewable control map. It is
intentionally concise; detailed auth flows live in `docs/auth-architecture.md`.

---

## 1. Assets

| Asset | Sensitivity | Location (typical) | Notes |
|-------|-------------|--------------------|-------|
| Jenkins API tokens / bearer access tokens | Secret | OS keyring (local); vault under user+workload (gateway) | Never CLI argv, git, logs, MCP results |
| OAuth refresh material | Secret | OS keyring / gateway vault | Memory-only access tokens preferred |
| Cache AEAD keys (ARC-009) | Secret | OS keyring (`cache_aead` per profile/version) | Never profile JSON, packs, logs, MCP, support bundles |
| Profile non-secret config | Internal | User config dir | Origins, auth method, policy refs; no secrets |
| L1 log frames / L2 seekable packs | Sensitive / untrusted | Per-user/profile cache | Build logs + artifacts; treat as untrusted input; optional L1 AEAD |
| SQLite metadata / indexes | Internal–sensitive | Per-user cache | No tokens; may index paths/refs |
| Policy / RBAC bundles | Integrity-critical | Signed overlay + local profile | MCP deny-only; never elevates Jenkins allow |
| Audit events | Sensitive | Local audit sink / gateway audit | Principal, action, decision; no secrets |
| Telemetry (opt-in/policy) | Internal | Redacted metrics | No raw logs, tokens, or full job paths if classified |
| TLS trust / proxy CA config | Integrity | Profile / system trust | Wrong CA → MITM risk |

---

## 2. Actors

| Actor | Trust posture |
|-------|----------------|
| Local OS user | Trusted for own keyring, cache, and process; not for other users |
| Cursor / model | Untrusted for policy elevation; tools must bound and redact output |
| MCP process (`jenkins-mcp`) | Trusted computing base for local mode; enforces policy ∩ budgets ∩ RO |
| Jenkins controller | Remote peer over HTTPS; may be compromised or misconfigured |
| External IdP (e.g. Entra) | Authorization server for browser/PKCE and gateway 3LO/OBO |
| Optional managed gateway / AgentCore | Trusted only under gateway threat model; must bind per-user credentials |
| Network attacker | Untrusted; TLS, origin pinning, no cleartext secrets |
| Shared/generic Jenkins SA | **Prohibited** for interactive users (not a supported actor) |

---

## 3. Trust boundaries

```text
[ Cursor / model ]
        |  MCP stdio (local) — tool args/results, no secrets in either direction
        v
[ jenkins-mcp process | per-OS-user ]
   | keyring        | profile config   | cache/store     | policy/audit
   | (Secret        | (non-secret)     | (user-private)  | (signed deny-
   |  Service)      |                  |                 |  only overlays)
   |
   | HTTPS + personal credential (API token Basic or Jenkins-audience Bearer)
   v
[ Jenkins resource server ]
   ^
   | OAuth AS endpoints are IdP/Entra (or approved AS), NOT stock Jenkins
[ External IdP ]
```

| Boundary | Control intent |
|----------|----------------|
| OS user ↔ keyring | Secret Service (Tier 1); profile isolation; no cross-user credential share |
| Cursor ↔ MCP (stdio) | No long-lived secrets in Cursor config; budgets on tool results; redaction |
| MCP ↔ Jenkins (HTTPS) | Origin allow-list, TLS verify, personal identity only, route inventory |
| MCP ↔ IdP | PKCE/loopback for local OAuth later; AS endpoints never stock Jenkins |
| Profile A ↔ Profile B | Separate credential, cache namespace, audit identity |
| Local mode ↔ Gateway mode | Separate credential providers; same policy contracts; no shared SA |

---

## 4. Data classes

| Class | Examples | Handling |
|-------|----------|----------|
| **Secrets** | API tokens, bearer/refresh tokens, client secrets if any | Keyring/vault; never logs/errors/MCP/argv/git |
| **Build logs / artifacts (untrusted + often sensitive)** | Console text, stack traces, env dumps, secrets accidentally printed | Bounded progressive transfer; treat as untrusted model input; SEC redaction; retention/quota |
| **Metadata** | Job/build refs, status, timestamps, stage names | Cache with user ACL; may still be sensitive by path |
| **Policy / integrity** | Signed RBAC, RO flags, budgets | Verify signature; fail closed on unknown fields |
| **Audit** | Who/what/denied/allowed | Retain per policy; no secret payloads |
| **Telemetry** | Counters, latencies, error codes | Aggregate/redact; off by default or policy-gated |

**Retention / export (baseline):** cache and audit retention are policy-defined; export/support bundles must scrub secrets and respect sensitivity; affinity packs stay inside the same profile isolation boundary.

---

## 5. Threats and control mapping

High/critical items map to backlog families. “RO kill switch” = global read-only true wins everywhere.

| Threat | Local | Gateway | Controls / backlog |
|--------|-------|---------|--------------------|
| Credential theft from argv/config/logs | Y | Y | AUTH-001.., SEC redaction, keyring ADR 0009 |
| Shared SA / credential substitution | Y | Y | AUTH-000, SEC-001 prohibition, per-subject vault |
| Cross-user/profile cache or handle leak | Y | Y | STO-001 isolation, profile namespaces |
| Prompt injection via Jenkins logs/tools | Y | Y | SEC redaction, budgets (MCP), untrusted-input posture |
| SSRF / open redirects via Jenkins URLs | Y | Y | NET origin allow-list, no arbitrary fetch |
| Wire / decompression bombs | Y | Y | NET/STO bounded reads; independent zstd frames |
| Archive corruption / bomb | Y | Y | STO checksums, decode limits, ARC-* |
| Local disk disclosure of L1 frames | Y | Y | ACL + FDE assumed; optional ARC-009 AEAD (see cache-encryption.md) |
| Cache key loss / revocation | Y | Y | Fail closed reads; N/N-1 rotation lite; no sync rewrite required |
| Bearer invalid → Basic/anon fallthrough | Y* | Y* | AUTH/OAUTH route coverage; jwt-auth-filter harden |
| Wrong audience / issuer JWT accepted | Y* | Y* | OAUTH jwt validation; exact Jenkins audience |
| OAuth consent/session replay | Y* | Y* | PKCE, state/nonce, short-lived tokens (OAUTH-*) |
| Policy bypass / elevation via MCP RBAC | Y | Y | POL deny-only; ∩ with Jenkins allow |
| Mutation when RO intended | Y | Y | RO kill switch; POL; omit mutation tools |
| Gateway vault cross-tenant mix-up | — | Y | GWY subject+workload binding, isolation tests |
| Network MITM | Y | Y | TLS verify, pinned origins, NET-* |
| Jenkins compromise | Y | Y | Assume malicious content; limit blast radius (RO, budgets) |
| Update / supply-chain tamper | Y | Y | Signed packages, pin SDKs, ARC ratarmount qualification |

\* OAuth-related rows apply when external-IdP or gateway 3LO/OBO is enabled (not Phase-1 API-token-only).

### Identity-path risk distinctions

| Path | Main residual risks |
|------|---------------------|
| Personal API token (first production) | Token exfil from keyring/session; over-scoped Jenkins user rights |
| External IdP → Jenkins-audience JWT (resource server) | Wrong aud/iss; filter fallthrough; incomplete route coverage |
| AgentCore 3LO/OBO vs **Entra** (not Jenkins AS) | Vault binding failures; consent replay; OBO mis-audience |
| Exact-audience JWT passthrough | Accepting non-Jenkins or generic gateway tokens |
| Conditional full Jenkins 3LO plugin (default **no-go**) | Full AS surface (consent, issuance, storage) — see [jas-no-go.md](../auth/jas-no-go.md); epic only after OAUTH-011 **go** |

---

## 6. Local vs gateway differences

| Topic | Local stdio | Managed gateway |
|-------|-------------|-----------------|
| Process trust | Same OS user as Cursor | Multi-tenant service near Jenkins |
| Credential store | Linux Secret Service (Tier 1) | Per-user (+ workload) vault |
| Transport to MCP | stdio | Gateway-approved MCP transport |
| Network to Jenkins | User network / VPN | Often low-latency near controller |
| Auth acquisition | API token; later local PKCE to IdP | AgentCore 3LO/OBO to Entra → Jenkins-audience token |
| Isolation unit | OS user + profile | Tenant/user/workload + profile policy |
| Shared SA | Forbidden | Forbidden |
| Extra threats | Malware as user, misplaced cache paths | Confused deputy, cross-user vault, gateway admin abuse |

Both modes share: fail-closed intersection authz, RO kill switch, deny-only MCP policy, no secrets in tool results, and **Jenkins is never documented as a native 3LO authorization server**.

---

## 7. Assumptions

1. Interactive use is **per-person** Jenkins identity only.  
2. Effective access = Jenkins allow **∧** global read-only **∧** MCP policy **∧** budgets.  
3. Stock Jenkins is a **resource server** candidate, not an OAuth authorization server (ADR 0003).  
4. Tier-1 clients are Rocky Linux + Ubuntu only; macOS and Windows out of scope.  
5. Policy overlays are restricting only; production fleets use signed Ed25519
   envelopes (MGR-001) with last-good anti-rollback.  
6. Build logs/artifacts may contain secrets and hostile content.  
7. Optional gateway is a separate deployment with its own review, not a weaker local mode.

---

## 8. Out of scope (baseline)

| Item | Rationale |
|------|-----------|
| Windows native client | No native FUSE; platform matrix (ADR 0008) |
| Shared / generic service accounts for interactive users | Audit and blast-radius failure |
| Treating Jenkins UI OIDC / `oic-auth` as MCP 3LO | Wrong protocol role |
| Full Jenkins-hosted OAuth AS plugin | Decision-gated contingency (ADR 0011); default no-go |
| Unbounded log download into model context | Budgets + progressive mirror design |
| Elevating access via MCP RBAC | Deny-only by design |

---

## 9. Residual / owner actions

- [ ] Security/platform **owner sign-off** on this model (acceptance criterion).  
- [ ] Keep control→task map current as AUTH/POL/NET/STO/SEC/OAUTH land.  
- [ ] Gateway-specific deep dive when GWY/OAUTH epics start (extends §6, not a rewrite).  

**Doc evidence for SEC-001 (agent):** assets, actors, boundaries, data classes, control map, identity-path split, local vs gateway, assumptions, out-of-scope, shared-SA prohibition.
