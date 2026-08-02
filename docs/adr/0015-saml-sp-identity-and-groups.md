# ADR 0015: SAML 2.0 service provider for identity + groups (POL-007)

- **Status:** Accepted  
- **Date:** 2026-08-01  
- **Owner:** engineering + security  
- **Related:** POL-007, POL-006, UI-003 residual, ADR 0003, ADR 0004, ADR 0014  

## Context

Enterprises often standardize on **SAML 2.0** for workforce SSO and group membership. The product already has:

- Deny-only MCP RBAC with **per-user/group bindings** (POL-006)
- Gateway JWT/OIDC group foundations (OAUTH-006)
- Admin console process-wide shared secret + role (UI-003 v1)

Operators need SAML as an **identity source** for admin SSO and (optionally) gateway bind — without a local user/password directory, and without treating Jenkins as a SAML IdP or OAuth AS (ADR 0003).

Multi-fleet sites need **config-managed** SP settings and group→role maps (gitops / signed files), not per-pod mutable user tables.

## Decision

1. **SAML role:** Product is a **SAML 2.0 Service Provider (SP)** only.  
   - Jenkins is **never** the SAML IdP or authorization server for MCP.  
   - Stock Jenkins is **not** AS (ADR 0003 / ADR 0013 continuity).

2. **Configuration SoT (multi-fleet):** SP settings, attribute map, and IdP-group → admin console role map live in **versioned configuration** (JSON file under XDG / env path). Secrets (SP signing/decryption keys) come from **env or secret-store files** (mode 0600) — never argv, never committed plain config.

3. **Identity mapping:** After **fail-closed** assertion validation (signature, issuer, audience/SP entity ID, recipient/ACS, NotBefore/NotOnOrAfter), map attributes →:
   - subject string (NameID or configured attribute; length-capped; never tool-arg spoofable)
   - groups (multi-value attribute; **FailOnOverage** default; never invent membership)
   - optional tenant/issuer pin

4. **POL-006:** Mapped groups feed `policy.Subject.Groups` so overlay `subjects.groups[]` denials apply after bind — same most-restrictive merge as gateway/JWT groups.

5. **Admin SSO:** When SAML is enabled for admin:
   - Unmapped groups → **deny** (fail closed; no silent elevation to process `--admin-role`)
   - Mapped group → console role (`viewer` | `operator` | `policy_admin`)
   - Shared-secret Bearer remains optional **complement** when SAML not required; when `saml.require=true`, unauthenticated callers cannot fall through to open loopback API
   - Session residual: process-local signed cookie session lite (not multi-pod HA)

6. **Secret-free forever:** Assertion XML, raw oversize NameIDs, signatures, cookies/tokens never in audit/logs/MCP/admin JSON. Use redacted subject labels / `audit.HashOpaque` for correlation.

7. **Offline lab:** Opt-in mock IdP fixtures under `testdata/saml-lab/` + Makefile; default `make test` stays offline without the lab. **Live Entra/Okta/ADFS pin remains residual** (mock ≠ production GO).

8. **Package:** Pure logic lives in `internal/saml` (stdlib crypto + XML). Admin BFF wires ACS/status under `/admin/v1/saml/*`. UI-011 SPA CRUD remains residual.

## Alternatives considered

| Option | Why rejected |
|--------|----------------|
| Local user/password DB for SAML users | Contradicts multi-fleet design; IdP owns accounts |
| Jenkins as SAML IdP / mint API tokens via SAML | ADR 0003 / product non-goal |
| Full crewjam/saml stack as only path | Heavier dep surface; still need fail-closed product rules — pure validate+map first |
| SPA-only user management without config SoT | Diverges multi-fleet (UI-011 residual only) |

## Consequences

**Benefits:** Config-managed multi-fleet SSO; POL-006 groups from SAML; admin role maps without inventing membership; residual honesty for live IdP.

**Costs:** ACS/browser interop residual depth; cookie CSRF when cookie sessions ship; operators must maintain SP metadata + role maps in config.

**Residuals:** Live IdP pin; encrypted assertions; multi-pod shared session store; full UI-011 Access SPA; `admin_saml_*` MCP tools (MCP-OPS residual until added).

## Owner

Engineering (implementation) · security (authn fail-closed review)
