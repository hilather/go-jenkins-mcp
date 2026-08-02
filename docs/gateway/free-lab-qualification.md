# Free-lab qualification bar (product) vs operator production pin

**Status:** Product policy (2026-08-01)  
**Audience:** agents, release owners, operators  
**Related:** [live-pin-blockers.md](live-pin-blockers.md) · [server-team-hosted.md](../roadmap/server-team-hosted.md) · [server-tier-a-jwt-oauth-critical-path.md](../roadmap/server-tier-a-jwt-oauth-critical-path.md) · [product-residuals.md](../security/product-residuals.md)

---

## 1. Two bars (do not collapse them)

| Bar | Who owns it | What “Done” means |
|-----|-------------|-------------------|
| **Product free-lab qualification** | This repository / maintainers | Offline contracts + **opt-in free Docker labs** (Jenkins compose, oauth-lab mocks, Keycloak SAML) green; residual honesty flags stay false for **site production** pins |
| **Operator production pin** | Site security / platform (optional) | Real Entra (or approved AS), real controller `jwt-auth-filter`/proxy version, Conditional Access, multi-pod HA — **only if that site needs it** |

**Unblock rule:** Product engineering is **not** blocked waiting for Microsoft Entra, AgentCore, or a customer’s production Jenkins RS lab. Those are **operator-owned residuals**, not open product DoD for Tier A free-lab GO.

**Honesty rule:** Never set `mode_*_live_*_qualified=true` from free labs or offline smoke alone. Those fields mean **site production live pin**, not “mocks passed.”

---

## 2. Free labs we keep (product SoT)

| Lab | Makefile | What it proves | What it is not |
|-----|----------|----------------|----------------|
| **Mode A** disposable Jenkins | `make live-jenkins-up/test/down` · `testdata/jenkins-compose/` | Personal token / vault Obtain shape against real Jenkins LTS lab | Shared SA, multi-pod |
| **Mode B/C mock OIDC + RS + token** | `make live-oauth-*` · `testdata/oauth-lab/` | Bearer mint, mock RS fallthrough shape, Mode C Obtain wire | Production Entra, production jwt-auth-filter |
| **Mode B real jwt-auth-filter + Keycloak** | `make live-jwt-rs-*` · `testdata/jwt-rs-lab/` | Real plugin + free OIDC IdP Bearer whoAmI + wrong-aud fail-closed | Site Entra / production controller pin |
| **SAML Keycloak** | `make live-saml-*` · `testdata/saml-lab/` | SP config, metadata, trust PEM, group map offline units | Live Entra SAML / full browser ACS pin |
| **Offline gate** | `make test`, `gateway qualify --offline`, `make residual-smoke` | Fail-closed contracts + residual honesty | Network IdP / corp CA |

Default `make test` / `make ci` stay **offline** (no Docker requirement).

---

## 3. What product Tier A free-lab GO requires

- [x] Offline HOST-001…011 / GWY / OAUTH foundations as already Done\* in the critical path  
- [x] Free Mode A lab path available  
- [x] Free Mode B/C mock oauth-lab path available  
- [x] residual-smoke never claims production live qualified  
- [x] Operator production pin documented as **optional residual** ([live-pin-blockers.md](live-pin-blockers.md) § operator-owned)

Optional free extensions (nice-to-have, not product blockers):

- Keycloak **OIDC** + disposable Jenkins + real `jwt-auth-filter` — **Done\*** free lab (`make live-jwt-rs-*`, `testdata/jwt-rs-lab/`)  
- Free-tier Entra **only** when an operator chooses Microsoft-shaped evidence  

---

## 4. Operator production pin (residual — not product open work)

Use [live-pin-blockers.md](live-pin-blockers.md) as a **runbook for sites that need production GO**, not as a list of unfinished open-source tasks.

| Residual | When an operator must close it |
|----------|--------------------------------|
| Entra app reg / CA / JWKS under load | Mode B/C against **their** Microsoft tenant |
| jwt-auth-filter (or proxy) LTS pin | Bearer to **their** Jenkins controllers |
| AgentCore Identity vault | They deploy AgentCore |
| Multi-pod HA (HOST-008) | `replicas` > 1 interactive gateway |

Until they attach evidence, doctor/residual-status correctly report `mode_*_live_*_qualified=false`.

---

## 5. Agent / release language

| Prefer | Avoid |
|--------|--------|
| “Tier A free-lab / offline Done\*” | “Blocked until live Entra” (for product backlog) |
| “Production pin residual (operator-owned)” | “OAUTH-009 incomplete” when free-lab + offline already Done\* |
| Keep free Docker labs current | Invent parallel paid-lab-only gates as product DoD |
| residual-smoke honesty | Flipping live-qualified flags offline |

See also [product-residuals.md](../security/product-residuals.md).
