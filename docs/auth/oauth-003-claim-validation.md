# OAUTH-003 offline claim validation matrix

**Status:** Offline unit/fixture matrix **done\*** (Wave 17 polish).  
**Live residual:** Jenkins `jwt-auth-filter` / RS lab and end-to-end bearer principal binding remain **OAUTH-005 / OAUTH-009** (not claimed here).  
**Code:** `internal/auth/jwt.go` (`ValidateAccessToken`), `claims.go` (groups), `live_credentials.go` (`ValidateServeAccessToken`), `oidc_login.go` (login-time JWT check).  
**Tests:** `jwt_test.go` (`TestValidateAccessToken_*`), `claims_test.go`, `live_credentials_test.go`, `rs_qualification_test.go`.

This document is the operator/agent-facing checklist for **MCP-side** access-token
validation. It does **not** replace live RS qualification on the Jenkins controller.

---

## 1. Token form classification

| Form | Heuristic | Local claim validation | Identity binding |
|------|-----------|------------------------|------------------|
| **JWT** | Compact JWS: three base64url segments, header starts with `eyJ` | Full matrix below via JWKS | Claims + AUTH-004 whoAmI at serve |
| **Opaque** | Anything else (reference token) | **Skipped** (no local claims) | **whoAmI only** (AUTH-004) |

Opaque tokens never go through JWT parse. Residual: no RFC 7662 introspection in MVP.

Size bound: raw token must be ≤ **16 KiB** (`MaxAccessTokenBytes`); empty token rejected.

---

## 2. JWT validation matrix (fail closed)

All of the following are enforced offline by `ValidateAccessToken` when form=JWT.
Errors **never** include raw token bytes (scrub + canary tests).

| Check | Behavior |
|-------|----------|
| **JWKS required** | JWT without usable JWKS keys → reject |
| **Algorithm** | Allow-list **RS256**, **ES256** only. **`alg=none`**, empty alg, **HS256**/HS\*, and other algs → reject |
| **Signature** | Verify against JWKS `kid` (unknown kid / wrong key / bad sig → reject) |
| **Issuer (`iss`)** | Exact match to profile issuer (trailing slash trimmed) |
| **Audience (`aud` / `resource`)** | Exact membership of configured **Jenkins** audience (`jenkinsAudience`) |
| **Known-bad audiences** | Profile audience must not be Graph / Graph app id / ARM / similar defaults — rejected even if profile is misconfigured |
| **Subject (`sub`)** | Required non-empty |
| **Expiry (`exp`)** | Required; reject when `now > exp + skew` |
| **Not before (`nbf`)** | When present, reject when `now < nbf - skew` |
| **Clock skew** | Default **60s** (`DefaultClockSkew`) |
| **Tenant (`tid`)** | When profile `tenantID` set → must match |
| **Authorized party** | When profile `clientID` set → `azp` / `appid` / `client_id` must match |
| **ID token rejection** | See §3 — never accepted as Jenkins API bearer |

JWKS rotation: multi-key sets accept tokens for any present `kid`; removed keys fail closed. Multi-issuer: wrong `iss` fails even if signed by a key present in a combined set.

---

## 3. ID token rejection (never Jenkins bearer)

An access token used against Jenkins must **not** be an OIDC **ID token**.
`Session.Secret` / Authorization Bearer always uses **access_token** only; `id_token`
is stored separately on the token bundle and is never sent to Jenkins.

| Signal | Result |
|--------|--------|
| Payload `token_use=id_token` | Reject |
| Payload `typ` indicates `id_token` | Reject |
| Payload `ver` indicates `id_token` | Reject |
| Payload `nonce` present **without** `token_use=access_token` | Reject |
| JOSE header `typ` is `id_token` / `id+jwt` / similar | Reject |
| Header `typ` empty / `JWT` / `at+jwt` | Allowed (not an ID-token signal alone) |

Explicit test: `TestValidateAccessToken_IDTokenShapeRejected` (Entra-like id_token shape).

---

## 4. Known-bad / common-mistake audiences

Rejected as Jenkins audience (case-insensitive match on the known-bad list), including
when the **profile** sets them as `jenkinsAudience`:

| Audience | Why |
|----------|-----|
| `https://graph.microsoft.com` (+ trailing slash / `/.default`) | Microsoft Graph |
| `00000003-0000-0000-c000-000000000000` | Graph application id |
| `https://management.azure.com` (+ slash) | Azure Resource Manager |
| `https://management.core.windows.net/` | Classic Azure management |

Wrong resource tokens that only carry these audiences fail the exact Jenkins audience check;
misconfigured profiles that set Graph as `jenkinsAudience` still fail the known-bad guard.

---

## 5. Where validation is wired

| Path | Behavior |
|------|----------|
| **`LoginOIDC`** | After code exchange: JWT-shaped `access_token` → discovery JWKS + `ValidateAccessToken` before keyring persist. Opaque → skip JWT parse. |
| **`serve` start** | `ValidateServeAccessToken` → discovery JWKS + `ValidateAccessToken` for JWT; opaque → log and continue to whoAmI. |
| **Mid-serve refresh** | New access tokens obtained via refresh are used as bearer; re-validation at next serve restart / residual continuous re-check is not a second validation stack. |
| **Groups (OAUTH-006 light)** | After JWT validation: `GroupsFromValidatedToken` / `ExtractGroups*` with `MaxStoredGroups` (64) and `MaxGroupNameBytes` (256). Count overage: truncate + residual, or fail when `FailOnOverage`. Oversize **names** always fail closed. **Entra group overage foundation (Done\*):** `_claim_names.groups` / `_claim_sources` or groups-as-reference **without** a concrete `groups` array fails closed in `ValidateAccessToken` + `ExtractGroups` (`CheckIncompleteGroupOverage`) — membership never invented; no Graph expansion (OAUTH-010 residual). Hybrid tokens with a full `groups` array keep the current path. |

There is **one** JWT validation stack: `ValidateAccessToken`. Callers must not invent a second parser for production decisions.

---

## 6. Residuals (not closed by this matrix)

| Residual | Task |
|----------|------|
| Live Jenkins `jwt-auth-filter` (or proxy) version pin, fallthrough, route coverage | **OAUTH-005 / OAUTH-009** |
| Live Entra end-to-end browser + bearer whoAmI principal | **OAUTH-005** lab |
| RFC 7662 introspection for opaque tokens | Deferred |
| Multi-instance / under-load JWKS HA beyond process-local `RefreshingJWKS` (HOST-001 TTL + stale-if-error + optional process-local max-stale) | OAUTH-009 / HOST-001 residual |
| Continuous mid-serve JWT re-validation on every refresh | Optional hardening residual |

---

## 7. Verify (offline)

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/auth -count=1 -run 'ValidateAccessToken|ExtractGroups|BoundGroups|ValidateServe'
make test
make lint
```
