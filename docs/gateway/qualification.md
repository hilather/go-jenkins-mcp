# Gateway 3LO/OBO qualification (GWY-003)

**Status:** Offline (mock) harness shipped — **live AgentCore pin residual**.  
**Related:** [README.md](README.md), [auth-architecture.md](../auth-architecture.md) §2.3, ADR 0003, OAUTH-006 claims/revocation.

This document is the **checklist for a live production pin** of AgentCore /
Entra-backed gateway credential acquisition. The offline suite proves local
fail-closed security and isolation properties without network.

**GWY-001 offline obtain path:** `TokenFetcher` + mock TLS AS / `HTTPTokenFetcher`
prove cache, consent, wrong-audience, and canary-free surfaces without real Entra.
Default provider remains `Live=false` (not_configured). See [README.md](README.md) §3.

---

## 1. Offline harness (available now)

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/gateway/ ./internal/gateway/qualify/ -count=1
jenkins-mcp gateway qualify --offline   # JSON summary, no secrets
```

| Case | Category | What it proves |
|------|----------|----------------|
| `jenkins_as_as_rejected` | security | AS origin cannot be stock Jenkins |
| `wrong_audience_rejected` | security | Resource audience mismatch fails closed |
| `wrong_subject_binding_rejected` | security | Bound subject cannot swap mid-session; tool args cannot impersonate |
| `subject_binding_contracts` | security | GWY-002: missing tenant/workload/subject/profile fail closed; env principal ≠ whoAmI deny; Valid() only with Jenkins principal; group overage fail-closed default |
| `token_never_in_errors` | security | Canary token absent from errors/String() |
| `consent_url_has_no_token` | security | Consent metadata has URL + session id only |
| `cross_user_cache_isolation` | security | Token cache keyed by user/workload/profile |
| `vault_hit_miss` | security | Live+Fetcher: second Obtain is cache hit (fetch count); Invalidate/Clear force miss; cross-user isolation holds |
| `idp_outage_chaos` | security | Mock IdP error/timeout/cancel → fail closed, no token, canary absent; recovery succeeds |
| `jwks_key_rotation_lite` | security | Offline JWKS kid selection + outage fail-closed contracts; mock fetcher rejects stale `key_id` (**partial** — not live Entra JWKS under load) |
| `concurrent_obtain_stub_under_budget` | performance | N=32 concurrent stub Obtain under 500ms wall budget |
| `fail_closed_obtain_latency` | performance | Fail-closed Obtain under 50ms |

**Residuals (always printed in JSON summary):**

- Live Entra / AgentCore network acquisition not exercised  
- Live Entra JWKS rotation under load and live IdP outage chaos (offline vault hit/miss + mock IdP outage + JWKS kid-lite Done*)
- Production P95/P99 token acquisition SLOs  
- Exact-audience JWT passthrough exception process  

### Offline vault / IdP / JWKS kid-lite (Done*)

| Property | Offline evidence | Residual |
|----------|------------------|----------|
| Vault hit | Same caller Obtain ×2 → mock Fetcher call count 1 | Durable AgentCore Identity vault (process memory only today) |
| Vault miss | `Invalidate` / `Cache.Clear` → fetch again; peer user cache intact | Live multi-instance vault |
| IdP outage | Fetcher error / `DeadlineExceeded` / cancel → authentication/timeout/cancelled; no canary; empty cache | Live Entra outage under concurrent tool load |
| IdP recovery | Healthy Fetcher after outage → Obtain + cache hit | Live recovery SLOs |
| JWKS kid rotation | Multi-key `KeyByID` overlap; stale kid after removal fail closed; mock fetcher `key_id` version gate | Live JWKS fetch/cache TTL/rotation under load (GWY-003 full pin) |

---

## 2. Live pin checklist (security)

Complete before enabling `CredentialProvider.Live` / production gateway mode.

| Gate | Evidence | Owner |
|------|----------|-------|
| Jenkins never configured as AS | Config validation + deployment review; ADR 0003 | Platform |
| Audience = exact Jenkins API resource | Token `aud` canary tests against live Entra app registration | Security |
| Subject / tenant / workload binding | OBO exchange maps to personal Jenkins principal; no shared SA | Security |
| Cross-user / cross-workload isolation | Cache, vault, audit correlation ids; no token reuse | Security |
| Consent replay / session binding | Authorization-code state/nonce; one-time code | Security |
| Revocation / refresh failure | IdP revoke + refresh fail → subsequent tool path fails closed (OAUTH-006) | Security |
| Invalid bearer no downgrade | No fallthrough to Basic/API-token/session/anonymous on OAuth-required routes | Security |
| Token never in logs/errors/MCP | Canary redaction tests on live traffic samples | Security |
| Groups overage | Cap 64; residual note; cannot broaden MCP deny-only | Security |
| Generic passthrough disabled | Production config audit; exact-audience exception recorded | Security |

---

## 3. Live pin checklist (performance)

| Gate | Target (starting point) | Evidence |
|------|-------------------------|----------|
| Token acquisition P95 (cold) | Fit tool SLO budget (document measured ms) | Load test + provider breakdown |
| Token acquisition P95 (cache hit) | << cold path; vault/memory hit metrics | Metrics |
| Fail-closed path | Fast reject (no multi-second hangs on bad config) | Chaos |
| Concurrent Obtain | Isolation under concurrent users; no shared token | Load |
| Jenkins call overhead with gateway identity | No unacceptable auth latency vs API-token baseline | A/B |

Offline concurrent stub budget (`ConcurrentObtainBudget` = 500ms for N=32) is a
**local CI guard only**, not a substitute for live SLO evidence.

---

## 4. Modes under test

| Mode | Live pin | Notes |
|------|----------|-------|
| `authorization_code` (3LO) | Required | Consent URL propagation; PKCE at AgentCore/Entra |
| `token_exchange` / OBO | Required | Jenkins-audience exchange; personal subject |
| Exact-audience JWT passthrough | Exception only | More restrictive than OBO; recorded approval |
| Generic token / Graph audience | **Disabled** | Never send to Jenkins |

---

## 5. Runbook hooks (incidents)

| Incident | Operator action |
|----------|-----------------|
| Consent / reauth storm | Check AS health; force reauth; do not widen cache TTL |
| JWKS / IdP outage | Fail closed; no anonymous/API-token downgrade on OAuth profiles |
| Suspected token leak | Rotate app credentials; invalidate vault/cache; audit canary |
| Cross-user isolation suspicion | Drain gateway; inspect cache keys; revoke sessions |
| Jenkins-as-AS misconfig | Config validation rejects; fix env to Entra AS |

---

## 6. Merge / acceptance notes (GWY-003 lite)

| Delivered | Residual |
|-----------|----------|
| `internal/gateway/qualify` offline suite (incl. vault hit/miss, IdP outage chaos, JWKS kid-lite) | Live AgentCore pin (full GWY-003 DoD) |
| `jenkins-mcp gateway qualify --offline` | Live load/chaos evidence; live JWKS rotation under load |
| This checklist | Signed production mode selection record |

OAUTH-006 (claims, groups, revocation, MCP policy binding) provides the offline
identity/policy matrix that gateway live pin must preserve.
