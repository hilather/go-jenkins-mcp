# Gateway 3LO/OBO qualification (GWY-003)

**Status:** Offline (mock) harness shipped — **modes A/B/C matrix Done***; **live AgentCore / Entra / jwt-auth-filter pin residual**.  
**Related:** [README.md](README.md), **[live-pin-blockers.md](live-pin-blockers.md)** (live production GO residual runbook), [auth-architecture.md](../auth-architecture.md) §2.3, ADR 0003, OAUTH-006 claims/revocation, [HOST-011](../roadmap/server-team-hosted.md), [oauth-lab](../../testdata/oauth-lab/README.md).

This document is the **checklist for a live production pin** of AgentCore /
Entra-backed gateway credential acquisition. The offline suite proves local
fail-closed security, **HOST-011 modes A/B/C Obtain shapes**, and isolation
properties without network.

**GWY-001 offline obtain path:** `TokenFetcher` + mock TLS AS / `HTTPTokenFetcher`
prove cache, consent, wrong-audience, and canary-free surfaces without real Entra.
Default provider remains `Live=false` (not_configured). See [README.md](README.md) §3.

**Honesty:** Offline qualify + oauth-lab smoke are **not** live Entra Done.
Do not mark GWY-003 full DoD until production pin evidence is attached.

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
| `mode_a_vault_obtain_basic` | security | **Mode A:** vault Obtain → Basic for subject; cross-subject miss; canary absent from errors/String/Status |
| `mode_b_jwt_vault_bearer` | security | **Mode B:** JWT vault Obtain → Bearer; `id_token` reject; wrong subject miss |
| `mode_c_agentcore_live_matrix` | security | **Mode C (HOST-011):** Live=false → not_configured; Live+mock Fetcher → Bearer; wrong audience fail; ConsentRequired metadata only |
| `host011_no_silent_fallthrough` | security | **HOST-011:** empty Mode B does not use Mode A token; residual Mode B fail closed; A stays Basic / B stays Bearer; invalid mode & primary-not-enabled fail start |
| `oauth009_offline_bearer_matrix` | security | **OAUTH-009:** wrong aud/exp/iss fail closed; ID token reject; OfflineFallthroughFixtures; Mode B empty ≠ Mode A; ModeMatrix residual honesty |
| `oauth010_mode_c_offline_matrix` | security | **OAUTH-010:** auth_code ConsentRequired (URL+session only); token_exchange Bearer; wrong audience; Live=false; Live=true nil Fetcher; ModeMatrix residual; Jenkins-as-AS reject (**not** live Entra Done) |
| `progressive_consent_residual` | security | **OAUTH-010 / GWY-001:** progressive consent residual honesty — browser 3LO not automated; metadata path Done*; ConsentRequired helpers + Error() canary-free |
| `concurrent_obtain_stub_under_budget` | performance | N=32 concurrent stub Obtain under 500ms wall budget |
| `fail_closed_obtain_latency` | performance | Fail-closed Obtain under 50ms |

**Residuals (always printed in JSON summary):**

- Live Entra / AgentCore network acquisition not exercised  
- Live Entra JWKS rotation under load and live IdP outage chaos (offline vault hit/miss + mock IdP outage + JWKS kid-lite + mode A/B/C matrix Done*)
- Mode B live jwt-auth-filter / IdP pin residual (OAUTH-009); offline JWT vault Bearer + claim fail-closed matrix Done* (`oauth009_offline_bearer_matrix`)
- Mode C live Entra 3LO/OBO + AgentCore Identity vault residual (OAUTH-010 / GWY-003); offline prototype matrix Done* (`oauth010_mode_c_offline_matrix` + `mode_c_agentcore_live_matrix`) — **do not claim live Entra Done**
- Mode C progressive consent UX residual (OAUTH-010 / GWY-001): browser 3LO not automated; ConsentRequired metadata path (authorization_url + session_id only) Done*; durable consent session store / multi-replica correlation residual
- OAUTH-010: `HTTPTokenFetcher` https mock AS in package tests (`TestOAUTH010_*` / `TestHTTPTokenFetcher_*`)
- Opt-in residual lab: `testdata/oauth-lab` + `make live-oauth-*` + `go test -tags=live_oauth` Mode C Obtain vs mock-token (TLS test shim; not default `make test`; not production Entra)
- Production P95/P99 token acquisition SLOs  
- Exact-audience JWT passthrough exception process  

Operator CLI residual snapshot (no Obtain): `jenkins-mcp gateway consent-residual`.

### Offline vault / IdP / JWKS kid-lite (Done*)

| Property | Offline evidence | Residual |
|----------|------------------|----------|
| Vault hit | Same caller Obtain ×2 → mock Fetcher call count 1 | Durable AgentCore Identity vault (process memory only today) |
| Vault miss | `Invalidate` / `Cache.Clear` → fetch again; peer user cache intact | Live multi-instance vault |
| IdP outage | Fetcher error / `DeadlineExceeded` / cancel → authentication/timeout/cancelled; no canary; empty cache | Live Entra outage under concurrent tool load |
| IdP recovery | Healthy Fetcher after outage → Obtain + cache hit | Live recovery SLOs |
| JWKS kid rotation | Multi-key `KeyByID` overlap; stale kid after removal fail closed; mock fetcher `key_id` version gate; process-local `RefreshingJWKS` TTL + stale-if-error + optional `JENKINS_MCP_HTTP_JWKS_MAX_STALE` (HOST-001 foundation) | Live Entra under load; multi-instance shared JWKS cache (GWY-003 full pin) |

### HOST-011 modes A/B/C offline matrix (Done*)

Cross-link: package tests in `internal/gateway` (`TestHOST011_*`) already prove auth-header shapes and no silent fallthrough. The qualify suite **invokes the same contracts** so GWY-003 evidence cannot drift.

| Mode | ID | Offline row | Residual |
|------|-----|-------------|----------|
| **A** | `api_token_vault` | `mode_a_vault_obtain_basic` — Basic for vault subject; cross-subject `not_found`; canary-free surfaces | Live Jenkins personal API token lab: `make live-jenkins-*` |
| **B** | `jwt_rs_bearer` | `mode_b_jwt_vault_bearer` — Bearer access token; ID token reject; wrong subject miss | Live jwt-auth-filter pin (OAUTH-009); mock RS: oauth-lab `mock-rs` |
| **C** | `agentcore_3lo_obo` | `mode_c_agentcore_live_matrix` (HOST-011) + `oauth010_mode_c_offline_matrix` (OAUTH-010 flow-mode matrix) — Live=false; Live=true nil Fetcher; auth_code consent metadata only; token_exchange Bearer; wrong audience; ModeMatrix residual honesty | Live Entra 3LO/OBO + AgentCore pin; mock peer: oauth-lab `mock-token` (`make live-oauth-*` HOST-015) |
| **Shared** | no fallthrough | `host011_no_silent_fallthrough` — Mode B empty ≠ Mode A token; invalid mode fail start; primary must be in enabled list | Multi-replica / production mode switch ops evidence |

### OAUTH-010 Mode C prototype matrix vs HOST-011 row

| Case | Why both |
|------|----------|
| `mode_c_agentcore_live_matrix` | HOST-011 Mode C Obtain shape row (shared with modes A/B matrix) |
| `oauth010_mode_c_offline_matrix` | OAUTH-010 named prototype: separates `authorization_code` vs `token_exchange`, Live=true without Fetcher, ModeMatrix residual text, Jenkins-as-AS reject |

Package suite: `go test ./internal/gateway -run TestOAUTH010 -count=1` (includes `HTTPTokenFetcher` mock AS). Docs: [oauth-capability-matrix.md](../auth/oauth-capability-matrix.md) §4.

---

## 2. Live pin checklist (security)

**Consolidated residual runbook (OAUTH-009 / OAUTH-010 / HOST-008 + residual-smoke
honesty):** [live-pin-blockers.md](live-pin-blockers.md). This section remains the
GWY-003-oriented security/performance pin; do **not** mark live Entra Done from
offline qualify alone.

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
| Groups overage | Cap 64; residual note; cannot broaden MCP deny-only. Entra incomplete overage (`_claim_names` without full `groups`) fail-closed foundation Done\*; Graph expansion residual | Security |
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
| `api_token_vault` (Mode A) | Site-optional | Personal API token vault; Basic wire; never shared SA |
| `jwt_rs_bearer` (Mode B) | Site-optional | Jenkins RS Bearer; never ID token as API credential |
| `authorization_code` (3LO, Mode C) | Required for Mode C production | Consent URL propagation; PKCE at AgentCore/Entra |
| `token_exchange` / OBO (Mode C) | Required for Mode C production | Jenkins-audience exchange; personal subject |
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
| Mode misconfig / silent fallthrough | `ModeMatrixFromEnviron` + qualify `host011_no_silent_fallthrough`; fix `JENKINS_MCP_GATEWAY_CREDENTIAL_MODE` / `ENABLED_MODES` |

---

## 6. Merge / acceptance notes (GWY-003 lite)

| Delivered | Residual |
|-----------|----------|
| `internal/gateway/qualify` offline suite (vault hit/miss, IdP outage, JWKS kid-lite, **modes A/B/C**, **HOST-011 no fallthrough**) | Live AgentCore / Entra pin (full GWY-003 DoD) |
| `jenkins-mcp gateway qualify --offline` | Live load/chaos evidence; live JWKS rotation under load |
| Mode matrix evidence linked to HOST-011 package tests | Live jwt-auth-filter version pin (OAUTH-009) |
| This checklist + oauth-lab residual run notes | Signed production mode selection record |

OAUTH-006 (claims, groups, revocation, MCP policy binding) provides the offline
identity/policy matrix that gateway live pin must preserve.

---

## 7. Opt-in oauth-lab residual pin (not default `make test`)

Use the disposable mock lab for **wire-level residual checks** after offline
qualify is green. This is **not** production Entra, not real `jwt-auth-filter`,
and not AgentCore Identity vault.

### Lab map

| Mode | Lab surface | Makefile |
|------|-------------|----------|
| **A** | Jenkins API token compose | `make live-jenkins-up/test/down` → [`testdata/jenkins-compose/`](../../testdata/jenkins-compose/) |
| **B** | `mock-oidc` + `mock-rs` | `make live-oauth-*` → [`testdata/oauth-lab/`](../../testdata/oauth-lab/) |
| **C** | `mock-token` (HTTPTokenFetcher-shaped JSON; HOST-015) | same oauth-lab — opt-in `-tags=live_oauth` Mode C Obtain via TLS **test shim** (lab HTTP residual; not Entra/AgentCore pin) |

### Commands

```bash
# From repository root (Docker required)
export PATH="$HOME/.local/go/bin:$PATH"

make live-oauth-up      # mock-oidc :18081, mock-rs :18082, mock-token :18083
make live-oauth-smoke   # curl smoke (no tokens in logs)
make live-oauth-test    # up + smoke + down -v
make live-oauth-down

# Offline pure-Go authlab (always in default make test path via package tests)
go test -count=1 ./internal/authlab/...
```

### Optional `//go:build live_oauth` package tests (HOST-015)

Mirrors `live_jenkins` opt-in pattern. **Skips** when lab healthz is unreachable
so a bare `-tags=live_oauth` without compose does not fail CI. Not in default
`make test`. Source: `internal/gateway/qualify/live_oauth_stub_test.go`.
Cross-link: [`testdata/oauth-lab/README.md`](../../testdata/oauth-lab/README.md)
(Makefile `live-oauth-*` help targets).

```bash
make live-oauth-up
go test -tags=live_oauth ./internal/gateway/qualify/ -count=1
make live-oauth-down
```

| Env (optional overrides) | Default |
|--------------------------|---------|
| `OAUTH_OIDC_PORT` | `18081` |
| `OAUTH_RS_PORT` | `18082` |
| `OAUTH_TOKEN_PORT` / `OAUTH_LAB_TOKEN_URL` | `18083` / `http://127.0.0.1:18083` |
| `LAB_AUDIENCE` | `jenkins-api` |

| Case (when lab up) | What it proves |
|--------------------|----------------|
| Healthz (token / oidc / rs) | Residual reachability |
| `HTTPTokenFetcher` + raw `http://` lab URL | **Rejected** (production https-only pin) |
| Mode C Obtain success | `HTTPTokenFetcher` + AgentCore Live Obtain + Bearer + cache hit via **TLS test shim** → HTTP mock-token |
| Wrong audience / consent / server_error | Fail closed; consent metadata only; canary-free errors |

**What it does not prove:** Entra Conditional Access, real AgentCore Identity
vault / 3LO browser, production RS plugin version, or production TLS termination
at the lab (compose stays loopback **HTTP**; tests inject a local TLS reverse
proxy so `HTTPTokenFetcher` can run). **Never mark live Entra Done from this tag.**

### Recommended residual order

1. Offline: `go test ./internal/gateway/ ./internal/gateway/qualify/ -count=1`
2. CLI: `jenkins-mcp gateway qualify --offline`
3. Authlab units: `go test ./internal/authlab/...`
4. Opt-in: `make live-oauth-test` + `go test -tags=live_oauth ./internal/gateway/qualify/ -count=1`
5. Full GWY-003 DoD: attach live Entra + AgentCore + jwt-auth-filter evidence (still open) — checklist: [live-pin-blockers.md](live-pin-blockers.md)
