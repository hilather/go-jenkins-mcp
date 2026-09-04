# ADR 0014: Operator admin console — reactive SPA + local BFF

- **Status:** Accepted (v1 scope)  
- **Date:** 2026-08-01  
- **Owner:** engineering (+ security for authz/CSP)  
- **Related:** UI-000–UI-010, ADR 0002 (stdio default), ADR 0004 (RO + deny-only RBAC), OPS-001, AUD-001, OBS-001  

## Context

Operators need a browser UI for day-2 tasks: effective policy / deny-only MCP RBAC, metrics, audit logs, doctor/cache. Today only CLI exists. The console must not become a second policy engine or put Jenkins/API tokens in the browser. MCP agents continue to use **stdio** (ADR 0002).

## Decision

1. **UI stack:** **React 18+ + TypeScript + Vite** SPA under `web/admin/`. Reactive server state via **TanStack Query** (or equivalent). Alternatives (Vue/Svelte) require a superseding ADR.

2. **Backend:** Dedicated **`jenkins-mcp admin serve`** (not the MCP Streamable HTTP path). Serves:
   - static SPA assets (dev: Vite proxy; prod: `embed` or `--assets-dir`)
   - **Admin BFF** JSON under `/admin/v1/*`

3. **Defaults (fail-closed):**
   - Admin HTTP **off** until explicit `admin serve`
   - Bind **loopback only** by default (`127.0.0.1`)
   - Optional shared secret: `Authorization: Bearer` or `X-Jenkins-MCP-Admin-Token` (constant-time); **required** if non-local residual is ever enabled
   - No CORS wildcard; same-origin when assets and API share the admin server

4. **Authn/z (v1 + UI-003 roles):**
   - **Shared-secret gate** for all `/admin/v1/*` when `--admin-token-env` / file set; when unset on loopback, **warn residual** (document as pilot-only) but still no secrets in responses; configured **role still applies**
   - Console roles via `--admin-role` (`viewer` / `operator` / `policy_admin`): process-wide, separate from MCP deny-only subjects; `GET /admin/v1/me` reports role + permissions; **no role can widen enterprise force_read_only**
   - v1 transport is **Bearer / header token** (not cookies) → **CSRF N/A** for shared-secret; future httpOnly cookie sessions must add CSRF (residual)
   - **Write/policy apply is out of v1 BFF** (UI-004 editor later); permission deny helpers exist and are tested; production write routes not shipped yet

5. **Data rules:**
   - Responses are **secret-free** (same scrubbing rules as support-bundle / show-effective)
   - Never return keyring material, tokens, Authorization headers, log bodies, or full job parameters
   - Audit fields only as defined in `internal/audit.Event`

6. **Separation:** Admin console is **not** MCP tool discovery. Disabling admin does not affect `serve --stdio`.

7. **Platforms:** Rocky/Ubuntu Tier-1 for build/serve; Windows not required.

## v1 HTTP API contract (`/admin/v1`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/v1/health` | Liveness `{status, version, commit, uiBuild?}` |
| GET | `/admin/v1/version` | Binary identity (same fields as `version --json` subset) |
| GET | `/admin/v1/me` | Auth state + role + permissions (no token value; UI-003) |
| GET | `/admin/v1/profiles` | Secret-free profile list (UI-007) |
| GET | `/admin/v1/profiles/{id}` | Secret-free profile detail (UI-007) |
| GET | `/admin/v1/profiles/{id}/policy/effective` | Effective policy (mirror `policy show-effective --json`) |
| GET | `/admin/v1/metrics` | In-process telemetry snapshot if available; else empty counters + residual note |
| GET | `/admin/v1/profiles/{id}/audit?limit=&before=&type=` | Tail/page audit events (cap limit ≤ 200) |
| GET | `/admin/v1/profiles/{id}/doctor?offline=1` | Bounded doctor summary JSON (offline default for safety) |
| GET | `/admin/v1/profiles/{id}/cache` | Cache quota/usage; `available:false` residual when store missing (UI-007) |
| GET | `/admin/v1/profiles/{id}/security-selfcheck` | Offline security self-check (UI-007) |
| POST | `/admin/v1/profiles/{id}/cache/evict-plan` | Non-destructive eviction plan (`read`) |
| POST | `/admin/v1/profiles/{id}/cache/evict` | Destructive evict (`cache_destructive` + `confirm: "EVICT"`) |
| POST | `/admin/v1/profiles/{id}/support-bundle` | Support-bundle preview/create (`cache_destructive`) |

Errors: JSON `{ "code": "<apperr code>", "message": "<safe>" }` with HTTP 4xx/5xx (`authentication`, `permission_denied`, …).

Full narrative: `docs/admin/api-v1.md`.

## Alternatives

| Alternative | Why not for v1 |
|-------------|----------------|
| Embed admin in MCP HTTP `/mcp` | Confuses agent transport with operator UI; larger attack surface |
| Server-rendered only (no SPA) | Weaker reactive UX for metrics/audit live views; still need API |
| Vue/Svelte without ADR | Need single default; React has broad hire/tooling familiarity |
| Full OIDC for admin in v1 | Overkill for loopback pilot; residual later |

## Consequences

- New packages: `internal/admin` (BFF), `web/admin` (SPA), CLI `admin serve`
- Make target `admin-ui` (packaged assets) and `admin-ui-check` (vitest + `tsc` + Vite production build). Merge-gate CI job `admin-ui` (Node 22) is required; Go-only `lint-test-build` does not compile TSX. Release `make admin-ui` is fail-closed (no `continue-on-error`).
- Security review for CSP and token residual on loopback without secret
- UI-003 roles + /me landed; UI-004+ write paths extend this ADR without changing secret-free rules
- **Agents must keep the console current** when shipping operator-relevant features (policy, metrics, audit, doctor/cache, profiles, packaging): update BFF + SPA + `docs/admin/api-v1.md` in the same change or document residual — see root `AGENTS.md`

## Residual

- Non-loopback admin bind
- Multi-tenant gateway admin
- Live multi-process metrics aggregation
- Policy apply/sign from browser (keys remain host-side only; UI-004)
- **Cookie / OIDC sessions:** not in v1; if introduced, require CSRF + httpOnly/secure cookies and logout invalidation (UI-003 residual vs full backlog “session bind”)
- Process-wide single role per `admin serve` (no multi-user session table yet)
- SPA `localStorage` token is pilot-only UX
