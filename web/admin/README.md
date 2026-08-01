# jenkins-mcp admin console (UI-001)

Reactive operator SPA for day-2 tasks: profiles, policy, metrics, audit, doctor, cache ops.

| Contract | Link |
|----------|------|
| ADR | [docs/adr/0014-admin-console-reactive-spa.md](../../docs/adr/0014-admin-console-reactive-spa.md) |
| Admin BFF API v1 | [docs/admin/api-v1.md](../../docs/admin/api-v1.md) |
| Operator guide | [docs/admin/README.md](../../docs/admin/README.md) |
| Agent policy | [AGENTS.md](../../AGENTS.md) — **keep this SPA current** when product features change |

## Agent hint: stay in sync with product features

When another change adds or alters **operator-relevant** behavior (policy, metrics,
audit, doctor/support-bundle, cache/evict, profiles, packaging), update the
matching page under `src/pages/`, client helpers in `src/api/`, and the BFF
contract (`docs/admin/api-v1.md` + `internal/admin`) in the **same change** —
or document an honest CLI-only residual on the page. Do not leave the console
silently stale. Full rules: root `AGENTS.md` → “Non-negotiable: keep the admin
console current”.

## Stack

- React 18 + TypeScript + Vite
- React Router
- TanStack Query (server state)
- package manager: **npm** (commit `package-lock.json`)

## Prerequisites

- **Node.js ≥ 18** and npm (Tier-1: Rocky Linux / Ubuntu)
- Optional: local admin BFF (`jenkins-mcp admin serve`, UI-002) on `127.0.0.1:8787`

Windows is out of scope (platform matrix).

## Develop

```bash
export PATH="$HOME/.local/node-v22.14.0-linux-x64/bin:$PATH"   # if needed
cd web/admin
npm install
npm run dev
```

Or from repo root:

```bash
make admin-ui-dev
```

Vite serves the SPA (default `http://127.0.0.1:5173`) and proxies `/admin` → `http://127.0.0.1:8787`.

## Production build

```bash
cd web/admin
npm ci
npm run build
# → web/admin/dist  (static assets for UI-002 / UI-008 embed)
```

Or:

```bash
make admin-ui
```

## Tests

```bash
cd web/admin
npm test          # vitest unit smoke (api client helpers)
npm run build     # primary v1 CI smoke: typecheck + production bundle
```

**v1 residual:** CI may treat `npm run build` as the merge-gate smoke when Node is available; full component e2e against the BFF is UI-002+.

## Profile and optional admin token

| Key | Source | Purpose |
|-----|--------|---------|
| Profile id | query `?profile=corp` or `localStorage` key `jenkins-mcp.admin.profile` | Default `corp` |
| Admin token | `localStorage` key `jenkins-mcp.admin.token` | Sent as `Authorization: Bearer` when set |

**Residual / quarantine:** token-in-`localStorage` is **pilot-only** UX (ADR 0014,
HOST-007). **Do not** treat it as production multi-host admin authn — prefer
httpOnly cookie + CSRF or reverse-proxy mTLS/OIDC residual before non-pilot
deploy. Layout shows process role from `GET /admin/v1/me` (UI-003) and a token
field (value never logged). The SPA has **no Jenkins credential fields** and
never displays vault tokens / raw subjects. Multi-user MCP readiness is **not**
signaled by SPA state (no `JENKINS_MCP_GATEWAY_MULTI_USER` pin).

Example (browser console, loopback only):

```js
localStorage.setItem("jenkins-mcp.admin.profile", "corp");
// localStorage.setItem("jenkins-mcp.admin.token", "<from admin serve>"); // never commit
```

## Routes

| Path | Page | API |
|------|------|-----|
| `/` | Overview | `GET /admin/v1/health`, `/version` |
| `/profiles` | Profiles (UI-007) | `GET /admin/v1/profiles`, `/profiles/{id}`, self-check, support-bundle (operator) |
| `/policy` | Policy | `GET /admin/v1/profiles/{id}/policy/effective` |
| `/metrics` | Metrics | `GET /admin/v1/metrics` |
| `/audit` | Audit | `GET /admin/v1/profiles/{id}/audit` |
| `/doctor` | Doctor | `GET /admin/v1/profiles/{id}/doctor?offline=1` |
| `/cache` | Cache (UI-007) | `GET .../cache`, `POST .../cache/evict-plan`, `POST .../cache/evict` (operator) |

### Profiles / Cache pages (UI-007)

- **Profiles:** list + detail (no secrets; `hasCredential` boolean only), offline security self-check, support-bundle preview/create when `/me` has `cache_destructive`.
- **Cache:** quota/usage (`available:false` residual when store missing), non-destructive eviction plan for all roles, destructive evict only when role is operator — double-confirm modal (type `EVICT` twice); server also requires exact `confirm: "EVICT"`.
- **Overview consent purge (HOST-007 Mode C):** `purge_expired` / `delete_session` as usual; destructive **clear_all** requires typing `CLEAR_ALL` (server also requires exact `confirm: "CLEAR_ALL"`; CLI `--all --confirm=CLEAR_ALL`).
- **Doctor:** run button + offline toggle (online needs admin shared secret on the BFF).
- **Doctor:** run button + offline toggle (online needs admin shared secret on the BFF). When the report includes `gateway_residual_status`, a residual card (`shared_subject_rate_file` / `shared_principal_cache_file` / `shared_jwks_file` / `shared_token_cache_file`, principal count honesty, live-pin-blockers pointer) appears after Overall — HOST-007 lite; does not drive overall; never tokens; path values never shown.
- **Residuals:** pin list UI, full cache repair/verify from SPA (use CLI); policy apply (UI-004).

### Metrics page (UI-005)

- Auto-refresh every **15s**; **pauses when the tab is hidden** (`document.visibilityState`) and resumes when visible.
- Manual **Pause / Resume** toggle and **Refresh now**.
- Session **history sparklines** (pure SVG) for preferred counter/gauge names when present, else top values by magnitude. Cap **≤ 60 points** per series (browser memory bound).
- **Export JSON** downloads the current secret-free snapshot as `metrics-snapshot.json` (client-side only).
- **Residual:** process-local registry only; **no multi-process / fleet aggregation** in v1 (MGR-002 residual). Empty maps when the registry is unset are expected.

### Audit page (UI-006)

- Filters: event **type** (text), **limit** (10/50/100/200), optional **before** (`datetime-local` and/or RFC3339 text). Wired to `fetchAudit` query params; react-query key includes filters.
- **Detail drawer** for a selected row — only schema fields present on the event (no invented secret fields; secret-shaped extra keys filtered client-side as defense-in-depth).
- **Load older** uses the last loaded event `time` as exclusive `before` cursor when the page is truncated; accumulates loaded events for export.
- **Export loaded JSON** — client-side download of currently loaded events only (not the full JSONL file).
- Empty / missing audit file messaging stays honest (empty list, not 500).
- **Residual:** no live SSE/WebSocket tail; no CSV export; filters do not invent non-schema fields.

## Frontend license / NOTICE residual

Runtime deps (React, React Router, TanStack Query) are MIT. Full license texts ship under `node_modules/<pkg>/LICENSE` after `npm ci`. A consolidated third-party NOTICE for the admin SPA is **residual** (generate at package/release time or when UI-008 embeds assets). Do not vendor secrets or private keys into this tree.

## Security notes

- No production secrets in frontend env or source.
- Responses are expected secret-free (BFF responsibility; same scrubbing as support-bundle / show-effective).
- Admin HTTP is fail-closed off until explicit `admin serve` (UI-002).
