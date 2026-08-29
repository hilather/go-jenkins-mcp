# Release notes — v0.8.0 (loopback admin console)

**Date:** 2026-08-29  
**Tag:** `v0.8.0`  
**Baseline:** continues `v0.7.0`  
**Merge commits:** [PR #24](https://github.com/hilather/go-jenkins-mcp/pull/24) (admin SPA); fail-closed [PR #13](https://github.com/hilather/go-jenkins-mcp/pull/13)–[PR #21](https://github.com/hilather/go-jenkins-mcp/pull/21); toolchain [PR #22](https://github.com/hilather/go-jenkins-mcp/pull/22); docs [PR #23](https://github.com/hilather/go-jenkins-mcp/pull/23) · [PR #25](https://github.com/hilather/go-jenkins-mcp/pull/25)

> Absolute HTTPS links only (pinned to this tag). Default pilot remains **read-only** local stdio. Admin HTTP (`jenkins-mcp admin serve`) and admin MCP stay **opt-in**. Mutations stay **off** unless `--allow-mutations`. This release does **not** claim live Entra pin, multi-pod HA, `site/` docs marketing, fleet graphs, or an SPA `/login` route.

## Highlights

### Loopback admin console SPA (PR #24)

Operator chrome for the **loopback** admin SPA under `web/admin` only (React + Vite; ADR 0014). Grouped rail **Status / Config / Ops**; dark-lab tokens + self-hosted IBM Plex (no CDN). Residual voice is a badge + one-line caveat + HOST-* details. Profile id and admin Bearer stay in the **rail footer** (`localStorage`); there is **no** `/login` page.

| Surface | What shipped |
|---------|----------------|
| **Overview** (`/`) | Snapshot: hero chips + runtime / live pins. Vault + consent stay compact ops cards. Live-pin 0/1 ECharts bar **removed**. Live-pin cards show “—” until residual-status succeeds (404 hides the column). Residual errors stay outside `<details>`. |
| **Metrics** (`/metrics`) | Preferred keys match the Go registry. Cumulative tool outcomes from 0. One cache usage/quota meter from **gauges** only (never invents 256 MiB). Subject-quota lines. HTTP counts/bytes as **tables**. Session ring ≤60; export is the current snapshot, not the ring. Process-local only — **no fleet graphs**. |
| **Leftover page bodies** | Same chrome on `/profiles`, `/policy`, `/access`, `/doctor`, `/audit`, `/cache`. Access uses `PageHeader` / `ErrorBanner` / `Loading`. Audit filters use `form-field`. Doctor ResidualCallout (HOST-007) is always on; field DL still gated on `gateway_residual_status`. Internals stay: policy overlay apply, Access bindings JSON/preview, audit filters/export, cache `EVICT` double-confirm, doctor checks. |

**Not in this SPA:** `site/` marketing pages, a dedicated fleet-cache page (BFF+MCP fleet-cache ops remain; **SPA page residual**), job/queue graphs, or `/login`. Unknown paths navigate to `/`.

SAML BFF `GET /admin/v1/saml/login` remains a live-redirect residual — **not** a console login page.

Stock `internal/admin/uiembed` is **not** rebaked by PR #24. Release packaging runs `make admin-ui` (continue-on-error) then `make package`; a missing `web/admin/dist` still packages with `admin_ui=missing`.

SoT: [ADR 0014](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/docs/adr/0014-admin-console-reactive-spa.md) · [web/admin/README.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/web/admin/README.md) (routes + Metrics rules). Operator enable path: [docs/admin/README.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/docs/admin/README.md) — leftover internals above match the SPA; ignore that page’s stale “UI-004 / UI-007 not yet” rows.

### Fail-closed and correctness fixes (PRs #13–#21)

| PR | Area |
|----|------|
| [#13](https://github.com/hilather/go-jenkins-mcp/pull/13) | Jenkins circuit half-open gating, cancel, auth write-back race |
| [#14](https://github.com/hilather/go-jenkins-mcp/pull/14) | Five fail-open bugs (deny evasion, group overage, cache subject) |
| [#15](https://github.com/hilather/go-jenkins-mcp/pull/15) | Graph cycle false positives, abandoned waits, bounded error bodies |
| [#16](https://github.com/hilather/go-jenkins-mcp/pull/16) | Regression-scan cancel, hard-cap log read, pagination cursor |
| [#17](https://github.com/hilather/go-jenkins-mcp/pull/17) | SAML fail-closed validation, HTTP issuer loopback, keyring temp race |
| [#18](https://github.com/hilather/go-jenkins-mcp/pull/18) | Audit rotation recovery, BFF gateway audit parity, purge authz, recursive scrubbing |
| [#19](https://github.com/hilather/go-jenkins-mcp/pull/19) | Data-plane store / logmirror / cachecontrol / resourcecache / archive / telemetry |
| [#20](https://github.com/hilather/go-jenkins-mcp/pull/20) | Flag-reorder derivation, rate-limit race, JSON redaction, login audit wiring |
| [#21](https://github.com/hilather/go-jenkins-mcp/pull/21) | Breaker probe slot, group-overage adapter, audit decision, atomic stage re-mirror |

### Toolchain and operator docs

| Change | Notes |
|--------|--------|
| [PR #22](https://github.com/hilather/go-jenkins-mcp/pull/22) | Go **1.25.13** (stdlib CVE fixes) + `klauspost/compress` **v1.18.7**; audit rotation test on root |
| [PR #23](https://github.com/hilather/go-jenkins-mcp/pull/23) | Optional operator Entra + jwt-auth-filter walkthrough — **not** a live Entra pin |
| [PR #25](https://github.com/hilather/go-jenkins-mcp/pull/25) | Agent hints point at sibling `hilather/mcp-integration-lab` (complementary; not a merge gate) |

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| Admin SPA chrome only | Existing `admin serve` loopback path unchanged. Rebuild/package with `make admin-ui` to ship the new static tree. Stock `uiembed` stays the pre-#24 bake (`UI_BUILD` v0.3.0-era) until `make admin-ui-embed`. |
| No new default-on HTTP | Admin BFF still **off** until `jenkins-mcp admin serve` (or local Docker). Token-in-`localStorage` remains **pilot-only**. |
| No SPA `/login` | Continue setting profile + Bearer in the rail footer (or `localStorage`). Do not expect a login route. |
| Go 1.25.13 | Rebuild from this tag (or install release packages). Older toolchains are out of CI. |

## Security / residual honesty

| Residual | Status |
|----------|--------|
| Live Entra / production jwt-auth-filter / AgentCore | Operator site pin — not free-lab DoD ([Issue #4](https://github.com/hilather/go-jenkins-mcp/issues/4); walkthrough is optional) |
| Multi-pod gateway HA | **Cancelled** (multi-fleet) |
| Fleet non-log object classes (protocol v2) | Default-off; [Issue #7](https://github.com/hilather/go-jenkins-mcp/issues/7) |
| ratarmount-rs dual L2 / FUSE | Optional/unqualified; [Issue #8](https://github.com/hilather/go-jenkins-mcp/issues/8); native Go L2 remains required |
| Cache-control HTTP/SPA engines | [Issue #10](https://github.com/hilather/go-jenkins-mcp/issues/10) still **open**: BFF typed inventory/config; SPA typed inventory / mode editor / telemetry charts; dump/purge/verify/repair/GC `Execute`; console-log store adapter; profile `cache` JSON persistence; free-lab type×mode×op matrix (package tests gate today) |
| Fleet-cache SPA page | BFF+MCP implemented; **no** dedicated SPA section (not a fleet graph) |
| SPA `/login` / cookie SSO | Not shipped; shared-secret + rail footer only |
| `site/` docs marketing | Not part of this release |
| SIEM audit ship | AUD-T residual |
| Raw cache dump | Startup-gated **off** by default |

Pilot default remains **read-only** stdio + personal API token.

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make fmt && make lint && make test
make docs-check
cd web/admin && npm ci && npm test && npm run typecheck && npm run build
# optional offline residual honesty (not part of default make test):
make residual-smoke
make build
./bin/jenkins-mcp version --json
# optional UI: make admin-ui-dev + jenkins-mcp admin serve
```

## See also

- [ADR 0014 — admin console SPA](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/docs/adr/0014-admin-console-reactive-spa.md)
- [docs/admin/README.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/docs/admin/README.md)
- [web/admin/README.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/web/admin/README.md)
- [gates.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/docs/release/gates.md)
- Previous: [RELEASE_NOTES_v0.7.0.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.0/docs/release/RELEASE_NOTES_v0.7.0.md)
