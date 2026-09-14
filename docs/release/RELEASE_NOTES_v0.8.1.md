# Release notes — v0.8.1 (admin SPA CI compile gate)

**Date:** 2026-09-14  
**Tag:** `v0.8.1`  
**Baseline:** continues `v0.8.0`  
**Merge commits:** [PR #27](https://github.com/hilather/go-jenkins-mcp/pull/27) (AccessPage shell props + `admin-ui` CI job)

> Absolute HTTPS links only (pinned to this tag). Default pilot remains **read-only** local stdio. Admin HTTP (`jenkins-mcp admin serve`) and admin MCP stay **opt-in**. Mutations stay **off** unless `--allow-mutations`. This release does **not** claim live Entra pin, multi-pod HA, `site/` docs marketing, fleet graphs, or an SPA `/login` route.

## Highlights

### Admin SPA compile gate + AccessPage shell alignment (PR #27)

`web/admin` AccessPage compiled against `Loading` / `ErrorBanner` / `PageHeader` props the rest of the admin SPA does not use, so `tsc --noEmit` failed on `npm run build`. Merge-gate CI stayed green because `lint-test-build` is Go-only and never compiled `web/admin`.

| Change | Notes |
|--------|--------|
| AccessPage | Uses shared shell APIs (`PageHeader` / `ErrorBanner` / `Loading`) consistent with other leftover page bodies |
| CI | New GitHub Actions job `admin-ui` (Node 22) runs vitest + typecheck + Vite production build |
| Docs | `web/admin/README.md`, ADR 0014, admin/testing architecture notes, `CONTRIBUTING.md`, `AGENTS.md` |

**Operator residual:** add `admin-ui` to GitHub branch protection required checks (cannot be done in this repo change alone).

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| SPA typecheck now gated in CI | Rebuild/package with `make admin-ui` / `make admin-ui-check` as before. No YAML or CLI flag changes. |
| No new default-on HTTP | Admin BFF still **off** until `jenkins-mcp admin serve`. Token-in-`localStorage` remains **pilot-only**. |

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
| Branch protection `admin-ui` required check | Operator follow-up after merge of #27 |
| SIEM audit ship | AUD-T residual |
| Raw cache dump | Startup-gated **off** by default |

Pilot default remains **read-only** stdio + personal API token.

## Gates checklist (REL-002 lite)

Evidence-oriented go/no-go per [gates.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.1/docs/release/gates.md). Offline packs do **not** complete production sign-off.

| Gate | Evidence | Status for this cut |
|------|----------|---------------------|
| Release notes current | This file (`docs/release/RELEASE_NOTES_v0.8.1.md`) | Required before tag |
| `make fmt` / `make lint` / `make test` | CI `lint-test-build` on tip SHA | Required |
| `make docs-check` | Docs job / local | Required |
| `make admin-ui-check` | CI `admin-ui` (Node 22): vitest + tsc + Vite build | Required (new in #27) |
| `make residual-smoke` (optional) | Offline residual honesty | Opt-in |
| `jenkins-mcp release-evidence --offline` | Lite JSON evidence | Opt-in / operator |
| Ownership sign-off | [evidence-template.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.1/docs/release/evidence-template.md) | Operator-owned |

## Verify

```bash
export PATH="$HOME/.local/go/bin:$PATH"
make fmt && make lint && make test
make docs-check
make admin-ui-check
# equivalent:
#   cd web/admin && npm ci && npm test && npm run typecheck && npm run build
# optional offline residual honesty (not part of default make test):
make residual-smoke
make build
./bin/jenkins-mcp version --json
# optional UI: make admin-ui-dev + jenkins-mcp admin serve
```

## See also

- [ADR 0014 — admin console SPA](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.1/docs/adr/0014-admin-console-reactive-spa.md)
- [docs/admin/README.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.1/docs/admin/README.md)
- [web/admin/README.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.1/web/admin/README.md)
- [gates.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.1/docs/release/gates.md)
- Previous: [RELEASE_NOTES_v0.8.0.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.1/docs/release/RELEASE_NOTES_v0.8.0.md)
