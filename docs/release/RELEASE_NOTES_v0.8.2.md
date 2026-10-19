# Release notes — v0.8.2 (Go 1.26.9 and admin SPA advisories)

**Date:** 2026-10-19  
**Tag:** `v0.8.2`  
**Baseline:** continues `v0.8.1`  
**Merge commits:** [PR #29](https://github.com/hilather/go-jenkins-mcp/pull/29) (sibling-lab docs) · [PR #30](https://github.com/hilather/go-jenkins-mcp/pull/30) (Go 1.26.8) · [PR #31](https://github.com/hilather/go-jenkins-mcp/pull/31) (source-map-js) · [PR #32](https://github.com/hilather/go-jenkins-mcp/pull/32) (react-router 6.30.6, nanoid, embed) · [PR #34](https://github.com/hilather/go-jenkins-mcp/pull/34) (Go 1.26.9) · [PR #33](https://github.com/hilather/go-jenkins-mcp/pull/33) (vitest 4.1.11) · [PR #35](https://github.com/hilather/go-jenkins-mcp/pull/35) (react-router 7.18.4, embed) · [PR #36](https://github.com/hilather/go-jenkins-mcp/pull/36) (principal-cache test clock)

> Absolute HTTPS links only (pinned to this tag). Default pilot remains **read-only** local stdio. Admin HTTP (`jenkins-mcp admin serve`) and admin MCP stay **opt-in**. Mutations stay **off** unless `--allow-mutations`. This release does **not** claim live Entra pin, multi-pod HA, `site/` docs marketing, fleet graphs, or an SPA `/login` route.

## Highlights

### Go toolchain, two moves (PR #30, then PR #34)

`v0.8.1` built with Go **1.25.13**. This cut does **not** jump straight to 1.26.9.

| Move | PR | What changed |
|------|----|----------------|
| `1.25.13` → `1.26.8` | [#30](https://github.com/hilather/go-jenkins-mcp/pull/30) | `go.mod` (`go 1.26.8`, no toolchain line, `go.sum` unchanged). CI Rocky fallback tarball `go1.26.8`. Images: `deploy/gateway` and `deploy/local` `golang:1.26.8-bookworm`; `testdata/oauth-lab` `golang:1.26.8-alpine`. README badge, `CONTRIBUTING.md`, `AGENTS.md`, `docs/getting-started/local-native.md`. |
| `1.26.8` → `1.26.9` | [#34](https://github.com/hilather/go-jenkins-mcp/pull/34) | Same build surfaces again: `go.mod` `go 1.26.9`, CI tarball `go1.26.9`, those three Dockerfiles `golang:1.26.9-*`, `CONTRIBUTING.md`, `docs/getting-started/local-native.md`. |

[#34](https://github.com/hilather/go-jenkins-mcp/pull/34) did not edit the README Go badge (still major `go-1.26`) or `AGENTS.md` (still “Go 1.26 toolchain”, no patch pin). Historical release notes, fleet Phase 0 snapshots, archive, perf baseline, and the release-evidence test fixture were left historical in [#30](https://github.com/hilather/go-jenkins-mcp/pull/30).

### Admin SPA advisories (PR #31, #32, #33, #35)

Lockfile at tip resolves `react-router` / `react-router-dom` **7.18.4**, `nanoid` **3.3.18** (dev), `source-map-js` **1.2.2** (dev), `vitest` **4.1.11** (dev).

| Change | Ships in the SPA bundle? | Embed |
|--------|--------------------------|--------|
| [#31](https://github.com/hilather/go-jenkins-mcp/pull/31) `source-map-js` 1.2.1 → 1.2.2 ([GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q); indexed source-map section offsets). Lockfile only. | No (dev). That PR reported byte-identical build output. | Not rebuilt |
| [#32](https://github.com/hilather/go-jenkins-mcp/pull/32) `react-router` / `react-router-dom` 6.30.4 → 6.30.6 and `@remix-run/router` 1.23.3 → 1.23.4 ([GHSA-jjmj-jmhj-qwj2](https://github.com/advisories/GHSA-jjmj-jmhj-qwj2)); `nanoid` 3.3.16 → 3.3.18 ([GHSA-2v37-7h3g-55p8](https://github.com/advisories/GHSA-2v37-7h3g-55p8), build-time via postcss). `vite.config.ts` `build.sourcemap: false` (no `*.map`, no `sourceMappingURL`). | react-router yes; nanoid is dev. | Rebuilt (`UI_BUILD` `v0.8.1-4-g0566c73`). Docs/comments stopped calling that tree a placeholder. |
| [#33](https://github.com/hilather/go-jenkins-mcp/pull/33) `vitest` ^3.0.4 → ^4.1.11 ([GHSA-5gmw-xhrv-c9v3](https://github.com/advisories/GHSA-5gmw-xhrv-c9v3), [GHSA-85c8-ppgw-ccpr](https://github.com/advisories/GHSA-85c8-ppgw-ccpr), [GHSA-82fw-gwwq-j7x9](https://github.com/advisories/GHSA-82fw-gwwq-j7x9)). Node engines `>=18` → `>=20`. | No (devDependency). That PR reported the production bundle byte-identical to the then-committed embed. | Not rebuilt |
| [#35](https://github.com/hilather/go-jenkins-mcp/pull/35) `react-router-dom` ^6.29.0 → ^7.18.4 ([GHSA-wrjc-x8rr-h8h6](https://github.com/advisories/GHSA-wrjc-x8rr-h8h6), [GHSA-337j-9hxr-rhxg](https://github.com/advisories/GHSA-337j-9hxr-rhxg)). Adds `web/admin/src/App.routing.test.tsx`. No `App.tsx` route-source edit. | Yes | Rebuilt (`UI_BUILD` `v0.8.1-5-g9ba50ea`) |

**Committed embed vs tag-time package.** Tip `5e3542d` ([#36](https://github.com/hilather/go-jenkins-mcp/pull/36)) does not touch `internal/admin/uiembed`. `internal/admin/uiembed/dist/UI_BUILD` stays `v0.8.1-5-g9ba50ea` from [#35](https://github.com/hilather/go-jenkins-mcp/pull/35). This notes change does not rebuild it. [`.github/workflows/release.yml`](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/.github/workflows/release.yml) checks `docs/release/RELEASE_NOTES_<tag>.md`, then runs `make admin-ui` (writes `web/admin/dist`, stamps `UI_BUILD` with the tag) before `make package`. That stages filesystem assets at `/usr/share/jenkins-mcp/admin-ui`. The workflow does **not** run `make admin-ui-embed`, so it does not replace the committed `go:embed` tree. A raw `go build` of the tag still serves the [#35](https://github.com/hilather/go-jenkins-mcp/pull/35) embed; packaged `admin serve` prefers the tag-time filesystem SPA when those assets are present.

### Gateway principal-cache test (PR #36)

`TestFilePrincipalCache_TTLAndMaxEntries` no longer sleeps to separate LRU `last_access` or to pass TTL. [#36](https://github.com/hilather/go-jenkins-mcp/pull/36) adds internal `FilePrincipalCache.SetNow`. `clock()` uses that func when set; otherwise `time.Now`. On-disk document shape, flock, and 0600 mode are unchanged. No CLI flag or env.

### Docs (PR #29)

[#29](https://github.com/hilather/go-jenkins-mcp/pull/29) drops the false “sibling lab jwt-rs / Entra profile is **being added**” claim in `AGENTS.md` and [`docs/testing/entra-jwt-rs-lab.md`](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/docs/testing/entra-jwt-rs-lab.md). [hilather/mcp-integration-lab#12](https://github.com/hilather/mcp-integration-lab/pull/12) (LabJenkins jwt-rs + Entra) was closed unmerged. The sibling has no Jenkins, jwt-rs, or Entra profile; its `make smoke` does not exercise them. The in-repo path stays `testdata/jwt-rs-lab` and that walkthrough. It still does **not** flip `mode_*_live_*_qualified` or close OAUTH-009/010.

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| Go build floor `1.25.13` → `1.26.8` ([#30](https://github.com/hilather/go-jenkins-mcp/pull/30)) → `1.26.9` ([#34](https://github.com/hilather/go-jenkins-mcp/pull/34)) | Build and image builds need Go **1.26.9+** (`go.mod`). No CLI flag, config schema, or YAML change. |
| Admin SPA Node engines `>=18` → `>=20` ([#33](https://github.com/hilather/go-jenkins-mcp/pull/33)) | Node ≥ 20 to run `make admin-ui` / `make admin-ui-check`. CI `admin-ui` already uses Node 22. The Go binary does not need Node. |
| `react-router-dom` 6 → 7 ([#35](https://github.com/hilather/go-jenkins-mcp/pull/35)) | Admin dependency + committed embed refresh. No new default-on HTTP. Admin BFF still **off** until `jenkins-mcp admin serve`. |
| No new default-on HTTP | Token-in-`localStorage` remains **pilot-only**. Mutations stay **off** unless `--allow-mutations`. |

## Security / residual honesty

| Residual | Status |
|----------|--------|
| Committed `internal/admin/uiembed` at tip | Last regenerated in [#35](https://github.com/hilather/go-jenkins-mcp/pull/35) (`UI_BUILD` `v0.8.1-5-g9ba50ea`), not at tip `5e3542d`. Not rebuilt for this notes file. |
| Tag publish SPA | `release.yml` `make admin-ui` then `make package` rebuilds the **packaged** filesystem SPA and stamps the tag. It does not run `make admin-ui-embed`. |
| `source-map-js` / `nanoid` / `vitest` | Dev or build-time. [#31](https://github.com/hilather/go-jenkins-mcp/pull/31) and [#33](https://github.com/hilather/go-jenkins-mcp/pull/33) did not refresh the embed. |
| Live Entra / production jwt-auth-filter / AgentCore | Still operator site pin — not free-lab DoD. [#29](https://github.com/hilather/go-jenkins-mcp/pull/29) only removes a false “being added” sibling-lab claim. |
| SPA `/login` / cookie SSO, `site/` marketing, fleet graphs, multi-pod HA | Not shipped in this cut |

Pilot default remains **read-only** stdio + personal API token.

## Gates checklist (REL-002 lite)

Evidence-oriented go/no-go per [gates.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/docs/release/gates.md). Offline packs do **not** complete production sign-off.

| Gate | Evidence | Status for this cut |
|------|----------|---------------------|
| Release notes current | This file (`docs/release/RELEASE_NOTES_v0.8.2.md`). Tag workflow resolves `docs/release/RELEASE_NOTES_${TAG}.md` and fails if missing. | Required before tag |
| `make fmt` / `make lint` / `make test` | CI `lint-test-build` on tip SHA | Required |
| `make docs-check` | Docs job / local | Required |
| `make admin-ui-check` | CI `admin-ui` (Node 22): vitest + tsc + Vite build | Required |
| `make residual-smoke` (optional) | Offline residual honesty | Opt-in |
| `jenkins-mcp release-evidence --offline` | Lite JSON evidence | Opt-in / operator |
| Ownership sign-off | [evidence-template.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/docs/release/evidence-template.md) | Operator-owned |

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

- [docs/testing/entra-jwt-rs-lab.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/docs/testing/entra-jwt-rs-lab.md)
- [web/admin/README.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/web/admin/README.md)
- [docs/packaging.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/docs/packaging.md)
- [gates.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/docs/release/gates.md)
- Previous: [RELEASE_NOTES_v0.8.1.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.2/docs/release/RELEASE_NOTES_v0.8.1.md)
