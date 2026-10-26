# Release notes — v0.8.3 (Go 1.26.10)

**Date:** 2026-10-26  
**Tag:** `v0.8.3`  
**Baseline:** continues `v0.8.2`  
**Merge commits:** [PR #38](https://github.com/hilather/go-jenkins-mcp/pull/38) (Go 1.26.10)

> Default pilot remains **read-only** local stdio. Admin HTTP (`jenkins-mcp admin serve`) and admin MCP stay **opt-in**. Mutations stay **off** unless `--allow-mutations`.

## Highlights

### Go toolchain 1.26.9 → 1.26.10 (PR #38)

Go 1.26.9 lacks the crypto/x509 fix for GO-2026-6809. [#38](https://github.com/hilather/go-jenkins-mcp/pull/38) moves `go.mod` to `go 1.26.10`, the CI Rocky fallback tarball to `go1.26.10`, `deploy/gateway` and `deploy/local` to `golang:1.26.10-bookworm`, `testdata/oauth-lab` to `golang:1.26.10-alpine`, and `CONTRIBUTING.md` and `docs/getting-started/local-native.md`. No code, CLI flag, config schema, or admin SPA change; the committed `internal/admin/uiembed` is untouched.

## Breaking / migration

| Change | Operator action |
|--------|-----------------|
| Go build floor `1.26.9` → `1.26.10` | Build and image builds need Go **1.26.10+** (`go.mod`). No runtime change. |

## Security / residual honesty

Residuals from [v0.8.2](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.3/docs/release/RELEASE_NOTES_v0.8.2.md) are unchanged.

## Gates checklist (REL-002 lite)

| Gate | Evidence | Status for this cut |
|------|----------|---------------------|
| Release notes current | This file. Tag workflow resolves `docs/release/RELEASE_NOTES_${TAG}.md` and fails if missing. | Required before tag |
| `make fmt` / `make lint` / `make test` | CI `lint-test-build` on tip SHA | Required |
| `make docs-check` | Docs job / local | Required |
| `make admin-ui-check` | CI `admin-ui` | Required |

## See also

- Previous: [RELEASE_NOTES_v0.8.2.md](https://github.com/hilather/go-jenkins-mcp/blob/v0.8.3/docs/release/RELEASE_NOTES_v0.8.2.md)
