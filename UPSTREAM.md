# Upstream seed baseline

This repository is an enterprise fork/import of the community seed project.
It preserves useful MCP/Jenkins tool behavior while replacing the monolithic
structure with the architecture in `docs/`.

## Upstream reference

| Field | Value |
|-------|--------|
| Upstream URL | https://github.com/simonfxr/go-jenkins-mcp |
| Upstream commit (frozen) | `83f66a9c57c0bc26044f654e589b6361787f0c89` |
| Upstream commit date | 2026-04-21 08:12:41 +0200 |
| Upstream summary | Improve Jenkins build and queue workflow for MCP clients. |
| License | MIT (Copyright (c) 2025 Simon Reiser) — see `LICENSE` |
| Import date (UTC) | 2026-07-31 |
| Baseline git tag | `upstream-simonfxr-baseline` |

## Seed files imported at baseline

These files match the upstream commit byte-for-byte at import (SHA-256):

| File | SHA-256 |
|------|---------|
| `main.go` | `dfcfad53dc8b837bceeb8bd1a58fbade760963577c89d062a33709edfe8a8093` |
| `schema.go` | `d9673c0f1ccf203824609b8a26b15129317b427315356279bc8765f3afb753de` |
| `go.mod` | `9fbaf7c9313c520c2ef3135c16bb1693839d5d2f77b59d4ea74c26ec1654c55a` |
| `go.sum` | `9f953a3dd92290a1176263fc4a33249da7468f8904bd6e926a85bdace3f483c3` |
| `LICENSE` | `f41d650254a93d0781e347b1f656b43fb59cfb0f735f3c43ea61000b320a5015` |
| `README.upstream.md` (upstream `README.md`) | `bd3084f8620a5f9bc9df0ed0c024fb2878b5c3c0acc6ec12b0b2ef6cfcde5c42` |

Verify:

```bash
sha256sum main.go schema.go go.mod go.sum LICENSE README.upstream.md
git show upstream-simonfxr-baseline:main.go | sha256sum
```

## Intent

- **Preserve** externally useful tool semantics where practical (compatibility fixtures in later tasks).
- **Do not preserve** monolithic `main.go` structure after Phase 0 refactor (`FND-004`).
- Known seed defects (unbounded progressive log reads, credentials via CLI/env, mutating tools always available) are **expected to change**; see `docs/` and `KNOWN_DEFECTS.md` once added (`FND-003`).

## Module path

Upstream module path at import: `github.com/simonfxr/go-jenkins-mcp`.

This fork publishes as `github.com/hilather/go-jenkins-mcp` (or the configured remote).
The module path may be updated after the baseline tag when packaging begins.
