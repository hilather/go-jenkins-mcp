# ARC-000 — `ratarmount-rs` qualification (go / no-go)

| Field | Value |
|-------|--------|
| **Task** | ARC-000 |
| **Status** | **Candidate pin recorded** — qualification **open** (not yet production go) |
| **Date** | 2026-08-01 |
| **Owner** | engineering (+ security for supply-chain approval) |
| **Related** | ADR 0007, architecture §10, ARC-001–ARC-004, ARC-012 |
| **Machine pin** | [`ratarmount-rs-pin.json`](ratarmount-rs-pin.json) |

## Candidate pin (latest release as of 2026-08-01)

| Field | Value |
|-------|--------|
| **Repository** | https://github.com/hilather/ratarmount-rs |
| **Owner** | `hilather` |
| **License** | MIT (`spdx`: MIT) |
| **Release tag** | **`v0.1.14`** |
| **Release URL** | https://github.com/hilather/ratarmount-rs/releases/tag/v0.1.14 |
| **Published** | 2026-08-01T00:54:57Z |
| **Commit SHA** | `eeff8502539375acb0e0bfae9d0b327fee0fbe4d` (peeled tag target) |
| **Workspace version** | `0.1.14` (`[workspace.package].version`) |
| **Tarball** | https://github.com/hilather/ratarmount-rs/archive/refs/tags/v0.1.14.tar.gz |

**Honesty:** This is the **current latest GitHub release** of the public `ratarmount-rs` tree. It is a **candidate pin for qualification**, not an automatic production go. MCP core continues to use the **native Go** L2 reader until ARC-000 acceptance is complete and ARC-004 ships.

### Pin policy

- Re-qualify before bumping the pin (new release / commit).
- Do not silently swap to Python [ratarmount](https://github.com/mxmlnkn/ratarmount) or other similarly named projects.
- If this repository becomes unavailable, fail closed to native Go and re-open ARC-000 with a new pin package.

## Decision summary

| Question | Result |
|----------|--------|
| Exact public repo named `ratarmount-rs` found? | **Yes** — `https://github.com/hilather/ratarmount-rs` |
| Latest release pin recorded? | **Yes** — **v0.1.14** @ `eeff8502539375acb0e0bfae9d0b327fee0fbe4d` |
| Production go for product adapter? | **Not yet** — run ARC-000 qualification checklist |
| Optional FUSE / Rust adapter (`ARC-004`) | **Unblocked for implementation work** after ARC-000 security/golden-byte gates; default product path remains native Go |
| Native Go seekable multi-frame reader | **Mandatory supported path** (`ARC-003`, Done*) |

## Qualification checklist (open)

1. [ ] Reproduce build of **v0.1.14** (`eeff850…`) on Rocky + Ubuntu; capture SBOM / `Cargo.lock` inputs.
2. [ ] Security review: unsafe Rust surfaces, parser boundaries, fuzzing posture, CVE/update/rollback owner.
3. [ ] Confirm seekable multi-frame `.tar.zst` dialect compatibility with pack format v1 (`docs/arc/pack-format-v1.md`).
4. [ ] Prototype integration modes: managed CLI/sidecar (preferred for isolation), optional native Linux FUSE inspection, direct FFI only if stable C API exists.
5. [ ] Golden packs: native Go vs adapter byte-identical member/range reads (or document measured compatibility repack).
6. [ ] Measure warm/cold range, concurrency, cancel, corruption, SELinux/AppArmor, memory; adapter failure degrades to native.
7. [ ] Record final go/no-go with pin immutability (tag + SHA) and update this file + `ratarmount-rs-pin.json` status to `production_go` or `no_go`.

## Platform and product constraints (unchanged)

- **Tier-1:** Rocky Linux + Ubuntu; native Linux FUSE may be used for *optional* human inspection after go.
- **Windows / WinFsp:** out of scope.
- **MCP core reads** must work via **direct API + native Go** when FUSE or the adapter is absent, failed, or policy-disabled.
- Durable on-disk contract is the **versioned multi-frame pack format**, not any particular reader.
- Ordinary **single-frame** `.tar.zst` is **never** accepted as performant random-access storage.

## Acceptance criteria (ARC-000)

| Criterion | Evidence |
|-----------|----------|
| Approved go/no-go names exact repository, commit/release, owner, license, … | **Pin filled** — qualification gates still open (checklist above) |
| If dependency cannot be accessed/approved, explicit deferred + native path | Native path remains production default until go |
| No silent substitution of similarly named projects | Pin is `hilather/ratarmount-rs` only |
| Rocky/Ubuntu FUSE qualify when adapter exists | Open (checklist) |
| Direct API / sidecar / FUSE measured | Open (checklist) |
| Golden bytes match adapter vs native | Open (checklist) |
| Adapter failure does not invalidate `ArchiveStore` / format | Interface isolation already holds for native |
| No single-frame `.tar.zst` as random access | Pack format v1 + native validator reject |

## Follow-up tasks (todo)

See `docs/jenkins-mcp-enterprise-agent-todo.md`:

| ID | Summary |
|----|---------|
| **ARC-000** | Complete qualification against pin **v0.1.14** |
| **ARC-000a** | Reproduce build + SBOM for pinned release |
| **ARC-000b** | Security / supply-chain review of pin |
| **ARC-000c** | Tier-1 FUSE + sidecar prototype measurements |
| **ARC-004** | Product adapter behind `ArchiveStore` (depends ARC-000 go) |
| **ARC-004a** | Sidecar/CLI lifecycle + sandbox |
| **ARC-004b** | Optional FUSE inspection path (diag only) |
| **ARC-012** | Seek-table / pack dialect compatibility with pin |

## Residual

- Production **go** not declared until checklist complete.
- Cargo metadata may still advertise an upstream repository string; **product pin URL** is `hilather/ratarmount-rs`.
- Native Go path remains the only required L2 reader for pilot/MCP.
