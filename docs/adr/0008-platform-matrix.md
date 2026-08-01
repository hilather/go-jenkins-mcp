# ADR 0008: Platform matrix (Rocky + Ubuntu GA; Windows out of scope)

- **Status:** Accepted  
- **Date:** 2026-07-31  
- **Owner:** engineering (packaging co-owner)  
- **Related:** architecture §19; FND-002; FND-007; PKG-001; FND-008  

## Context

L2 archive inspection and preferred `ratarmount-rs` integration rely on **native Linux FUSE**. Windows has no in-box FUSE; WinFsp would add kernel/filter-driver, signing, and endpoint-security burden outside this product’s support model. Enterprise pilot targets common Linux workstation/server distros used by the organization.

## Decision

| Tier | Platforms | Role |
|------|-----------|------|
| **Tier 1 (GA / pilot gate)** | **Rocky Linux** (all major series currently in Rocky support lifecycle); **Ubuntu** (all LTS currently in Canonical standard/ESM support; Desktop and Server share one binary) | Required CI, packages (RPM/DEB + portable tarball), keyring, stdio MCP, L1 storage, optional Linux FUSE L2 |
| **Tier 2 (nice-to-have)** | **macOS** | Non-blocking; optional artifacts; Keychain when exercised |
| **Out of scope** | **Windows** (native client) | No Windows packages, no WinFsp assumption, no native FUSE claim |

Architectures: `amd64`/`x86_64` required; `aarch64` when CI and signing cover it.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Windows + WinFsp | Third-party driver burden; out of support model. |
| Linux-only single distro | Misses Ubuntu or Rocky enterprise footprints. |
| macOS as Tier 1 | FUSE/keyring/packaging variance; not pilot gate. |

## Consequences

- Makefile/CI target Linux; no Windows client targets.  
- Docs and `AGENTS.md` must not claim Windows support.  
- Expanding the matrix requires amending this ADR and architecture §19.
