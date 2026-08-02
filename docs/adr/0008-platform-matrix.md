# ADR 0008: Platform matrix (Rocky + Ubuntu GA; macOS and Windows out of scope)

- **Status:** Accepted (amended 2026-08-01 — macOS dropped)  
- **Date:** 2026-07-31  
- **Owner:** engineering (packaging co-owner)  
- **Related:** architecture §19; FND-002; FND-007; PKG-001; FND-008  

## Context

L2 archive inspection and preferred `ratarmount-rs` integration rely on **native Linux FUSE**. Windows has no in-box FUSE; WinFsp would add kernel/filter-driver, signing, and endpoint-security burden outside this product’s support model. macOS (Keychain, packaging, FUSE/macFUSE variance) is not an enterprise pilot or release target for this product. Enterprise pilot targets common Linux workstation/server distros used by the organization.

## Decision

| Tier | Platforms | Role |
|------|-----------|------|
| **Tier 1 (GA / pilot gate)** | **Rocky Linux** (all major series currently in Rocky support lifecycle); **Ubuntu** (all LTS currently in Canonical standard/ESM support; Desktop and Server share one binary) | Required CI, packages (RPM/DEB + portable tarball), keyring (Secret Service), stdio MCP, L1 storage, optional Linux FUSE L2 |
| **Out of scope** | **macOS**, **Windows** (native clients) | No darwin packages, no Keychain product support, no Windows packages, no WinFsp assumption, no native FUSE claim on non-Linux |

Architectures: `amd64`/`x86_64` required; `aarch64` (Linux) when CI and signing cover it.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Windows + WinFsp | Third-party driver burden; out of support model. |
| Linux-only single distro | Misses Ubuntu or Rocky enterprise footprints. |
| macOS as Tier 1 or Tier 2 | FUSE/keyring/packaging variance; not pilot/release gate — **dropped**. |

## Consequences

- Makefile/CI target **Linux only**; no macOS CI jobs, no Windows client targets.  
- Docs and `AGENTS.md` must not claim macOS or Windows support.  
- Expanding the matrix requires amending this ADR and architecture §19.
