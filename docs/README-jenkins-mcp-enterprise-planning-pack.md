# Enterprise Jenkins MCP planning pack

This package turns `simonfxr/go-jenkins-mcp` into an implementation-ready plan for a local, per-user, enterprise Jenkins MCP for Cursor, with an optional near-source AgentCore/managed-gateway deployment.

**Revision date:** July 31, 2026  
**Revision focus:** Engineer authentication findings; Jenkins' lack of native 3LO; external-IdP, AgentCore user-delegated 3LO, and OBO options; global read-only enforcement; deny-only MCP RBAC; wire-bandwidth controls; seekable Zstandard/`ratarmount-rs` storage; and Tier-1 OS matrix (Rocky Linux + Ubuntu; macOS nice-to-have; Windows excluded — no native FUSE).

## Deliverables

- `../AGENTS.md` - **mandatory agent policy** for this repo: tests for every feature, regression tests for every fix, code review on every change set, docs kept current, and incomplete work tracked with next steps.
- `jenkins-mcp-enterprise-architecture.docx` - polished human-readable architecture, security, storage, performance, testing, deployment, and delivery plan.
- `jenkins-mcp-enterprise-architecture.pdf` - visually verified fixed-layout rendering of the human-readable plan.
- `jenkins-mcp-enterprise-architecture.md` - reviewable source for version control and agent context.
- `jenkins-mcp-enterprise-agent-todo.md` - dependency-aware implementation backlog with 121 unique tasks and 565 task acceptance checks (577 checklist items in the complete file, including shared DoD).
- `jenkins-mcp-enterprise-task-index.json` - machine-readable task index with 244 dependency edges and an acyclic dependency graph.
- `SHA256SUMS` - integrity hashes for package contents.

## Key decisions in this revision

1. Jenkins core is not treated as a native three-legged OAuth authorization server. Stock Jenkins remains a resource/API server; its normal scripted-client path is a personal API token.
2. Local OAuth uses Authorization Code with PKCE against Entra ID or another approved authorization server and sends only a Jenkins-audience access token to a qualified Jenkins bearer-token filter, hardened proxy, or equivalent resource-server component.
3. AgentCore can use user-delegated authorization-code 3LO or OBO/token exchange against Entra. Its discovery, authorization, and token endpoints point to the external authorization server, not stock Jenkins. A full Jenkins authorization-server plugin is a separately owned conditional epic after a formal decision gate.
4. Personal Jenkins API tokens remain a supported local bootstrap path, stored in the operating-system credential store rather than Cursor configuration.
5. The default is globally read-only. Cursor can request it using `--read-only` or `JENKINS_MCP_READ_ONLY=true`; signed enterprise and emergency policy can force it. The most restrictive source wins, and enforcement occurs below tool discovery.
6. Optional MCP-side RBAC is deny-only: it can reduce a user's Jenkins-authorized surface by tool, target, argument, data volume, cache/export behavior, and mutation policy, but can never grant Jenkins access.
7. Network accounting separates encoded wire bytes from decoded bytes. Large text responses are stream-decoded directly into bounded parsers or compressed storage, with no unbounded plaintext staging copy.
8. Large logs are mirrored progressively and compressed immediately into independent Zstandard frames. Random access is defined at frame/checkpoint boundaries, not arbitrary blocks within one frame.
9. Related completed logs are grouped only when identity, controller/profile, authorization, sensitivity, retention, encryption, size, and lifecycle policy match. Packs use seekable multi-frame `.tar.zst`, TAR/member indexes, checksums, and deterministic rollover.
10. The preferred L2 engine is the engineering-referenced `ratarmount-rs`, behind `ArchiveStore`. Public research did not identify an authoritative repository under that exact name, so production first requires the exact internal dependency and pinned revision, followed by code, license, supply-chain, Tier-1 Linux platform (Rocky/Ubuntu) including native FUSE, recovery, compatibility, and performance qualification. A native Go reader remains mandatory for non-mount paths.
11. The preferred zero-recompression path copies unchanged compressed L1 payload frames and surrounds them with generated TAR header/padding frames. A standards-compatible one-time repack path remains the correctness fallback.
12. **Local client OS matrix:** Tier 1 (GA / pilot gate) is Rocky Linux (all currently supported major series) and Ubuntu (all currently supported LTS Desktop/Server; same binary). Tier 2 (nice-to-have, non-blocking) is macOS. **Windows is out of scope** (no native FUSE; WinFsp not assumed). Linux packages are signed RPM (Rocky) and DEB (Ubuntu) plus portable tarball; credentials use Linux Secret Service.

## Recommended starting sequence

Begin with the repository baseline/refactor and performance measurements, including a CI matrix that covers Rocky majors and Ubuntu LTS. Then lock the security architecture (`SEC-001`, `AUTH-000`), implement the global read-only and policy foundations (`POL-001` through `POL-005`), obtain and qualify the exact `ratarmount-rs` dependency (`ARC-000`) on Linux FUSE-capable hosts, and prove bounded progressive transfer plus independent-frame storage before expanding OAuth, gateway, diagnostics, or mutations. Ship signed Rocky/Ubuntu packages in `PKG-001`; treat macOS artifacts as optional; do not build Windows clients.

The Markdown backlog is the task source of truth. The JSON index is intended for dependency-aware agent orchestration. Root `AGENTS.md` is mandatory agent policy (tests, regressions, review, docs, next-step tracking) for every implementation session.
