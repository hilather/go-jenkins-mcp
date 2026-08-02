# Architecture Decision Records (ADRs)

**Task:** FND-006 (MCP SDK pin), FND-008 (decision capture)  
**Source of truth for product decisions:** [`../jenkins-mcp-enterprise-architecture.md`](../jenkins-mcp-enterprise-architecture.md)  
**Owner of this index:** engineering  

These ADRs freeze irreversible or hard-to-change choices before implementation hardens around them. They must stay consistent with the architecture Key Decisions and platform matrix. When code or config encodes a choice, link the applicable ADR in a comment or docs cross-reference.

## Approval

| Change type | Required approval |
|-------------|-------------------|
| Auth, identity, OAuth, keyring, Jenkins authz plugin scope | Security + architecture |
| Global read-only, MCP RBAC, tool budgets, audit of denials | Security + architecture |
| L1/L2 storage format, compression frames, archive readers | Architecture (+ security if encryption/ACL) |
| Package layout, transport defaults, SDK pin (non-auth) | Engineering (architecture review recommended) |
| Platform matrix (add/remove OS) | Architecture + packaging owners |

ADR status values: **Accepted** (binding), **Proposed** (not yet binding), **Superseded** (replaced by a later ADR), **Deferred** (decision postponed with explicit gate).

## Index

| ADR | Title | Status | Tasks |
|-----|-------|--------|-------|
| [0001](0001-package-layout.md) | Package layout and bounded contexts | Accepted | FND-004, FND-008 |
| [0002](0002-local-stdio-default.md) | Local stdio as default MCP transport | Accepted | FND-008, MCP-001 |
| [0003](0003-jenkins-not-oauth-authorization-server.md) | Jenkins is not an OAuth authorization server | Accepted | FND-008, AUTH-000 ([summary](../auth-architecture.md)) |
| [0004](0004-global-read-only-and-deny-only-rbac.md) | Global read-only default and deny-only MCP RBAC | Accepted | FND-008, POL-* |
| [0005](0005-independent-zstd-frames-l1.md) | Independent Zstandard frames for L1 logs | Accepted | FND-008, LOG-* |
| [0006](0006-mcp-go-sdk.md) | Official MCP Go SDK pin and protocol versions | Accepted | FND-006 |
| [0007](0007-seekable-multiframe-tar-zst-l2.md) | Seekable multi-frame tar.zst L2 + readers | Accepted | FND-008, ARC-000 |
| [0008](0008-platform-matrix.md) | Platform matrix (Rocky + Ubuntu; no Windows) | Accepted | FND-008, PKG-001 |
| [0009](0009-personal-api-token-secret-service.md) | Personal API token in Linux Secret Service first | Accepted | FND-008, AUTH-* |
| [0010](0010-tool-response-budgets.md) | Tool response budgets (64 KiB / 1 MiB) | Accepted (planned enforcement) | FND-008, MCP budgets |
| [0011](0011-custom-jenkins-authz-plugin-gated.md) | Custom Jenkins authorization-server plugin is decision-gated | Accepted | FND-008, AUTH-000 |
| [0012](0012-signed-policy-bundles-ed25519.md) | Signed enterprise policy bundles (Ed25519 envelope) | Accepted | FND-008, MGR-001, CFG-002 |
| [0013](0013-jas-default-no-go-enforcement.md) | Jenkins-as-AS default no-go enforced in code (JAS-001) | Accepted | JAS-001, OAUTH-011, AUTH-000 |
| [0014](0014-admin-console-reactive-spa.md) | Operator admin console: React SPA + local BFF | Accepted | UI-000–UI-010 |
| [0015](0015-saml-sp-identity-and-groups.md) | SAML 2.0 SP for identity + groups (config SoT) | Accepted | POL-007, POL-006, UI-003 residual |

## Conventions

Each ADR records:

1. **Context** — forces and constraints  
2. **Decision** — what we will do  
3. **Alternatives** — options considered and why rejected  
4. **Consequences** — benefits, costs, residual risks  
5. **Owner** — accountable role (default: engineering; security-sensitive ADRs also list security)

Do not invent decisions that contradict architecture Key Decisions. Prefer one ADR amendment (or a superseding ADR) over silent drift in code.
