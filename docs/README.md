# Documentation index — go-jenkins-mcp

<p>
  <a href="https://hilather.github.io/go-jenkins-mcp/"><strong>Product site</strong></a>
  · <a href="../README.md">Repository README</a>
  · <a href="https://github.com/hilather/go-jenkins-mcp/releases">Releases</a>
</p>

**Wave 20 (DOC-001 / DOC-002):** short user/admin/agent docs synced to waves 16–19 code.  
Do **not** treat this tree as a claim of full production OAuth / gateway readiness — residuals stay explicit.

## Start here (by role)

| Role | Doc |
|------|-----|
| Pilot / developer (Cursor stdio) | [user/README.md](user/README.md) |
| Platform operator / packager | [admin/README.md](admin/README.md) |
| **Local Docker support / admin UI** (no host install) | [`../deploy/local/README.md`](../deploy/local/README.md) · `make local-docker-up` |
| Security reviewer | [security/operator-guide.md](security/operator-guide.md) · [security/threat-model.md](security/threat-model.md) |
| Coding agent / model | [agent-usage.md](agent-usage.md) · [tool-contracts.md](tool-contracts.md) · root [`AGENTS.md`](../AGENTS.md) |
| Pilot evidence kit | [pilot/README.md](pilot/README.md) · [pilot/checklist.md](pilot/checklist.md) |

## Core product docs

| Doc | Purpose |
|-----|---------|
| [user/README.md](user/README.md) | Install Tier-1, profile, API-token login, RO Cursor stdio, OIDC residual, mutations preview |
| [admin/README.md](admin/README.md) | Packages, policy CLI, gateway, telemetry, HTTP loopback; admin SPA (UI-000–UI-009) |
| [`../deploy/local/README.md`](../deploy/local/README.md) | **First-class** disposable admin BFF/SPA + optional lab Jenkins (Docker; not Cursor stdio) |
| [agent-usage.md](agent-usage.md) | Triage flow; Wave 18–19 tools (queue cancel, ext-logs ACL, change correlation, search re-eval, start_job params) |
| [tool-contracts.md](tool-contracts.md) | MCP tool inventory, budgets, error codes, side effects |
| [packaging.md](packaging.md) | RPM/DEB/tar, XDG paths, update-check, HTTP mode notes, local Docker pointer |
| [policy-rbac.md](policy-rbac.md) | Deny-only RBAC + overlay schema |
| [auth-architecture.md](auth-architecture.md) | Auth surfaces; Jenkins is not a 3LO AS |
| [observability.md](observability.md) | Metrics, doctor, telemetry wiring |

## Security & privacy

| Doc | Purpose |
|-----|---------|
| [security/operator-guide.md](security/operator-guide.md) | Keyring, secrets hygiene, RO, support bundles |
| [security/policy-bundles.md](security/policy-bundles.md) | Signed Ed25519 policy envelopes (MGR-001) |
| [security/fleet-telemetry.md](security/fleet-telemetry.md) | Opt-in telemetry privacy (MGR-002) |
| [security/privacy-data-retention.md](security/privacy-data-retention.md) | Data classes & retention (QA-006) |
| [security/threat-model.md](security/threat-model.md) | Assets, actors, trust boundaries |
| [security/cache-encryption.md](security/cache-encryption.md) | Optional L1 AEAD residual |

## Auth / OAuth residuals

| Doc | Purpose |
|-----|---------|
| [auth/oauth-capability-matrix.md](auth/oauth-capability-matrix.md) | Capability matrix |
| [auth/jwt-auth-filter-qualification.md](auth/jwt-auth-filter-qualification.md) | RS qualification + **live lab residual** |
| [auth/jas-no-go.md](auth/jas-no-go.md) | Jenkins-as-AS default no-go |
| [auth/oauth-003-claim-validation.md](auth/oauth-003-claim-validation.md) | Claim validation notes |

## Gateway / adapters / storage

| Doc | Purpose |
|-----|---------|
| [gateway/README.md](gateway/README.md) | Managed gateway foundation |
| [gateway/deployment.md](gateway/deployment.md) | Deploy scaffold + non-secret env |
| [gateway/qualification.md](gateway/qualification.md) | Offline qualify residual |
| [adapters/README.md](adapters/README.md) | Optional adapters (default off) |
| [adapters/ext-logs.md](adapters/ext-logs.md) | External logs + Jenkins ACL preflight |
| [adapters/work-items.md](adapters/work-items.md) | Change / work-item correlation |
| [adapters/otel-correlate.md](adapters/otel-correlate.md) | Trace refs |
| [arc/pack-format-v1.md](arc/pack-format-v1.md) | L2 pack format |
| [arc/ratarmount-rs-pin.json](arc/ratarmount-rs-pin.json) | Candidate pin: `ratarmount-rs` **v0.1.14** |
| [arc/ratarmount-rs-qualification.md](arc/ratarmount-rs-qualification.md) | ARC-000 pin + qualification checklist |
| [tst/README.md](tst/README.md) | Route matrix + opt-in live Jenkins |

## Planning, progress, release

| Doc | Purpose |
|-----|---------|
| [jenkins-mcp-enterprise-architecture.md](jenkins-mcp-enterprise-architecture.md) | Architecture SoT |
| [jenkins-mcp-enterprise-agent-todo.md](jenkins-mcp-enterprise-agent-todo.md) | Task backlog SoT |
| [jenkins-mcp-enterprise-task-index.json](jenkins-mcp-enterprise-task-index.json) | Machine-readable task graph |
| [README-jenkins-mcp-enterprise-planning-pack.md](README-jenkins-mcp-enterprise-planning-pack.md) | Planning pack overview |
| [phase0-progress.md](phase0-progress.md) · [phase1-progress.md](phase1-progress.md) · [phase2-progress.md](phase2-progress.md) | Wave boards |
| [release/gates.md](release/gates.md) | REL-002 gates |
| [release/update.md](release/update.md) | Update-check contract |
| [adr/README.md](adr/README.md) | Architecture decision records |

## Residual honesty (do not over-claim)

- Live Entra / jwt-auth-filter lab / AgentCore obtain pin — residual  
- SaaS log/ticket clients — residual  
- Cursor host stdio CI — residual (Wave 25 offline binary `make stdio-smoke` does not close it) 
- HTTP MCP: loopback-hardened but **no** socket client auth (KD-008)  
- Windows — out of scope

## Roadmaps

| [roadmap/server-team-hosted.md](roadmap/server-team-hosted.md) | Path from local pilot → team/server-hosted gateway (Tier A/B) |
