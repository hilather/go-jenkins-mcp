# Enterprise Jenkins MCP - Agent-Ready Implementation Backlog

**Seed repository:** `https://github.com/simonfxr/go-jenkins-mcp`  
**Target:** Local per-user Jenkins MCP for Cursor plus optional per-user AgentCore/managed-gateway deployment  
**Primary priorities:** Per-user identity, fail-closed read-only/RBAC, network efficiency, seekable compressed storage, interactive performance  
**Companion design:** `jenkins-mcp-enterprise-architecture.md`  
**Revision:** Engineer authentication, read-only/RBAC, and seekable-Zstandard notes incorporated; Tier-1 OS matrix (Rocky Linux + Ubuntu; macOS nice-to-have; Windows excluded — no native FUSE)

---

## How an implementation agent must use this backlog

**Repo agent policy:** read and obey root `AGENTS.md` for every session. The
rules below are backlog-specific; `AGENTS.md` is mandatory for tests,
regressions, code review, documentation, and incomplete-work tracking.

### Quality gates (non-negotiable — see `AGENTS.md`)

1. **Tests for every feature:** no feature or behavior change without automated tests in the same change (unit + integration/contract as applicable; success/failure/cancel/limits).
2. **Regression tests for every fix:** each bug fix lands with a red–green regression test; re-run the relevant suite after the fix.
3. **Code review for every change set:** structured review (prefer `/review`) after tests/docs; fix bug-severity findings before treating work as done or committing large behavioral changes.
4. **Documentation always updated:** behavior, CLI/tool contracts, architecture, packaging, and agent guidance stay in sync with the code in the same change; no silent capability claims.
5. **Todo / backlog tracking:** work against task IDs; maintain session todos; if incomplete, leave explicit **next steps** (remaining work, blockers, verification); never check acceptance/DoD boxes without demonstrated evidence.
6. **Admin console kept current:** operator-relevant features (policy, metrics, audit, doctor/cache, profiles, day-2 CLI) update `internal/admin` + `web/admin` + `docs/admin/api-v1.md` in the same change, or leave an explicit residual TODO — never silent drift (see `AGENTS.md`).
7. **Docker integration scaffolds:** for external systems (Jenkins, IdP/JWT RS, gateway, HTTP peers), extend or add Compose under `testdata/` / `deploy/` with opt-in Makefile targets — **not** default `make test`. Prefer mocks for Entra; never bake secrets. See `AGENTS.md` “Docker integration scaffolds” and **HOST-012…HOST-015**.

### Backlog workflow

1. Work on **one task ID per pull request** unless the task explicitly permits a paired change.
2. Read the companion architecture and every dependency task before editing code.
3. Use a fresh isolated workspace for repository inspection/execution; expose only the intended workspace and remove it afterward.
4. Preserve seed behavior through tests, then move it behind bounded interfaces; do not reproduce the monolithic structure.
5. Do not add a network dependency, persistent format, auth flow, policy language, or cryptographic choice without an ADR.
6. Treat Jenkins data, logs, artifacts, URLs, OAuth responses, archive metadata, and model input as untrusted.
7. Never place tokens in CLI arguments, source, fixtures, snapshots, CI output, logs, MCP schemas/results, or support bundles.
8. Every tool and internal operation has server-enforced network, disk, CPU/time, fan-out, and result bounds. Caller limits only reduce bounds.
9. Attach before/after measurements for performance-sensitive changes: latency, CPU, allocation/RSS, network, disk, compression, amplification, and MCP bytes.
10. Every storage task includes crash/recovery, corruption, compatibility, and bounded-read tests.
11. Every behavior change updates schema/tool/user/admin/security documentation and relevant ADRs.
12. Keep the **operator admin console** current with operator-relevant product changes (BFF/SPA/API contract or documented residual) — see `AGENTS.md`.
13. Do not add mutating Jenkins tools until global read-only, MCP RBAC, audit, preview/confirmation, and mutation-policy epics are approved.
14. Treat effective access as `Jenkins allow AND global mode AND MCP policy AND operation budgets`; MCP policy only reduces access.
15. A Cursor/profile setting can enable read-only but cannot disable a stronger enterprise or emergency read-only state.
16. Jenkins is not a native 3LO authorization server. Do not confuse UI OIDC login, outbound workload OIDC, or credential frameworks with delegated API authorization.
17. Do not send ID/Graph/generic gateway tokens to Jenkins. Bearer mode requires a validated access token for the exact Jenkins resource/audience.
18. Zstandard random access is based on independent frames/checkpoints plus a seek table. Do not call arbitrary blocks inside one frame independently seekable.
19. Never produce a conventional single-frame `.tar.zst` for L2 and call it random access; validate frame count, seek table, TAR, and checksums.
20. Managed/gateway mode preserves the personal subject end to end and never collapses users into a generic Jenkins identity.
21. `ratarmount-rs` is the preferred L2 engine, but all durable data must remain readable through the versioned format and native fallback.
22. AgentCore authorization, token, discovery, and consent endpoints point to Entra ID or another approved authorization server, not Jenkins, unless the conditional Jenkins authorization-server epic receives an explicit go decision.
23. Count encoded wire bytes and decoded bytes separately. Stream the decoded response directly into bounded parsers or independent Zstandard frames; never stage an unbounded plaintext log merely to compress it later.
24. Batch only related logs whose user, profile/controller, authorization policy, retention, sensitivity, and encryption domains match; never improve locality by weakening isolation.
25. If a task or session is only partially done, record **next steps** (remaining acceptance criteria, blockers, follow-up task IDs, verification commands) before stopping; do not leave status implied.

### Definition of done for every task

- [ ] Implementation is isolated to the task scope.
- [ ] Unit tests cover success, failure, cancellation, and limits.
- [ ] Integration tests are added where Jenkins, OAuth, keyring, storage, or sidecars are involved.
- [ ] Bug fixes include a regression test that failed before the fix and passes after.
- [ ] No secret values appear in logs or errors under canary tests.
- [ ] Static analysis, race tests where applicable, vulnerability scan, and format/lint checks pass.
- [ ] Performance evidence is attached when the task can affect CPU, memory, network, disk, startup, or response size.
- [ ] Documentation and changelog are updated.
- [ ] Structured code review completed; bug-severity findings fixed or explicitly accepted by the user.
- [ ] A rollback or backward-compatibility note is included for persistent-format or configuration changes.
- [ ] Acceptance criteria below are demonstrated, not merely asserted.
- [ ] If anything remains incomplete, next steps are written and no DoD item is falsely checked.

### Priority legend

- **P0:** Required before a secure pilot.
- **P1:** Required for enterprise production or the core product value.
- **P2:** Valuable expansion after the core is stable.
- **P3:** Optional or environment-specific.

---

# Phase 0 - Baseline, architecture, and proof

## FND-001 - Create the internal fork and freeze the upstream baseline

**Priority:** P0  
**Dependencies:** None  
**Parallel-safe:** No; first task

**Objective**

Create the controlled source repository and preserve a reproducible reference to the seed project.

**Implementation**

- Fork or import the upstream repository under the approved organization.
- Record upstream URL, commit SHA, license, and import date.
- Add `UPSTREAM.md`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, and ownership rules.
- Protect the default branch and require reviewed pull requests.
- Tag the untouched import as `upstream-simonfxr-baseline`.

**Acceptance criteria**

- [ ] A clean checkout at the baseline tag matches the selected upstream commit.
- [ ] MIT license attribution is retained.
- [ ] Default branch cannot be directly pushed by ordinary contributors.
- [ ] Repository ownership and security reporting paths are documented.

**Evidence/tests**

- Baseline file hash report.
- Branch protection screenshot or policy export.

---

## FND-002 - Establish reproducible local and CI build environments

**Priority:** P0  
**Dependencies:** FND-001

**Objective**

Make builds deterministic enough to compare behavior and produce trusted releases.

**Implementation**

- Pin the supported Go toolchain through `go.mod` and CI configuration.
- Add package scripts for the **Tier-1** matrix: Rocky Linux and Ubuntu (`linux/amd64`, plus `linux/aarch64` when the support matrix requires it). Prefer oldest-supported glibc baselines per Rocky major and Ubuntu LTS so newer minors stay binary-compatible.
- Add optional **Tier-2** macOS (`darwin/arm64`, `darwin/amd64`) build jobs that may be best-effort and non-blocking.
- **Do not** add Windows client targets, installers, or release gates (Windows is out of scope: no native FUSE).
- Run unit/integration tests on Rocky- and Ubuntu-based containers/VMs covering every major/LTS listed in the support matrix.
- Add a development container or documented isolated build environment without embedding secrets.
- Enable module checksum verification and fail on dirty generated files.
- Add `make`/Taskfile targets for build, test, race, lint, benchmark, SBOM, and package (including `rpm` and `deb` artifact targets).

**Acceptance criteria**

- [ ] A fresh environment can build and test using one documented command on Rocky and Ubuntu baselines.
- [ ] Two clean builds from the same commit produce matching source manifests; binary reproducibility gaps are documented.
- [ ] CI never requires a real Jenkins credential for unit tests.
- [ ] Build outputs include version, commit, dirty state, Go version, and build time policy.
- [ ] CI produces Tier-1 artifacts for Rocky (RPM and/or linux tarball) and Ubuntu (DEB and/or linux tarball); macOS artifacts are optional and do not gate merges; no Windows artifacts are required or gated.

---

## FND-003 - Characterize and lock current seed behavior

**Priority:** P0  
**Dependencies:** FND-002

**Objective**

Create compatibility tests before refactoring.

**Implementation**

- Inventory every current MCP tool, argument, default, output field, error shape, timeout, and side effect.
- Build an HTTP fixture server that emulates the Jenkins endpoints currently used.
- Add golden contract tests for jobs, build details, queue, log range/tail, start, stop, wait, and build search.
- Record known defects separately so tests do not enshrine unsafe behavior as desired behavior.

**Acceptance criteria**

- [ ] Every currently documented tool has at least one successful contract test.
- [ ] Failure, timeout, cancellation, nested-folder, and malformed-response cases are covered.
- [ ] Known over-download and credential-handling defects are documented as expected-to-change.
- [ ] Refactoring can prove no accidental contract regression.

---

## FND-004 - Refactor the monolith into bounded packages

**Priority:** P0  
**Dependencies:** FND-003

**Objective**

Separate concerns without changing supported behavior.

**Implementation**

Create packages for application lifecycle, configuration, profile, authentication, Jenkins HTTP/API, capabilities, MCP server, tools, policy, log mirror, storage, archive, search, diagnostics, redaction, audit, and telemetry. Move code in small steps behind interfaces.

**Acceptance criteria**

- [ ] Jenkins client code imports no MCP package.
- [ ] Tool handlers construct no raw HTTP request.
- [ ] Authentication is not a global string.
- [ ] No production `.go` file exceeds an agreed review threshold without an exception ADR.
- [ ] Existing compatibility tests pass.
- [ ] Package dependency graph contains no cycles and matches the architecture.

---

## FND-005 - Define stable internal contracts and error taxonomy

**Priority:** P0  
**Dependencies:** FND-004

**Objective**

Prevent ad hoc coupling and make failures actionable without exposing secrets.

**Implementation**

- Define typed references for profile, job, build, queue item, log generation, stage, test, artifact, and node.
- Define error codes for authentication, authorization, not found, capability missing, throttled, timeout, cancelled, corrupt cache, quota, policy denial, and upstream protocol errors.
- Add safe wrapping that separates internal diagnostics from model-visible messages.

**Acceptance criteria**

- [ ] Tool handlers map all expected failures to stable codes.
- [ ] Errors never contain authorization headers, tokens, cookies, or raw secret parameters.
- [ ] Error codes are documented and contract-tested.
- [ ] Internal cause chains remain available in local diagnostic mode without leaking to MCP output.

---

## FND-006 - Upgrade and pin the official MCP Go SDK

**Priority:** P0  
**Dependencies:** FND-004

**Objective**

Use an approved stable SDK version with current security and protocol behavior.

**Implementation**

- Select the newest stable, security-reviewed v1.x release compatible with the supported Cursor fleet.
- Record the selected protocol versions in an ADR.
- Enable official conformance tests.
- Preserve stdio as default; keep Streamable HTTP behind an explicit feature/policy flag.
- Ensure cancellation reaches tool handler contexts.

**Acceptance criteria**

- [ ] MCP conformance passes for every declared protocol version.
- [ ] Cursor stdio startup, discovery, tool calls, cancellation, and shutdown pass an integration smoke test.
- [ ] HTTP mode, if compiled/shipped, has localhost/origin/body protections enabled.
- [ ] SDK downgrade/upgrade compatibility is documented.

---

## FND-007 - Build the CI quality and security pipeline

**Priority:** P0  
**Dependencies:** FND-002

**Objective**

Make quality, security, and format regressions visible on every change.

**Implementation**

Add Go tests, race tests, lint, formatting, `govulncheck`, dependency/license review, secret scanning, code scanning, fuzz smoke tests, SBOM generation, and artifact retention. Separate untrusted pull-request jobs from secret-bearing integration jobs.

**Acceptance criteria**

- [ ] Required checks block merge.
- [ ] Untrusted CI cannot access Jenkins/OAuth secrets.
- [ ] Findings have documented severity and remediation policy.
- [ ] Generated SBOM is attached to release candidates.

---

## FND-008 - Add architecture decision records

**Priority:** P0  
**Dependencies:** FND-004

**Objective**

Capture security, compatibility, and persistent-format decisions before implementation hardens around them.

**Implementation**

Create ADRs for local stdio, authentication provider boundaries, Jenkins-not-an-authorization-server, local PKCE, AgentCore 3LO/OBO, JWT resource-server validation, global read-only precedence, deny-only MCP RBAC, log frame format, seekable TAR/Zstandard, semantic batching, native and `ratarmount-rs` readers, zero-recompression option, encryption, tool budgets, and signing.

**Acceptance criteria**

- [ ] Every listed decision records context, decision, alternatives, consequences, and owner.
- [ ] The custom Jenkins authorization-server plugin is explicitly decision-gated rather than assumed.
- [ ] Code/config schemas link to applicable ADRs.
- [ ] ADR changes affecting auth, policy, or storage require designated security/architecture approval.

---

## PERF-001 - Establish baseline network, memory, and latency benchmarks

**Priority:** P0  
**Dependencies:** FND-003

**Objective**

Quantify the seed implementation before optimization.

**Implementation**

Benchmark startup, job listing, build detail, queue polling, log range, log tail, waits, and search using controlled fixture sizes. Measure wire bytes, decoded bytes, allocations, peak memory, wall time, and MCP result size.

**Acceptance criteria**

- [ ] Benchmarks include 1 MiB, 100 MiB, and 1 GiB logical logs.
- [ ] The current log over-download is reproduced and quantified.
- [ ] Results are stored in machine-readable form and summarized in CI artifacts.
- [ ] Reference hardware/software is documented.

---

## SEC-001 - Formalize the threat model and data classification

**Priority:** P0  
**Dependencies:** FND-008

**Objective**

Turn security assumptions into reviewable controls for local and optional gateway deployment.

**Implementation**

Document assets, actors, data classes, and trust boundaries for local OS user/keyring, Cursor, MCP process, signed policy/RBAC, Jenkins, external IdP, AgentCore authorization-code/OBO providers and token vault, gateway subjects/workloads, logs/artifacts, SQLite/seekable archives, the qualified `ratarmount-rs` sidecar/library, updates, and optional mutations. Include bearer downgrade/fallthrough, OAuth consent/session replay, wrong audience/issuer, cross-user cache/handle/archive leakage, prompt injection, SSRF/redirects, wire/decompression bombs, archive corruption/bombs, shared-account substitution, and Jenkins compromise assumptions.

**Acceptance criteria**

- [ ] Security/platform owners approve local and gateway threat models.
- [ ] Every high/critical threat maps to backlog tasks and tests.
- [ ] Data retention, telemetry, cache isolation, archive affinity, and export classifications are explicit.
- [ ] API-token, external-IdP resource-server, AgentCore 3LO/OBO, exact-audience passthrough, and conditional Jenkins 3LO risks are distinguished.
- [ ] Shared/generic Jenkins identities are explicitly prohibited for interactive users.

---

## AUTH-000 - Lock the Jenkins authentication architecture and no-native-3LO terminology

**Priority:** P0  
**Dependencies:** FND-008, SEC-001

**Objective**

Prevent implementation and documentation from relying on OAuth capabilities Jenkins does not provide.

**Implementation**

Write an ADR and security review note that distinguishes Jenkins scripted Basic/API-token access, browser OIDC security realms, outbound build workload OIDC, credentials frameworks, JWT bearer resource-server validation, external Entra/IdP authorization, AgentCore user-delegated authorization-code 3LO, AgentCore on-behalf-of/token exchange, a narrow broker/filter, and a full Jenkins-hosted authorization server. Record the evaluated plugin categories and the order in which alternatives must be tried. State explicitly that AgentCore provider discovery/authorization/token endpoints are Entra or another approved authorization server, not Jenkins, unless the conditional authorization-server epic is approved and implemented.

**Acceptance criteria**

- [ ] The architecture explicitly states Jenkins core is not the required three-legged OAuth authorization server.
- [ ] Initial supported identity paths are a personal API token and an external-IdP Jenkins-audience access token.
- [ ] AgentCore evaluates per-user authorization-code 3LO and OBO/RFC 8693/RFC 7523 exchange before a custom Jenkins authorization server.
- [ ] AgentCore OAuth endpoints never point at stock Jenkins.
- [ ] A full Jenkins 3LO plugin is a conditional separately owned/security-reviewed epic with a default no-go posture.
- [ ] Security/platform owners approve terminology, attribution, token audience, and shared-account prohibitions.

---

## ARC-000 - Obtain and qualify the exact `ratarmount-rs` dependency

**Priority:** P0  
**Dependencies:** FND-002, FND-008  
**Status:** Candidate pin recorded (2026-08-01) — qualification open  
**Pin:** [`docs/arc/ratarmount-rs-pin.json`](arc/ratarmount-rs-pin.json) · [qualification](arc/ratarmount-rs-qualification.md)

| Pin field | Value |
|-----------|--------|
| Repository | https://github.com/hilather/ratarmount-rs |
| Release | **v0.1.14** (latest as of 2026-08-01) |
| Commit | `eeff8502539375acb0e0bfae9d0b327fee0fbe4d` |
| License | MIT |
| Release URL | https://github.com/hilather/ratarmount-rs/releases/tag/v0.1.14 |

**Objective**

Turn the preferred Rust archive implementation into a measured, security-reviewed go/no-go decision against an **exact pinned release**, without guessing the repository and without replacing the mandatory native Go reader.

**Implementation**

Use the candidate pin above (do not silently substitute Python ratarmount or other similarly named projects). Review build reproducibility, release/signing process, SBOM/crates, unsafe Rust, parser boundaries, fuzzing, CVE response, supported seekable-Zstandard dialect, index format, Tier-1 platform behavior (Rocky Linux, Ubuntu) including **native Linux FUSE**, optional macOS behavior, and recovery semantics. Prototype managed local sidecar/CLI (preferred isolation), optional Linux FUSE mount for inspection, and direct library/FFI only if a stable C API exists; do **not** design for WinFsp/Windows. Keep MCP core reads functional via direct API/native Go when FUSE is absent. Verify independent-frame seekable `.tar.zst` compatibility and compare all reads with the native Go fallback. Benchmark index build/load, range access, concurrency, cancellation, SELinux/AppArmor, truncation, corruption, crash recovery, and endpoint protection on representative Rocky/Ubuntu images. On go: set pin JSON `status` to `production_go` and unlock ARC-004 product wiring.

**Acceptance criteria**

- [x] Candidate pin names exact repository, release tag, commit SHA, owner, and license (v0.1.14 / `eeff850…` / MIT).
- [ ] Approved production go/no-go records provenance, SBOM/dependencies, build process, update/rollback plan, and security-response owner.
- [ ] If the pin cannot be reproduced or approved, status is explicit no-go/deferred and the native reader remains the only supported path.
- [ ] No similarly named project is substituted without engineering confirmation (pin is `hilather/ratarmount-rs` only).
- [ ] Rocky Linux and Ubuntu qualify native Linux FUSE mount paths; MCP still serves log/search reads via direct API or native Go when FUSE is unavailable.
- [ ] Direct API, sidecar, and Linux FUSE mount choices are measured and documented; WinFsp/Windows is out of scope.
- [ ] Qualified adapter and native reader return identical golden pack/member/range bytes (or documented compatibility repack).
- [ ] Warm/cold read, index, memory, concurrency, cancellation, corruption, recovery, and EDR measurements exist for the pin.
- [ ] Adapter failure/disablement does not invalidate `ArchiveStore` or the durable format.
- [ ] No ordinary single-frame `.tar.zst` is accepted as performant random-access storage.

### Follow-up tasks (pin → product)

#### ARC-000a - Reproduce build and SBOM for pin v0.1.14

**Priority:** P0  
**Dependencies:** ARC-000 (pin), FND-002

- [ ] Checkout `eeff8502539375acb0e0bfae9d0b327fee0fbe4d` / tag `v0.1.14` and build default workspace members on Rocky + Ubuntu.
- [ ] Capture `Cargo.lock` (or generate and hash), Rust toolchain version, and feature flags used for the product integration path.
- [ ] Produce SBOM (e.g. `cargo cyclonedx` / org standard) and store under `docs/arc/` or release evidence (no secrets).
- [ ] Document how to re-fetch the pin tarball and verify SHA of tag object.

#### ARC-000b - Security and supply-chain review of pin v0.1.14

**Priority:** P0  
**Dependencies:** ARC-000a

- [ ] Review unsafe Rust, parser/FFI boundaries, and trust model for untrusted pack bytes.
- [ ] Confirm license set (MIT + transitive) is acceptable; record CVE-response / update owner.
- [ ] Define update/rollback: how product bumps pin (tag+SHA only), and how adapter disable returns to native Go.
- [ ] Fuzz or bounded adversarial inputs for open/list/range on multi-frame `.tar.zst` (time-boxed).

#### ARC-000c - Tier-1 sidecar + optional FUSE prototype (pin v0.1.14)

**Priority:** P0  
**Dependencies:** ARC-000a

- [ ] Sidecar/CLI: lifecycle, timeout, cancel, no public listener, controlled index paths, sanitized errors.
- [ ] Optional FUSE mount on Rocky + Ubuntu for **diagnostic inspection only** (not required for MCP).
- [ ] Measure index build/load, warm/cold range, concurrency, cancel, SELinux/AppArmor notes.
- [ ] Prove adapter kill/disable leaves native Go `ArchiveStore` reads working.

---

## ARC-000 / ARC-004 gate

Do **not** ship ARC-004 in the default pilot binary until ARC-000 production go is recorded. Native Go L2 remains the only required path for RO pilot.

---

# Phase 1 - Secure local read-only MVP

## CFG-001 - Implement versioned profile configuration

**Priority:** P0  
**Dependencies:** FND-005

**Objective**

Represent non-secret controller, authentication, policy, and storage configuration safely and support migration.

**Implementation**

Define a strict schema for profile name, Jenkins origin, auth method (`api_token`, `oidc_bearer`, optional `agentcore_delegated`), issuer/client/resource/scopes, TLS/proxy, HTTP content-encoding policy, cache, seekable-pack parameters, read-only request, policy references, and feature toggles. `agentcore_delegated` covers user-delegated authorization-code 3LO and OBO/token exchange selected by the managed deployment. Use atomic writes and reject unsafe/unknown fields.

**Acceptance criteria**

- [ ] Configuration contains no secret material.
- [ ] Read-only can be requested through profile or Cursor CLI/environment without allowing a stronger enforced value to be disabled.
- [ ] Invalid origins, authorization-server endpoints, token audiences, unsafe data paths, duplicate profiles, and unsupported versions fail clearly.
- [ ] A stock Jenkins URL cannot be configured as an authorization or token endpoint for a non-conditional profile.
- [ ] Migration tests cover every released schema version.

---

## CFG-002 - Add enterprise policy overlay and fail-closed precedence

**Priority:** P0  
**Dependencies:** CFG-001, FND-008

**Objective**

Allow centrally managed restrictions and make the effective read-only/policy state deterministic.

**Implementation**

Define precedence across built-in emergency safe mode, signed enterprise policy, machine/admin policy, profile, environment compatibility settings, and CLI/Cursor non-secret overrides. Restrictions combine monotonically: a lower layer may further restrict, never widen. Add secret-free `config effective` output with rule/source provenance.

**Acceptance criteria**

- [ ] User/Cursor values cannot override enforced read-only, origin, auth, quota, RBAC, storage, or telemetry restrictions.
- [ ] Conflicting or invalid security policy fails closed into a documented safe mode.
- [ ] Effective configuration shows each value, source, enforcement status, and signature state without secrets.
- [ ] Tests prove `--read-only=false`/environment/profile cannot defeat a stronger true value.

---

## AUTH-001 - Introduce the credential-provider abstraction

**Priority:** P0  
**Dependencies:** CFG-001, FND-005

**Objective**

Remove authentication logic from global configuration and HTTP call sites.

**Implementation**

Define provider/session/status interfaces for API token and OIDC. Sessions supply request authentication without exposing token values to tools. Add fake providers for tests.

**Acceptance criteria**

- [ ] Jenkins client receives an auth session, not a raw credential string.
- [ ] Tool packages cannot access token bytes.
- [ ] Session refresh/cancellation behavior is testable.
- [ ] Auth status output is sanitized.

---

## AUTH-002 - Implement OS credential-store backends

**Priority:** P0  
**Dependencies:** AUTH-001

**Objective**

Keep long-lived secrets local and outside Cursor configuration.

**Implementation**

Implement the Tier-1 **Linux Secret Service** backend (`libsecret` / org.freedesktop.secrets) for Rocky Linux and Ubuntu Desktop/Server sessions. Document and test headless Rocky/Ubuntu behavior when no Secret Service is available (fail closed by default; policy-controlled protected file only when explicitly approved). Implement **macOS Keychain** as a Tier-2 nice-to-have adapter that is not required for pilot exit. Do **not** implement Windows Credential Manager (Windows clients are out of scope). Namespace entries by application, OS user, profile, controller origin, auth method, and account identity.

**Acceptance criteria**

- [ ] API tokens can be stored, loaded, replaced, and deleted under the current OS user on Rocky/Ubuntu with Secret Service.
- [ ] Another local user cannot read the credential through normal APIs.
- [ ] Error and debug paths never print the secret.
- [ ] Headless fallback is disabled unless policy explicitly allows a protected file; Rocky/Ubuntu server images without an unlocked keyring fail closed with a clear `doctor` diagnosis.
- [ ] Backend tests use mocks or isolated test entries and clean them up.
- [ ] macOS Keychain, if present, passes the same store/load/delete contract tests but is not a release gate.
- [ ] No Windows Credential Manager code path is required for pilot or production gates.

---

## AUTH-003 - Add API-token login, logout, and status commands

**Priority:** P0  
**Dependencies:** AUTH-002

**Objective**

Provide a safe per-user setup flow.

**Implementation**

Prompt for username and token through a non-echoing terminal input. Store the token in the keyring. Verify it against Jenkins before declaring login successful. Remove secret CLI flags from normal documentation and deprecate them in code.

**Acceptance criteria**

- [ ] `login --method api-token` never echoes or persists the token outside the keyring.
- [ ] Failed verification does not retain the credential unless explicitly chosen for troubleshooting and policy permits it.
- [ ] `status` shows profile, identity, method, and health without a token.
- [ ] `logout` removes the credential and invalidates in-memory sessions.
- [ ] Environment credential compatibility emits a policy-controlled warning and is off in enterprise mode.

---

## AUTH-004 - Verify and bind the Jenkins user identity

**Priority:** P0  
**Dependencies:** AUTH-003, NET-001

**Objective**

Ensure the process is operating as the intended individual, not anonymous or a shared identity.

**Implementation**

Call an approved Jenkins identity endpoint after authentication. Store only sanitized identity metadata. Detect unexpected anonymous fallback or identity changes.

**Acceptance criteria**

- [ ] Startup or first remote call verifies the principal.
- [ ] Anonymous fallback fails closed for profiles requiring auth.
- [ ] Identity mismatch invalidates the session and produces an audit event.
- [ ] Tests cover renamed accounts and controller responses missing optional fields.

---

## NET-001 - Implement normalized origin pinning and safe URL construction

**Priority:** P0  
**Dependencies:** CFG-001, FND-005

**Objective**

Prevent SSRF and credential forwarding while supporting folders and reverse-proxy prefixes.

**Implementation**

- Parse and normalize the configured Jenkins base URL once.
- Construct endpoint paths from typed references and escaped path segments.
- Accept Jenkins-provided absolute URLs only when scheme, host, port, and approved base path match policy.
- Reject userinfo, fragments, unsupported schemes, and ambiguous encodings.

**Acceptance criteria**

- [ ] Credentials are never sent to an unapproved origin.
- [ ] Tests cover malicious Location headers, protocol-relative URLs, encoded separators, IPv6, IDNs, alternate ports, and path-prefix Jenkins deployments.
- [ ] Nested job/folder names round-trip correctly.
- [ ] No tool accepts an arbitrary URL for a Jenkins request.

---

## NET-002 - Build the shared enterprise HTTP transport

**Priority:** P0  
**Dependencies:** NET-001, AUTH-001

**Objective**

Provide efficient connection reuse, bounded cancellation, and measured wire compression.

**Implementation**

Create one shared transport/client per profile with connection pooling, HTTP/2, keep-alive, explicit dial/TLS/header/idle timeouts, context propagation, and sanitized instrumentation. Advertise only approved response content encodings by profile and endpoint class. Use `gzip` as the compatibility baseline for large textual endpoints where Jenkins/proxies support it; qualify HTTP Zstandard or Brotli only through explicit interoperability and CPU measurements. Count encoded wire bytes before decompression and decoded bytes after decompression. Stream the decoder into the bounded response parser or independent-Zstandard-frame writer without a full plaintext staging buffer.

**Acceptance criteria**

- [ ] Repeated requests reuse connections under a fixture that supports it.
- [ ] Cancellation closes active reads and decompression promptly.
- [ ] Timeout and content-decoding failures map to stable error codes.
- [ ] Transport and idle connections close on profile removal or process shutdown.
- [ ] Benchmarks show fewer handshakes than per-request clients.
- [ ] Metrics separately report encoded wire bytes, decoded bytes, compression ratio, decoder CPU, and endpoint/profile identity without secrets.
- [ ] Each content encoding can be disabled per profile or endpoint class when a proxy/controller is incompatible.
- [ ] A large text response can flow directly from the network decoder into Zstandard frame storage without an unbounded plaintext copy.

---

## NET-003 - Add body limits, safe retries, throttling, and circuit breaking

**Priority:** P0  
**Dependencies:** NET-002

**Objective**

Bound resource use and avoid accidental duplicate side effects.

**Implementation**

- Limit encoded-wire and decoded response sizes independently by endpoint class; abort both compression bombs and oversized uncompressed bodies.
- Retry only idempotent reads and explicitly safe polling.
- Honor bounded `Retry-After`; add jittered backoff.
- Add per-profile rate and concurrency limits plus a simple circuit breaker.
- Never automatically retry a build trigger or stop operation.

**Acceptance criteria**

- [ ] Oversized encoded or decoded JSON/XML/text fails before unbounded allocation or disk use.
- [ ] Compression-bomb and deceptive-header fixtures fail within configured CPU, time, and decoded-byte bounds.
- [ ] Retry tests distinguish GET/read from POST/mutation.
- [ ] A 429/503 storm does not create synchronized request amplification.
- [ ] Circuit state is observable and recovers safely.

---

## NET-004 - Support custom CAs, proxies, and optional mTLS

**Priority:** P1  
**Dependencies:** NET-002, CFG-001

**Objective**

Operate in enterprise networks without weakening TLS.

**Implementation**

Support approved CA bundles/system store, proxy configuration, proxy bypass, and optional client certificate references. Avoid an `insecure-skip-verify` production mode; permit only an explicit diagnostic mode that cannot persist silently.

**Acceptance criteria**

- [ ] Custom CA and proxy integration tests pass.
- [ ] mTLS key material is loaded through approved protected sources and never logged.
- [ ] Proxy redirects cannot receive Jenkins credentials unexpectedly.
- [ ] TLS diagnostics explain chain/hostname errors without suggesting permanent verification disablement.

---

## POL-001 - Implement the global read-only kill switch

**Priority:** P0  
**Dependencies:** FND-005, CFG-002

**Objective**

Make read-only a cross-layer safety invariant that can be enabled from Cursor and forced by enterprise policy.

**Implementation**

Classify tools and Jenkins requests by effect. Compute effective read-only with monotonic precedence. Omit mutations from discovery, deny direct handler/service calls, and block classified Jenkins mutation endpoints below the tool layer. Keep OAuth/token-exchange POSTs in a separate authentication class. Expose effective state and sources in `status`/`doctor`.

**Acceptance criteria**

- [ ] Default installation is read-only.
- [ ] Cursor `args: ["--read-only"]` and `JENKINS_MCP_READ_ONLY=true` enable read-only.
- [ ] No lower-precedence setting can disable enterprise-enforced read-only.
- [ ] Unregistered, direct, aliased, crafted, redirected, and future-unclassified mutation attempts fail closed.
- [ ] Authentication/token refresh continues to function in read-only mode.
- [ ] Every tool and Jenkins request has an effect classification test.

---

## POL-002 - Define the deny-only MCP RBAC policy model

**Priority:** P0  
**Dependencies:** POL-001, AUTH-004

**Objective**

Restrict users below their Jenkins permissions without creating an alternate privilege-granting authority.

**Implementation**

Define subjects, roles, bindings, tools/capabilities, profiles, job/folder/view/branch/node/artifact resources, actions, argument constraints, data-volume limits, cache/export controls, time/expiry, and explicit deny rules. The evaluator returns decision, matched rule IDs, constraints, and safe explanation. Default deny mutations.

**Acceptance criteria**

- [ ] Effective access is Jenkins allow AND global mode AND MCP policy.
- [ ] No policy rule can synthesize a Jenkins credential or mark a Jenkins denial as allowed.
- [ ] Resource patterns are canonicalized and tested against nested folders/branches and ambiguous encodings.
- [ ] Limits returned by policy can only lower server hard limits.
- [ ] Policy language is deterministic, bounded, and cannot execute arbitrary code or network calls.

---

## POL-003 - Bind RBAC subjects to verified identities

**Priority:** P0  
**Dependencies:** POL-002, AUTH-004

**Objective**

Ensure policy evaluates trusted identity rather than caller-supplied usernames.

**Implementation**

For API-token mode bind OS user/profile and verified Jenkins principal. For OAuth bind validated issuer/tenant/subject plus verified Jenkins principal and approved groups. For AgentCore bind the validated gateway caller/workload identity and exchanged token subject. Define rename, missing-claim, group-overage, and identity-change behavior.

**Acceptance criteria**

- [ ] Tool input cannot choose or override the policy subject.
- [ ] Unexpected anonymous/principal/subject changes invalidate the session.
- [ ] Group/role removals take effect within the approved cache/revalidation window.
- [ ] Identity metadata retained in cache/audit is minimized and profile-isolated.

---

## POL-004 - Enforce RBAC at registry, handler, service, cache, and network boundaries

**Priority:** P0  
**Dependencies:** POL-003, MCP-002, NET-001

**Objective**

Prevent bypass through discovery gaps, direct calls, cached data, or new Jenkins endpoints.

**Implementation**

Add reusable authorization middleware at MCP registry/handler, domain service, LogStore/ArtifactStore reads, integration adapter, and Jenkins request classifier. Re-evaluate current policy for cached content. Fail closed for unclassified tools/actions/endpoints. Return bounded explanations and correlation IDs.

**Acceptance criteria**

- [ ] A denied tool is absent when policy permits omission and is still denied if invoked directly.
- [ ] Cached content cannot be read after policy/resource access is removed.
- [ ] A newly introduced tool/request class is denied until explicitly classified.
- [ ] Policy checks are cancellation-aware and have measured low overhead.
- [ ] Every denial is auditable without leaking sensitive policy internals.

---

## POL-005 - Add RBAC/read-only conformance and adversarial tests

**Priority:** P1  
**Dependencies:** POL-004, TST-001

**Objective**

Prove global read-only and MCP RBAC cannot be bypassed and cannot elevate Jenkins access.

**Implementation**

Build a matrix across identities, groups, profiles, nested jobs, cached data, tool aliases, direct JSON-RPC, redirects, plugin endpoints, mutations, limits, policy updates, and role revocation. Include property tests showing effective decisions are monotonic as restrictions are added.

**Acceptance criteria**

- [ ] All bypass cases fail closed.
- [ ] Jenkins-denied resources remain denied even under an MCP allow rule.
- [ ] Adding a deny/restriction never increases effective access.
- [ ] Policy reload/revocation races do not permit a stale mutation or cache read.
- [ ] Performance overhead and decision-cache behavior meet the approved budget.

---

## MCP-001 - Enforce central result-size and pagination budgets

**Priority:** P0  
**Dependencies:** FND-006, FND-005

**Objective**

Prevent large MCP responses regardless of tool implementation.

**Implementation**

Add middleware and reusable pagers enforcing default 64 KiB target, 1 MiB hard maximum, item limits, excerpt limits, truncation metadata, and opaque continuations.

**Acceptance criteria**

- [ ] No tool can bypass the hard result limit.
- [ ] Truncation is explicit and continuation is stable for the documented lifetime.
- [ ] Pagination does not duplicate or skip items in deterministic fixtures.
- [ ] Handles reveal no filesystem path, secret, or unapproved identifier.

---

## MCP-002 - Replace URL/string inputs with typed references

**Priority:** P0  
**Dependencies:** FND-005, NET-001

**Objective**

Reduce malformed calls, SSRF risk, and model-side URL construction.

**Implementation**

Define JSON schemas for profile, job full name, build number, queue ID, stage ID, artifact path, and log evidence reference. Add compatibility adapters for old tool names where necessary.

**Acceptance criteria**

- [ ] Public tool schemas contain no arbitrary request URL or header field.
- [ ] Validation errors identify the invalid field and allowed form.
- [ ] Nested jobs and multibranch names work without manual URL encoding.
- [ ] Compatibility aliases have a documented removal plan.

---

## LOG-001 - Correct log range acquisition and eliminate hidden over-download

**Priority:** P0  
**Dependencies:** NET-003, PERF-001

**Objective**

Ensure a small log request cannot read or transfer the full remaining console log.

**Implementation**

Replace unbounded body reads with a streaming, counting reader. Use Jenkins progressive offsets correctly. Separate remote mirror acquisition from tool range responses. Add transfer metrics.

**Acceptance criteria**

- [ ] Requesting 8 KiB from a 1 GiB fixture does not allocate or return the remaining 1 GiB.
- [ ] Wire/decompressed byte limits are demonstrated in tests.
- [ ] Partial responses do not advance the committed mirror offset incorrectly.
- [ ] Cancellation terminates the read and leaves recoverable state.
- [ ] Benchmark shows the measured over-download defect is removed.

---

## LOG-002 - Implement the progressive log-generation state machine

**Priority:** P0  
**Dependencies:** LOG-001, STO-002

**Objective**

Mirror running and completed logs incrementally and detect rewrites/truncation.

**Implementation**

Track committed offset, reported next offset, more-data flag, build state, prefix/boundary fingerprints, poll schedule, and generation ID. Use adaptive polling and single-flight per log.

**Acceptance criteria**

- [ ] Each normal log byte is downloaded once per generation.
- [ ] Concurrent readers do not trigger duplicate remote fetches.
- [ ] Truncation/restart creates a new generation rather than corrupting offsets.
- [ ] Completed logs stop polling.
- [ ] Crash/restart resumes from the last committed offset.

---

## STO-001 - Create secure data directories and ACL validation

**Priority:** P0  
**Dependencies:** CFG-001, SEC-001

**Objective**

Keep cached Jenkins data private to the current OS user.

**Implementation**

Choose per-user local application-data paths, create them with restrictive ACLs/modes, reject shared/cloud-synced paths by policy, and implement `cache path/status` diagnostics.

**Acceptance criteria**

- [ ] New directories are current-user-only on supported OSes.
- [ ] Unsafe inherited permissions are detected and not silently accepted.
- [ ] Path traversal and symlink/junction attacks are tested.
- [ ] Cache paths never include credentials or raw sensitive parameters.

---

## STO-002 - Implement versioned SQLite metadata store

**Priority:** P0  
**Dependencies:** STO-001, FND-005

**Objective**

Persist profiles' non-secret cache metadata, log generations, chunks, and leases transactionally.

**Implementation**

Design normalized tables and migrations for controllers, jobs, builds, log generations, chunks, line checkpoints, archives, pins, leases, and maintenance journal. Configure WAL/checkpoint policy based on benchmark.

**Acceptance criteria**

- [ ] Schema version and migrations are explicit.
- [ ] Transactions preserve offset/chunk consistency under injected crashes.
- [ ] Corrupt database behavior is detected and documented.
- [ ] No tokens or authorization headers are stored.
- [ ] Concurrent read/write tests pass with the race detector.

---

## STO-003 - Implement immutable line-aware Zstandard frames

**Priority:** P0  
**Dependencies:** STO-002, LOG-002

**Objective**

Store incoming log bytes compactly without full raw-log staging and make the compressed payload reusable by the seekable TAR/Zstandard cold tier.

**Implementation**

Stream decoded Jenkins bytes directly into independent checksummed Zstandard payload frames, targeting an initial 8 MiB raw frame with a benchmarked 1-32 MiB range and newline-aware cut points. No payload frame may depend on data or entropy tables from another frame. Store raw/compressed offsets, line checkpoints, checksum, codec level, optional versioned dictionary ID, generation, and archive-reuse metadata. Dictionaries are optional, immutable, checksummed, retained for the full data lifetime, and may not create cross-frame decode dependency. Design the L1 payload format so the exact compressed payload-frame bytes can be copied between separately generated TAR header and padding frames during compatible L2 promotion; do not require the L1 payload to contain a TAR header.

**Acceptance criteria**

- [ ] No completed full raw log copy is required on disk.
- [ ] Any payload frame can be decompressed independently under a strict output limit.
- [ ] Line/raw-offset metadata round-trips across long lines and UTF-8/binary-like bytes.
- [ ] Frame format, optional dictionary references, checksums, and archive-reuse metadata are versioned and corruption is detected.
- [ ] A fixture promotes L1 payload frames into a valid seekable TAR/Zstandard pack without recompressing the log payload bytes.
- [ ] Benchmarks cover compression levels, frame sizes, dictionaries, ingest CPU, decode latency, ratio, and write amplification.

---

## STO-004 - Make chunk commit and recovery crash-safe

**Priority:** P0  
**Dependencies:** STO-003

**Objective**

Guarantee that the cache is discoverably old or new after interruption, never half-committed.

**Implementation**

Use temporary files, fsync policy, atomic rename, SQLite transaction, and recovery journal. Implement startup cleanup of orphan temp files and verification of committed objects.

**Acceptance criteria**

- [ ] Fault injection at every commit step leaves recoverable state.
- [ ] The logical offset never points past durable data.
- [ ] Orphan files are reclaimed safely.
- [ ] Recovery duration is bounded by metadata, not a full scan of all log bytes.

---

## LOG-003 - Build byte/line indexes and bounded local reads

**Priority:** P0  
**Dependencies:** STO-003, STO-004

**Objective**

Serve byte ranges, line ranges, and tails locally without full decompression.

**Implementation**

Create line checkpoints per chunk and APIs for raw byte range, line range, tail-by-lines, and tail-by-bytes. Decompress only intersecting independent frames/windows and report requested versus decompressed bytes.

**Acceptance criteria**

- [ ] Reads across chunk boundaries are correct.
- [ ] UTF-8 boundary behavior is documented; raw byte evidence remains authoritative.
- [ ] Cached 64 KiB read meets the calibrated p95 target.
- [ ] A tail read does not decompress all earlier chunks.
- [ ] Returned evidence includes generation, ranges, and checksum.

---

## LOG-004 - Stream multi-log operations directly into compressed collections

**Priority:** P0  
**Dependencies:** LOG-003, STO-003, POL-004

**Objective**

Keep fan-out diagnostics network/disk efficient and preserve semantic locality for later archive packing.

**Implementation**

Introduce bounded acquisition sessions/collection IDs. Deduplicate requested log generations, fetch concurrently under profile budgets, and stream every response directly into independent frames. Record build/stage/downstream relationships and collection membership. Do not pack running logs; seal them independently first.

**Acceptance criteria**

- [ ] A large multi-build operation never buffers or writes all logs raw.
- [ ] Duplicate log requests share one acquisition and one stored generation.
- [ ] Cancellation stops fetch/compression and leaves recoverable committed frames.
- [ ] Collection fan-out, total remote bytes, CPU, memory, and disk are policy-bounded.
- [ ] Related sealed logs can later be selected as one semantic pack without cross-profile mixing.

---

## SEARCH-001 - Implement high-throughput literal search

**Priority:** P0  
**Dependencies:** LOG-003

**Objective**

Find text locally with bounded context and minimal decompression.

**Implementation**

Support case-sensitive/insensitive literal search, match count limit, before/after lines, selected build/log scope, cancellation, and deterministic ordering. Add optional chunk-level token/Bloom summaries only if benchmarks justify them.

**Acceptance criteria**

- [ ] Search never returns more matches or bytes than policy permits.
- [ ] 1 GiB benchmark meets or calibrates the target with results documented.
- [ ] Cancellation is checked frequently.
- [ ] Matches include exact evidence references and sanitized excerpts.
- [ ] False-negative behavior is impossible for the base literal path.

---

## SEARCH-002 - Implement safe regular-expression search

**Priority:** P0  
**Dependencies:** SEARCH-001

**Objective**

Provide expressive search without catastrophic backtracking.

**Implementation**

Use Go's RE2-compatible engine. Limit pattern size, matches, context, and scanned data. Reject unsupported constructs clearly.

**Acceptance criteria**

- [ ] Adversarial patterns cannot cause unbounded CPU or memory growth.
- [ ] Scan and output limits are enforced server-side.
- [ ] Results are consistent across chunk boundaries where pattern semantics allow it.
- [ ] 1 GiB benchmark and cancellation tests pass.

---

## SEC-002 - Implement layered secret and sensitive-data redaction

**Priority:** P0  
**Dependencies:** SEC-001, LOG-003

**Objective**

Prevent credentials and configured sensitive patterns from reaching the model or telemetry.

**Implementation**

Add exact known-secret matchers, structured parameter redaction, built-in token/key/connection-string detectors, enterprise patterns, and optional customer-data rules. Redact after evidence selection and before MCP serialization.

**Acceptance criteria**

- [ ] Secret canaries are absent from MCP output, logs, metrics, errors, and support bundles.
- [ ] Redaction reports category/count without revealing value.
- [ ] Overlapping and split-across-buffer secrets are covered.
- [ ] False-positive test corpus preserves useful diagnostic content.
- [ ] Policy defines whether raw local cache remains unredacted or is redacted before persistence.

---

## SEC-003 - Sanitize control sequences and label untrusted content

**Priority:** P0  
**Dependencies:** LOG-003, MCP-001

**Objective**

Keep terminal escapes, hyperlinks, and prompt-like log content from manipulating clients or agents.

**Implementation**

Strip or encode ANSI CSI/OSC, control characters, bidi controls according to policy, and unsafe link schemes. Wrap excerpts in structured fields explicitly labeled as untrusted build output.

**Acceptance criteria**

- [ ] Terminal title/hyperlink/clipboard/control attacks are neutralized.
- [ ] Malicious fake system/tool instructions remain data, not control fields.
- [ ] Raw checksums/ranges allow forensic retrieval under authorized local tooling.
- [ ] Sanitization is deterministic and fuzz-tested.

---

## AUD-001 - Add privacy-preserving local audit events

**Priority:** P0  
**Dependencies:** FND-005, SEC-002

**Objective**

Provide attribution and operational evidence without recording content.

**Implementation**

Record version/profile startup, auth events, verified identity, tool name, hashed/opaque target, duration, result code, cache state, network/output bytes, policy denials, and maintenance actions. Rotate and protect audit files.

**Acceptance criteria**

- [ ] No prompt, full job parameter, excerpt, token, or artifact content is recorded by default.
- [ ] Events have stable schema and correlation IDs.
- [ ] Retention and optional export are policy-controlled.
- [ ] Audit failures do not leak data or silently authorize mutations.

---

## OBS-001 - Add structured diagnostic logging and core metrics

**Priority:** P1  
**Dependencies:** AUD-001, PERF-001

**Objective**

Make performance and failures measurable locally.

**Implementation**

Instrument tool, Jenkins HTTP, cache, compression, search, OAuth, archive, and maintenance operations. Add private rotating logs and optional metrics exporter with low-cardinality labels.

**Acceptance criteria**

- [ ] Network bytes, MCP bytes, cache hits, duplicate bytes avoided, and latency are observable.
- [ ] Sensitive names/content are excluded or pseudonymized by default.
- [ ] Logging overhead is benchmarked and bounded.
- [ ] Debug mode remains safe for normal support collection.

---

## OPS-001 - Implement `doctor`, cache status, and safe support diagnostics

**Priority:** P0  
**Dependencies:** AUTH-004, NET-004, STO-004, OBS-001

**Objective**

Let users and support staff diagnose setup problems without exposing secrets.

**Implementation**

Check binary/version, config/policy, ACL/free space, keyring access, DNS/TLS/proxy, identity, permissions, capabilities, cache integrity sample, archive adapter, and slow/unsafe paths. Add a privacy-scrubbed support bundle with preview.

**Acceptance criteria**

- [ ] Common auth, TLS, proxy, permission, and disk failures produce actionable results.
- [ ] Output passes secret-canary tests.
- [ ] Support bundle lists included categories before creation.
- [ ] Bundle generation is bounded and excludes raw logs by default.

---

## PKG-001 - Produce signed Tier-1 pilot packages (Rocky Linux, Ubuntu)

**Priority:** P0  
**Dependencies:** FND-007, AUTH-003, OPS-001

**Objective**

Deliver trustworthy local executables that Cursor can launch on every Tier-1 Linux OS without secrets in configuration. macOS packages are optional nice-to-have artifacts. Windows packages are out of scope.

**Implementation**

- **Rocky Linux:** signed `.rpm` for each supported Rocky major series in the matrix, plus a portable `linux/amd64` tarball; XDG per-user data paths; Secret Service integration; SELinux smoke notes; document optional `fuse`/`fuse3` dependency for L2 mount.
- **Ubuntu:** signed `.deb` for each supported Ubuntu LTS in the matrix, plus the same portable tarball where appropriate; XDG paths; Secret Service; AppArmor smoke notes; same FUSE package notes.
- Document secret-free Cursor `command`/`args` examples for Linux paths.
- Optional **macOS** archive/app bundle may be produced on a best-effort cadence; do not block pilot on notarization or Keychain polish.
- Do **not** produce Windows `.exe`/MSI/MSIX or WinFsp-based packaging.
- Version metadata, SBOM, and provenance accompany every Tier-1 artifact.

**Acceptance criteria**

- [ ] Installed binary signature validates on Rocky RPM and Ubuntu DEB baselines listed in the support matrix.
- [ ] Ordinary operation requires no root rights unless deployment policy mandates them.
- [ ] Uninstall behavior for cache and credentials is explicit and user-controlled on each Tier-1 OS.
- [ ] Cursor starts the MCP over stdio with profile-only arguments on Rocky and Ubuntu.
- [ ] SELinux/AppArmor compatibility smoke tests pass on Tier-1 images.
- [ ] macOS artifacts, if published, are labeled best-effort and are not required for pilot exit.
- [ ] Release evidence does not claim Windows support.

---

## TST-001 - Create the disposable Jenkins integration-test and route matrix

**Priority:** P0  
**Dependencies:** FND-007, NET-002

**Objective**

Test real Jenkins behavior, identity, authorization, and every route used by the MCP rather than relying only on mocks.

**Implementation**

Automate disposable Jenkins LTS/plugin environments with freestyle, Pipeline, folders, views, parameters, queue, running/completed/truncated logs, stage/node logs, JUnit, artifacts, multibranch/matrix, upstream/downstream, permissions, reverse-proxy prefixes, API-token auth, OIDC UI realm where relevant, and JWT bearer filter/proxy variants. Generate a machine-readable route manifest for controller/job/build APIs, identity, progressive text, Pipeline/test endpoints, artifact bytes, crumbs, queue, and optional mutations.

**Acceptance criteria**

- [ ] CI/scheduled jobs cover the declared Jenkins/core/plugin/reverse-proxy matrix.
- [ ] Tests use ephemeral credentials/tokens and destroy environments.
- [ ] API-token, global read-only, MCP-RBAC, inaccessible-resource, and identity-attribution cases pass.
- [ ] Fixtures deterministically produce large/growing/truncated and related root/stage/downstream/test logs.
- [ ] Every route is classified as auth/read/mutation and linked to policy/auth positive and negative tests.
- [ ] Adding an OAuth-required route without anti-fallback coverage fails CI.

---

# Phase 2 - External-IdP OAuth resource-server and L2 seekable storage

## OAUTH-001 - Add external-IdP OIDC profile and discovery validation

**Priority:** P1  
**Dependencies:** AUTH-000, AUTH-001, CFG-002, NET-004

**Objective**

Represent approved external identity-provider settings without treating Jenkins as an authorization server.

**Implementation**

Add issuer, tenant restrictions, public client ID, scopes, Jenkins resource/audience, redirect policy, token type, group policy, and optional RFC 9728 protected-resource discovery. Fetch discovery/JWKS through hardened origin-constrained transport. Explicitly reject configurations that point authorization/token endpoints at Jenkins unless a separately approved authorization-server plugin exists.

**Acceptance criteria**

- [ ] Issuer/discovery origins exactly match approved policy.
- [ ] Local client has no embedded client secret.
- [ ] Jenkins resource/audience and requested scopes are explicit.
- [ ] Metadata cache honors expiry and key rotation without trusting unknown issuers.
- [ ] Negative tests cover Jenkins UI-login endpoints falsely configured as OAuth token endpoints.

---

## OAUTH-002 - Implement local Authorization Code with PKCE browser login

**Priority:** P1  
**Dependencies:** OAUTH-001, AUTH-002

**Objective**

Authenticate each local user through the corporate browser/IdP without collecting their password.

**Implementation**

Generate state, nonce, verifier/S256 challenge; bind a loopback callback; open the system browser; validate callback; exchange code with the external IdP; clean up listener/session state. Device flow is optional and separately approved.

**Acceptance criteria**

- [ ] Cryptographic state/nonce/verifier and exact redirect binding are used.
- [ ] Replay, wrong state, duplicate callback, port race, cancellation, and timeout fail safely.
- [ ] Corporate password never enters the MCP process.
- [ ] Returned access token is requested for the Jenkins resource, not Graph or a generic audience.

---

## OAUTH-003 - Validate access tokens and identity binding strictly

**Priority:** P1  
**Dependencies:** OAUTH-002

**Objective**

Accept only access tokens intended for the approved Jenkins resource and bind them to a stable subject.

**Implementation**

Validate signature/algorithm, issuer/tenant, audience, token type/use, expiry/not-before, authorized party/client, nonce where applicable, and bounded clock skew. Distinguish ID tokens from API access tokens and never send an ID token to Jenkins. Normalize subject and approved group claims.

**Acceptance criteria**

- [x] Wrong issuer/tenant/audience/algorithm/type/time/client tests fail closed. *(offline `ValidateAccessToken` table; Wave 17)*
- [x] An ID token or Graph token is rejected for Jenkins API authentication. *(offline; live RS residual OAUTH-005/009)*
- [x] JWKS rotation succeeds without accepting unknown issuers. *(offline multi-kid / wrong-issuer tests)*
- [x] Token contents are never logged or persisted outside approved keyring fields. *(scrub + canary tests)*

**Evidence:** `docs/auth/oauth-003-claim-validation.md`; `go test ./internal/auth -run ValidateAccessToken`.  
**Residual:** live jwt-auth-filter / Entra pin remains OAUTH-005/009.

---

## OAUTH-004 - Implement refresh-token persistence and single-flight refresh

**Priority:** P1  
**Dependencies:** OAUTH-003, AUTH-002

**Objective**

Maintain a usable browser-authenticated session without repeated prompts or token races.

**Implementation**

Persist refresh tokens only when policy allows, in the OS credential store. Keep access tokens in memory. Refresh early with jitter and single-flight coordination. Update keyring state atomically when refresh-token rotation occurs.

**Acceptance criteria**

- [ ] Concurrent calls trigger at most one refresh.
- [ ] Rotated refresh tokens replace old values atomically.
- [ ] Revoked/invalid refresh fails closed and requests re-login.
- [ ] Process restart can restore a permitted session without exposing token data.
- [ ] Logout removes all OAuth session material.

---

## OAUTH-005 - Integrate Jenkins bearer resource-server authentication

**Priority:** P1  
**Dependencies:** OAUTH-003, TST-001, OAUTH-008

**Objective**

Call Jenkins with an externally issued Jenkins-audience access token under the personal Jenkins identity.

**Implementation**

Configure/test `jwt-auth-filter`, an approved fork, or reverse proxy for audience, JWKS, protected API paths, principal/group mapping, and RFC 9728 metadata. Add bearer auth sessions. Detect invalid-bearer fallthrough, Basic/anonymous fallback, wrong principal, and missing protected paths.

**Acceptance criteria**

- [ ] Jenkins reports the expected individual principal and applies its RBAC.
- [ ] Wrong/missing/expired bearer fails closed on OAuth-required paths.
- [ ] Basic/API-token fallback behavior matches explicit policy, not accidental filter chaining.
- [ ] Protected route coverage includes APIs plus progressive text, Pipeline/test endpoints, artifact-byte paths, identity/crumb/queue paths, and enabled mutations.
- [ ] Audit attributes requests to the personal Jenkins principal.

---

## OAUTH-006 - Test claims, groups, revocation, and MCP policy binding

**Priority:** P1  
**Dependencies:** OAUTH-005, POL-003

**Objective**

Prove identity and both authorization layers behave under enterprise edge cases.

**Implementation**

Test direct groups, Entra overage/reference behavior, large sets, renamed users, removed roles, disabled accounts, token expiry/revocation, key rotation, clock skew, and Jenkins principal mapping. Verify MCP policy subject/group bindings update within the approved window.

**Partial progress (foundation)**

- [x] **Entra group overage fail-closed foundation (Done\*):** `_claim_names` /
  `_claim_sources` or groups-as-ref without a full `groups` array fails closed
  at `ValidateAccessToken` / `ExtractGroups` / gateway `ResolveHTTPInbound`
  (no invented membership). Hybrid concrete `groups` array OK. Lab path
  unchanged. Secret/endpoint canaries. **Residual:** Microsoft Graph membership
  expansion (OAUTH-010); live Entra under load; full role-removal window matrix.

**Acceptance criteria**

- [ ] Jenkins and MCP policy permissions reflect role removal within the approved window.
- [x] Group overage cannot silently broaden access. *(count cap + Entra incomplete overage fail-closed foundation; Graph expansion still residual)*
- [ ] Identity changes invalidate incompatible sessions/cache bindings.
- [ ] Effective permission remains the intersection of Jenkins and MCP policy.

---

## OAUTH-007 - Add OAuth logout, session diagnostics, and recovery

**Priority:** P1  
**Dependencies:** OAUTH-004, OAUTH-005

**Objective**

Make session state understandable and safely removable.

**Implementation**

Add status fields for issuer, principal, expiry, refresh availability, and Jenkins identity; optional provider revocation when supported; local token removal; and safe recovery from corrupt keyring entries.

**Acceptance criteria**

- [ ] Status contains no token claims beyond approved identity metadata.
- [ ] Logout immediately prevents further remote calls from the process.
- [ ] Provider revocation is attempted only when supported and errors are clearly distinguished from local logout.
- [ ] Corrupt/partial credentials do not crash startup.

---

## OAUTH-008 - Document and test the Jenkins OAuth capability matrix

**Priority:** P0  
**Dependencies:** AUTH-000, FND-003, TST-001

**Objective**

Prevent selection of plugins that do not provide delegated API bearer authentication.

**Implementation**

Create versioned capability tests/documentation for Jenkins core/API tokens, `oic-auth`, `oidc-provider`, `github-oauth`, `oauth-credentials`, `jwt-auth-filter`, and approved proxies. Classify each as browser security realm, outbound workload issuer, credential framework, bearer resource server, or authorization server.

**Acceptance criteria**

- [ ] No UI-login plugin is represented as an API authorization server.
- [ ] Automated `doctor` output identifies detected plugins and supported auth modes.
- [ ] The matrix cites exact tested versions and expected endpoints/headers.
- [ ] A deployment with only `oic-auth` clearly falls back to the API-token provider rather than attempting bearer API calls.

---

## OAUTH-009 - Qualify and harden `jwt-auth-filter` or its replacement

**Priority:** P1  
**Dependencies:** OAUTH-005, TST-001, POL-004

**Objective**

Determine whether the current bearer resource-server control is production-ready and close its documented gaps.

**Implementation**

Inspect and measure invalid-token fallthrough, Basic/API-token/session/anonymous fallback, protected-path matching, non-API route coverage, claim configurability, groups/overage, scope enforcement, JWKS fetch/cache/outage/key rotation, audience matching, multiple issuers, performance, audit identity, and upgrades. Decide whether to contribute upstream, maintain an internal fork/companion filter, enforce at a reverse proxy, or replace it. The local MCP calls Jenkins REST routes; protecting only `/mcp/**` is insufficient.

**Acceptance criteria**

- [ ] A written go/no-go and exact JCasC/proxy/plugin configuration are approved.
- [ ] OAuth-required routes fail closed for missing/malformed/expired/wrong-audience bearer tokens.
- [ ] Progressive log and artifact download routes are protected, not only `/**/api/**`.
- [ ] JWT failure cannot silently succeed through Basic/API-token/UI-session/anonymous authentication.
- [ ] Claim/group/overage, JWKS cache/outage/rotation, and scope behavior meet requirements.
- [ ] Security review, performance evidence, rollback, and emergency disable plans exist for any fork/proxy.

**Offline residual note (honest):** Offline classifier + Bearer claim matrix (wrong aud/exp/iss, ID-token reject, Mode B no Basic fallthrough) + doctor/self-check Mode B residual are **Done*** foundations (`docs/auth/jwt-auth-filter-qualification.md`, Wave 33 + OAUTH-009 expand; qualify case `oauth009_offline_bearer_matrix`; GWY-003 cross-link). Mock Docker lab path is HOST-012…014 (`make live-oauth-*`) — **not** a production pin. **Live Entra + real jwt-auth-filter version pin remain open — do not claim live Entra Done.**

**Offline evidence (not live go):**
- `go test ./internal/auth ./internal/gateway ./internal/gateway/qualify -count=1`
- Doctor `rs_auth` / self-check `rs_qualification`: `live_lab_still_required=true`; Mode B → warn + `mode_b_live_rs_qualified=false`

---

## OAUTH-010 - Prototype AgentCore per-user Jenkins 3LO/OBO token acquisition

**Priority:** P2  
**Dependencies:** OAUTH-005, POL-003, FND-005  
**Status:** **Partial / offline prototype matrix Done\*** — **do not claim live Entra Done**

**Objective**

Confirm the real AgentCore provider contract and integrate the existing per-user identity pattern without a shared Jenkins identity.

**Implementation**

Obtain the approved AgentCore Identity/Gateway contract and prototype these paths in order:

1. User-delegated Authorization Code (`AUTHORIZATION_CODE`/user federation) through an AgentCore `CustomOauth2` or approved Microsoft provider. Discovery, authorization, issuer, and token endpoints point to Entra ID or another approved authorization server; the requested resource/audience is the dedicated Jenkins API.
2. Microsoft on-behalf-of or standards-based token exchange using the approved RFC 8693 or RFC 7523 profile to obtain a short-lived Jenkins-audience token.
3. Direct JWT passthrough only when the inbound token was already issued for the exact Jenkins resource, both gateway and Jenkins validate it, and security approves the audience model.
4. A narrow internal broker/filter only when the first three cannot satisfy a documented requirement.

Bind inbound gateway subject and workload identity to the downstream token subject, tenant, Jenkins resource, MCP policy subject, cache namespace, and audit correlation. Use AgentCore's user/workload-bound credential provider and token-vault semantics for access/refresh material. Stream an authorization URL to the caller when interactive consent is required. Keep Jira/Confluence VPC routing, Bitbucket Cloud consent implementation, and Jira automation PAT details outside Jenkins core code.

**Acceptance criteria**

- [x] A compatibility matrix records which Authorization Code, OBO/token-exchange, and exact-audience passthrough paths work and the precise provider/resource configuration. — **offline prototype matrix Done\*** (`docs/auth/oauth-capability-matrix.md` §4; qualify `oauth010_mode_c_offline_matrix` + HOST-011 `mode_c_agentcore_live_matrix`). Live Entra path cells remain residual.
- [x] AgentCore issuer/authorization/token endpoints are Entra/approved authorization-server endpoints, never stock Jenkins, unless OAUTH-011 has an explicit go decision and the conditional plugin exists. — offline `ValidateProviderConfig` + qualify Jenkins-as-AS reject; live endpoint pin residual
- [ ] Authorization-code consent is session-bound and access/refresh material is stored under the correct user and workload identity. — offline ConsentRequired metadata + process cache Done\*; durable AgentCore vault residual
- [x] One user cannot obtain/use another user's downstream token, cache entry, evidence handle, or archive namespace. — offline cache isolation / qualify vault hit-miss (process memory)
- [ ] Token audience is Jenkins and Jenkins sees the expected individual principal. — offline wrong-audience fail + Bearer shape Done\*; live whoAmI principal residual
- [ ] Refresh/cache/vault storage is per-user, centrally revocable, and contains no user-pasted Jenkins key. — process cache Done\*; durable vault residual
- [x] Direct passthrough rejects generic gateway, ID, Graph, wrong-tenant, and wrong-audience tokens. — offline wrong-audience + claim paths; generic passthrough remains disabled
- [x] No generic Jenkins account is used. — Obtain requires caller subject; no shared-SA fallback
- [x] Local and gateway auth providers remain independent and testable. — package + qualify offline suites

**Offline residual note (honest):** Gateway Obtain fail-closed + pluggable `TokenFetcher` mock + `HTTPTokenFetcher` https mock AS + HOST-015 `mock-token` lab + doctor Mode C residual are foundation only (`docs/auth/oauth-capability-matrix.md` §4; `make live-oauth-*`). **Live Entra 3LO/OBO + AgentCore production pin remain open** (GWY-003) — **never mark live Entra Done from offline evidence.**

**Offline evidence (Done\*):**

| Artifact | Role |
|----------|------|
| `TestOAUTH010_ModeC_OfflinePrototypeMatrix` | Named offline suite: Live=false; Live=true nil Fetcher; auth_code consent; token_exchange Bearer; wrong aud; HTTPTokenFetcher mock AS; ModeMatrix residual |
| qualify `oauth010_mode_c_offline_matrix` | GWY-003 qualify row (complements HOST-011 `mode_c_agentcore_live_matrix`) |
| doctor `gateway_status` Mode C residual | `mode_c_live_agentcore_qualified=false`; warn when Mode C explicit / LIVE / multi-user |
| `make live-oauth-*` + `-tags=live_oauth` HOST-015 | Opt-in mock-token peer + Mode C Obtain residual (not production Entra; TLS test shim residual) |

---

## OAUTH-011 - Run the decision gate for a Jenkins-hosted 3LO authorization server

**Priority:** P2  
**Dependencies:** OAUTH-009, OAUTH-010, security architecture approval  
**Status:** **Done\*** residual formal **default no-go** (not a funded **go** for JAS plugin)

**Objective**

Make the default decision **no-go** and approve a full Jenkins OAuth authorization-server plugin only when a concrete, funded requirement remains unsolved after external-IdP resource-server, AgentCore authorization-code, OBO/token-exchange, passthrough, proxy/filter, and narrow-broker prototypes.

**Implementation**

Document every unmet gateway/client requirement after the simpler prototypes, why each alternative fails, security and long-term maintenance ownership, client/scopes/consent requirements, key and token lifecycle, conformance obligations, migration impact, and exit strategy. A desire for Jenkins-branded OAuth endpoints or symmetry with another product is not sufficient justification.

**Evidence (default no-go residual):** [`docs/auth/jas-no-go.md`](auth/jas-no-go.md) §4.1 decision log; ADR 0013; capability matrix; `gateway.ValidateProviderConfig` + `auth.RejectJenkinsAsAuthorizationServer` canaries. Live Entra/AgentCore pins remain open and do **not** re-open Jenkins-as-AS.

**Acceptance criteria**

- [x] Decision records explicit go/no-go criteria, evidence, approvers, owner, funding, and support horizon. — §4.1 residual formalization (org pen-test sign-off residual for any future **go**)
- [x] The default/no-evidence result is no-go and closes or deprioritizes the conditional JAS epic. — JAS-002…005 not scheduled under default no-go
- [x] A go decision identifies a specific blocker that cannot be solved safely by Entra/AgentCore, a resource filter/proxy, token exchange, or a narrow broker. — N/A for **no-go**; criteria documented for re-open
- [x] A go decision funds separate threat modeling, key management, secure token storage, OAuth conformance, independent review, penetration testing, release engineering, and incident ownership. — N/A for **no-go**; funding none under default
- [x] The MCP core and local release do not depend on the plugin before or after this gate.

---

## ARC-001 - Implement the `ArchiveStore` abstraction and object model

**Priority:** P1  
**Dependencies:** ARC-000, STO-004

**Objective**

Decouple cold-storage policy from ratarmount implementation details.

**Implementation**

Define pack publish/open/range-read/verify/delete/list interfaces, archive references, entry metadata, health, and errors. Require opaque entry IDs, checksums, cancellation, and bounded reads.

**Acceptance criteria**

- [ ] L1 code depends only on `ArchiveStore`, not ratarmount APIs.
- [ ] Fake store supports deterministic unit tests.
- [ ] Range reads enforce policy limits.
- [ ] Store implementations expose capabilities without leaking paths to MCP tools.

---

## ARC-002 - Specify seekable TAR/Zstandard pack format v1

**Priority:** P1  
**Dependencies:** ARC-001, STO-003, ARC-000

**Objective**

Define an immutable self-describing random-access format compatible with the native reader and the qualified `ratarmount-rs` adapter.

**Implementation**

Specify the opaque TAR namespace; semantic collection/affinity manifests; independent Zstandard frames; final seek-table/checkpoint frame; compressed/uncompressed frame offsets; TAR member offsets/sizes; line/evidence indexes; checksums; optional versioned dictionaries/encryption; rollover limits; and schema evolution. Initial raw payload-frame target is 8 MiB with a benchmarked 1-32 MiB range; initial physical pack target is 4-16 GiB. Define the preferred promotion representation as a deterministic sequence of small generated TAR-header frames, copied L1 compressed payload frames, optional small generated TAR-padding frames, TAR termination frames, and the final seek table. Define a compatibility repack writer for readers that reject this frame layout. Ban ordinary single-frame `.tar.zst`.

**Acceptance criteria**

- [ ] Fixtures cover related root/stage/downstream/test logs, small-member bundles, split large members, empty/long-line/binary-like data, generated header/padding frames, and corruption.
- [ ] Validator confirms TAR termination, multiple frame bounds, seek table, manifests, offsets, limits, dictionaries, and checksums.
- [ ] Member/range lookup requires no full-pack decompression.
- [ ] Sequential standard Zstandard decompression recovers a standards-compliant TAR stream.
- [ ] A fixture proves copied L1 payload-frame bytes are unchanged in the preferred L2 pack.
- [ ] Native and qualified `ratarmount-rs` readers return byte-identical results for golden packs; incompatible readers use the measured compatibility repack path.
- [ ] Format/version/endian/limits/migration policy are documented and fuzzable.

---

## ARC-003 - Implement the native Go seekable TAR/Zstandard reader

**Priority:** P1  
**Dependencies:** ARC-002, ARC-000

**Objective**

Keep the product functional and recoverable without FUSE or `ratarmount-rs`.

**Implementation**

Parse and validate the selected seek table, map raw TAR/member ranges to independent frames, decompress only required frames under limits, verify checksums and optional dictionary identities, and expose `ArchiveStore.OpenRange`. Support catalog rebuild/inspection without extracting packs. Correctly span generated header, reused payload, and padding frame boundaries.

**Acceptance criteria**

- [ ] Reads return exact member/range bytes for every format fixture.
- [ ] A 64 KiB range never triggers full-pack decompression and reports amplification.
- [ ] Malformed frame/seek/TAR/dictionary metadata fails safely under fuzzing.
- [ ] Rocky Linux and Ubuntu recover via native Go without FUSE; Linux FUSE mount is optional for inspection; Windows/WinFsp is out of scope.
- [ ] Reader output matches the qualified `ratarmount-rs` adapter byte-for-byte when that adapter is available.

---

## ARC-004 - Implement the qualified `ratarmount-rs` adapter

**Priority:** P1  
**Dependencies:** ARC-000 (production go), ARC-002, ARC-003  
**Pin target:** `hilather/ratarmount-rs` **v0.1.14** @ `eeff8502539375acb0e0bfae9d0b327fee0fbe4d` (see `docs/arc/ratarmount-rs-pin.json`)

**Objective**

Use the preferred archive implementation without making it a single point of failure; MCP default remains native Go.

**Implementation**

Implement the approved managed sidecar/CLI (preferred) or direct API after ARC-000 go. Embed or document the pin (tag + SHA). Sandbox/lifecycle/limits, controlled index location, cancellation, health checks, and sanitized errors. Optional FUSE mount mode is diagnostic only. Never require FUSE for tool reads. Expose capability flags (`RatarmountAdapter`, `FUSEMountAvailable`) honestly.

**Acceptance criteria**

- [ ] Adapter opens/list/range-reads pack-format-v1 packs within limits against pin **v0.1.14**.
- [ ] No public listener or arbitrary user path traversal exists.
- [ ] Sidecar/FFI failure degrades to native reader where possible.
- [ ] Index corruption/mismatch is detected and recoverable.
- [ ] Supply-chain/update/rollback process is documented (bump pin JSON + re-qualify).
- [ ] Default pilot/serve path works with adapter disabled.

#### ARC-004a - Sidecar/CLI lifecycle and sandbox (pin v0.1.14)

**Priority:** P1  
**Dependencies:** ARC-004, ARC-000c

- [ ] Spawn/kill/timeout/cancel policies; resource limits (CPU/RSS/files).
- [ ] No listen on non-loopback; pack paths allowlisted to profile data dir only.
- [ ] Health check + fail-closed handoff to native Go.
- [ ] Operator docs: enable/disable, logs (secret-free), troubleshooting.

#### ARC-004b - Optional FUSE inspection path (diag only)

**Priority:** P2  
**Dependencies:** ARC-004a, ARC-000c

- [ ] Rocky + Ubuntu FUSE mount for human inspection of L2 packs (not MCP hot path).
- [ ] Policy/default-off; document residual SELinux/AppArmor.
- [ ] Windows explicitly unsupported.

---

## ARC-005 - Build transactional L1-to-L2 packing and compaction

**Priority:** P1  
**Dependencies:** ARC-003, ARC-004, ARC-010, ARC-011

**Objective**

Publish semantic seekable packs without data loss or interactive stalls.

**Implementation**

Acquire packing leases, assemble/copy frames or use compatibility repack, finalize TAR and seek table, fsync, build indexes, verify through both readers, atomically publish catalog, then release L1. Journal every phase and bound compaction priority/concurrency.

**Acceptance criteria**

- [ ] Crash at every transition leaves either valid L1 or published L2 discoverable.
- [ ] Source frames are not deleted before dual-reader verification/publish commit.
- [ ] Interactive reads do not wait on index build/compaction.
- [ ] Disk-full/cancel/corruption recovery is deterministic.
- [ ] Compaction preserves collection, policy, retention, and checksum metadata.

---

## ARC-006 - Add archive index lifecycle and corruption recovery

**Priority:** P1  
**Dependencies:** ARC-004, ARC-005

**Objective**

Keep archive indexes trustworthy and recoverable without synchronous full scans.

**Implementation**

Bind index metadata to pack checksum/size/schema, create indexes off the request path, detect stale/mismatched indexes, rebuild asynchronously, quarantine corrupt packs, and fall back to native reads when possible.

**Acceptance criteria**

- [ ] A stale or wrong index is never trusted.
- [ ] MCP reads never trigger an unbounded synchronous index build.
- [ ] Existing valid indexes load within the calibrated target.
- [ ] Rebuild can be cancelled/resumed or restarted safely.
- [ ] `cache verify/repair` reports exact affected objects.

---

## ARC-007 - Implement quota, retention, pinning, and eviction across L1/L2

**Priority:** P1  
**Dependencies:** ARC-005, STO-002

**Objective**

Bound disk use while protecting active investigations and running builds.

**Implementation**

Track physical/logical bytes by tier/profile/type. Add configurable quotas, LRU/age/result rules, pins, active-reader leases, low-disk threshold, dry-run, and deterministic eviction order.

**Acceptance criteria**

- [ ] Default total quota is enforced without exhausting the volume.
- [ ] Running/pinned/leased objects are not evicted.
- [ ] Dry-run explains each candidate and reclaimed-byte estimate.
- [ ] Metadata remains consistent after interrupted eviction.
- [ ] Successful versus failed build retention can be configured separately.

---

## ARC-008 - Add full/sampled integrity verification and repair commands

**Priority:** P1  
**Dependencies:** ARC-006, ARC-007

**Objective**

Detect bit rot, tampering, orphaned catalog rows, and incomplete transitions.

**Implementation**

Implement fast metadata/sample verification and explicit full verification. Rebuild derived indexes, re-fetch from Jenkins when permitted/available, or mark data unavailable with reason.

**Acceptance criteria**

- [ ] Verification reports pack, entry, checksum, catalog, and index issues separately.
- [ ] Repair never overwrites the only known-good copy without validation.
- [ ] Full verification is cancellable and progress-aware.
- [ ] Results are safe for support sharing.

---

## ARC-009 - Add optional application-level cache encryption

**Priority:** P2  
**Dependencies:** AUTH-002, ARC-002, STO-003, security approval

**Objective**

Support environments requiring encryption beyond OS ACL/full-disk encryption.

**Implementation**

Select an approved AEAD, manage per-profile/versioned keys in the OS credential store, authenticate headers/metadata, stream encrypt independent chunks/entries, and define key rotation/recovery policy.

**Acceptance criteria**

- [ ] Tampering fails authentication before plaintext is returned.
- [ ] Keys never enter config, logs, MCP, or pack manifests.
- [ ] Rotation does not require all data to be rewritten synchronously.
- [ ] Loss/revocation behavior is documented and tested.
- [ ] Deduplication/equality leakage tradeoff is approved.

---

## ARC-010 - Implement zero-recompression TAR header/payload/padding frame assembly

**Priority:** P1  
**Dependencies:** ARC-002, STO-003

**Objective**

Avoid decompressing or recompressing sealed log payload frames during normal L2 promotion.

**Implementation**

For each TAR member, generate a small independent frame containing the deterministic TAR header, copy the already-compressed L1 payload frames in member order, and generate a small independent padding frame only when TAR alignment requires it. Generate TAR end-of-archive frames, append the final seek-table/checkpoint frame, and compute manifests/checksums over both compressed and logical representations. Record frame roles and uncompressed offsets so readers can map ranges across header, payload, and padding frames. Keep a feature-gated compatibility path that streams decompressed L1 bytes through a conventional seekable-pack writer when the qualified adapter cannot consume the preferred layout.

**Acceptance criteria**

- [ ] Preferred assembled output sequentially decompresses to a standards-compliant TAR with correct headers, member sizes, padding, and termination.
- [ ] Promotion copies compressed L1 payload-frame bytes byte-for-byte and does not invoke payload decompression/recompression.
- [ ] Only generated header/padding/termination metadata is newly compressed in the preferred path.
- [ ] Seek entries and member indexes map correctly across header, payload, padding, and frame boundaries.
- [ ] Native and qualified `ratarmount-rs` readers pass identical random-read fixtures, or the compatibility path is selected automatically and explicitly measured.
- [ ] Crash/cancel/disk-full tests never publish a partial pack.
- [ ] Benchmarks quantify CPU, wall time, write amplification, and extra bytes versus compatibility recompression.

---

## ARC-011 - Implement related-log affinity batching and pack rollover

**Priority:** P1  
**Dependencies:** ARC-002, LOG-004, STO-002

**Objective**

Batch logs normally used by one diagnosis into the same bounded archive when policy, retention, and locality make sense.

**Implementation**

Plan packs by user/profile/controller, root job/build or investigation collection, pipeline/downstream graph, time, sensitivity, retention/encryption class, member count, raw/compressed size, and access heat. Co-locate root console, stage/node, discovered downstream/matrix-child logs, text test evidence, manifests, line maps, and diagnostic indexes. Split oversized collections deterministically with a shared collection ID/continuation metadata. Optionally co-pack tiny adjacent builds only when all policy/lifecycle dimensions match. Keep binary artifacts separate unless explicitly approved.

**Acceptance criteria**

- [ ] Related root/stage/downstream/test logs normally share one affinity pack until a bound requires rollover.
- [ ] No pack mixes users, profiles/controllers, or incompatible sensitivity/retention/encryption classes.
- [ ] Oversized fan-out splits deterministically while preserving relationship/evidence references.
- [ ] Late members never mutate a published pack and do not block interactive reads indefinitely.
- [ ] Evicting one collection avoids rewriting unrelated hot collections beyond thresholds.
- [ ] Metrics quantify locality, packs touched per diagnosis, dead space, and expected read amplification.

---

## ARC-012 - Validate seek-table and ratarmount compatibility variants

**Priority:** P1  
**Dependencies:** ARC-003, ARC-004, ARC-010  
**Pin target:** `ratarmount-rs` **v0.1.14** @ `eeff8502539375acb0e0bfae9d0b327fee0fbe4d`

**Objective**

Prove the exact Zstandard random-access representation works across supported readers and versions.

**Implementation**

Create a matrix for official seekable format, concatenated independent frames, checksummed seek entries, small-member bundling, split members, dictionaries/encryption, truncated tables, and index rebuild. Compare with an independently implemented seekable-Zstandard/t2sz-compatible writer where licensing and format compatibility allow.

**Acceptance criteria**

- [ ] Supported variants have versioned golden packs and byte-identical reads.
- [ ] Single-frame and unsupported variants are rejected with actionable diagnostics.
- [ ] Upgrade/downgrade behavior and reader version matrix are documented.
- [ ] Corrupt/malicious seek tables cannot cause unbounded reads or wrong-member data.

---

## PERF-002 - Qualify L2 seekable packs at enterprise scale

**Priority:** P1  
**Dependencies:** ARC-005, ARC-006, ARC-012

**Objective**

Prove the selected pack/reader design improves capacity without harming interactive latency or CPU.

**Implementation**

Benchmark multiple frame sizes, small-member bundle thresholds, pack sizes, compression levels, zero-recompression and compatibility repack paths on at least 100 GiB physical/logically larger data. Measure ratio, ingest/promotion throughput, index build/load, warm/cold range latency, amplification, concurrent reads, RSS, antivirus impact, corruption, and fallback.

**Acceptance criteria**

- [ ] No member/range read performs full-pack extraction/decompression.
- [ ] Random-read amplification and p95 latency meet approved targets or are recalibrated with evidence.
- [ ] Zero-recompression path has measured CPU/wall/disk benefits and no correctness loss.
- [ ] Index/compaction work remains outside interactive latency.
- [ ] A go/no-go for exact ratarmount-rs version and pack parameters is recorded.

---

# Phase 3 - Enterprise Jenkins coverage and diagnostics

## JEN-001 - Implement controller capability discovery and cache

**Priority:** P0  
**Dependencies:** NET-003, TST-001

**Objective**

Discover supported Jenkins APIs/plugins and degrade cleanly.

**Implementation**

Capture Jenkins version, core endpoints, Pipeline REST API availability/version, test/artifact capabilities, permissions for representative endpoints, and optional plugin signals. Cache with TTL and invalidate on version change or explicit refresh.

**Acceptance criteria**

- [ ] Tools check capability objects rather than guessing from errors.
- [ ] Missing optional plugins produce a clear capability error/fallback.
- [ ] Capability discovery is bounded and does not require admin permission.
- [ ] Results include freshness and source.

---

## JEN-002 - Harden jobs, folders, views, multibranch, and matrix discovery

**Priority:** P0  
**Dependencies:** JEN-001, MCP-001, MCP-002

**Objective**

Provide efficient, typed job discovery across enterprise layouts.

**Implementation**

Use Jenkins tree/depth selectors, stable pagination, local filters, full folder names, views, disabled/buildable state, and last-build summaries. Add capability-aware multibranch/PR and matrix parent/child representation.

**Acceptance criteria**

- [ ] Large job trees are paginated and do not return full nested graphs by default.
- [ ] Nested names containing spaces/special characters work.
- [ ] Multibranch and matrix fixtures have stable typed references.
- [ ] Network-byte benchmark demonstrates selective field retrieval.

---

## JEN-003 - Implement paginated build history and baseline resolution

**Priority:** P0  
**Dependencies:** JEN-002

**Objective**

Retrieve only the builds needed for triage and comparison.

**Implementation**

Support filters for result, time, branch, commit, cause, and selected non-secret parameters. Resolve last successful/failed/unstable/completed and selected baseline. Stop scanning when limits/condition are met.

**Acceptance criteria**

- [ ] History scans have max builds/time/network limits.
- [ ] Results distinguish cached versus refreshed metadata.
- [ ] Secret parameter values are never returned or indexed.
- [ ] Baseline resolution is deterministic in fixtures with aborted/running builds.

---

## JEN-004 - Complete queue, running-build, and adaptive wait behavior

**Priority:** P0  
**Dependencies:** JEN-001, NET-003

**Objective**

Observe live work efficiently without aggressive polling.

**Implementation**

Provide queue list/item, running builds, executor placement, cancellation-aware waits, initial fast polling followed by backoff/jitter, and a maximum wait budget. Reuse shared state across concurrent waiters.

**Acceptance criteria**

- [ ] Multiple waiters do not multiply remote polls linearly.
- [ ] Completed/cancelled items stop polling immediately.
- [ ] Wait results include latest known state and timeout/cancellation distinction.
- [ ] Poll schedule and request counts meet benchmark expectations.

---

## PIPE-001 - Add Pipeline REST stage graph support

**Priority:** P1  
**Dependencies:** JEN-001, JEN-003

**Objective**

Expose stage status/timing/parallel structure when the Pipeline REST API is available.

**Implementation**

Model pipeline runs, stages, parallel branches, start/duration/result, and failed stage. Use version/capability adapters and bounded node retrieval.

**Acceptance criteria**

- [ ] Pipeline fixture stages match Jenkins UI/API data.
- [ ] Parallel branches are represented without flattening ambiguity.
- [ ] Missing plugin/API produces a documented fallback.
- [ ] Large pipelines are paginated or summarized within MCP budgets.

---

## PIPE-002 - Mirror and index stage/node logs

**Priority:** P1  
**Dependencies:** PIPE-001, LOG-002, LOG-003

**Objective**

Apply the same efficient storage/search model to stage-specific logs.

**Implementation**

Create log keys for stage/node sources, progressive acquisition where supported, source labels, merged timeline metadata, and local line/search indexes. Avoid duplicating bytes already present in the console log unless APIs genuinely provide separate content.

**Acceptance criteria**

- [ ] Stage log reads use bounded local storage.
- [ ] Duplicate-content policy and storage impact are measured.
- [ ] Evidence identifies stage/node and source API.
- [ ] Missing/partial stage logs do not corrupt the console generation.

---

## TEST-001 - Parse and expose JUnit test results

**Priority:** P1  
**Dependencies:** JEN-001, MCP-001

**Objective**

Provide structured test summaries and bounded failure evidence.

**Implementation**

Retrieve Jenkins test result APIs where available; model suites/cases, status, age, duration, stdout/stderr references, and failure stack traces. Store large details in bounded local objects/handles.

**Acceptance criteria**

- [ ] Summary counts match Jenkins fixtures.
- [ ] Very large test suites remain paginated and bounded.
- [ ] Failure text passes redaction/sanitation.
- [ ] Missing test plugin/data returns an empty/capability result, not an invented success.

---

## TEST-002 - Implement flaky, new-failure, and duration-regression analysis

**Priority:** P1  
**Dependencies:** TEST-001, JEN-003

**Objective**

Analyze test history locally without repeatedly fetching full reports.

**Implementation**

Cache compact test outcomes, compute failure frequency/recency, distinguish new versus previously failing tests, and compare duration against configurable baselines.

**Acceptance criteria**

- [ ] Lookback and network/cache limits are enforced.
- [ ] Classification includes sample size and confidence, not binary certainty alone.
- [ ] Renamed/parameterized test identities have documented matching rules.
- [ ] Historical queries use cached compact data after initial fetch.

---

## SCM-001 - Add SCM revision and changes-since-baseline correlation

**Priority:** P1  
**Dependencies:** JEN-003, JEN-001

**Objective**

Show what changed between a failed build and a selected green/baseline build.

**Implementation**

Extract repository identity, branch, revision(s), Jenkins changesets, culprits, commit range, and modified-file summaries. Label culprit data as Jenkins-reported correlation, not proof.

**Acceptance criteria**

- [ ] Build-to-build change result is bounded and paginated.
- [ ] Credentials embedded in repository URLs are stripped.
- [ ] Multi-SCM builds are represented explicitly.
- [ ] Missing change data is reported without guessing.

---

## GRAPH-001 - Build bounded upstream/downstream traversal

**Priority:** P1  
**Dependencies:** JEN-003, PIPE-001

**Objective**

Trace orchestration and component failures across related builds.

**Implementation**

Combine Jenkins causes/actions, upstream/downstream links, Pipeline build-step data where exposed, trigger-plugin data where accessible, and matrix children. Add cycle detection, node/depth/fan-out limits, and parallel fetch bounds.

**Acceptance criteria**

- [ ] Cyclic fixture terminates deterministically.
- [ ] Permission-denied/missing nodes are represented safely.
- [ ] Traversal returns a graph handle/summary under output limits.
- [ ] Earliest failure time and first failing leaves are computed from evidence.
- [ ] Network request limits are enforced per traversal.

---

## ART-001 - Add artifact metadata and selective bounded download

**Priority:** P1  
**Dependencies:** JEN-003, NET-003, STO-001

**Objective**

Let users inspect relevant artifacts without bulk download.

**Implementation**

List artifact relative paths/names/sizes when available. Stream selected downloads through size, time, checksum, content-type, quota, and cancellation limits into an isolated cache namespace.

**Acceptance criteria**

- [ ] No artifact is downloaded during list-only operations.
- [ ] Download aborts before exceeding configured compressed/raw limits.
- [ ] Paths cannot escape the artifact workspace.
- [ ] Checksums and source build references are recorded.
- [ ] Artifact quota is separate and enforceable.

---

## ART-002 - Implement safe artifact and archive inspection

**Priority:** P1  
**Dependencies:** ART-001, SEC-003

**Objective**

Read approved text/structured data and inventories without executing untrusted content.

**Implementation**

Support bounded text, JSON, XML, and archive inventory. Apply file-count, nesting, expansion-ratio, expanded-byte, symlink/device, path, CPU, and time limits. Prefer random inventory/read APIs over extraction.

**Acceptance criteria**

- [ ] Zip-slip, symlink, device, absolute path, and archive-bomb fixtures are blocked.
- [ ] No artifact is executed or loaded as a dynamic library.
- [ ] Parsing uses bounded readers and safe XML settings.
- [ ] Temporary workspaces are private and cleaned after cancellation/crash recovery.
- [ ] Returned content is redacted/sanitized and bounded.

---

## HEALTH-001 - Add node, executor, label-demand, and queue-pressure tools

**Priority:** P1  
**Dependencies:** JEN-004, JEN-001

**Objective**

Explain why builds are waiting or running slowly using authorized Jenkins data.

**Implementation**

Expose node online/offline state, labels, executors, busy/idle state, offline cause, queue demand by label, and saturation summaries. Avoid admin-only fields unless the user is authorized and policy permits them.

**Acceptance criteria**

- [ ] Queue-delay fixtures produce evidence-backed summaries.
- [ ] Large node lists are paginated.
- [ ] Sensitive environment/system properties are not returned.
- [ ] Missing permissions are distinguished from no nodes/data.

---

## HEALTH-002 - Add controller version, plugin capability, and health summary

**Priority:** P1  
**Dependencies:** JEN-001

**Objective**

Diagnose capability gaps and basic controller health without administrative mutation.

**Implementation**

Expose Jenkins version, selected plugin/version capabilities, safe monitor summaries, and compatibility warnings. Do not require full plugin inventory when a targeted capability probe suffices.

**Acceptance criteria**

- [ ] Capability report explains which product features are available/unavailable.
- [ ] Admin-only data is omitted when inaccessible.
- [ ] Plugin/controller changes invalidate stale capability cache.
- [ ] No update/install/disable action is exposed.

---

## DIAG-001 - Implement deterministic error extraction and signatures

**Priority:** P1  
**Dependencies:** SEARCH-002, TEST-001, PIPE-002

**Objective**

Reduce noisy logs into repeatable candidate failures before model interpretation.

**Implementation**

Add timestamp/severity parsing, stack-trace grouping, repeated-line folding, common build-tool adapters, first/last meaningful error, normalized signature hashes, and evidence ranges. Keep parsers pluggable and conservative.

**Acceptance criteria**

- [ ] Every extracted event maps to exact source evidence.
- [ ] Parser failure falls back to raw literal rules without losing data.
- [ ] Volatile values are normalized only through documented rules.
- [ ] False-positive/negative corpus and performance benchmarks exist.

---

## DIAG-002 - Implement `jenkins_diagnose_build`

**Priority:** P1  
**Dependencies:** DIAG-001, PIPE-001, TEST-002, SCM-001, GRAPH-001

**Objective**

Answer the primary triage question in one bounded call.

**Implementation**

Combine build result, failed stage, deterministic errors, test failures, changes since green, related build failures, and selected evidence. Add confidence and heuristic labels. Use local cache first and a request budget across remote sources.

**Acceptance criteria**

- [ ] Result stays under default response budget for enterprise fixtures.
- [ ] Every conclusion cites evidence or states that evidence is unavailable.
- [ ] Ambiguous fixtures return multiple candidates/low confidence rather than a fabricated root cause.
- [ ] Repeated calls avoid duplicate log downloads.
- [ ] End-to-end latency/network benchmarks are recorded.

---

## DIAG-003 - Implement `jenkins_compare_builds`

**Priority:** P1  
**Dependencies:** DIAG-001, TEST-002, SCM-001, PIPE-001

**Objective**

Compare a failing build with a selected baseline efficiently.

**Implementation**

Compare results, timing/stages, safe parameters, revisions/changes, tests, error signatures, related builds, and artifacts metadata. Return only differences by default.

**Acceptance criteria**

- [ ] Identical builds produce a compact no-material-difference result.
- [ ] Secret parameters are excluded.
- [ ] Large change/test sets paginate through handles.
- [ ] Comparison uses cached summaries after first retrieval.

---

## DIAG-004 - Implement `jenkins_find_regression_window`

**Priority:** P1  
**Dependencies:** DIAG-001, JEN-003, TEST-002

**Objective**

Find the first build exhibiting an error signature or test failure with minimal remote work.

**Implementation**

Use cached indexes and bounded search over build history; employ binary search only when monotonic assumptions are valid, otherwise scan with explicit limits. Return first-known good/bad and uncertainty gaps.

**Acceptance criteria**

- [ ] Algorithm never assumes monotonicity silently.
- [ ] Missing/evicted builds create an explicit uncertain interval.
- [ ] Maximum builds/network bytes/time are enforced.
- [ ] Result cites the matching evidence in boundary builds.

---

## DIAG-005 - Implement `jenkins_trace_failure_graph`

**Priority:** P1  
**Dependencies:** GRAPH-001, DIAG-001

**Objective**

Identify the earliest/leaf failures in a bounded related-build graph.

**Implementation**

Traverse with limits, diagnose failed nodes in priority order, deduplicate shared descendants, and return a compact graph summary plus handles.

**Acceptance criteria**

- [ ] High-fan-out and cyclic graphs remain within request/network/output budgets.
- [ ] Earliest failure and first failing leaf are distinguished.
- [ ] Missing permission/data lowers confidence explicitly.
- [ ] Shared descendant logs are mirrored once.

---

## DIAG-006 - Implement `jenkins_survey_recent_failures`

**Priority:** P2  
**Dependencies:** DIAG-001, JEN-002, JEN-003

**Objective**

Summarize recurring failure signatures across an approved job scope.

**Implementation**

Select jobs/builds through explicit patterns and bounded time/lookback; fetch compact summaries first; mirror logs only for unresolved candidates; cluster exact/normalized signatures; report counts and examples.

**Acceptance criteria**

- [ ] Scope, job count, build count, bytes, and duration are policy-bounded.
- [ ] Cached summaries prevent repeated broad downloads.
- [ ] Clusters include representative evidence and normalization method.
- [ ] Cross-job survey is disabled by default if policy requires explicit enablement.

---

## DIAG-007 - Implement `jenkins_explain_queue_delay`

**Priority:** P1  
**Dependencies:** HEALTH-001, JEN-004

**Objective**

Explain queue wait using labels, executors, blockage reason, and recent demand.

**Implementation**

Combine queue item reason, required labels, matching nodes, executor utilization, quiet-down/offline states where authorized, and recent wait samples. Label estimates as heuristic.

**Acceptance criteria**

- [ ] Common no-executor, offline-label, throttling, blocked, and upstream-wait fixtures are differentiated.
- [ ] Unauthorized admin data is not required for a useful result.
- [ ] Result includes freshness and evidence endpoints.
- [ ] No unsupported ETA is presented as fact.

---

## PERF-003 - Optimize high-level diagnostics under fixed budgets

**Priority:** P1  
**Dependencies:** DIAG-002, DIAG-003, DIAG-005

**Objective**

Ensure triage tools reduce, rather than multiply, Jenkins calls and model tokens.

**Implementation**

Add shared request plans, deduplicated fetches, compact cached summaries, priority ordering, early stopping, and per-operation network/time/output budgets. Profile CPU and allocations.

**Acceptance criteria**

- [ ] Diagnose/compare/graph fixtures have recorded request and byte ceilings.
- [ ] Repeated calls show high cache hit and near-zero repeated log bytes.
- [ ] Cancellation stops dependent work.
- [ ] Tool results meet response SLOs without omitting truncation indicators.

---

# Phase 4 - Controlled mutations, AgentCore gateway

> **Server / team-hosted roadmap (planning SoT):** [`docs/roadmap/server-team-hosted.md`](roadmap/server-team-hosted.md)  
> Prioritize existing **GWY-001–004**, **OAUTH-009/010**, **MGR-001**, and proposed **HOST-001…** gap tasks there. Local stdio remains default (ADR 0002). Do not invent a parallel product epic.

, and optional integrations

## MUT-001 - Implement mutation policy, preview, and confirmation framework

**Priority:** P2  
**Dependencies:** POL-004, AUD-001, MCP-002, security approval

**Objective**

Create a reusable safety gate before registering any mutating Jenkins tool.

**Implementation**

Define disabled/allowlisted modes, per-profile/job/action policy, parameter restrictions, dry-run preview, explicit human confirmation payload, cooldown, rate limit, correlation ID, and audit record. Confirmation must bind to the exact normalized action and expire quickly.

**Acceptance criteria**

- [ ] Default/global read-only policy registers no mutation tools and the request classifier blocks mutation endpoints.
- [ ] Confirmation for one target/parameter set cannot authorize another.
- [ ] Secret parameters are blocked or handled through an approved non-model path.
- [ ] Denial, expiry, replay, and race tests pass.
- [ ] Mutation policy cannot be weakened by user settings against enterprise policy.

---

## MUT-002 - Add safe parameterized build triggering

**Priority:** P2  
**Dependencies:** MUT-001, JEN-002, JEN-004

**Objective**

Trigger approved builds without duplicate enqueues or hidden parameters.

**Implementation**

Fetch parameter definitions, validate names/types/choices, show preview, confirm, perform a single non-retried enqueue, and return queue reference. Add optional client-generated correlation parameter only when job policy explicitly supports it.

**Wave 18 note:** `GetJenkinsJob` / `GetJobParameterDefinitions` surface `property.parameterDefinitions`
(String/Choice/Boolean/Password; `_class` fallback; secret defaults scrubbed). `mutation.ValidateAgainstDefinitions`
rejects unknown names, bad choices, bad booleans, Password/Credentials/Secret types, and unsupported File/Run/…
types. `jenkins_start_job` normalizes → validates (fresh defs) → MUT-001 preview/confirm → single non-retried
`buildWithParameters` POST. Sensitive-name heuristic remains an extra defense. Docs: `tool-contracts.md`,
`agent-usage.md`.

**Residuals:** Jenkins “required without default” is not consistently available on all definition types
(omitted params allowed for Jenkins defaults). Active Choices / dynamic plugins not fully modeled.
Optional client-generated correlation parameter not implemented (needs explicit job policy support).

**Acceptance criteria**

- [x] No automatic retry can create a duplicate build. *(NET-003: mutation POST not auto-retried; token single-use)*
- [x] Unknown/secret/unsupported parameters are rejected. *(name + definition type + choice/bool checks)*
- [x] Preview exactly matches executed request after normalization. *(normalized map stored on token; redacted in preview)*
- [x] Jenkins permission is checked by the actual request and failures are attributable. *(enqueue POST; execute fail audit)*
- [x] Audit event contains no secret values. *(target hash / reason codes only; param values not audited)*

---

## MUT-003 - Add queue cancellation and build stop

**Priority:** P2  
**Dependencies:** MUT-001, JEN-004

**Objective**

Allow narrowly approved interruption actions with clear target state.

**Implementation**

Implement separate actions for queue cancellation and running build stop, each with fresh status, preview, confirmation, no automatic retry, and post-action verification.

**Acceptance criteria**

- [x] Completed/wrong-state targets are not treated as successful stops.
- [x] Confirmation includes controller, full job, build/queue ID, and current state.
- [x] Repeated requests are idempotent only in their reported outcome, not blindly resent.
- [x] All actions are locally audited and Jenkins-attributed to the user.

**Wave 17 note:** `jenkins_stop_build` + `jenkins_cancel_queue_item` both use MUT-001 preview/confirm;
client `CancelQueueItem` POSTs `/queue/cancelItem?id=`; missing/cancelled/assigned queue items
and finished builds return clear non-success errors; RO omits tools; force-registered RO denies.

---

## INT-001 - Create a capability-scoped integration adapter framework

**Priority:** P2  
**Dependencies:** FND-004, CFG-002

**Objective**

Add external systems without expanding the core process's default permissions.

**Implementation**

Define adapter lifecycle, auth isolation, capabilities, tool/resource registration, policy, rate limits, telemetry, and data classification. Load only explicitly enabled, signed/approved adapters.

**Acceptance criteria**

- [ ] Core Jenkins operation has no dependency on optional adapters.
- [ ] Adapter failure cannot crash the core server.
- [ ] Adapter credentials are separately namespaced.
- [ ] Cross-system data movement is explicit in tool contracts and policy.

---

## INT-002 - Add optional OpenTelemetry correlation

**Priority:** P3  
**Dependencies:** INT-001, DIAG-002

**Objective**

Correlate builds with approved traces/logs using identifiers already present in build metadata.

**Implementation**

Support explicit trace/span/service identifiers, bounded queries through an approved backend adapter, and evidence references. Do not send log text to telemetry services merely to search it.

**Acceptance criteria**

- [ ] Integration is disabled by default.
- [ ] Queries are scoped to approved identifiers/time ranges.
- [ ] Credentials and returned data follow separate policy/retention.
- [ ] Diagnostics label external evidence source and freshness.

---

## INT-003 - Add optional external log-system adapters

**Priority:** P3  
**Dependencies:** INT-001, SEC-002

**Objective**

Retrieve logs that Jenkins links to but does not store, without weakening local bounds.

**Implementation**

Create adapters for approved systems only, with per-user auth, query allowlists, time/byte/result limits, redaction, local chunking, and source-specific evidence. Avoid arbitrary query-language passthrough to the model.

**MVP landed (framework stub):** adapter `ext-logs` (`noop`/`mock`/optional HTTPS JSON), tool
`jenkins_query_external_logs` (disabled by default), bounds + redaction + evidence labels.
**Wave 18:** fail-closed Jenkins ACL preflight (`GetBuildDetailsByJob` before querier;
401/403/404 no external call); default adapter rate limit for non-noop backends (10 / 1/s).
Docs: `docs/adapters/ext-logs.md`. **Residual:** real Splunk/ELK clients, per-user adapter
credentials, local L1 chunking of external payloads, fleet metrics export, POL-004 Target
job binding (offline policy — separate from Jenkins ACL preflight).

**Acceptance criteria**

- [x] Model cannot submit unrestricted backend queries. *(MVP: max query length; free-text only; no SPL/Lucene passthrough)*
- [ ] Returned external logs use the same storage/search/evidence controls. *(MVP: redaction + evidence labels; full local storage/search residual)*
- [x] Source credentials never cross into Jenkins requests or vice versa. *(MVP: no credentials path; keyring namespace residual for SaaS)*
- [x] Jenkins job access preflight before external query. *(Wave 18: GetBuildDetailsByJob; querier not called on deny/missing)*
- [ ] Network and data-volume budgets are measurable. *(MVP: hard entry/excerpt/body caps + default token bucket for non-noop; fleet metrics residual)*

---

## INT-004 - Add optional work-item and source-host correlation

**Priority:** P3  
**Dependencies:** INT-001, SCM-001

**Objective**

Enrich triage with explicitly referenced Jira/Bitbucket/GitHub/GitLab objects.

**Implementation**

Resolve approved keys/commit/PR identifiers, retrieve minimal metadata, and return links/summaries. Avoid broad project scraping or automatic inclusion of private discussion content.

**MVP landed:** pure extractors in `internal/correlate`, tool `jenkins_get_change_correlation`
(disabled by default; enable via `work-items` adapter), optional work-items stub (refs only,
no network). Docs: `docs/adapters/work-items.md`. **Residual:** real ticket-system APIs and
per-user ticket credentials.

**Acceptance criteria**

- [x] Correlation requires an explicit identifier or policy-approved extraction rule. *(MVP: allowlisted patterns on params/changeSets)*
- [ ] Access uses the current user's separate credentials. *(N/A for stub; residual when ticket API lands)*
- [x] Results remain bounded and source-labeled.
- [x] Failure of external correlation does not block Jenkins diagnosis. *(SCM failure degrades; adapter stub failure ignored)*

---

## GWY-001 - Implement AgentCore per-user Jenkins 3LO/OBO credential provider

**Priority:** P2  
**Dependencies:** OAUTH-010, INT-001

**Status:** **Partial** — offline mock Obtain + **Live opt-in foundation**
(`EnableLiveHTTPFetcher` / `JENKINS_MCP_GATEWAY_LIVE` + `HTTPTokenFetcher`).
**Not fully Done** (real Entra/AgentCore pin, durable vault, 3LO browser UX,
refresh/revocation SLOs remain GWY-003 / OAUTH-010).

**Objective**

Provide an optional gateway credential provider that obtains Jenkins-audience tokens for the validated caller through user-delegated authorization-code 3LO and/or OBO/token exchange.

**Implementation**

Integrate AgentCore workload identity and outbound OAuth credential retrieval. Support approved `AUTHORIZATION_CODE` user federation with an Entra-backed `MicrosoftOAuth2`/`CustomOauth2` provider and approved `TOKEN_EXCHANGE` or JWT authorization-grant OBO. When consent is needed, propagate the AgentCore authorization URL/session metadata to the caller without exposing tokens. Cache and refresh only through approved AgentCore Identity/Token Vault semantics keyed to user and workload. Never point provider authorization/token endpoints at stock Jenkins and never fall back to a shared Jenkins identity.

**Acceptance criteria**

- [ ] Each request is attributable to the validated caller, workload, and Jenkins principal.
- [ ] Authorization-code consent and callback/session binding cannot be replayed across users/providers.
- [ ] Token cache, refresh, force-reauthentication, and revocation behavior is isolated per user/workload.
- [ ] Wrong subject, audience, tenant, provider, return URL, or session binding fails closed.
- [x] Provider exposes no token, client secret, or authorization code to MCP tools, logs, or support bundles. *(canary tests; Live foundation)*
- [x] Jenkins endpoints are never used as OAuth authorization/token endpoints unless the conditional JAS epic is deployed and approved. *(ValidateProviderConfig + tests)*

---

## GWY-002 - Bind gateway identity and MCP RBAC policy

**Priority:** P2  
**Dependencies:** GWY-001, POL-003

**Objective**

Apply the same deny-only authorization model to gateway callers.

**Implementation**

Map trusted AgentCore/Entra subject, tenant, groups/roles, workload identity, and exchanged Jenkins subject into the policy subject. Define mismatch and group-overage behavior. Revalidate policy on each call or within an approved short cache.

**Acceptance criteria**

- [ ] Caller-supplied tool arguments cannot change identity.
- [ ] Inbound and exchanged subjects must satisfy approved binding rules.
- [ ] Role removal and emergency deny propagate within the approved window.
- [ ] Gateway policy cannot grant Jenkins-denied access.

---

## GWY-003 - Run gateway 3LO/OBO security and performance qualification

**Priority:** P2  
**Dependencies:** GWY-002, OAUTH-009  
**Status:** **Partial Done*** (offline qualify expanded) — **not** live Entra / AgentCore / jwt-auth-filter production pin

**Objective**

Prove AgentCore mode meets identity, consent, latency, availability, isolation, and audit requirements across user-delegated 3LO and OBO/token exchange. Qualify HOST-011 modes **A/B/C** (evidence or residual per mode).

**Implementation**

Load/chaos-test authorization-code consent and session binding, OBO/token exchange, access/refresh-token vault hits/misses, force reauthentication, IdP/JWKS outages, revocation, concurrency, cross-user/workload isolation, gateway retries, Jenkins fallback behavior, and end-to-end audit. Compare user-delegated 3LO, OBO/token exchange, and exact-Jenkins-audience JWT passthrough. Document the selected production mode and why the alternatives are disabled or retained only for testing.

**Offline Done* (this slice)**

- [x] Offline suite `internal/gateway/qualify` + `jenkins-mcp gateway qualify --offline` (no network)
- [x] Mode A row: vault Obtain → Basic; cross-subject miss; secret canary (`mode_a_vault_obtain_basic`)
- [x] Mode B row: JWT vault Obtain → Bearer; ID token reject; wrong subject miss (`mode_b_jwt_vault_bearer`)
- [x] Mode C row: Live=false not_configured; Live+mock Fetcher Bearer; wrong audience; ConsentRequired metadata only (`mode_c_agentcore_live_matrix`)
- [x] HOST-011 no silent fallthrough invoked from qualify suite (`host011_no_silent_fallthrough`; also package `TestHOST011_*`)
- [x] Docs: [`docs/gateway/qualification.md`](gateway/qualification.md) modes matrix + oauth-lab residual run notes
- [x] Opt-in residual: `go test -tags=live_oauth ./internal/gateway/qualify/` (skips unless lab up; Mode C Obtain + HTTPTokenFetcher vs mock-token via TLS test shim when up; not default `make test`; **not** live Entra Done)

**Still open (full DoD — do not claim live Entra Done)**

- [ ] No cross-user/workload token reuse, consent replay, cache leakage, or shared-account behavior occurs **under live Entra/AgentCore**.
- [ ] P95/P99 token acquisition and cache-hit latency fit the tool SLO and include provider/vault/Jenkins breakdowns (**live**).
- [ ] IdP, JWKS, vault, gateway, and Jenkins outages fail safely without identity downgrade (**live** pin).
- [ ] Generic-token passthrough is disabled in production; exact-audience passthrough requires a specific approved exception and remains more restrictive than OBO.
- [ ] Tests prove missing/invalid bearer cannot downgrade into Basic, API-token, session-cookie, anonymous, or shared-service authentication on OAuth-required routes (**live RS / jwt-auth-filter**).
- [ ] Runbook covers consent/provider/vault/JWKS/Entra/Jenkins incidents and user reauthorization (offline runbook rows exist; live ops evidence residual).
- [ ] Live AgentCore sidecar / Entra network acquisition pin + signed production mode selection record.

**Residual lab (opt-in, not production):** `testdata/oauth-lab/` + `make live-oauth-*` (HOST-012…015). Mode A: `make live-jenkins-*`. See qualification.md §7.

**Acceptance criteria** (full task — check only with live evidence)

- [ ] No cross-user/workload token reuse, consent replay, cache leakage, or shared-account behavior occurs.
- [ ] P95/P99 token acquisition and cache-hit latency fit the tool SLO and include provider/vault/Jenkins breakdowns.
- [ ] IdP, JWKS, vault, gateway, and Jenkins outages fail safely without identity downgrade.
- [ ] Generic-token passthrough is disabled in production; exact-audience passthrough requires a specific approved exception and remains more restrictive than OBO.
- [ ] Tests prove missing/invalid bearer cannot downgrade into Basic, API-token, session-cookie, anonymous, or shared-service authentication on OAuth-required routes.
- [ ] Runbook covers consent/provider/vault/JWKS/Entra/Jenkins incidents and user reauthorization.

---

## GWY-004 - Package the optional AgentCore/managed gateway deployment

**Priority:** P2  
**Dependencies:** GWY-003, MGR-001, PKG-001

**Objective**

Run the same MCP core near Jenkins for bandwidth efficiency while preserving personal identity, policy, and storage isolation.

**Implementation**

Produce a signed non-root Linux container/service with approved Streamable HTTP integration, AgentCore subject/credential provider, per-user/tenant/profile cache namespace, quotas, health/readiness, private ratarmount-rs sidecar/library, structured correlation/audit, and separate Jenkins-to-gateway versus gateway-to-client byte metrics. Apply the same global read-only default and deny-only MCP RBAC as local mode.

**Acceptance criteria**

- [ ] Every call is bound to an authenticated individual subject and verified Jenkins principal.
- [ ] No shared/generic Jenkins credential exists for interactive users.
- [ ] Tokens, cached content, continuations, and archive handles are isolated across users/policies.
- [ ] Global read-only and MCP RBAC behavior matches local mode.
- [ ] Image is minimal/non-root/signed with SBOM/provenance and bounded resources.
- [ ] Near-source deployment demonstrates measurable bandwidth benefit without unacceptable auth/latency cost.

**Packaging scaffold note (honest):** `deploy/gateway/` is **hardened scaffold** (non-root distroless, resource limits, secret-free compose/kustomize, `/healthz`+`/readyz` probes — HOST-005; `.env.example` lists MULTI_USER / JWKS max stale / path prefix / REQUIRE_SIGNED_POLICY / subject concurrency lab flags). **Not** production DoD: no signed org image, no live AgentCore sidecar, no bandwidth study, no multi-tenant quotas.

---

# Server / team-hosted deployment epic (HOST-*) — implement all auth modes

**Planning SoT:** [`docs/roadmap/server-team-hosted.md`](roadmap/server-team-hosted.md)  
**Standing decision:** Tier A implements **all three** Jenkins credential modes as first-class; a site enables one or more and picks a default. Do **not** collapse the epic to “OAuth only” or “JWT only.”

| Mode | ID | Jenkins wire | Obtain path | Primary tasks |
|------|-----|--------------|-------------|---------------|
| **A** | `api_token_vault` | Basic personal API token | Per-user vault (never shared SA) | **HOST-009**, HOST-003 |
| **B** | `jwt_rs_bearer` | Bearer Jenkins-audience JWT | External IdP (Entra) issuance; Jenkins **jwt-auth-filter** RS only | **OAUTH-009**, **HOST-010** |
| **C** | `agentcore_3lo_obo` | Bearer JWT (typical) | AgentCore 3LO and/or OBO against **Entra AS** | **OAUTH-010**, **GWY-001**, HOST-003 |

**Shared (all modes):** HOST-001, HOST-002, GWY-002, HOST-003, HOST-004, HOST-005, HOST-006, HOST-011, GWY-003/004, MGR-001, REL-001/002.  
**Docker labs (opt-in):** **HOST-012** (umbrella + Makefile), **HOST-013** (mode B JWT/RS compose), **HOST-014** (mock OIDC IdP), **HOST-015** (mode C mock token/3LO). Extend `testdata/jenkins-compose/` / new `testdata/oauth-lab/` — never default `make test`.  
**Ops residual:** HOST-007 (admin). **Tier B:** HOST-008 (HA).

**Agent rule:** When implementing HOST/GWY/OAUTH for server-side, keep operator admin console residual notes current (`AGENTS.md`). Prefer one task ID per PR; modes may parallelize after HOST-001 + GWY-002. **Always scaffold Docker for integration labs where possible** (`AGENTS.md`).

---

## HOST-001 - Harden Streamable HTTP for multi-user gateway authn

**Priority:** P0  
**Dependencies:** GWY-002, MCP-001  
**Status:** **Partial Done*** offline (mid-session subject rebind + RequireSubject); **not** live Entra production

**Objective**

Authenticated individual subjects on MCP HTTP in gateway mode (shared secret alone is not multi-user identity).

**Acceptance criteria**

- [x] Non-local bind requires authenticated subject (not anonymous).
- [x] Shared-secret is transport gate only if retained; still requires per-user identity.
- [x] Session/request credentials bind to identity fingerprint; mid-session subject change fails closed (`internal/mcpserver` `Mcp-Session-Id`→`IdentityFingerprint`; gateway `Binding.Revalidate` for `policy.Subject`).
- [x] Tokens never in logs/errors/metrics/support bundles (canaries).
- [x] Gateway mode cannot enable anonymous multi-user; local KD-008 residual remains explicit for non-gateway.

**Residual:** multi-instance / under-load JWKS HA (process-local TTL refresh + stale-if-error + optional `JENKINS_MCP_HTTP_JWKS_MAX_STALE` fail-closed landed; multi-instance shared JWKS still residual); live Entra / jwt-auth-filter; durable multi-replica session store.

---

## HOST-002 - Reverse-proxy and non-loopback deployment matrix

**Priority:** P1  
**Dependencies:** HOST-001, NET-001  

**Objective**

Safe placement behind site reverse-proxy (TLS, path prefix, Host/Origin).

**Acceptance criteria**

- [x] Documented allowed deployment shapes (no CORS wildcard). — `docs/gateway/deployment.md` §3; compose/README; wildcard origins fail closed in `ValidateHTTPConfig`
- [x] Empty AllowedHosts / AllowedOrigins fail closed for non-local. — existing mcpserver tests + HOST-002 wildcard fixture
- [x] Path-prefix reverse-proxy support (app strip). — `HTTPConfig.PathPrefix` / `--http-path-prefix` / `JENKINS_MCP_HTTP_PATH_PREFIX`; MCP only under prefix; dual `/healthz`+`{prefix}/healthz`; fail-closed validation; offline unit tests
- [x] Path-prefix + origin pin **offline** fixture matrix. — `TestHOST002_PathPrefixOriginPinFixtureMatrix`: exact Origin under prefix; wrong Origin 403; Host allow-list non-local+prefix; health root + `{prefix}/healthz` unauth; `X-Forwarded-Host`/`X-Forwarded-Prefix` not trusted (`TrustedProxy` default false residual)
- [ ] Path-prefix origin pin **live** matrix (NET-001 residual). — offline fixtures + docs matrix ship; **live edge container Host/Origin/X-Forwarded rewrite residual**; `TrustedProxy=true` trust path residual (still fail-closed)
- [x] Health endpoints do not leak secrets or broad inventory without auth. — `/healthz` `/readyz` secret-free exact-path (+ prefixed when PathPrefix set); unit canaries

**Status:** **Partial / Done*** for docs + code fail-closed matrix + path-prefix strip + offline origin pin fixtures + `TrustedProxy` residual (default false). Live reverse-proxy edge origin pin matrix remains residual.

---

## HOST-003 - Gateway serve wiring: live Obtain to Jenkins client

**Priority:** P0  
**Dependencies:** GWY-001 (mode C), HOST-009 (mode A), HOST-010 (mode B), GWY-002  

**Status:** **Partial / foundation Done\*** for Mode A + Mode C Live-opt-in Ready
path (Obtain AuthProvider, clear static, whoAmI via Obtain, ConsentRequired
metadata, no other-subject fallthrough). Mode B Live residual (HOST-010).
Bootstrap local session before Ready wire remains residual for multi-user
gateway without local keyring (HOST-001).

**Objective**

When `--gateway` and provider Ready, Jenkins credentials come from **Obtain for the bound subject and enabled mode** — never silent shared keyring/SA fallthrough.

**Acceptance criteria**

- [x] Mode A → Basic personal token for subject only.
- [x] Mode B/C → Bearer access token only (never ID token as API credential). *(Mode C Ready + unit tests; Mode B residual provider not Ready)*
- [x] Obtain failure does not use another subject’s credential.
- [x] ConsentRequired (mode C) surfaces auth URL metadata only. — Obtain → AuthProvider → `mapToolErr` progressive `authorization_url` + `session_id` (tool path residual documented; full 3LO browser UX residual)
- [x] Unit/integration tests per mode with mocks. *(A + C offline; B residual)*
- [x] `docs/gateway/README.md` residuals closed for wiring. *(wiring section; Entra pin still residual)*

---

## HOST-004 - Multi-tenant cache and continuation isolation

**Priority:** P0  
**Dependencies:** GWY-002, STO layout  

**Acceptance criteria**

- [x] Cache key includes subject/tenant/profile (or process isolation enforced and tested).
- [x] Continuations fail closed across subjects when multi-tenant.
- [x] Two-user offline test: no shared archive handle / cache hit leakage.
- [x] Support-bundle/doctor remain secret-free under multi-user layout.

**Foundation done (package APIs + offline tests):** `CacheKey` includes `Tenant`;
`Caller.CacheKey` / `SubjectKey`; `jenkins.BindSubjectToPageFilter` +
`*WithSubject` page-token helpers; two-user cache + Alice/Bob page_token tests;
`docs/gateway/README.md` §3c. **Serve wire Done*:** `tools.RegisterOptions.SubjectKey`
from `gateway.SubjectKey` when `--gateway`; list tools (`list_jobs` / `get_jobs` /
`list_builds`) use `*WithSubject` pagination; Alice/Bob tools-path regression.
**Residual:** per-HTTP-request SubjectKey swap; durable L1/L2 archive namespace
(STO / HOST-008).

---

## HOST-005 - Gateway health, readiness, and resource envelope

**Priority:** P1  
**Dependencies:** GWY-004 scaffold  

**Acceptance criteria**

- [x] Readiness fails or clearly residual when gateway provider not Ready. — `/readyz` + `ReadyCheck` when `--gateway`; 503 + `gateway_ready:false`; non-gateway process-up residual documented
- [x] Non-root image; writable only cache/config volumes where practical. — distroless nonroot; compose/k8s read-only root + volume mounts
- [x] Documented CPU/memory/FD limits for pilot. — 1 CPU / 512Mi limits; FD residual site ulimit noted
- [x] Compose/kustomize examples secret-free. — `.env.example` non-secret only; no tokens in yaml

**Status:** **Done*** for scaffold envelope + probe contracts. Live AgentCore pin and signed image remain GWY-003/004 residuals.

---

## HOST-006 - Per-subject rate limits and multi-tenant budgets

**Priority:** P1  
**Dependencies:** MCP-001, HOST-001  

**Acceptance criteria**

- [x] Per-subject concurrent tool/preview caps (policy may only reduce).
- [x] Process absolute ceilings still apply.
- [x] Tests or documented fair-share policy for cross-subject starvation.
- [x] Mutation confirm tokens cannot replay across subjects.

**Foundation done:** `gateway.SubjectLimiter` (`subject_limits.go`) with
per-subject + process ceilings, `Hold`/`WithSubjectSlot`, fair-share tests,
`StatusMap` secret-free. **Token-bucket rate Done* foundation:**
`gateway.SubjectRateLimiter` (`subject_rate.go`) — default **30**/min + burst
**10** per subject, process **300**/min + burst **60**; Alice/Bob isolation +
process fair-share + secret-free `StatusMap` tests. Mutation confirms bound to
`mutation.Binding` = profile + principal + ExternalSubject + tenant; multi-user
`BindingFromContext` / serve `MutationBindingFromContext` via
`mutationBindingFromGatewayCtx` (prefer Valid `PolicySubject` PrincipalID =
JenkinsUserID from HTTP JenkinsPrincipal/lab header; else Caller +
`PrincipalCache` Obtain principal when set, else process principal) so Alice
preview cannot confirm as Bob on ExternalSubject **or** PrincipalID; cooldown
keys and audit use effective binding. **Done\*** Obtain→Binding principal via
process-local `PrincipalCache` (Mode A vault username; Binding-only). **Serve
wire Done*:** `tools.SubjectSlotLimiter` + `tools.SubjectRateLimiter`; `addTool`
Allow then Hold under `--gateway`; env concurrent + rate/burst
(`JENKINS_MCP_SUBJECT_RATE_PER_MINUTE` 0 = rate disabled).
**Policy rate reduction Done\* foundation:** overlay optional
`max_tools_per_minute` / `max_tools_burst` → `SubjectRateLimiter.LowerRate`
(lower only). **Residual:** multi-replica (HOST-008); admin SPA subject-rate
knobs; Obtain does not rewrite `policy.Subject` on request ctx mid-call.

---

## HOST-007 - Gateway operator admin path (non-SaaS)

**Priority:** P2  
**Dependencies:** UI-003–UI-009, ADR 0014  

**Acceptance criteria**

- [x] Document non-loopback admin only with token (+ residual mTLS/OIDC design). — `docs/admin/README.md` HOST-007 section
- [x] No Jenkins API tokens or vault material in browser responses. — canaries; `GET /admin/v1/gateway/vault` hash-only; CLI-only vault write residual
- [x] Multi-operator sessions: residual “single process role” or designed sessions + CSRF. — **documented residual** single process `--admin-role`
- [x] Quarantine localStorage token UX for non-pilot. — documented pilot-only / quarantine for production (`web/admin/README.md` + admin HOST-007)
- [x] CSP preserved under reverse-proxy; secret-free note of **enabled auth modes**. — CSP guidance; `enabledModes` on health + gateway/vault
- [x] Secret-free multi-user residual note: no admin/`JENKINS_MCP_GATEWAY_MULTI_USER` production-ready pin; `enabledModes` is config enablement only.

**Status:** **Done*** for operator residual documentation + secret-free mode listing + multi-user honesty. Cookie sessions / multi-operator OIDC remain residual.

---

## HOST-008 - HA / multi-replica residual (Tier B)

**Priority:** P3  
**Dependencies:** HOST-003, HOST-004, durable vault  

**Acceptance criteria**

- [x] Single-replica Tier A default documented. — `docs/gateway/deployment.md` §9 runbook; kustomize/compose `replicas: 1` comments
- [x] Multi-replica checklist: shared vault, affinity, no memory-only token cache, audit aggregation. — expanded checklist in deployment.md §9 (not implemented)
- [x] Explicit non-goal until vault exists. — documented non-goal; do not claim multi-replica Done
- [x] Secret-free residual surfaces: doctor `gateway_status` + admin health/vault (`multi_user_enabled` / `multiUserEnabled`, `credential_mode`, `gateway_ready=false`, `ha_multi_replica=false`)

**Status:** **Done*** as **documentation residual** + secret-free status fields only. **No multi-replica runtime.**

---

## HOST-009 - Mode A: per-user personal API token vault (gateway)

**Priority:** P0  
**Dependencies:** HOST-001, GWY-002, AUTH-001 / ADR 0009  

**Objective**

Multi-user gateway with **personal API tokens only** (no OAuth/JWT required on Jenkins for this mode).

**Acceptance criteria**

- [x] Provision/rotate/revoke per-user API token in vault (CLI: `jenkins-mcp gateway vault put|set|delete|revoke|list|status|exists`; legacy `vault-put`/`vault-delete`). **Residual:** admin SPA/BFF vault **write** (secret-free status only); live multi-host shared vault (HOST-008).
- [x] Obtain returns credentials only for bound subject; cross-subject fails closed (`APITokenVaultProvider` + unit tests).
- [x] No process-wide or default API token fallthrough (missing key → not_found; no ambient keyring).
- [x] Secret canaries on logs, admin JSON, MCP, support bundles (CLI list/status canaries; admin vault status hashes only).
- [x] RO + deny-only RBAC unchanged.
- [x] Documented as first-class Tier A mode (`docs/gateway/README.md` Mode A operator section).

---

## HOST-010 - Mode B: Jenkins JWT resource-server bearer path

**Priority:** P0  
**Dependencies:** OAUTH-009, OAUTH-003, OAUTH-005, HOST-001, GWY-002  

**Objective**

End-to-end **Bearer Jenkins-audience JWT** with Jenkins as **RS only** (`jwt-auth-filter` or approved proxy). Complements IdP issuance; never claims Jenkins is an AS.

**Acceptance criteria**

- [ ] Live OAUTH-009: invalid Bearer no Basic/session/anonymous fallthrough on OAuth-required routes.
- [ ] Claim validation (iss/aud/exp/nbf); ID token never used as Jenkins API credential.
- [ ] Graph / generic gateway / wrong-audience rejected.
- [ ] Gateway/local path can send Bearer without mixing Basic on the same call.
- [ ] Doctor/self-check honest when RS not qualified.
- [ ] Operator docs: Entra app + jwt-auth-filter version pin for mode B.

---

## HOST-011 - Auth mode matrix and fail-closed mode switch (A + B + C)

**Priority:** P0  
**Dependencies:** HOST-009, HOST-010, GWY-001 (or mocks), HOST-003  

**Objective**

Configure and qualify **all three** modes. No silent cross-mode fallthrough.

**Acceptance criteria**

- [ ] Explicit config for enabled modes: `api_token_vault`, `jwt_rs_bearer`, `agentcore_3lo_obo`.
- [x] Offline matrix row per mode: Obtain → correct auth header shape (Basic vs Bearer). — package `TestHOST011_*` + qualify `mode_a_*` / `mode_b_*` / `mode_c_*`
- [x] Disabled/failed mode does not use another subject’s or another mode’s credential. — `TestHOST011_ObtainAuthMatrixOffline` + qualify `host011_no_silent_fallthrough`
- [x] GWY-003/host qualify documents evidence or residual per mode. — offline Done*; live residual in `docs/gateway/qualification.md` (GWY-003 full DoD still open)
- [ ] Operator guide: when to choose A vs B vs C; never shared SA.
- [ ] Admin residual lists enabled modes (secret-free).

---

## HOST-012 - Docker lab umbrella for server-side auth (opt-in Makefile)

**Priority:** P0  
**Dependencies:** TST-001 (jenkins-compose pattern), HOST-009 (mode A can reuse existing lab)  

**Objective**

One documented entry point to bring up disposable Docker labs for modes A/B/C without putting them on default `make test` / `make ci`.

**Implementation**

- Extend `testdata/jenkins-compose/` and/or add `testdata/oauth-lab/` (+ optional `testdata/gateway-lab/`).  
- Makefile targets (names may vary): `live-oauth-up` / `live-oauth-test` / `live-oauth-down` (and/or `live-auth-lab-*`) that compose the right profiles.  
- Reuse patterns from `make live-jenkins-*` (wait health, ephemeral secrets, `down -v`).  
- README: which services, ports, env vars, residual vs production Entra/jwt-auth-filter pin.

**Acceptance criteria**

- [ ] Documented Compose files exist for at least mode A (existing Jenkins) and stubs for B/C lab profiles.
- [ ] Opt-in Makefile targets; **not** part of default `make test` / `make ci`.
- [ ] Tear-down removes volumes; no secrets committed; disposable passwords only.
- [ ] README cross-links OAUTH-009, HOST-010, HOST-014/015, gateway docs.
- [ ] Fail closed: lab docs never recommend shared Jenkins SA or Jenkins-as-AS.

---

## HOST-013 - Docker scaffold: Jenkins JWT resource-server lab (mode B)

**Priority:** P0  
**Dependencies:** HOST-012, OAUTH-009 offline contracts  

**Objective**

Disposable Jenkins (or RS proxy) lab that exercises **Bearer JWT** validation for mode B — ideally with `jwt-auth-filter` when plugin install is practical, otherwise a **documented mock RS reverse-proxy** that enforces audience/iss/exp fail-closed for contract tests.

**Implementation**

- Compose profile: Jenkins LTS + plugins (or nginx/caddy mock RS in front of fixture API).  
- Init/config: OAuth-required routes; invalid Bearer must not fall through to Basic/anonymous (match OAUTH-009 matrix).  
- Mint test JWTs via **HOST-014** mock IdP (or local test keys in lab only).  
- `go test -tags=live_oauth` / `live_jwt` package(s) opt-in.

**Acceptance criteria**

- [ ] `make …-up` brings lab healthy; docs list residual if real jwt-auth-filter pin deferred.
- [ ] Automated opt-in test: valid Jenkins-audience JWT → allowed; wrong aud/exp/iss → 401/403.
- [ ] Invalid Bearer does not succeed via Basic/session/anonymous on OAuth-required routes (lab or mock RS).
- [ ] No production secrets in image/compose; JWKS/keys are lab-only and rotated on rebuild.
- [ ] Tear-down destroys lab keys/tokens.

---

## HOST-014 - Docker scaffold: mock OIDC IdP (PKCE / claims)

**Priority:** P0  
**Dependencies:** HOST-012, OAUTH-001…003 offline  

**Objective**

Mock OIDC authorization server (Keycloak, WireMock+fixtures, or small Go IdP container) for offline **mode B** token issuance and claim-validation integration without real Entra.

**Implementation**

- Compose service with discovery, JWKS, authorize/token (as needed for MCP PKCE or static test tokens).  
- Seed clients and a **Jenkins API audience**.  
- Scripts/tests: fetch token, assert aud/iss; reject Graph-like wrong audience.  
- Document residual: not production Entra Conditional Access / tenant policy.

**Acceptance criteria**

- [ ] Discovery + JWKS reachable on loopback from host tests.
- [ ] Can mint access tokens with configurable aud/iss/exp for HOST-013.
- [ ] Wrong-audience / expired tokens fail MCP or RS tests as designed.
- [ ] No client secrets committed; lab client is public/PKCE or disposable secret in volume.
- [ ] Opt-in only; clean `down -v`.

---

## HOST-015 - Docker scaffold: mock AgentCore / token-exchange endpoint (mode C)

**Priority:** P0  
**Dependencies:** HOST-012, GWY-001 offline mock, OAUTH-010  
**Status:** **Scaffold Done\*** (mock peer + opt-in live_oauth Mode C Obtain residual) — **not** live Entra / AgentCore Identity vault

**Objective**

Disposable HTTP peer that simulates AgentCore/Entra **token exchange / OBO / authorization-code token** responses so gateway `TokenFetcher` / Obtain can be integration-tested without live AgentCore.

**Implementation**

- Compose service implementing minimal token endpoint(s) used by `HTTPTokenFetcher` / mode C.  
- Fixtures: success token (Jenkins audience), wrong audience, 5xx, slow response, consent-required metadata.  
- Wire `gateway qualify` or `go test -tags=live_oauth` against compose network (TLS **test shim** → HTTP lab; production `HTTPTokenFetcher` is https-only).  
- Never host “Jenkins AS”; AS base URL must not be the Jenkins origin (existing reject rules).

**Evidence (mock residual only):** `testdata/oauth-lab/` + `make live-oauth-*`; `internal/gateway/qualify/live_oauth_stub_test.go` (`//go:build live_oauth`); docs residual in oauth-lab README + `docs/gateway/qualification.md` §7.

**Acceptance criteria**

- [x] Obtain Live path against mock returns credential for correct subject/audience. — `TestLiveOAuth_ModeC_ObtainSuccess` (TLS shim residual)
- [x] Wrong audience / error fixtures fail closed without shared SA fallthrough. — `TestLiveOAuth_ModeC_WrongAudienceFailClosed` + `TestLiveOAuth_ModeC_ServerErrorFailClosed`
- [x] ConsentRequired-shaped response exposes auth URL metadata only (no tokens in logs). — `TestLiveOAuth_ModeC_ConsentMetadataOnly`
- [x] Document residual vs real AgentCore Identity vault. — oauth-lab README + qualification §7 (TLS residual; not Entra Done)
- [x] Opt-in Makefile target; secret-free compose. — `make live-oauth-*`

---

## MGR-001 - Sign and enforce enterprise policy bundles

**Priority:** P2  
**Dependencies:** CFG-002, POL-002, FND-008  
**Status:** **Done\*** MVP + multi-sig lite + `JENKINS_MCP_REQUIRE_SIGNED_POLICY` pin; HSM / true *t*-of-*n* / gateway push residual

**Objective**

Let security centrally constrain auth, tools, limits, storage, telemetry, and updates.

**Implementation**

Define versioned signed policy bundles, trusted keys, expiry/rollback rules, local cache, and safe bootstrap. Policies can disable features/lower limits but not include credentials.

**Evidence:** [`docs/security/policy-bundles.md`](security/policy-bundles.md) (enterprise gateway pin checklist); `internal/policy` Ed25519 + last-good; env `JENKINS_MCP_REQUIRE_SIGNED_POLICY=1` fails closed without trusted keys / unsigned.

**Acceptance criteria**

- [x] Invalid, expired, downgraded, or untrusted policy fails according to documented safe mode. — Ed25519 + last-good; REQUIRE_SIGNED pin lite
- [x] User config cannot weaken enforced values. — force_read_only tests
- [x] Effective policy and source are explainable without leaking sensitive internal details. — `policy show-effective` / doctor signature_state
- [x] Key rotation and emergency policy replacement are tested. — higher `bundle_seq` + multi-sig lite; HSM residual

---

## MGR-002 - Add privacy-preserving fleet health telemetry

**Priority:** P3  
**Dependencies:** OBS-001, MGR-001

**Objective**

Measure adoption, errors, versions, performance, and security posture without centralizing Jenkins content.

**Implementation**

Export approved aggregate metrics/events with pseudonymous installation/profile identifiers, low cardinality, batching, backoff, and local queue limits. No logs, prompts, tokens, artifact content, or raw job parameters.

**Acceptance criteria**

- [ ] Export schema receives privacy/security approval.
- [ ] Telemetry can be disabled or mandated only through policy.
- [ ] Offline queue is bounded and encrypted/protected as required.
- [ ] Network failures do not affect MCP operation.
- [ ] A user/admin can inspect categories being exported.

---

## UPD-001 - Implement managed release and update lifecycle

**Priority:** P2  
**Dependencies:** PKG-001, MGR-001

**Objective**

Deliver signed upgrades with rollback/migration safety.

**Implementation**

Prefer existing enterprise software distribution. If self-update is approved, use signed metadata, staged channels, version pinning, rollback protection, preflight, last-known-good, and policy controls.

**Acceptance criteria**

- [ ] Unsigned/tampered update is rejected.
- [ ] Storage/config migrations run only after verification and preflight.
- [ ] Failed update can restore the previous binary when supported.
- [ ] Emergency adapter/feature disable mechanism is documented and tested.

---

# Conditional epic - Jenkins-hosted OAuth authorization server (execute only after OAUTH-011 go decision)

## JAS-001 - Create authorization-server threat model and protocol profile

**Priority:** P3  
**Dependencies:** OAUTH-011 (go decision), security ownership

**Objective**

Define the exact reason Jenkins must issue delegated tokens and the supported OAuth profile.

**Implementation**

Specify actors, clients, redirect types, grants, scopes, consent, audiences, token lifetimes, keys, revocation, incident ownership, Jenkins permission mapping, and excluded flows. Prefer OAuth 2.1 authorization code + PKCE and prohibit implicit/password grants.

**Acceptance criteria**

- [ ] Threat model and protocol profile receive security approval.
- [ ] External IdP resource-server/proxy/broker alternatives are shown insufficient for the approved blocker.
- [ ] Long-term plugin maintenance and emergency key/revocation ownership are assigned.

---

## JAS-002 - Implement client registration, authorization, PKCE, and consent

**Priority:** P3  
**Dependencies:** JAS-001

**Objective**

Issue one-time authorization codes only to approved clients and exact redirects.

**Implementation**

Build client registry/admin controls, exact redirect validation, state/session/CSRF binding, PKCE S256, user consent, scope selection, Jenkins-permission checks, code expiry/single use, and audit. No model-visible client secrets for public clients.

**Acceptance criteria**

- [ ] Open redirect, code interception/replay, CSRF, consent confusion, and client mix-up tests fail safely.
- [ ] Authorization cannot grant scopes beyond current Jenkins permissions and admin policy.
- [ ] Codes are short-lived, one-time, and bound to client/redirect/PKCE/user.

---

## JAS-003 - Implement token issuance, JWKS, scopes, and key rotation

**Priority:** P3  
**Dependencies:** JAS-002

**Objective**

Issue short-lived audience-bound access tokens that resource endpoints can validate.

**Implementation**

Create signed JWT access tokens, issuer metadata, JWKS, key rotation/overlap, audience/resource indicators, scope/subject claims, bounded clocks, and token endpoint client handling. Keep signing keys in approved Jenkins credentials/HSM integration.

**Acceptance criteria**

- [ ] Tokens validate across rotation and cannot be used for another audience/client.
- [ ] Scopes map deterministically to Jenkins/MCP capability classes.
- [ ] Signing keys never appear in logs/config/support bundles.
- [ ] Metadata/JWKS endpoints have caching and availability tests.

---

## JAS-004 - Implement refresh rotation, revocation, logout, and introspection policy

**Priority:** P3  
**Dependencies:** JAS-003

**Objective**

Support lifecycle controls expected from a production authorization server.

**Implementation**

Implement refresh-token rotation/reuse detection, per-user/client revocation, expiry, admin emergency revoke, logout/session coupling as approved, optional introspection for opaque tokens, storage encryption, cleanup, and audit.

**Acceptance criteria**

- [ ] Stolen/reused refresh token is detected and token family revoked.
- [ ] User/client/admin revocation takes effect within the approved window.
- [ ] Token records are encrypted/minimized and migrations are tested.
- [ ] Failure/recovery does not resurrect revoked credentials.

---

## JAS-005 - Run OAuth conformance, independent review, and staged rollout

**Priority:** P3  
**Dependencies:** JAS-004, QA-005

**Objective**

Treat the plugin as a security product before any gateway dependency.

**Implementation**

Run protocol/conformance suites, fuzzing, penetration test, load/HA/upgrade tests, key-loss/rotation drills, compatibility matrix, documentation, SBOM/signing, incident runbook, canary, and rollback.

**Acceptance criteria**

- [ ] Independent security review has no unresolved critical/high findings.
- [ ] Conformance and adversarial test evidence is retained.
- [ ] Canary proves audit/latency/revocation and no Jenkins UI/API regressions.
- [ ] MCP retains API-token/external-resource-server rollback paths.

---

# Phase 5 - Hardening, validation, and production rollout

## QA-001 - Fuzz parsers, URL/path handling, storage formats, and MCP inputs

**Priority:** P1  
**Dependencies:** Core Phase 1-3 features

**Objective**

Find panics, hangs, excessive allocation, and unsafe parsing behavior.

**Implementation**

Add persistent fuzz targets for job paths, Jenkins JSON/XML models, progressive headers/state, log sanitation/redaction, chunk/manifest/index parsers, artifact/archive parsing, OAuth callbacks/tokens/exchange, subject-bound policy handles, Zstandard frame/seek tables, and tool inputs.

**Acceptance criteria**

- [ ] Seed corpora include malformed and security fixtures.
- [ ] Fuzz jobs have memory/time guards and retain crashing inputs.
- [ ] No known panic/hang remains in supported parsing paths.
- [ ] Security-relevant crashes receive tracked remediation.

---

## QA-002 - Add chaos and fault-injection suites

**Priority:** P1  
**Dependencies:** LOG-002, STO-004, ARC-006, OAUTH-004

**Objective**

Validate recovery under partial failures rather than only clean errors.

**Implementation**

Inject network disconnects, slow reads, truncated bodies, wrong offsets, process kill, disk full, fsync/rename/database failures, corrupt frames/seek tables/TAR members/packs/indexes, sidecar crashes, OAuth revocation/JWKS outage/fallback attempts, policy replacement, clock skew, and Jenkins restart.

**Acceptance criteria**

- [ ] No fault creates an undetected logically valid but corrupt cache state.
- [ ] Remote mutations are never duplicated by fault recovery.
- [ ] Recovery time and behavior are documented.
- [ ] Test suite can reproduce failures deterministically.

---

## QA-003 - Establish continuous performance regression testing

**Priority:** P1  
**Dependencies:** PERF-001, PERF-002, PERF-003

**Objective**

Prevent silent degradation in the product's highest-priority qualities.

**Implementation**

Run representative benchmarks on stable hardware or calibrated runners. Track p50/p95/p99, CPU, RSS, allocations, Jenkins/gateway/client network bytes, disk bytes, compression ratio, frames opened, read amplification, affinity locality, cache hits, and MCP output bytes. Define alert/fail thresholds.

**Acceptance criteria**

- [ ] More than approved regression thresholds block or alert with comparison data.
- [ ] Cold/warm cache states are separated.
- [ ] Rocky/Ubuntu SELinux or AppArmor-on measurements are included for Tier-1 Linux baselines.
- [ ] Results are retained and graphable by commit/release.

---

## QA-004 - Test configuration, database, chunk, and archive migrations

**Priority:** P1  
**Dependencies:** Released schema candidates

**Objective**

Ensure upgrades do not strand or corrupt locally cached investigations.

**Implementation**

Create fixtures from every supported prior schema/version, perform upgrade/downgrade or rollback where promised, inject interruption, and verify lazy rebuild of derived indexes.

**Acceptance criteria**

- [ ] Upgrade from every supported release passes.
- [ ] Interrupted migration resumes or rolls back safely.
- [ ] Large archives do not require full content rewrite solely for metadata migration unless explicitly approved.
- [ ] Unsupported downgrade produces a clear, non-destructive message.

---

## QA-005 - Conduct independent security review and penetration test

**Priority:** P0  
**Release timing:** Before broad production  
**Dependencies:** Secure read-only feature complete; OAuth and archive paths complete if shipping

**Objective**

Validate the threat model and implementation with independent reviewers.

**Implementation**

Review auth/token lifecycle, Jenkins/gateway configuration, SSRF/redirects, local IPC, keyring, cache ACL/encryption, redaction, prompt injection, artifacts/archives, sidecar, update/supply chain, and mutation controls.

**Acceptance criteria**

- [ ] No unresolved critical/high finding remains at release.
- [ ] Medium findings have owners and accepted timelines.
- [ ] Retest verifies fixes.
- [ ] Operational Jenkins-side OAuth guidance is included in scope.

---

## QA-006 - Complete privacy and data-retention review

**Priority:** P0  
**Release timing:** Before broad production  
**Dependencies:** SEC-002, ARC-007, MGR-002 if shipping

**Objective**

Approve what data is cached, exported, retained, purged, and included in support artifacts.

**Implementation**

Map fields/data flows, classify logs/artifacts/test data, define quotas/retention/purge, verify logout/uninstall behavior, review telemetry, and document user/admin controls.

**Acceptance criteria**

- [ ] Data inventory and retention matrix are approved.
- [ ] Cache purge can remove profile/all local data without leaving catalog references.
- [ ] Telemetry/support bundles match approved categories.
- [ ] Known secure-erasure limitations on SSDs are documented accurately.

---

## DOC-001 - Write user, admin, security, and operator documentation

**Priority:** P0  
**Dependencies:** Feature-complete release candidate

**Objective**

Make installation, authentication, policy, troubleshooting, and maintenance unambiguous.

**Implementation**

Create guides for Cursor setup with `--read-only`, API-token login, local external-IdP OAuth and the no-native-Jenkins-3LO distinction, Jenkins JWT route protection, AgentCore user-delegated 3LO/OBO, MCP-side RBAC, profiles, proxy/CA/mTLS, HTTP content encoding and bandwidth metrics, seekable-Zstandard/`ratarmount-rs` affinity storage, quotas, `doctor`, read-only/mutations, support bundles, upgrades, and incident response.

**Acceptance criteria**

- [ ] A new pilot user completes setup without receiving a plaintext secret example.
- [ ] Security guide explains no native Jenkins 3LO, external issuer/resource audience, AgentCore 3LO/OBO provider endpoints, complete route coverage, fallback-auth risk, and conditional plugin scope.
- [ ] Cursor examples show `--read-only` and `JENKINS_MCP_READ_ONLY=true`; they do not advertise a generic inverse switch that can bypass stronger policy.
- [ ] Storage guide explains direct network-decode-to-L1 payload frames, encoded versus decoded byte metrics, header/payload/padding frame assembly, affinity packs, seek tables, qualified `ratarmount-rs`/native readers, compatibility repack, recovery, and why single-frame `.tar.zst` is rejected.
- [ ] Troubleshooting maps common error codes to safe actions.

---

## DOC-002 - Publish tool-contract and agent-usage guidance

**Priority:** P1  
**Dependencies:** MCP/diagnostic tools complete

**Objective**

Help models and developers call tools efficiently and verify conclusions.

**Implementation**

Document preferred high-level tools, bounded primitive fallbacks, evidence references, continuations, freshness, truncation, heuristic confidence, and mutation confirmation semantics. Include examples that avoid repeated downloads.

**Acceptance criteria**

- [ ] Examples begin with triage tools rather than dumping logs.
- [ ] Every tool has schema, bounds, errors, and side-effect classification.
- [ ] Guidance tells agents to treat build output as untrusted data.
- [ ] Compatibility/deprecation policy is documented.

---

## REL-001 - Run a limited read-only pilot

**Priority:** P0  
**Dependencies:** Phase 1 complete, QA-005/006 scoped approval, PKG-001, DOC-001  
**Status:** **Partial / kit Done\*** — operator Rocky/Ubuntu live cohorts remain residual; mode matrix + offline evidence pack present

**Objective**

Validate real workflows and performance with a small approved user group.

**Implementation**

Deploy signed Tier-1 builds (Rocky Linux, Ubuntu), collect approved metrics and structured feedback, sample network/cache behavior, track auth/support issues, and maintain rapid rollback. Use API-token and OAuth cohorts if OAuth is ready. Pilot cohorts must include Rocky and Ubuntu users. macOS participants are optional and non-blocking. Windows is not a pilot platform.

**Evidence kit:** [`docs/pilot/README.md`](pilot/README.md), [`docs/pilot/checklist.md`](pilot/checklist.md) §0 mode matrix (stdio + A/B/C), `make pilot-evidence`, `pilot-check`. Offline gateway qualify is **not** live multi-user GO.

**Acceptance criteria**

- [ ] No shared credentials are used. — operator-owned live pilot
- [ ] Network and result-size targets are measured on real workflows. — operator-owned
- [ ] No secret/privacy incident occurs; any incident triggers the documented response. — operator-owned
- [ ] Pilot exit report lists defects, SLOs, adoption, and go/no-go recommendation. — operator-owned; template includes modes piloted
- [ ] Pilot evidence includes successful install/login/diagnose on Rocky and on Ubuntu. — operator-owned; kit/checklist ready
- [x] Evidence checklist records **modes piloted** (stdio / A / B / C) and gateway residual honesty. — checklist §0 + README matrix

---

## REL-002 - Pass production release gates

**Priority:** P0  
**Dependencies:** All features selected for release  
**Status:** **Partial / lite Done\*** — offline `release-evidence` + gates/template mode matrix; full production sign-off residual

**Objective**

Make production approval evidence-based.

**Implementation**

Assemble a versioned release-evidence bundle, execute every applicable security, performance, reliability, compatibility, and usability gate, record deviations and approved exceptions, collect named owner sign-offs, and produce a go/no-go decision linked to the exact release artifacts. The release pipeline must block publication when a mandatory gate has no passing evidence or approved exception.

**Evidence kit:** [`docs/release/gates.md`](release/gates.md), [`docs/release/evidence-template.md`](release/evidence-template.md) modes matrix, residual `gateway_modes_live` in `release-evidence` JSON. **Does not claim production GO.**

**Acceptance criteria**

- [ ] Security: personal identity, secret handling, read-only default, origin controls, cache privacy, SBOM/signing, and independent review pass.
- [ ] Performance: no hidden log over-download, cache reuse, response limits, reference SLOs, and L2 random access pass.
- [ ] Reliability: crash/disk/corruption/cancellation/outage/migration tests pass.
- [ ] Compatibility: Jenkins LTS/plugin, OS, Cursor, MCP conformance, and auth matrices pass.
- [x] Compatibility honesty: release evidence lists **modes piloted** (A/B/C/stdio) and gateway offline residual. — template + residual id
- [ ] Usability: install, profile, login, identity verification, diagnosis, cache purge, and `doctor` complete successfully from documentation.
- [ ] Ownership: on-call/support, vulnerability response, Jenkins-side OAuth owner, and release owner are named.

---

# Cross-cutting acceptance scenarios

These scenarios become end-to-end tests and release evidence.

## Scenario A - Personal API token with no plaintext secret

- Signed local binary starts from a secret-free Cursor profile.
- User enters a personal token through a non-echoing prompt; it exists only in Linux Secret Service (Rocky/Ubuntu) and process memory.
- Status and Jenkins audit show the expected person.
- Logout removes credential, invalidates sessions/handles, and blocks new remote calls.

## Scenario B - Cursor/global read-only cannot be weakened or bypassed

- Cursor launches with `--read-only` or `JENKINS_MCP_READ_ONLY=true`; signed policy can also force read-only.
- Mutation tools are absent from discovery.
- Crafted JSON-RPC, alias, direct service, continuation, background task, redirect, and unsafe Jenkins path attempts are denied below the tool layer.
- A user/profile false value cannot override a stronger true source.
- OAuth token exchange/refresh remains functional because auth POSTs are separately classified.

## Scenario C - MCP RBAC restricts a Jenkins administrator

- Jenkins permits broad read/write access, while MCP policy permits only bounded read/diagnosis in selected folders.
- Artifact download, cross-folder search, export, trigger, and excessive history/log scans are denied before remote/cache access.
- Jenkins-denied objects remain denied even under an MCP allow rule.
- Policy/role removal invalidates decisions and subject-bound handles within the approved window.

## Scenario D - External IdP OAuth, not false native Jenkins 3LO

- Local MCP performs Authorization Code + PKCE against Entra/approved IdP.
- Access token has the dedicated Jenkins resource/audience and personal subject.
- Jenkins resource filter maps the person/groups and applies existing Jenkins RBAC.
- ID, Graph, generic gateway, wrong-tenant, and wrong-audience tokens fail.
- Status/docs say external issuer + Jenkins resource-server mode, not Jenkins-hosted 3LO.

## Scenario E - Bearer protection covers every route and cannot fall through

- Route manifest includes JSON/XML APIs, progressive text, Pipeline/stage logs, tests, artifact bytes, identity, crumbs, queue, and enabled mutations.
- Valid bearer succeeds as expected person on each route.
- Missing/malformed/expired/wrong-audience bearer cannot fall through to Basic/API-token/UI-session/anonymous access in OAuth-required mode.
- Audit preserves personal attribution.

## Scenario F - One-gigabyte running log remains bounded

- A 1 GiB growing log is mirrored incrementally; each byte is fetched once per generation.
- Raw memory stays bounded and bytes are committed immediately as independent checksummed Zstandard frames.
- Tail/search/diagnosis reuses local data and fetches only new suffixes.
- Default MCP response remains near 64 KiB and never exceeds 1 MiB.
- Cancellation stops network, compression, indexing, search, and polling promptly.

## Scenario G - Related logs become a seekable affinity archive

- Root console, stage/node, downstream/matrix-child, and text test evidence share one collection only when user/profile/controller, authorization policy, sensitivity, retention, encryption, size, and lifecycle permit.
- Packer creates a multi-frame seekable `.tar.zst`, TAR/collection manifest, seek table, and indexes; oversized collections split deterministically.
- Preferred zero-recompression path generates small TAR header/padding frames around unchanged copied L1 compressed payload frames; fallback repack remains correct.
- Qualified `ratarmount-rs` and native reader return byte-identical ranges when the adapter is available.
- A 64 KiB request opens only bounded intersecting frames; interruption leaves valid L1 or published L2.

## Scenario H - AgentCore 3LO/OBO preserves per-user Jenkins identity

- Gateway validates an Entra user and obtains a Jenkins-audience credential through user-delegated Authorization Code, OBO/token exchange, or explicitly approved exact-audience passthrough, keyed to the user/workload binding.
- OAuth discovery, authorization, issuer, and token endpoints are Entra/approved authorization-server endpoints, not stock Jenkins.
- No generic service account or user-pasted long-lived Jenkins key is used.
- Two users cannot share downstream tokens, consent sessions, cached results, evidence handles, or archives.
- Jenkins and MCP audit correlate the actual person and workload.
- Near-source mode measurably reduces VPN/client transfer.

## Scenario I - Evidence-backed diagnosis

- Pipeline fails in a downstream component with a JUnit failure and related commit range.
- One diagnosis returns failed stage, likely cause, test/change/graph summaries, exact evidence handles, confidence, freshness, and truncation.
- No full log, secret, terminal-control exploit, or model-directed instruction escapes sanitization.
- Repeated call downloads no duplicate completed log bytes and normally touches one affinity collection.

## Scenario J - Mutation cannot happen accidentally

- Mutations become visible only after global read-only is off and signed MCP RBAC allows an exact action/target/parameter set.
- Tool returns normalized preview; subject-bound confirmation is expiring and single-use.
- Request executes once without unsafe retry and returns queue/build/audit correlation.
- Replay, changed target/parameter, lost permission, emergency read-only, or policy update denies execution.

---

# Phase 6 - Operator admin console (reactive SPA)

**Goal:** Browser-based **admin front end** for operators to manage local/enterprise pilot deployments: administrative tasks, **deny-only MCP RBAC / policy** (view + controlled edit), **performance/metrics**, and **audit log** inspection. Implementation uses a **reactive UI framework** (SPA) talking to a **local admin BFF** that reuses existing CLI/library controls — not a second policy engine.

**Agent hint (standing rule — all phases):** When implementing **any** operator-relevant feature outside this phase (policy, metrics/telemetry, audit fields, doctor/support-bundle, cache/pins/quota, profiles, packaging, day-2 CLI), **keep the admin console current** in the same change: update `internal/admin` BFF, `web/admin` SPA, and `docs/admin/api-v1.md` when that domain is already exposed — or leave an explicit residual TODO. Do not let CLI/library behavior drift silently ahead of the console. Full policy: root **`AGENTS.md`** → “Non-negotiable: keep the admin console current”.

**Non-goals / constraints (global):**

- **No secrets in the browser** (tokens, keyring material, raw Authorization headers never returned).
- **Not multi-tenant SaaS control plane** in v1 (single operator host / loopback or mTLS-gated bind; residual multi-tenant gateway isolation remains).
- **Windows out of scope** for packaging; Tier-1 Rocky/Ubuntu (+ optional macOS).
- **stdio MCP** remains the agent path; admin console is **operator-only**, separate from Cursor tool discovery.
- Policy writes remain **fail-closed**, signed-overlay-aware, and cannot widen enterprise `force_read_only`.
- Prefer **React + TypeScript + Vite** (or ADR-selected equivalent reactive stack: Vue/Svelte) with component state + server state (e.g. TanStack Query).

**Depends on:** OPS-001, AUD-001, OBS-001, POL-001–005, CFG-001/002, MGR-001 (for signed policy), DOC-001.

---

## UI-000 - ADR: admin console architecture, reactive framework, and threat model

**Priority:** P1  
**Dependencies:** SEC-001, FND-008, OPS-001, AUD-001, OBS-001

**Objective**

Lock architecture before UI code: reactive framework choice, process boundaries, authn/z for operators, data classes, and residual risks.

**Implementation**

Write ADR(s) covering: (1) **reactive SPA** framework + TS toolchain; (2) **local admin BFF** (extend `jenkins-mcp` HTTP loopback or dedicated `admin serve` subcommand) vs embedding static assets; (3) operator authentication (OS user + optional shared-secret/token for loopback; no Jenkins token in browser); (4) read vs write surfaces; (5) CSP, CORS, cookie/token storage policy; (6) mapping console actions to existing `policy` / `telemetry` / audit / doctor packages. Update threat model for admin UI XSS, CSRF, local privilege escalation, and audit leakage.

**Acceptance criteria**

- [ ] ADR records chosen reactive framework and why alternatives were rejected.
- [ ] Threat model lists admin UI assets/actors and high/critical mitigations.
- [ ] Explicit: MCP tool path and admin path are separate; RO pilot does not require the console.
- [ ] Bind defaults: loopback-only unless advanced residual flag; Windows not required.
- [ ] No design requires placing API tokens or OIDC refresh tokens in browser storage.

---

## UI-001 - Scaffold reactive admin SPA and static asset pipeline

**Priority:** P1  
**Dependencies:** UI-000, FND-002, PKG-001

**Objective**

Create a maintainable SPA workspace that builds into versioned static assets consumable by the Go binary or reverse proxy.

**Implementation**

Scaffold `web/admin/` (or `ui/admin/`) with the ADR framework (default recommendation: **React 18+ / TypeScript / Vite**). Add lint/format/test scripts, design tokens minimal layout (nav: Overview, Policy/RBAC, Metrics, Audit, Cache/Doctor), routing, and `make admin-ui` / CI job that produces `dist/admin/` artifacts. Embed or serve assets via Go `embed` in a later task; v1 may use `admin serve --assets-dir`. No production secrets in frontend env.

**Acceptance criteria**

- [ ] `make admin-ui` (or documented npm/pnpm script) builds production assets reproducibly.
- [ ] Unit/component test harness runs in CI (smoke).
- [ ] SPA has shell routes for Policy, Metrics, Audit, Diagnostics placeholders.
- [ ] License/NOTICE for frontend deps recorded; SBOM path residual or generated.
- [ ] Build does not require Windows; documented on Rocky/Ubuntu.

---

## UI-002 - Local admin BFF / HTTP API (read path)

**Priority:** P1  
**Dependencies:** UI-000, OPS-001, OBS-001, AUD-001, POL-005

**Objective**

Expose a **secret-free JSON API** for the SPA that wraps existing libraries/CLI semantics (doctor, telemetry snapshot, effective policy, audit tail).

**Implementation**

Add `jenkins-mcp admin serve` (or extend loopback HTTP with `/admin/v1/*` behind explicit enable flag default-off). Endpoints (v1 read): health, version, effective config/policy (reuse policy show-effective), telemetry snapshot, doctor offline/online (bounded), audit list/tail with pagination + filters (type, tool, reason, time), cache status summary. All responses scrubbed; fail closed on missing profile. Shared-secret or OS-session gate required even on loopback residual. OpenAPI/JSON schema for the SPA.

**Acceptance criteria**

- [ ] Default: admin HTTP **disabled**; enable only with explicit flag/env.
- [ ] Loopback bind default; non-local requires stronger residual flags + token + host/origin allow-lists.
- [ ] Canary tests: no token/password/Authorization in any admin JSON body.
- [ ] API errors use stable codes; never raw transport dumps.
- [ ] Contract tests cover pagination caps and invalid filters fail closed.

---

## UI-003 - Operator authentication and admin RBAC for the console

**Priority:** P0  
**Dependencies:** UI-002, AUTH-001, POL-002, SEC-001

**Objective**

Ensure only authorized **operators** use write surfaces; read surfaces still require local operator authn.

**Implementation**

Define admin roles (e.g. `viewer`, `operator`, `policy_admin`) separate from MCP deny-only RBAC subjects. Bind session to local operator identity (not Jenkins end-user spoofable via query params). Session tokens httpOnly/secure where applicable; CSRF protection for cookie sessions. Map roles to API routes. Document that console RBAC does not replace Jenkins authorization or MCP deny lists.

**Acceptance criteria**

- [x] Unauthenticated requests denied (when token configured → 401; token required for non-local).
- [x] `viewer` cannot mutate policy/cache destructive ops (`PermPolicyWrite` / `PermCacheDestructive` deny + middleware 403 tests).
- [x] `policy_admin` still cannot defeat enterprise `force_read_only` (`CanWidenForceReadOnly` always false).
- [x] Tests for privilege escalation (role matrix + RequirePermission) and secret canaries (token never in JSON).
- [ ] Logout invalidates session (in-process + durable residual documented). **Residual:** v1 is shared-secret Bearer/header (no cookie session table); “logout” = drop client token; durable multi-session invalidation deferred with cookie/OIDC.

**Implementation notes (landed lite):** `internal/admin` Role/Permission, `--admin-role`, `GET /admin/v1/me`, `RequirePermission` / `CheckPermission`. No production write routes yet (UI-004). CSRF N/A for Bearer; documented residual for future cookie sessions.

---

## UI-004 - Policy / deny-only MCP RBAC viewer and controlled editor

**Priority:** P1  
**Dependencies:** UI-001, UI-002, UI-003, POL-001–005, MGR-001, CFG-002

**Objective**

Operators can **see effective RBAC/policy** and propose/apply controlled changes without hand-editing JSON only.

**Implementation**

**Viewer:** render effective force RO, deny_tools, deny_job_prefixes, deny_node/view/artifact/branch patterns, signature state, source provenance (enterprise vs profile). **Editor (draft → validate → apply):** form/structured editor for pilot overlay fields; client-side validation; server validate against schema; optional sign step (keys never in browser — invoke local sign via BFF with keys-dir on server host only). Show dry-run diff of effective policy before apply. Hot-reload awareness (last-good).

**Acceptance criteria**

- [ ] Effective policy page matches `policy show-effective` for the same profile.
- [ ] Invalid overlays rejected with field-level errors; no partial apply.
- [ ] Apply path cannot widen enforced enterprise restrictions.
- [ ] Signature required mode fail-closed when configured.
- [ ] Audit events emitted for policy view (optional) and policy apply/deny.
- [ ] Reactive UI updates after apply without full manual reload (query invalidation).

---

## UI-005 - Performance and metrics dashboard

**Priority:** P1  
**Dependencies:** UI-001, UI-002, OBS-001, PERF-001

**Objective**

Monitor application performance and operational metrics from the console.

**Implementation**

Dashboard cards/charts (reactive): tool_calls, mcp_tool_ok/error/deny, Jenkins HTTP request/error/byte counters, circuit open events, cache maint/evict/pack gauges, identity reverify denials if exposed. Auto-refresh with backoff; pause on hidden tab. Link to budgets and serve log-level guidance. Optional export of secret-free snapshot JSON. No high-cardinality labels (no job names/tokens as series).

**Acceptance criteria**

- [ ] Metrics match `telemetry show` / in-process registry for same process or documented scrape model.
- [ ] Refresh does not leak secrets; empty/missing metrics show residual honesty.
- [ ] Caps on history series length to bound memory in the SPA.
- [ ] Document residual: multi-process fleet aggregation not in v1 (MGR-002 residual).

---

## UI-006 - Audit log browser

**Priority:** P1  
**Dependencies:** UI-001, UI-002, UI-003, AUD-001

**Objective**

Inspect privacy-preserving audit events without shell access to JSONL files.

**Implementation**

Table + filters: time range, type, tool, decision, reasonCode, principalId (non-secret). Detail drawer for single event. Pagination / cursor; hard caps on page size. Optional live tail (SSE/WebSocket) with backpressure. Download scrubbed CSV/JSON export. Never show job parameters, log bodies, or tokens (not present in schema — enforce in API).

**Acceptance criteria**

- [ ] Events match on-disk audit JSONL for the profile (spot-check tests).
- [ ] Filters cannot be used to exfiltrate non-schema fields.
- [ ] Large audit files do not load entirely into browser memory.
- [ ] Export is secret-free and size-capped.

---

## UI-007 - Administrative task surfaces (profiles, doctor, cache)

**Priority:** P2  
**Dependencies:** UI-002, UI-003, OPS-001, CFG-001

**Objective**

Cover day-2 admin tasks operators currently do via CLI.

**Implementation**

Pages/actions: profile list/show (no secrets), doctor run + result view, cache status/verify summary, pin list, quota usage, support-bundle trigger (download scrubbed zip path), security self-check results. Destructive cache ops require confirm modal + operator role + optional `--confirm` equivalent server-side.

**Acceptance criteria**

- [ ] Doctor/self-check/cache status parity with CLI for documented fields.
- [ ] Destructive actions double-confirm and are audited.
- [ ] Profile show never returns keyring material.

---

## UI-008 - Serve integration, CSP, and packaging

**Priority:** P1  
**Dependencies:** UI-001, UI-002, PKG-001, FND-006

**Objective**

Ship the console safely with the binary/packages.

**Implementation**

`embed` or package `dist/admin` assets; `admin serve --profile …` wires BFF + static. Strict CSP, no inline secrets, Subresource Integrity residual for CDN (default: no CDN). Document reverse-proxy residual. Rocky/Ubuntu packages optionally include assets; portable tarball includes them. Health/readiness for admin port separate from MCP stdio.

**Acceptance criteria**

- [ ] Fresh install serves console from packaged assets without npm on the target host.
- [ ] CSP blocks unexpected script origins in automated check.
- [ ] Admin port off by default in pilot docs; enable path documented.
- [ ] Version endpoint shows UI asset build id + binary version.

---

## UI-009 - E2E tests and adversarial checks for admin console

**Priority:** P1  
**Dependencies:** UI-004, UI-005, UI-006, UI-003, POL-005, TST-001

**Objective**

Prevent console regressions and authz bypasses.

**Implementation**

Playwright/Cypress (or ADR choice) against BFF+SPA: login gate, policy view, metrics render, audit filter, privilege escalation attempts, XSS canaries in audit fields, CSRF on writes. Go contract tests for admin API. CI job optional non-gate then promote.

**Status (honest):** Done* for **Go adversarial/contract gate** + **documented opt-in E2E smoke** (`make admin-e2e` → `dist/admin-e2e/status.json`). Full-browser Playwright/Cypress and HAR scrub automation remain residual (no new heavy deps). CSRF N/A for v1 Bearer/header auth.

**Acceptance criteria**

- [x] E2E smoke in CI **or** documented opt-in with artifact (`make admin-e2e` / `scripts/admin-e2e-smoke.sh` → `dist/admin-e2e/status.json`; **not** default `make test`/`ci`).
- [x] XSS/canary payloads in reason/tool fields do not execute (asserted as **JSON text only** / HTML-escaped wire + CSP; browser “does not execute” residual without Playwright).
- [x] viewer cannot apply policy in automated test (`TestUI009_ViewerCannotApplyPolicy` + e2e curl 403).
- [x] Secret canary never appears in network/API responses (`TestUI009_SecretCanaryAbsentAcrossRoutes` + e2e canary scrub; full HAR residual).

**Evidence**

- `internal/admin/ui009_adversarial_test.go` (`TestUI009_*`)
- `scripts/admin-e2e-smoke.sh`, Makefile `admin-e2e`
- `docs/admin/api-v1.md` § Testing (UI-009)

---

## UI-010 - Accessibility, i18n residual, and operator UX polish

**Priority:** P2  
**Dependencies:** UI-001, UI-004, UI-005, UI-006

**Objective**

Production-usable console for operators.

**Implementation**

Keyboard nav, focus traps in modals, contrast, ARIA for tables/live regions (metrics refresh, audit tail). Empty/error/residual states honest. Optional i18n residual. Link out to docs/admin and pilot checklist.

**Acceptance criteria**

- [ ] Critical flows usable keyboard-only.
- [ ] Automated a11y smoke (axe) on primary routes.
- [ ] Residual banners for unsigned policy, disabled telemetry, adapter-off, etc.

---

# Recommended implementation sequence

1. FND-001 through FND-008, PERF-001, SEC-001, AUTH-000, and ARC-000.
2. CFG-001/002, AUTH-001 through AUTH-004, NET-001 through NET-004, and STO-001/002.
3. POL-001 through POL-004 plus MCP-001/002. No mutation tool may be registered before these controls exist.
4. LOG-001/002 and STO-003/004; then LOG-003/004, SEARCH-001/002, SEC-002/003, and POL-005.
5. AUD-001, OBS-001, OPS-001, TST-001, PKG-001, and the local read-only pilot gate.
6. OAUTH-001 through OAUTH-008, then OAUTH-009. Run OAUTH-010 as the AgentCore 3LO/OBO feasibility prototype and OAUTH-011 as the explicit Jenkins-authorization-server decision gate.
7. ARC-001 through ARC-004, ARC-010 through ARC-012, ARC-005 through ARC-008, and PERF-002. ARC-011 defines bounded semantic grouping before ARC-005 publishes packs.
8. JEN/PIPE/TEST/SCM/GRAPH/ART/HEALTH, followed by DIAG-001 through DIAG-007 and PERF-003.
9. Optional **server/team-hosted** path (see `docs/roadmap/server-team-hosted.md`): implement **all three** auth modes — **HOST-009** (API token vault), **OAUTH-009+HOST-010** (JWT RS bearer), **OAUTH-010+GWY-001** (AgentCore 3LO/OBO) — plus **HOST-001–006**, **HOST-011** mode matrix, **HOST-012…015** Docker labs (mock IdP/JWT RS/token peer; opt-in Makefile), **GWY-002–004**, **MGR-001**, **REL-001/002**. Sites pick which modes to enable; engineering ships all.
10. Execute JAS-001 through JAS-005 only after an OAUTH-011 **go** decision. The normal external-IdP resource-server/AgentCore 3LO-OBO release path must not depend on this conditional epic.
11. QA, documentation, local/gateway pilots, and production release gates.
12. **Admin console (Phase 6):** UI-000 → UI-001/002/003 → UI-004 (policy/RBAC) + UI-005 (metrics) + UI-006 (audit) in parallel where deps allow → UI-007/008 → UI-009/010. Reactive SPA + local admin BFF; native MCP stdio path unchanged. Keep console residual notes current as HOST modes land (`AGENTS.md`).

Tasks in a step run in parallel only when declared dependencies permit. Authentication semantics, signed policy, public tools, subject/cache isolation, Zstandard/TAR formats, `ratarmount-rs` compatibility, and **admin console authz/CSP** require architecture and security review.

---

# First sprint recommendation

Complete or substantially advance:

- FND-001 through FND-004 and PERF-001.
- LOG-001 proof that an 8 KiB request against a large log transfers and allocates only bounded bytes.
- SEC-001 and AUTH-000 to lock no-native-3LO terminology, identity, and trust boundaries.
- POL-001 demonstration from Cursor configuration, including direct/crafted bypass attempts.
- POL-002/003 policy schema and trusted-subject spike that restricts a Jenkins administrator to one read-only folder.
- OAUTH-008 capability matrix proving the roles of Jenkins core, `oic-auth`, `oidc-provider`, `github-oauth`, `oauth-credentials`, and `jwt-auth-filter`.
- ARC-000 code, license, supply-chain, API, Tier-1 platform (Rocky/Ubuntu + Linux FUSE), recovery, and performance qualification of the exact engineering-supplied `ratarmount-rs` repository and pinned revision.
- ARC-002 spike producing and validating a multi-frame seekable `.tar.zst`, rejecting a single-frame archive, and reading the same range through the native reader and the qualified Rust path when available.

The sprint demo should preserve existing Jenkins reads while showing bounded network/allocation behavior, secret-free local configuration, effective read-only provenance, deny-only RBAC, an approved authentication ADR, an honest exact-dependency `ratarmount-rs` qualification status, and measured random access into compressed related-log storage.
