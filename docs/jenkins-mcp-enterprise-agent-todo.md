# Enterprise Jenkins MCP - Agent-Ready Implementation Backlog

**Seed repository:** `https://github.com/simonfxr/go-jenkins-mcp`  
**Target:** Local per-user Jenkins MCP for Cursor plus optional per-user AgentCore/managed-gateway deployment  
**Primary priorities:** Per-user identity, fail-closed read-only/RBAC, network efficiency, seekable compressed storage, interactive performance  
**Companion design:** `jenkins-mcp-enterprise-architecture.md`  
**Revision:** Engineer authentication, read-only/RBAC, and seekable-Zstandard notes incorporated

---

## How an implementation agent must use this backlog

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
12. Do not add mutating Jenkins tools until global read-only, MCP RBAC, audit, preview/confirmation, and mutation-policy epics are approved.
13. Treat effective access as `Jenkins allow AND global mode AND MCP policy AND operation budgets`; MCP policy only reduces access.
14. A Cursor/profile setting can enable read-only but cannot disable a stronger enterprise or emergency read-only state.
15. Jenkins is not a native 3LO authorization server. Do not confuse UI OIDC login, outbound workload OIDC, or credential frameworks with delegated API authorization.
16. Do not send ID/Graph/generic gateway tokens to Jenkins. Bearer mode requires a validated access token for the exact Jenkins resource/audience.
17. Zstandard random access is based on independent frames/checkpoints plus a seek table. Do not call arbitrary blocks inside one frame independently seekable.
18. Never produce a conventional single-frame `.tar.zst` for L2 and call it random access; validate frame count, seek table, TAR, and checksums.
19. Managed/gateway mode preserves the personal subject end to end and never collapses users into a generic Jenkins identity.
20. `ratarmount-rs` is the preferred L2 engine, but all durable data must remain readable through the versioned format and native fallback.
21. AgentCore authorization, token, discovery, and consent endpoints point to Entra ID or another approved authorization server, not Jenkins, unless the conditional Jenkins authorization-server epic receives an explicit go decision.
22. Count encoded wire bytes and decoded bytes separately. Stream the decoded response directly into bounded parsers or independent Zstandard frames; never stage an unbounded plaintext log merely to compress it later.
23. Batch only related logs whose user, profile/controller, authorization policy, retention, sensitivity, and encryption domains match; never improve locality by weakening isolation.

### Definition of done for every task

- [ ] Implementation is isolated to the task scope.
- [ ] Unit tests cover success, failure, cancellation, and limits.
- [ ] Integration tests are added where Jenkins, OAuth, keyring, storage, or sidecars are involved.
- [ ] No secret values appear in logs or errors under canary tests.
- [ ] Static analysis, race tests where applicable, vulnerability scan, and format/lint checks pass.
- [ ] Performance evidence is attached when the task can affect CPU, memory, network, disk, startup, or response size.
- [ ] Documentation and changelog are updated.
- [ ] A rollback or backward-compatibility note is included for persistent-format or configuration changes.
- [ ] Acceptance criteria below are demonstrated, not merely asserted.

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
- Add build scripts for Windows, Linux, and macOS targets required by policy.
- Add a development container or documented isolated build environment without embedding secrets.
- Enable module checksum verification and fail on dirty generated files.
- Add `make`/Taskfile targets for build, test, race, lint, benchmark, SBOM, and package.

**Acceptance criteria**

- [ ] A fresh environment can build and test using one documented command.
- [ ] Two clean builds from the same commit produce matching source manifests; binary reproducibility gaps are documented.
- [ ] CI never requires a real Jenkins credential for unit tests.
- [ ] Build outputs include version, commit, dirty state, Go version, and build time policy.

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

**Objective**

Turn the preferred but not yet supplied Rust archive implementation into a measured, security-reviewed go/no-go decision without guessing which project is intended.

**Implementation**

Obtain the exact repository URL, owner, commit or release, license, provenance, support model, and expected integration mode from engineering. If the dependency cannot be supplied or reproduced, record an explicit no-go/deferred result and continue with the native Go reader; never substitute a similarly named public project silently. Review build reproducibility, release/signing process, SBOM/crates, unsafe Rust, parser boundaries, fuzzing, CVE response, supported seekable-Zstandard dialect, index format, Windows behavior, and recovery semantics. Prototype direct library/FFI, managed local sidecar/CLI, and optional FUSE/WinFsp modes as applicable, while keeping normal MCP reads independent of a mounted filesystem. Verify independent-frame seekable `.tar.zst` compatibility and compare all reads with the native Go fallback. Benchmark index build/load, range access, concurrency, cancellation, endpoint protection, truncation, corruption, crash recovery, and antivirus/EDR impact.

**Acceptance criteria**

- [ ] Approved go/no-go names the exact repository, commit/release, owner, license, provenance, SBOM/dependencies, build process, update/rollback plan, and security-response owner.
- [ ] If the exact dependency cannot be accessed, reproduced, or approved, status is explicit no-go/deferred and the native reader remains the supported path.
- [ ] No similarly named project is substituted or described as the intended dependency without engineering confirmation.
- [ ] Windows works without mandatory FUSE, or the limitation is explicitly rejected/accepted by endpoint security and product owners.
- [ ] Direct API, sidecar, and mount integration choices are measured and documented; FUSE/WinFsp is never required for ordinary reads.
- [ ] Qualified adapter and native reader return identical golden pack/member/range bytes.
- [ ] Warm/cold read, index, memory, concurrency, cancellation, corruption, recovery, and EDR measurements exist.
- [ ] Adapter failure/disablement does not invalidate `ArchiveStore` or the durable format.
- [ ] No ordinary single-frame `.tar.zst` is accepted as performant random-access storage.

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

Implement Windows Credential Manager first, then required macOS Keychain/Linux Secret Service adapters. Namespace entries by application, OS user, profile, controller origin, auth method, and account identity.

**Acceptance criteria**

- [ ] API tokens can be stored, loaded, replaced, and deleted under the current OS user.
- [ ] Another local user cannot read the credential through normal APIs.
- [ ] Error and debug paths never print the secret.
- [ ] Headless fallback is disabled unless policy explicitly allows a protected file.
- [ ] Backend tests use mocks or isolated test entries and clean them up.

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

## PKG-001 - Produce signed Windows-first pilot packages

**Priority:** P0  
**Dependencies:** FND-007, AUTH-003, OPS-001

**Objective**

Deliver a trustworthy local executable that Cursor can launch without secrets in configuration.

**Implementation**

Build signed Windows x64 package, install/uninstall flow, per-user data paths, version metadata, SBOM, provenance, and secret-free Cursor configuration documentation. Add ARM64 only if required by the support matrix.

**Acceptance criteria**

- [ ] Installed binary signature validates.
- [ ] Ordinary operation requires no administrator rights unless deployment policy mandates it.
- [ ] Uninstall behavior for cache and credentials is explicit and user-controlled.
- [ ] Cursor starts the MCP over stdio with profile-only arguments.
- [ ] Endpoint-protection compatibility smoke tests pass.

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

- [ ] Wrong issuer/tenant/audience/algorithm/type/time/client tests fail closed.
- [ ] An ID token or Graph token is rejected for Jenkins API authentication.
- [ ] JWKS rotation succeeds without accepting unknown issuers.
- [ ] Token contents are never logged or persisted outside approved keyring fields.

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

**Acceptance criteria**

- [ ] Jenkins and MCP policy permissions reflect role removal within the approved window.
- [ ] Group overage cannot silently broaden access.
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

---

## OAUTH-010 - Prototype AgentCore per-user Jenkins 3LO/OBO token acquisition

**Priority:** P2  
**Dependencies:** OAUTH-005, POL-003, FND-005

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

- [ ] A compatibility matrix records which Authorization Code, OBO/token-exchange, and exact-audience passthrough paths work and the precise provider/resource configuration.
- [ ] AgentCore issuer/authorization/token endpoints are Entra/approved authorization-server endpoints, never stock Jenkins, unless OAUTH-011 has an explicit go decision and the conditional plugin exists.
- [ ] Authorization-code consent is session-bound and access/refresh material is stored under the correct user and workload identity.
- [ ] One user cannot obtain/use another user's downstream token, cache entry, evidence handle, or archive namespace.
- [ ] Token audience is Jenkins and Jenkins sees the expected individual principal.
- [ ] Refresh/cache/vault storage is per-user, centrally revocable, and contains no user-pasted Jenkins key.
- [ ] Direct passthrough rejects generic gateway, ID, Graph, wrong-tenant, and wrong-audience tokens.
- [ ] No generic Jenkins account is used.
- [ ] Local and gateway auth providers remain independent and testable.

---

## OAUTH-011 - Run the decision gate for a Jenkins-hosted 3LO authorization server

**Priority:** P2  
**Dependencies:** OAUTH-009, OAUTH-010, security architecture approval

**Objective**

Make the default decision **no-go** and approve a full Jenkins OAuth authorization-server plugin only when a concrete, funded requirement remains unsolved after external-IdP resource-server, AgentCore authorization-code, OBO/token-exchange, passthrough, proxy/filter, and narrow-broker prototypes.

**Implementation**

Document every unmet gateway/client requirement after the simpler prototypes, why each alternative fails, security and long-term maintenance ownership, client/scopes/consent requirements, key and token lifecycle, conformance obligations, migration impact, and exit strategy. A desire for Jenkins-branded OAuth endpoints or symmetry with another product is not sufficient justification.

**Acceptance criteria**

- [ ] Decision records explicit go/no-go criteria, evidence, approvers, owner, funding, and support horizon.
- [ ] The default/no-evidence result is no-go and closes or deprioritizes the conditional JAS epic.
- [ ] A go decision identifies a specific blocker that cannot be solved safely by Entra/AgentCore, a resource filter/proxy, token exchange, or a narrow broker.
- [ ] A go decision funds separate threat modeling, key management, secure token storage, OAuth conformance, independent review, penetration testing, release engineering, and incident ownership.
- [ ] The MCP core and local release do not depend on the plugin before or after this gate.

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
- [ ] Windows works without FUSE/WinFsp.
- [ ] Reader output matches the qualified `ratarmount-rs` adapter byte-for-byte when that adapter is available.

---

## ARC-004 - Implement the qualified `ratarmount-rs` adapter

**Priority:** P1  
**Dependencies:** ARC-000, ARC-002

**Objective**

Use the preferred archive implementation without making it a single point of failure.

**Implementation**

Implement the approved direct Rust API or managed sidecar. Pin version, sandbox/lifecycle/limits, controlled index location, cancellation, health checks, and sanitized errors. Optional mount mode is diagnostic only.

**Acceptance criteria**

- [ ] Adapter opens/list/range-reads supported packs within limits.
- [ ] No public listener or arbitrary user path traversal exists.
- [ ] Sidecar/FFI failure degrades to native reader where possible.
- [ ] Index corruption/mismatch is detected and recoverable.
- [ ] Supply-chain/update/rollback process is documented.

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

# Phase 4 - Controlled mutations, AgentCore gateway, and optional integrations

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

**Acceptance criteria**

- [ ] No automatic retry can create a duplicate build.
- [ ] Unknown/secret/unsupported parameters are rejected.
- [ ] Preview exactly matches executed request after normalization.
- [ ] Jenkins permission is checked by the actual request and failures are attributable.
- [ ] Audit event contains no secret values.

---

## MUT-003 - Add queue cancellation and build stop

**Priority:** P2  
**Dependencies:** MUT-001, JEN-004

**Objective**

Allow narrowly approved interruption actions with clear target state.

**Implementation**

Implement separate actions for queue cancellation and running build stop, each with fresh status, preview, confirmation, no automatic retry, and post-action verification.

**Acceptance criteria**

- [ ] Completed/wrong-state targets are not treated as successful stops.
- [ ] Confirmation includes controller, full job, build/queue ID, and current state.
- [ ] Repeated requests are idempotent only in their reported outcome, not blindly resent.
- [ ] All actions are locally audited and Jenkins-attributed to the user.

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

**Acceptance criteria**

- [ ] Model cannot submit unrestricted backend queries.
- [ ] Returned external logs use the same storage/search/evidence controls.
- [ ] Source credentials never cross into Jenkins requests or vice versa.
- [ ] Network and data-volume budgets are measurable.

---

## INT-004 - Add optional work-item and source-host correlation

**Priority:** P3  
**Dependencies:** INT-001, SCM-001

**Objective**

Enrich triage with explicitly referenced Jira/Bitbucket/GitHub/GitLab objects.

**Implementation**

Resolve approved keys/commit/PR identifiers, retrieve minimal metadata, and return links/summaries. Avoid broad project scraping or automatic inclusion of private discussion content.

**Acceptance criteria**

- [ ] Correlation requires an explicit identifier or policy-approved extraction rule.
- [ ] Access uses the current user's separate credentials.
- [ ] Results remain bounded and source-labeled.
- [ ] Failure of external correlation does not block Jenkins diagnosis.

---

## GWY-001 - Implement AgentCore per-user Jenkins 3LO/OBO credential provider

**Priority:** P2  
**Dependencies:** OAUTH-010, INT-001

**Objective**

Provide an optional gateway credential provider that obtains Jenkins-audience tokens for the validated caller through user-delegated authorization-code 3LO and/or OBO/token exchange.

**Implementation**

Integrate AgentCore workload identity and outbound OAuth credential retrieval. Support approved `AUTHORIZATION_CODE` user federation with an Entra-backed `MicrosoftOAuth2`/`CustomOauth2` provider and approved `TOKEN_EXCHANGE` or JWT authorization-grant OBO. When consent is needed, propagate the AgentCore authorization URL/session metadata to the caller without exposing tokens. Cache and refresh only through approved AgentCore Identity/Token Vault semantics keyed to user and workload. Never point provider authorization/token endpoints at stock Jenkins and never fall back to a shared Jenkins identity.

**Acceptance criteria**

- [ ] Each request is attributable to the validated caller, workload, and Jenkins principal.
- [ ] Authorization-code consent and callback/session binding cannot be replayed across users/providers.
- [ ] Token cache, refresh, force-reauthentication, and revocation behavior is isolated per user/workload.
- [ ] Wrong subject, audience, tenant, provider, return URL, or session binding fails closed.
- [ ] Provider exposes no token, client secret, or authorization code to MCP tools, logs, or support bundles.
- [ ] Jenkins endpoints are never used as OAuth authorization/token endpoints unless the conditional JAS epic is deployed and approved.

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

**Objective**

Prove AgentCore mode meets identity, consent, latency, availability, isolation, and audit requirements across user-delegated 3LO and OBO/token exchange.

**Implementation**

Load/chaos-test authorization-code consent and session binding, OBO/token exchange, access/refresh-token vault hits/misses, force reauthentication, IdP/JWKS outages, revocation, concurrency, cross-user/workload isolation, gateway retries, Jenkins fallback behavior, and end-to-end audit. Compare user-delegated 3LO, OBO/token exchange, and exact-Jenkins-audience JWT passthrough. Document the selected production mode and why the alternatives are disabled or retained only for testing.

**Acceptance criteria**

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

---

## MGR-001 - Sign and enforce enterprise policy bundles

**Priority:** P2  
**Dependencies:** CFG-002, POL-002, FND-008

**Objective**

Let security centrally constrain auth, tools, limits, storage, telemetry, and updates.

**Implementation**

Define versioned signed policy bundles, trusted keys, expiry/rollback rules, local cache, and safe bootstrap. Policies can disable features/lower limits but not include credentials.

**Acceptance criteria**

- [ ] Invalid, expired, downgraded, or untrusted policy fails according to documented safe mode.
- [ ] User config cannot weaken enforced values.
- [ ] Effective policy and source are explainable without leaking sensitive internal details.
- [ ] Key rotation and emergency policy replacement are tested.

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
- [ ] Windows endpoint-security-on measurements are included.
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

**Objective**

Validate real workflows and performance with a small approved user group.

**Implementation**

Deploy signed builds, collect approved metrics and structured feedback, sample network/cache behavior, track auth/support issues, and maintain rapid rollback. Use API-token and OAuth cohorts if OAuth is ready.

**Acceptance criteria**

- [ ] No shared credentials are used.
- [ ] Network and result-size targets are measured on real workflows.
- [ ] No secret/privacy incident occurs; any incident triggers the documented response.
- [ ] Pilot exit report lists defects, SLOs, adoption, and go/no-go recommendation.

---

## REL-002 - Pass production release gates

**Priority:** P0  
**Dependencies:** All features selected for release

**Objective**

Make production approval evidence-based.

**Implementation**

Assemble a versioned release-evidence bundle, execute every applicable security, performance, reliability, compatibility, and usability gate, record deviations and approved exceptions, collect named owner sign-offs, and produce a go/no-go decision linked to the exact release artifacts. The release pipeline must block publication when a mandatory gate has no passing evidence or approved exception.

**Acceptance criteria**

- [ ] Security: personal identity, secret handling, read-only default, origin controls, cache privacy, SBOM/signing, and independent review pass.
- [ ] Performance: no hidden log over-download, cache reuse, response limits, reference SLOs, and L2 random access pass.
- [ ] Reliability: crash/disk/corruption/cancellation/outage/migration tests pass.
- [ ] Compatibility: Jenkins LTS/plugin, OS, Cursor, MCP conformance, and auth matrices pass.
- [ ] Usability: install, profile, login, identity verification, diagnosis, cache purge, and `doctor` complete successfully from documentation.
- [ ] Ownership: on-call/support, vulnerability response, Jenkins-side OAuth owner, and release owner are named.

---

# Cross-cutting acceptance scenarios

These scenarios become end-to-end tests and release evidence.

## Scenario A - Personal API token with no plaintext secret

- Signed local binary starts from a secret-free Cursor profile.
- User enters a personal token through a non-echoing prompt; it exists only in Windows Credential Manager and process memory.
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

# Recommended implementation sequence

1. FND-001 through FND-008, PERF-001, SEC-001, AUTH-000, and ARC-000.
2. CFG-001/002, AUTH-001 through AUTH-004, NET-001 through NET-004, and STO-001/002.
3. POL-001 through POL-004 plus MCP-001/002. No mutation tool may be registered before these controls exist.
4. LOG-001/002 and STO-003/004; then LOG-003/004, SEARCH-001/002, SEC-002/003, and POL-005.
5. AUD-001, OBS-001, OPS-001, TST-001, PKG-001, and the local read-only pilot gate.
6. OAUTH-001 through OAUTH-008, then OAUTH-009. Run OAUTH-010 as the AgentCore 3LO/OBO feasibility prototype and OAUTH-011 as the explicit Jenkins-authorization-server decision gate.
7. ARC-001 through ARC-004, ARC-010 through ARC-012, ARC-005 through ARC-008, and PERF-002. ARC-011 defines bounded semantic grouping before ARC-005 publishes packs.
8. JEN/PIPE/TEST/SCM/GRAPH/ART/HEALTH, followed by DIAG-001 through DIAG-007 and PERF-003.
9. Optional AgentCore productionization (GWY-001 through GWY-004), signed policy/fleet management, controlled mutations, and external integrations.
10. Execute JAS-001 through JAS-005 only after an OAUTH-011 **go** decision. The normal external-IdP resource-server/AgentCore 3LO-OBO release path must not depend on this conditional epic.
11. QA, documentation, local/gateway pilots, and production release gates.

Tasks in a step run in parallel only when declared dependencies permit. Authentication semantics, signed policy, public tools, subject/cache isolation, Zstandard/TAR formats, and `ratarmount-rs` compatibility require architecture and security review.

---

# First sprint recommendation

Complete or substantially advance:

- FND-001 through FND-004 and PERF-001.
- LOG-001 proof that an 8 KiB request against a large log transfers and allocates only bounded bytes.
- SEC-001 and AUTH-000 to lock no-native-3LO terminology, identity, and trust boundaries.
- POL-001 demonstration from Cursor configuration, including direct/crafted bypass attempts.
- POL-002/003 policy schema and trusted-subject spike that restricts a Jenkins administrator to one read-only folder.
- OAUTH-008 capability matrix proving the roles of Jenkins core, `oic-auth`, `oidc-provider`, `github-oauth`, `oauth-credentials`, and `jwt-auth-filter`.
- ARC-000 code, license, supply-chain, API, Windows, recovery, and performance qualification of the exact engineering-supplied `ratarmount-rs` repository and pinned revision.
- ARC-002 spike producing and validating a multi-frame seekable `.tar.zst`, rejecting a single-frame archive, and reading the same range through the native reader and the qualified Rust path when available.

The sprint demo should preserve existing Jenkins reads while showing bounded network/allocation behavior, secret-free local configuration, effective read-only provenance, deny-only RBAC, an approved authentication ADR, an honest exact-dependency `ratarmount-rs` qualification status, and measured random access into compressed related-log storage.
