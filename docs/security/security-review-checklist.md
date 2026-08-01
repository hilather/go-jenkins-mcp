# Security review checklist (QA-005 MVP self-assessment)

**Status:** Automated self-check + operator checklist for implemented controls  
**Not a claim:** This document and `jenkins-mcp security self-check` do **not** complete an independent penetration test. External review remains required before broad production (see residuals).

**Related:** [threat-model.md](./threat-model.md), [operator-guide.md](./operator-guide.md), [policy-bundles.md](./policy-bundles.md), [privacy-data-retention.md](./privacy-data-retention.md), [fleet-telemetry.md](./fleet-telemetry.md), [ADR 0003](../adr/0003-jenkins-not-oauth-authorization-server.md), [ADR 0004](../adr/0004-global-read-only-and-deny-only-rbac.md)

---

## How to run the offline self-check

```bash
export PATH="$HOME/.local/go/bin:$PATH"
jenkins-mcp security self-check
jenkins-mcp security self-check --json
jenkins-mcp security self-check --profile <id> --json   # OIDC structural when oidc_bearer
```

Exit codes:

| Overall | Exit | Meaning |
|---------|------|---------|
| `ok` / `warn` / `info` | 0 | Canaries passed; warn is advisory (e.g. unsigned pilot policy) |
| `fail` | non-zero | At least one hard canary failed |

The report always sets `independent_review_required: true`.

---

## Control map (implemented → review evidence)

| ID | Control | Implementation evidence | Self-check item | Reviewer focus |
|----|---------|-------------------------|-----------------|----------------|
| **POL-001** | Global read-only default; force RO cannot be defeated; mutations opt-in default false | `internal/policy/readonly.go`; serve defaults; ADR 0004 | `read_only_default`, `mutations_opt_in_default` | CLI/env/profile source OR; no surprise mutation registration (`AllowMutationsOptIn` false) |
| **MUT-001** | Mutation preview/confirm; token TTL + confirm cooldown; process-local rate limit; Binding (profile+principal+ExternalSubject+tenant) | `internal/mutation` Manager (DefaultTokenTTL 2m, DefaultConfirmCooldown 5s); multi-user `BindingFromContext`; serve `mutationBindingFromGatewayCtx` prefers PolicySubject PrincipalID | `mutation_confirm_cooldown_residual`; Alice/Bob binding + PrincipalID-only mismatch tests | Offline Preview+Confirm + immediate re-Confirm denied (`confirm_cooldown`); Alice token rejected for Bob (`binding_mismatch`) including PrincipalID; mutations remain opt-in / RO default; **Done\*** per-request principal via HTTP claim/lab **or** PrincipalCache after Obtain; policy RBAC JenkinsUserID also prefers PrincipalCache after Obtain (`policySubjectFromGatewayCtx`) |
| **POL-002/003** | Deny-only MCP RBAC; subjects from verified process identity | `internal/policy/rbac.go`, `subject.go` | (unit POL-005) | No `allow_tools` / `grant_jenkins`; empty/anon deny |
| **POL-004** | Multi-layer PEPs (handler, Jenkins network, store) | `enforce.go`, `requestclass.go` | (unit) | Unclassified POST fail closed under RO |
| **POL-005** | Adversarial / monotonicity tests | `conformance_test.go`, tools pol tests | (unit suite) | Adding deny never increases access |
| **SEC-002** | Layered redaction / model sanitize + enterprise patterns file + **Writer line buffer** | `internal/redact` (incl. `Writer` line reassembly), serve `JENKINS_MCP_REDACT_PATTERNS_FILE`, `redact validate-patterns` | `redaction_canary`, `writer_split_line_canary`, `report_canary_leak`, enterprise_load_test, serve helper | Canary secrets never in logs/MCP/support; split-Write Bearer canary absent after Flush; invalid patterns fail closed; no match logging |
| **SEC-001** | Threat model + data classes | [threat-model.md](./threat-model.md) | (doc review) | Assets, actors, trust boundaries current |
| **AUTH-001/002** | Personal API token in OS keyring (Tier-1 Secret Service) | `internal/keyring`, login CLI | doctor keyring presence | No tokens in argv/profile JSON/git |
| **AUTH-004** | whoAmI bind / mid-serve re-verify + configurable TTL + Wave 28 audit on fail-closed re-verify + **Wave 29** ListTools AuthGate empty-list | `identity.go`, `identity_reverify.go`, serve AuthGate + `--identity-reverify-ttl` / `JENKINS_MCP_IDENTITY_REVERIFY_TTL`; audit sink on gate; `list_tools_filter.go` AuthGate | identity_test (Parse bounds); identity_reverify_test (TTL + audit once/no flood/nil sink); ListToolsFilter_AuthGate*; doctor identity | Not every-call whoAmI (by design); residual: TTL window for revoked token until next re-verify |
| **OAUTH-001** | External IdP OIDC profile; Jenkins not AS | `profile.OIDC`, discovery | `oidc_profile_structural` | Audience = Jenkins resource; issuer ≠ Jenkins |
| **OAUTH-003+** | Token validation / audience | `internal/auth` JWT | residual live | Access token for Jenkins RS only |
| **OAUTH-009** | jwt-auth-filter / RS offline contracts + OfflineFallthroughFixtures matrix | `rs_qualification.go`, `rs_fallthrough.go` | `rs_qualification` | Fixture count ≥12 (Basic/anon + status-wins expand); `live_lab_still_required`; Mode B → warn + `residual_id=oauth009_offline`; offline fallthrough/JWKS/routes; live lab residual (not Entra Done) |
| **KD-008** | Streamable HTTP shared-secret + Host allow-list; non-local always requires token + origins + hosts | `internal/mcpserver` `ValidateHTTPConfig` / `RequireToken` / `AllowNonLocal` / `AllowedHosts`; CLI `JENKINS_MCP_HTTP_DENY_ANONYMOUS` alias | `http_require_token_residual`, `http_allowed_hosts_residual` | Empty token + non-local fail closed; empty AllowedHosts + non-local fail closed (independent of token); loopback without require-token / deny-anonymous residual (off by default; prefer stdio) |
| **NET-001** | Origin pin; no credential cross-origin | `internal/jenkins/origin.go` | `jenkins_origin_pin_residual` | Pure offline NormalizeBaseURL+SameOrigin; live reverse-proxy residual |
| **NET-004** | TLS verify; diagnostic insecure dual-gated | transport + env gate | `origin_tls_posture` | Never persist skip-verify |
| **MGR-001** | Signed policy bundles (Ed25519) | `bundle.go`, `ed25519.go`, `overlay.go` | `policy_signature_mode` | Production: trusted keys + `JENKINS_MCP_REQUIRE_SIGNED_POLICY=1` |
| **MGR-002** | Fleet telemetry **off by default**; overlay `fleet_telemetry_force_off` pin lite | `internal/telemetry/fleet`, `internal/policy` | `telemetry_default_off`, `fleet_telemetry_force_off_residual` | Categories approved; no logs/tokens; `policy_overlay_pin=true` lite (privacy board + HSM residual) |
| **OPS-001** | Privacy-scrubbed support bundle | `support_bundle.go` | `support_bundle_canary` | Excludes keyring, full logs, auth headers |
| **MCP-001** | Tool response budgets; absolute hard-max + soft-target process caps | `internal/tools` `ResolveHardMaxBytes`, `AbsoluteMaxHardMaxBytes` (64 MiB), `ResolveTargetBytes`, `AbsoluteMaxTargetBytes` (64 MiB), `EnforceBudget` | `hard_max_resolve_residual`, `operator_caps_snapshot` | Hard default 1 MiB (raise ≤ 64 MiB); soft target default 64 KiB (raise ≤ 64 MiB); oversize fail closed; soft clamped to live hard max; overlay only lowers hard; serve log is byte counts only |
| **ARC-009** | Cache AEAD keys in keyring only | cache key CLI | doctor/cache key status | Keys never in packs/profile |
| **GWY-002** | Identity not spoofable via tool args | `RejectIdentityToolArgs` | POL-005 spoof tests | Gateway binding only |
| **TST-001** | Route matrix classified auth/read/mutation | `docs/tst/route-matrix.json` | (unit matrix) | Every CallJenkins path inventoried |
| **PKG-001** | Signed packages / supply chain | residual | residual | Release signing evidence |

---

## Reviewer walk-through (manual)

Use this during independent review; check boxes only when **external** evidence exists.

### Authentication and tokens

- [ ] API tokens / OIDC refresh material only in OS secret store (or gateway vault)
- [ ] No secrets in CLI argv examples, fixtures, CI logs, MCP schemas/results
- [ ] Login does not print token values; logout clears keyring entry
- [ ] OIDC: issuer is external IdP; Jenkins is resource server only (ADR 0003)
- [ ] Access tokens validated for configured Jenkins audience

### Authorization (RO + RBAC)

- [ ] Default process is read-only; mutations absent from ListTools
- [ ] `--allow-mutations` defeated by force_read_only / enterprise overlay
- [ ] MCP deny restricts even Jenkins admins
- [ ] MCP allow never elevates Jenkins-denied resources
- [ ] Policy reload / deny expansion blocks store reads (CheckStoreRead)
- [ ] Strict mode denies unknown tools
- [ ] Tool args cannot set subject / impersonation keys

### Network and Jenkins surface

- [ ] Credentials only to pinned origin; cross-origin redirect refused
- [ ] Route matrix complete for MCP CallJenkins paths ([TST-001](../tst/README.md))
- [ ] Mutation and unclassified POSTs blocked under RO at network PEP
- [ ] Progressive logs bounded (LOG-001); no unbounded ReadAll
- [ ] TLS verification default; diagnostic insecure dual-gated and loud

### Local storage and support

- [ ] Profile data dirs user-private (STO-001)
- [ ] Support bundle categories match OPS-001 exclusions
- [ ] Cache encryption keys (if enabled) only in keyring
- [ ] Audit events free of Authorization headers / tokens

### Telemetry and policy integrity

- [ ] Telemetry off unless explicit enable + approved categories
- [ ] Production policy: signed Ed25519 bundle, trusted keys, last-good cache
- [ ] Unsigned pilot overlays documented as non-production

### Gateway (if in scope)

- [ ] Per-user delegated credentials; no shared SA
- [ ] Identity binding from gateway only; RejectIdentityToolArgs enforced
- [ ] Same RO ∩ MCP policy ∩ budgets as local mode

---

## Offline self-check items (Wave 34 expand)

| Item | Status meaning (typical) | What it proves offline |
|------|--------------------------|------------------------|
| `redaction_canary` | ok | `RedactText` removes planted Bearer/password canary |
| `writer_split_line_canary` | ok | `redact.Writer` reassembles split Authorization Bearer across two `Write`s + `Flush` (Wave 33 line buffer) |
| `support_bundle_canary` | ok | Category plan excludes tokens/keyring/auth headers/full logs |
| `policy_signature_mode` | info/warn/ok | Signature state of loaded policy (pilot unsigned → warn) |
| `oidc_profile_structural` | skip/ok/fail | Profile OIDC structural validate when `--profile` supplied |
| `rs_qualification` | warn | OfflineFallthroughFixtures ≥12, inventory/JWKS contracts; **`live_lab_still_required`** |
| `http_require_token_residual` | warn | `ValidateHTTPConfig` rejects empty token + `AllowNonLocal` (supplies AllowedHosts so token path is exercised); documents loopback residual (KD-008); message names `--http-require-token` / `JENKINS_MCP_HTTP_REQUIRE_TOKEN` / `JENKINS_MCP_HTTP_DENY_ANONYMOUS` (Wave 41; default off) |
| `http_allowed_hosts_residual` | ok | `ValidateHTTPConfig` rejects `AllowNonLocal` with empty `AllowedHosts` (origins+token set; host fail-closed independent of token); complete non-local config accepted (KD-008 / Wave 36) |
| `telemetry_default_off` | ok/warn | Fleet telemetry env not enabled by default |
| `fleet_telemetry_force_off_residual` | ok | MGR-002: ForceOff + overlay `fleet_telemetry_force_off` pin; `policy_overlay_pin=true`; HSM/multi-sig residual |
| `read_only_default` | ok | Builtin RO effective; force defeats allow-mutations |
| `mutations_opt_in_default` | ok | `AllowMutationsOptIn` false under zero Inputs (no surprise mutations) |
| `origin_tls_posture` | ok/warn | NET-004: diagnostic insecure TLS env not set |
| `jenkins_origin_pin_residual` | ok | Wave 50 / NET-001: pure offline NormalizeBaseURL and SameOrigin (same-host accept; cross-host/scheme reject; empty/relative fail closed) + WhoAmIPath shape; Details `normalize_base_ok`/`same_origin_accept`/`cross_origin_reject`/`whoami_path_present=true`, `residual_live_reverse_proxy=false` |
| `hard_max_resolve_residual` | ok | Wave 38: `ResolveHardMaxBytes` default → `DefaultHardMaxBytes`; value &gt; `AbsoluteMaxHardMaxBytes` (64 MiB) fails closed (MCP-001) |
| `operator_caps_snapshot` | ok/info | Wave 43–51: secret-free caps including soft TargetBytes constants (default 64 KiB / absolute 64 MiB) + resilience/HTTP/identity/collect/survey/diagnose keys; live soft-target offline honesty (`live_target_bytes_available_offline=false`) (MCP-001) |
| `listfilter_deny_only_residual` | ok | Wave 39 + Wave 40 polish: `NameDeniedByPatterns` empty patterns/name → false; `Deny*FromEvaluator` nil/empty/copy-out for nodes/jobs/views/artifacts/branches (POL-004 list-row privacy helpers present) |
| `policy_resource_deny_residual` | ok | Wave 39: `DocumentFromOverlay` copies `deny_view_names` / `deny_artifact_paths` / `deny_branch_names` / `deny_node_names` without elevating; nil overlay → pilot empty denials |
| `policy_multisig_lite_residual` | ok | Wave 42 / MGR-001: offline multi-sig lite canary — ephemeral dual keys, `MinSignatures=2` verifies 2-of-2 and fail-closes 1-of-2; Details `multi_sig_lite=true`, `residual_true_threshold=false`, `residual_hsm=false` (true *t*-of-*n* threshold crypto / HSM not implemented) |
| `adapter_framework_residual` | ok | Wave 43 / INT-001: offline adapter framework canary — empty Config loads nothing (deny-by-default), builtins present, noop Start/Health ok; Details `default_deny=true`, `builtins_present=true`, `production_otlp=false`, `production_ext_logs_saas=false`, `production_work_items_saas=false` (production OTLP/Splunk/ELK/Jira SaaS clients not implemented) |
| `adapter_allowlist_provenance_lite` | ok | Wave 44–45 / INT-001: Ed25519 allowlist provenance lite + dual-control MinSignatures lite (2-of-2 ok / 1-of-2 fail-closed); residual_cosign/hsm/sbom/multi_party/true_threshold false |
| `jenkins_resilience_residual` | ok | Wave 45 / NET-003: GET/HEAD retry + circuit; POST never auto-retry; residual live chaos |
| `update_lkg_residual` | ok | Wave 47 / UPD-001: LKG residual honesty offline — metadata only, not installed binary; install/rollback operator-owned; residual_auto_install=false |
| `mutation_confirm_cooldown_residual` | ok | Wave 48 / MUT-001: DefaultTokenTTL + DefaultConfirmCooldown positive; Manager defaults enforce confirm cooldown offline (second Confirm denied); Details `cooldown_enforced=true`, `mutations_opt_in_default=true`; residual gateway multi-tenant / live remote mutation |
| `report_canary_leak` | ok | Planted canary absent from full serialized report |

Messages and details are secret-free; the planted canary must never appear in JSON/text output.

---

## Residuals for independent review / pen-test

These are **explicitly out of scope** for the offline self-check MVP:

1. **External adversarial engagement** — social engineering, host compromise, Cursor plugin supply chain.
2. **Live Jenkins + IdP lab** — jwt-auth-filter, reverse-proxy, OAuth anti-fallback matrix (TST-001 live residual); offline RS matrix is Done* only for classifiers.
3. **HTTP loopback shared-secret optional** — KD-008 residual: loopback without `--http-require-token` / `JENKINS_MCP_HTTP_REQUIRE_TOKEN` / `JENKINS_MCP_HTTP_DENY_ANONYMOUS` remains open to local processes (default for pilot); prefer stdio (ADR 0002). Non-local always requires token (self-check asserts).
4. **Gateway production threat model** — full AgentCore 3LO/OBO, token vault, multi-tenant isolation.
5. **Supply chain** — reproducible builds, package signatures (PKG-001), update manifest trust (when shipping).
6. **Long-duration cache forensics** — SSD secure erase limitations (documented in privacy guide).
7. **Prompt-injection full red-team** — model-facing log/artifact content beyond unit canaries.
8. **Critical/high finding closure** — org process: owners, timelines, retest (QA-005 acceptance).

Until independent review signs off, treat release as **pilot-only** where policy requires it.

---

## Acceptance mapping (QA-005)

| Criterion | MVP self-assessment | Full independent review |
|-----------|---------------------|-------------------------|
| No unresolved critical/high at release | Track via org process | Required |
| Medium findings owned + timelines | Checklist residuals | Required |
| Retest of fixes | CI unit + self-check | Required |
| Operational Jenkins OAuth guidance in scope | [auth-architecture.md](../auth-architecture.md) | Confirm with reviewers |

---

## Change control

When adding a security-sensitive control:

1. Map it in this table with evidence paths.
2. Prefer an offline canary in `RunSecuritySelfCheck` or a POL-005/unit test.
3. Never mark pen-test complete from self-check alone.
