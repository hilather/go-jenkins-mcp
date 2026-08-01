# Privacy and data-retention review (QA-006 MVP pack)

**Audience:** security reviewers, privacy, platform owners, pilot operators.  
**Related:** [operator-guide.md](operator-guide.md), [threat-model.md](threat-model.md), [cache-encryption.md](cache-encryption.md), [release gates (REL-002)](../release/gates.md), [observability](../observability.md)

This document is the **MVP privacy / data-retention inventory** for go-jenkins-mcp.
It maps what is stored, exported, retained, purged, and deliberately excluded.
SSD secure-erasure limitations are stated honestly.

---

## 1. Data classes

| Class | Examples | Sensitivity | Default location (Tier-1 Linux) |
|-------|----------|-------------|----------------------------------|
| **Credentials** | Jenkins API tokens, optional cache AEAD keys | **Secret** | OS Secret Service (`libsecret`); never profile JSON |
| **Profile config** | Jenkins URL, username, TLS **paths**, RO flags | Low–medium | `$XDG_CONFIG_HOME/jenkins-mcp/profiles/` |
| **L1 log frames** | Progressive console text (compressed independent zstd frames) | Medium–high (build content) | Profile data dir under `$XDG_DATA_HOME/jenkins-mcp/` |
| **L2 packs** | Seekable multi-frame `.tar.zst` affinity packs | Medium–high | `<dataDir>/archives/` |
| **Store metadata** | SQLite gen catalog, quotas, pins, pack refs | Medium | Profile data dir |
| **Audit events** | Tool allow/deny, login success/fail (privacy-preserving fields) | Low–medium | Profile data dir audit JSONL |
| **Telemetry (local)** | In-process counters, structured logs with redaction | Low | Process memory; optional stderr |
| **Support bundle** | Version, doctor, cache status, metrics snapshot | Low (scrubbed) | `$XDG_CACHE_HOME/jenkins-mcp/…` zip mode 0600 |
| **Policy overlay** | Deny-tools, force RO, result caps | Low | Operator-supplied path / env |
| **Adapter state** | Optional INT-001 lifecycle only (MVP: none by default) | Low | Process memory |

### Classification notes

- Treat **all Jenkins-sourced text** (logs, test names, artifact metadata) as **untrusted** and potentially sensitive.
- **Tokens and private keys** are secrets; any presence in non-keyring surfaces is a defect.
- **Audit** stores opaque target hashes and reason codes — not full log bodies or prompts.

---

## 2. Retention defaults

| Data class | Default retention | Notes |
|------------|-------------------|-------|
| Credentials (keyring) | Until `logout` / manual keyring delete | Not time-TTL'd by MCP |
| Profile JSON | Until `profile remove` | Non-secret fields only |
| L1 frames | Quota + maintenance eviction; optional L1 release after verified L2 | `app.Maintainer` + `store.QuotaManager` |
| L2 packs | Until eviction / manual cache purge | Format versioned; recovery paths documented in archive docs |
| Audit JSONL | Size-based rotation (file sink) | No in-process remote SIEM ship (residual **AUD-T-010…012**); host-agent tail OK — see [audit-trail-review.md](audit-trail-review.md) |
| Support bundles | Operator-managed; not auto-uploaded | Create on demand; preview first |
| Local telemetry | Process lifetime | In-process counters; stderr logs redacted |
| Fleet telemetry queue | Bounded local queue under XDG data | **Disabled by default** (MGR-002); see [fleet-telemetry.md](fleet-telemetry.md) |
| Adapters | Process lifetime | Disabled by default |

**Residual:** org-wide retention SLAs, legal hold, and **in-process** remote SIEM shipping remain open (task backlog in [audit-trail-review.md](audit-trail-review.md)). Operators may ship local `audit.jsonl` via host agents today. Fleet **telemetry** export requires explicit `JENKINS_MCP_TELEMETRY=1` plus privacy approval of the schema in [fleet-telemetry.md](fleet-telemetry.md) — that plane is not the AUD-001 audit trail.

---

## 3. Purge commands and controls

| Goal | Command / action |
|------|------------------|
| Remove Jenkins credential | `jenkins-mcp logout --profile <id>` |
| Remove profile config | `jenkins-mcp profile remove <id>` |
| Inspect cache | `jenkins-mcp cache status --profile <id>` |
| Verify / repair cache | `jenkins-mcp cache verify|repair --profile <id>` |
| Quota-driven eviction | Serve-time maintenance (default on); `--no-cache-maintenance` disables loop |
| Full local data wipe | Delete profile data dir under XDG data home **and** logout; then remove profile |
| Support bundle | `jenkins-mcp support-bundle --profile <id> [--preview]` |

**Logout / uninstall:** logout drops keyring entries for the profile origin; it does not always delete on-disk log frames. Operators who need “leave no catalog references” should remove the profile data directory after logout (catalog is SQLite under that tree). Automated full-wipe CLI is a residual improvement.

### SSD / secure erasure residual

Deleting files (including `shred`-like tools) does **not** guarantee cryptographic erase on SSDs with wear-leveling. For high-sensitivity controllers:

1. Prefer **full-disk encryption** at the OS level.
2. Prefer **opt-in cache AEAD** (ARC-009) so discarded frames are ciphertext.
3. Document that `rm` of the data dir is **best-effort** against forensic recovery on flash media.

---

## 4. Encryption residual

| Layer | MVP posture |
|-------|-------------|
| TLS to Jenkins | Verify on by default; custom CA / mTLS via profile **paths** |
| At-rest L1 frames | Optional AES-256-GCM (ARC-009); off unless key init |
| At-rest L2 body | Re-encrypt residual; do not claim full L2 AEAD by default |
| Audit / support zip | Filesystem ACLs + 0600; not AEAD-wrapped |
| Keyring | OS Secret Service |

See [cache-encryption.md](cache-encryption.md).

---

## 5. What is **never** exported

These must not appear in MCP tool results, audit JSON, support bundles, telemetry labels, CLI status, or doctor messages:

| Item | Enforcement |
|------|-------------|
| API tokens / passwords | Keyring-only; canary tests |
| Authorization headers | Redact + bundle exclusions |
| Full build logs in telemetry | Metrics are counters only |
| Full build logs in support bundle | Explicitly excluded category |
| Artifact bodies | Excluded from bundle |
| Private keys / client key material | Paths only in profile |
| Cookies | Excluded |
| Raw HTTP transcripts | Not collected |
| Adapter secrets (future) | Separate namespace; same canary rules |

**Preview first:** `jenkins-mcp support-bundle --preview` lists included/excluded categories without writing a zip.

### Automated canaries (must stay green)

```bash
go test ./internal/diagnostics/ -count=1 -run 'Canary|SupportBundle'
go test ./internal/audit/ -count=1 -run 'Canary|Redaction'
go test ./internal/redact/ -count=1 -run 'Canary'
# Combined privacy surface (QA-006):
go test ./internal/diagnostics/ ./internal/audit/ -count=1 -run 'Privacy|Canary'
```

---

## 6. Support bundle categories (approved)

| Included (OPS-001 / Wave 23) | Excluded |
|------------------------------|----------|
| version / commit / GOOS | tokens, keyring values |
| effective profile (no secrets) | full_build_logs / raw_log_samples |
| doctor report (sanitized) | artifact bodies |
| cache status | Authorization headers |
| capability summary (secret keys dropped) | cookies / private keys |
| metrics snapshot | raw HTTP |
| error signature hashes (no full log text) | planted canary secrets |
| security_self_check (offline QA-005) | cache encryption keys |
| release_evidence_lite (version/runtime only) | full REL-002 gate pack claims |
| rs_qualification_summary (offline OAUTH-009 matrix) | live jwt-auth-filter lab secrets |
| gateway-residual-status.json (always; BuildGatewayResidualStatus) | tokens/subjects; never live GO claims |

---

## 7. Telemetry policy (local + fleet MVP)

| Allowed | Forbidden |
|---------|-----------|
| Counter increments (tool calls, cache hits) | Log text payloads |
| Redacted structured fields | Tokens, Authorization |
| Error signature hashes | Unbounded stack dumps with request bodies |
| Fleet export schema v1 (allowlisted counters, apperr codes, pseudonymous install id) | Free-text labels, raw profile ids, credential URLs |

Fleet health telemetry (MGR-002) is documented in [fleet-telemetry.md](fleet-telemetry.md).
**Disabled by default.** Enable only after privacy review of that schema.

---

## 8. REL-002 gate checklist (privacy / retention)

Use with [`docs/release/gates.md`](../release/gates.md) and [`evidence-template.md`](../release/evidence-template.md).

| # | Gate | Evidence | Pass? |
|---|------|----------|-------|
| P1 | Data inventory approved (this doc §1–2) | Link + reviewer sign-off | |
| P2 | Support-bundle exclusions match §5–6 | `go test ./internal/diagnostics -run Canary` + `--preview` | |
| P3 | Audit redaction canary | `go test ./internal/audit -run Canary` | |
| P4 | Cache purge path documented (§3) | Operator guide + pilot checklist | |
| P5 | Encryption residual honest (§4) | No over-claim of default at-rest crypto | |
| P6 | Telemetry has no full logs (§7) | Code review + telemetry tests | |
| P7 | SSD erase limitations stated (§3) | This doc | |
| P8 | No secrets in release artifacts | `release-evidence --offline`; SBOM without env secrets | |
| P9 | Adapters default off (INT-001) | `go test ./internal/adapter -run DisabledByDefault` | |
| P10 | Independent privacy/security review | QA-005 / org process | |

**REL-002 decision:** privacy rows above must be **pass** or **approved exception** before broad production.

---

## 9. User / admin controls summary

| Control | Who | How |
|---------|-----|-----|
| Read-only | User / enterprise | `--read-only`, env, profile, enterprise force |
| Deny tools | Enterprise | Policy overlay `deny_tools` |
| Result size | Enterprise | Overlay `max_result_bytes` (lower only) |
| Cache encryption | User | `cache key init` (opt-in) |
| Support share | User | Explicit bundle command + preview |
| Integrations | User / operator | `--enable-adapter` (default none) |
| Fleet telemetry | User / operator | Off by default; `JENKINS_MCP_TELEMETRY=1`; inspect via `telemetry status` / `show` |

---

## 10. Residuals (not claimed done)

- [ ] Signed allowlist / adapter provenance
- [ ] Automated full-profile wipe command with catalog verification
- [x] Fleet telemetry export schema privacy notes (MGR-002 MVP) — see [fleet-telemetry.md](fleet-telemetry.md); formal board sign-off residual
- [ ] Guaranteed secure erase on SSD
- [ ] Legal hold / e-discovery workflow
- [ ] Field-level retention TTLs per data class in SQLite

---

## Revision

| Date | Change |
|------|--------|
| 2026-08 | QA-006 MVP pack: inventory, purge, canaries, REL-002 checklist |
| 2026-08 | MGR-002: fleet telemetry schema + controls link |
